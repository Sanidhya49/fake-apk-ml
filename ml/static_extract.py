"""Static extractor for Android APKs using Androguard.

This module exposes `extract(apk_path: str) -> dict` and a simple CLI:

Usage:
    python -m ml.static_extract data

It walks the provided folder, finds `.apk` files, parses them,
and writes one JSON per APK into `artifacts/static_jsons/`.
Errors are logged and processing continues.
"""

import json
import os
import sys
import tempfile
import zipfile
from typing import Dict, List
import logging

from androguard.misc import AnalyzeAPK

# Quiet Androguard logs by default; still prints errors
logging.getLogger("androguard").setLevel(logging.WARNING)

from .utils import ensure_dirs, get_sha256


SUSPICIOUS_API_NAMES = [
    "getDeviceId",
    "sendTextMessage",
    "SmsManager",
    "DexClassLoader",
    "TYPE_SYSTEM_ALERT_WINDOW",
    "addView",
    "HttpURLConnection",
    "openConnection",
]


def _list_exported(a) -> List[str]:
    """Return a list of exported components (activities and services)."""
    exported = []
    try:
        for activity, info in (a.get_activities() or []):
            # Androguard returns tuples starting androguard 4.X (name, info)
            name = activity if isinstance(activity, str) else getattr(activity, "name", None)
            if not name:
                continue
            if info and info.get("exported"):
                exported.append(name)
    except Exception:
        # Fallback for older androguard or parsing oddities
        try:
            for activity in a.get_activities():
                if a.get_activity_exported(activity):
                    exported.append(activity)
        except Exception:
            pass
    # services
    try:
        for service, info in (a.get_services() or []):
            name = service if isinstance(service, str) else getattr(service, "name", None)
            if not name:
                continue
            if info and info.get("exported"):
                exported.append(name)
    except Exception:
        try:
            for service in a.get_services():
                if a.get_service_exported(service):
                    exported.append(service)
        except Exception:
            pass
    return sorted(set(exported))


def _get_cert_subject(a) -> str:
    try:
        certs = a.get_certificates()
        if not certs:
            return "unknown"
        cert = certs[0]
        subject = getattr(cert, "subject", None)
        if subject:
            return str(subject)
        # Some versions expose X509 object differently
        try:
            return cert.subject.human_friendly
        except Exception:
            return "unknown"
    except Exception:
        return "unknown"


def _get_cert_issuer(a) -> str:
    try:
        certs = a.get_certificates()
        if not certs:
            return "unknown"
        cert = certs[0]
        issuer = getattr(cert, "issuer", None)
        if issuer:
            return str(issuer)
        try:
            return cert.issuer.human_friendly
        except Exception:
            return "unknown"
    except Exception:
        return "unknown"


def _extract_domains_from_zip(apk_or_bundle_path: str) -> List[str]:
    """Heuristic: scan archive contents for URL-like domains.

    Lightweight IOC extraction; we do not fully decode DEX.
    """
    import re

    url_re = re.compile(rb"(?:(?:https?://)?)([a-zA-Z0-9.-]{3,255}\.[a-zA-Z]{2,24})")
    seen = set()
    out: List[str] = []
    try:
        with zipfile.ZipFile(apk_or_bundle_path, 'r') as zf:
            for zi in zf.infolist():
                if zi.file_size > 5 * 1024 * 1024:
                    continue
                try:
                    with zf.open(zi) as fh:
                        data = fh.read()
                        for m in url_re.finditer(data):
                            dom = m.group(1).decode(errors="ignore").lower().strip('.')
                            if dom and dom not in seen:
                                seen.add(dom)
                                out.append(dom)
                except Exception:
                    continue
    except Exception:
        pass
    return out[:200]


def _count_dex_files(apk_or_bundle_path: str) -> int:
    """Return number of .dex files inside the archive (cheap heuristic)."""
    try:
        with zipfile.ZipFile(apk_or_bundle_path, 'r') as zf:
            return sum(1 for zi in zf.infolist() if zi.filename.lower().endswith('.dex'))
    except Exception:
        return 0


def _parse_cn(name_text: str) -> str:
    """Extract CN=... from the certificate string if present (best-effort)."""
    import re
    try:
        m = re.search(r"CN=([^,>]+)", str(name_text))
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return ""


def _resolve_actual_apk(apk_path: str) -> (str, callable):
    """Return a real APK file path to analyze.

    For .apks/.xapk bundles, extract the embedded base APK to a temp file and
    return its path along with a cleanup function. For normal .apk files,
    return the original path and a no-op cleanup.
    """
    lower = apk_path.lower()
    if lower.endswith((".apks", ".xapk")):
        tmpdir = tempfile.mkdtemp(prefix="apk_bundle_")
        chosen = None
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Prefer a file named base.apk; else choose the largest .apk inside
                apk_members = [zi for zi in zf.infolist() if zi.filename.lower().endswith('.apk')]
                if not apk_members:
                    raise FileNotFoundError("Bundle does not contain any .apk files")
                base = None
                for zi in apk_members:
                    if os.path.basename(zi.filename).lower() == 'base.apk':
                        base = zi
                        break
                chosen = base or max(apk_members, key=lambda zi: zi.file_size)
                out_path = os.path.join(tmpdir, os.path.basename(chosen.filename))
                with zf.open(chosen) as src, open(out_path, 'wb') as dst:
                    dst.write(src.read())
            return out_path, (lambda: __import__('shutil').rmtree(tmpdir, ignore_errors=True))
        except Exception:
            # Cleanup tempdir if extraction failed
            try:
                __import__('shutil').rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass
            raise
    # Normal .apk
    return apk_path, (lambda: None)


def _minimal_record(apk_path: str, sha256: str, package: str = "", version: str = "", app_label: str = "", error: str = "") -> Dict:
    return {
        "file_name": os.path.basename(apk_path),
        "sha256": sha256,
        "package": package or "",
        "version": version or "",
        "permissions": [],
        "exported": [],
        "suspicious_apis": {name: 0 for name in SUSPICIOUS_API_NAMES},
        "cert_subject": "unknown",
        "cert_issuer": "unknown",
        "app_label": app_label or "",
        "domains": [],
        "source_path": os.path.abspath(apk_path),
        "parse_error": error or "",
    }


def extract(apk_path: str, quick: bool = False) -> Dict:
    """Extract simple static features from an APK file.

    Returns a dictionary with keys:
      - file_name, sha256, package, version
      - permissions: List[str]
      - exported: List[str]
      - suspicious_apis: Dict[str, int]
      - cert_subject: str
    """
    sha256 = get_sha256(apk_path)
    real_apk_path, cleanup = _resolve_actual_apk(apk_path)
    try:
        # Parse APK
        a, _, dx = AnalyzeAPK(real_apk_path)

        # Basic identifiers
        package = a.get_package() or ""
        version_name = a.get_androidversion_name() or ""
        try:
            app_label = a.get_app_name() or ""
        except Exception:
            app_label = ""

        # APK size (bytes) for easy reporting
        try:
            file_size = os.path.getsize(apk_path)
        except Exception:
            file_size = 0

        # Permissions
        try:
            permissions = sorted({p.split(".")[-1] for p in (a.get_permissions() or [])})
        except Exception:
            permissions = []

        # Exported activities/services
        exported = _list_exported(a)

        # Suspicious APIs via method names across the analysis
        suspicious = {name: 0 for name in SUSPICIOUS_API_NAMES}
        if not quick:
            try:
                for method in dx.get_methods():
                    mname = method.method.name if hasattr(method, "method") else getattr(method, "name", "")
                    for needle in suspicious.keys():
                        if needle in mname:
                            suspicious[needle] = 1
            except Exception:
                pass

        cert_subject = _get_cert_subject(a)
        cert_issuer = _get_cert_issuer(a)
        cert_subject_cn = _parse_cn(cert_subject) if cert_subject and cert_subject != "unknown" else ""
        cert_issuer_cn = _parse_cn(cert_issuer) if cert_issuer and cert_issuer != "unknown" else ""

        # IOC domains and DEX count from archive scan (still cheap). Do this before cleanup()!
        domains = _extract_domains_from_zip(real_apk_path) if not quick else []
        num_dex = _count_dex_files(real_apk_path)

        # SDK info and component counts (best-effort)
        try:
            min_sdk = int(a.get_min_sdk_version() or -1)
        except Exception:
            min_sdk = -1
        try:
            target_sdk = int(a.get_target_sdk_version() or -1)
        except Exception:
            target_sdk = -1
        try:
            activities = a.get_activities() or []
            num_activities = len(activities)
        except Exception:
            activities = []
            num_activities = 0
        try:
            services = a.get_services() or []
            num_services = len(services)
        except Exception:
            services = []
            num_services = 0
        try:
            receivers = a.get_receivers() or []
            num_receivers = len(receivers)
        except Exception:
            receivers = []
            num_receivers = 0
        try:
            main_activity = a.get_main_activity() or ""
        except Exception:
            main_activity = ""

        return {
            "file_name": os.path.basename(apk_path),
            "sha256": sha256,
            "package": package,
            "version": version_name,
            "permissions": permissions,
            "exported": exported,
            "suspicious_apis": suspicious,
            "cert_subject": cert_subject,
            "cert_issuer": cert_issuer,
            "cert_subject_cn": cert_subject_cn,
            "cert_issuer_cn": cert_issuer_cn,
            "app_label": app_label,
            "domains": domains,
            "file_size": int(file_size),
            "num_dex": int(num_dex),
            "min_sdk": int(min_sdk),
            "target_sdk": int(target_sdk),
            "num_activities": int(num_activities),
            "num_services": int(num_services),
            "num_receivers": int(num_receivers),
            "num_permissions": int(len(permissions)),
            "num_exported": int(len(exported)),
            "main_activity": main_activity,
            # keep original path to infer labels later
            "source_path": os.path.abspath(apk_path),
        }
    except Exception as e:
        # Return minimal record instead of failing outright
        return _minimal_record(apk_path, sha256, error=str(e))
    finally:
        # Ensure temporary bundle extraction is cleaned up after all reads
        try:
            cleanup()
        except Exception:
            pass


def _walk_apks(root: str) -> List[str]:
    apks = []
    for r, _d, files in os.walk(root):
        for f in files:
            name = f.lower()
            if name.endswith((".apk", ".apks", ".xapk")):
                apks.append(os.path.join(r, f))
    return apks


def main_cli():
    if len(sys.argv) < 2:
        print("Usage: python -m ml.static_extract <folder_with_apks> [--quick] [--workers N]")
        sys.exit(1)
    folder = sys.argv[1]
    quick = False
    workers = 1
    # Simple arg parse
    if "--quick" in sys.argv[2:]:
        quick = True
    if "--workers" in sys.argv[2:]:
        try:
            idx = sys.argv.index("--workers")
            workers = max(1, int(sys.argv[idx + 1]))
        except Exception:
            workers = 1
    ensure_dirs()
    out_dir = os.path.join("artifacts", "static_jsons")
    os.makedirs(out_dir, exist_ok=True)

    apks = _walk_apks(folder)
    print(f"Found {len(apks)} APKs under {folder}. Using workers={workers} quick={quick}.")

    def _process_one(args):
        idx, apk = args
        try:
            sha = get_sha256(apk)
            out_path = os.path.join(out_dir, f"{sha}.json")
            if os.path.exists(out_path):
                return f"[{idx}/{len(apks)}] SKIP {apk}"
            data = extract(apk, quick=quick)
            if not isinstance(data, dict) or not data.get('sha256'):
                data = _minimal_record(apk, sha256=sha, error="no_data_or_sha256")
            out_path = os.path.join(out_dir, f"{data['sha256']}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return f"[{idx}/{len(apks)}] OK {apk}"
        except Exception as e:
            return f"[{idx}/{len(apks)}] ERROR {apk}: {e}"

    if workers <= 1:
        for item in map(_process_one, enumerate(apks, 1)):
            print(item)
    else:
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            for msg in ex.map(_process_one, enumerate(apks, 1)):
                print(msg)


if __name__ == "__main__":
    main_cli()



