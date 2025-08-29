"""Feature builder: converts static JSONs into a ML-ready features.csv.

Usage:
    python -m ml.feature_builder
"""

import glob
import json
import os
from typing import Dict, List

import pandas as pd

from .utils import ensure_dirs, load_bank_whitelist


PERMISSIONS_OF_INTEREST = [
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "SYSTEM_ALERT_WINDOW",
    "READ_CONTACTS",
    "INTERNET",
]

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

SUSPICIOUS_TLDS = {"tk","top","xyz","club","click","win","work","rest","cn","ru"}
BANK_TERMS = ["hdfc","sbi","barclays","icici","axis","kotak","upi","paytm","phonepe","hsbc","bank"]


def _label_from_path(source_path: str) -> str:
    path = source_path.replace("\\", "/").lower()
    if "/data/fake/" in path:
        return "fake"
    if "/data/legit/" in path:
        return "legit"
    return "unknown"


def build_dataframe() -> pd.DataFrame:
    ensure_dirs()
    json_dir = os.path.join("artifacts", "static_jsons")
    bank_whitelist = load_bank_whitelist()
    records: List[Dict] = []
    for path in glob.glob(os.path.join(json_dir, "*.json")):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        feature_row: Dict[str, int] = {}

        # Permission flags
        perms = set(data.get("permissions", []))
        for p in PERMISSIONS_OF_INTEREST:
            feature_row[p] = 1 if p in perms else 0

        # Suspicious APIs
        susp_dict = data.get("suspicious_apis", {})
        for name in SUSPICIOUS_API_NAMES:
            feature_row[f"api_{name}"] = int(bool(susp_dict.get(name, 0)))

        # Count suspicious
        feature_row["count_suspicious"] = int(sum(feature_row[f"api_{n}"] for n in SUSPICIOUS_API_NAMES))

        # Certificate presence
        cert_subject = data.get("cert_subject", "unknown")
        feature_row["cert_present"] = 0 if not cert_subject or cert_subject == "unknown" else 1

        # Certificate issuer basic flag
        cert_issuer = data.get("cert_issuer", "unknown")
        feature_row["issuer_present"] = 0 if not cert_issuer or cert_issuer == "unknown" else 1
        # CN/package mismatch heuristic
        pkg = (data.get("package") or "").lower()
        cn = str(cert_subject).lower()
        feature_row["cn_matches_package"] = 1 if (pkg and pkg in cn) else 0
        # Subject/Issuer CNs (best-effort)
        subject_cn = (data.get("cert_subject_cn") or "").lower()
        issuer_cn = (data.get("cert_issuer_cn") or "").lower()
        feature_row["issuer_cn_google_android"] = 1 if ("google" in issuer_cn or "android" in issuer_cn) else 0
        feature_row["subject_cn_contains_pkg"] = 1 if (pkg and pkg in subject_cn) else 0
        feature_row["issuer_subject_cn_equal"] = 1 if (subject_cn and issuer_cn and subject_cn == issuer_cn) else 0

        # Impersonation heuristic
        app_label = (data.get("app_label") or "").lower()
        feature_row["label_contains_bank"] = 1 if any(k in app_label for k in ["bank","upi","pay","wallet"]) else 0
        # Package contains bank-like terms
        feature_row["package_contains_bank"] = 1 if any(k in pkg for k in ["bank","upi","pay","wallet"]) else 0

        # URL/Domain IOCs
        domains = [d.lower() for d in data.get("domains", [])]
        feature_row["num_domains"] = len(domains)
        feature_row["num_http"] = 0  # not separating http/https from heuristic scan
        feature_row["num_suspicious_tld"] = sum(1 for d in domains if d.split(".")[-1] in SUSPICIOUS_TLDS)

        # Impersonation score (coarse): max partial match with bank terms
        name_blob = ((data.get("package") or "") + " " + (data.get("app_label") or "")).lower()
        try:
            from rapidfuzz import fuzz  # type: ignore
            sim = max(fuzz.partial_ratio(name_blob, t) for t in BANK_TERMS)
        except Exception:
            sim = 0
        feature_row["impersonation_score"] = int(sim)

        # Official package flag using whitelist
        pkg = (data.get("package") or "").strip()
        feature_row["pkg_official"] = 1 if pkg in bank_whitelist else 0

        # Lightweight metadata-derived features
        feature_row["num_dex"] = int(data.get("num_dex", 0) or 0)
        feature_row["num_permissions"] = int(data.get("num_permissions", 0) or 0)
        feature_row["num_exported"] = int(data.get("num_exported", 0) or 0)
        feature_row["min_sdk"] = int(data.get("min_sdk", -1) or -1)
        feature_row["target_sdk"] = int(data.get("target_sdk", -1) or -1)
        feature_row["num_activities"] = int(data.get("num_activities", 0) or 0)
        feature_row["num_services"] = int(data.get("num_services", 0) or 0)
        feature_row["num_receivers"] = int(data.get("num_receivers", 0) or 0)
        feature_row["file_size_mb"] = int(max(0, int((data.get("file_size", 0) or 0) // (1024*1024))))
        feature_row["main_activity_present"] = 1 if (data.get("main_activity") or "") else 0
        # Permission signals
        feature_row["perm_query_all_packages"] = 1 if "QUERY_ALL_PACKAGES" in set(data.get("permissions", [])) else 0
        # Textual signals
        app_label = (data.get("app_label") or "")
        feature_row["app_label_len"] = int(len(app_label))
        feature_row["package_len"] = int(len(pkg))
        feature_row["package_has_digit"] = 1 if any(ch.isdigit() for ch in pkg) else 0
        try:
            app_label.encode("ascii")
            feature_row["app_label_non_ascii"] = 0
        except Exception:
            feature_row["app_label_non_ascii"] = 1

        # Label
        feature_row["label"] = _label_from_path(data.get("source_path", ""))

        # Keep id columns to help debugging
        feature_row["sha256"] = data.get("sha256", "")
        feature_row["file_name"] = data.get("file_name", "")
        feature_row["package"] = data.get("package", "")
        feature_row["version"] = data.get("version", "")
        feature_row["app_label_text"] = data.get("app_label", "")
        records.append(feature_row)

    if not records:
        raise RuntimeError("No JSONs found in artifacts/static_jsons/. Run static extraction first.")

    df = pd.DataFrame(records)
    # Place id columns first for readability
    id_cols = ["sha256", "file_name"]
    other_cols = [c for c in df.columns if c not in id_cols]
    df = df[id_cols + other_cols]
    return df


def main():
    df = build_dataframe()
    # Print class balance
    counts = df["label"].value_counts(dropna=False)
    print("Class balance:\n", counts.to_string())

    out_csv = os.path.join("artifacts", "features.csv")
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    df.to_csv(out_csv, index=False)
    print(f"Saved features -> {out_csv}")


if __name__ == "__main__":
    main()



