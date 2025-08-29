"""FastAPI inference service for APK fake/legit detection.

Run locally:
    uvicorn ml.infer_service:app --host 0.0.0.0 --port 9000
"""

import os
import tempfile
from typing import Dict, List

import numpy as np
from fastapi import FastAPI, File, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse

from . import static_extract
from .utils import ensure_dirs, load_model, vectorize_feature_dict, get_sha256, load_bank_whitelist
import json
from rapidfuzz import fuzz


app = FastAPI(title="Fake APK ML Inference", version="1.0")
# Load .env if present (prefer .env over inherited env vars for reproducibility)
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except Exception:
    pass
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


MODEL_PATH = os.path.join("models", "xgb_model.joblib")


def _vectorize_from_extract(extract_dict: Dict, feature_order: List[str]) -> Dict:
    # Build the same features as in feature_builder
    permissions = set(extract_dict.get("permissions", []))
    suspicious = extract_dict.get("suspicious_apis", {})

    base: Dict[str, int] = {}
    # Permissions of interest (must match builder)
    for p in ["READ_SMS", "SEND_SMS", "RECEIVE_SMS", "SYSTEM_ALERT_WINDOW", "READ_CONTACTS", "INTERNET"]:
        base[p] = 1 if p in permissions else 0

    # Suspicious apis
    for name in [
        "getDeviceId",
        "sendTextMessage",
        "SmsManager",
        "DexClassLoader",
        "TYPE_SYSTEM_ALERT_WINDOW",
        "addView",
        "HttpURLConnection",
        "openConnection",
    ]:
        base[f"api_{name}"] = int(bool(suspicious.get(name, 0)))

    base["count_suspicious"] = int(sum(base[k] for k in base if k.startswith("api_")))
    base["cert_present"] = 0 if extract_dict.get("cert_subject", "unknown") in ("", "unknown") else 1
    # New features mirrored from feature_builder
    cert_issuer = extract_dict.get("cert_issuer", "unknown")
    base["issuer_present"] = 0 if not cert_issuer or cert_issuer == "unknown" else 1
    pkg = (extract_dict.get("package") or "").lower()
    cn = str(extract_dict.get("cert_subject", "")).lower()
    base["cn_matches_package"] = 1 if (pkg and pkg in cn) else 0
    # Additional CN-based features to fully mirror feature_builder
    subject_cn = (extract_dict.get("cert_subject_cn") or "").lower()
    issuer_cn = (extract_dict.get("cert_issuer_cn") or "").lower()
    base["issuer_cn_google_android"] = 1 if ("google" in issuer_cn or "android" in issuer_cn) else 0
    base["subject_cn_contains_pkg"] = 1 if (pkg and pkg in subject_cn) else 0
    base["issuer_subject_cn_equal"] = 1 if (subject_cn and issuer_cn and subject_cn == issuer_cn) else 0
    app_label = (extract_dict.get("app_label") or "").lower()
    base["label_contains_bank"] = 1 if any(k in app_label for k in ["bank","upi","pay","wallet"]) else 0
    base["package_contains_bank"] = 1 if any(k in pkg for k in ["bank","upi","pay","wallet"]) else 0
    domains = [d.lower() for d in extract_dict.get("domains", [])]
    base["num_domains"] = len(domains)
    base["num_http"] = 0
    suspicious_tlds = {"tk","top","xyz","club","click","win","work","rest","cn","ru"}
    base["num_suspicious_tld"] = int(sum(1 for d in domains if d.split(".")[-1] in suspicious_tlds))

    # Impersonation score (optional lightweight): similarity between package/app_label and known bank keywords
    whitelist = load_bank_whitelist()
    bank_terms = list({*([n.lower() for n in whitelist.values()]), *whitelist.keys(), "hdfc","sbi","barclays","icici","axis","kotak","upi","paytm","phonepe","hsbc","bank"})
    name_blob = ((extract_dict.get("package") or "") + " " + (extract_dict.get("app_label") or "")).lower()
    try:
        sim = max(fuzz.partial_ratio(name_blob, t) for t in bank_terms)
    except Exception:
        sim = 0
    base["impersonation_score"] = int(sim)
    # Is official package (verified by whitelist)
    pkg = (extract_dict.get("package") or "").strip()
    base["pkg_official"] = 1 if pkg in whitelist else 0

    # Mirror new metadata features from feature_builder
    base["num_dex"] = int(extract_dict.get("num_dex", 0) or 0)
    base["num_permissions"] = int(extract_dict.get("num_permissions", 0) or 0)
    base["num_exported"] = int(extract_dict.get("num_exported", 0) or 0)
    base["min_sdk"] = int(extract_dict.get("min_sdk", -1) or -1)
    base["target_sdk"] = int(extract_dict.get("target_sdk", -1) or -1)
    base["num_activities"] = int(extract_dict.get("num_activities", 0) or 0)
    base["num_services"] = int(extract_dict.get("num_services", 0) or 0)
    base["num_receivers"] = int(extract_dict.get("num_receivers", 0) or 0)
    try:
        base["file_size_mb"] = int(max(0, int((extract_dict.get("file_size", 0) or 0) // (1024*1024))))
    except Exception:
        base["file_size_mb"] = 0
    base["main_activity_present"] = 1 if (extract_dict.get("main_activity") or "") else 0
    base["perm_query_all_packages"] = 1 if "QUERY_ALL_PACKAGES" in set(extract_dict.get("permissions", [])) else 0
    try:
        app_label = (extract_dict.get("app_label") or "")
        base["app_label_len"] = int(len(app_label))
        pkgl = (extract_dict.get("package") or "").lower()
        base["package_len"] = int(len(pkgl))
        base["package_has_digit"] = 1 if any(ch.isdigit() for ch in pkgl) else 0
        try:
            app_label.encode("ascii")
            base["app_label_non_ascii"] = 0
        except Exception:
            base["app_label_non_ascii"] = 1
    except Exception:
        pass

    vec_list = vectorize_feature_dict(base, feature_order)
    return {"vector": vec_list, "feature_map": base}


def _try_load_cached_json(sha: str):
    path = os.path.join("artifacts", "static_jsons", f"{sha}.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Ignore minimal/error caches to force a fresh full parse
                if isinstance(data, dict) and data.get("parse_error"):
                    return None
                return data
        except Exception:
            return None
    return None


@app.post("/scan")
async def scan_apk(
    file: UploadFile = File(...),
    quick: bool = Query(False, description="Quick mode: manifest/cert only"),
    debug: bool = Query(False, description="Include debug fields in response"),
):
    ensure_dirs()
    # Save to a temp file
    suffix = os.path.splitext(file.filename or "sample.apk")[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        model_obj = load_model(MODEL_PATH)
        model = model_obj["model"]
        feature_order = model_obj["feature_order"]
        saved_thr = float(model_obj.get("tuned_threshold", 0.61))

        # Reuse cached JSON if available to speed up repeat scans
        try:
            sha = get_sha256(tmp_path)
        except Exception:
            sha = None

        ext = None
        if sha:
            cached = _try_load_cached_json(sha)
            if cached:
                ext = cached
        if ext is None:
            try:
                ext = static_extract.extract(tmp_path, quick=quick)
            except Exception as e:
                # Retry with quick=True if full parse failed
                if not quick:
                    try:
                        ext = static_extract.extract(tmp_path, quick=True)
                    except Exception:
                        ext = None
                else:
                    ext = None
            if not isinstance(ext, dict):
                return JSONResponse({"error": "parse_failed", "detail": "Could not parse APK"}, status_code=422)
            # Persist to cache for future fast scans
            try:
                sha = ext.get("sha256")
                if sha:
                    cache_dir = os.path.join("artifacts", "static_jsons")
                    os.makedirs(cache_dir, exist_ok=True)
                    cache_path = os.path.join(cache_dir, f"{sha}.json")
                    if not os.path.exists(cache_path):
                        with open(cache_path, "w", encoding="utf-8") as _f:
                            json.dump(ext, _f, ensure_ascii=False)
            except Exception:
                pass
        v = _vectorize_from_extract(ext, feature_order)
        X = np.array([v["vector"]])
        # Probability of class 1 (fake)
        try:
            prob = float(model.predict_proba(X)[0, 1])
        except Exception:
            # Fallback if model lacks predict_proba
            raw = model.predict(X)[0]
            prob = float(int(raw))

        # Unified decision threshold for both label and risk (default 0.61)
        import os as _os
        try:
            threshold = float(_os.environ.get("ML_FAKE_THRESHOLD", str(saved_thr)))
        except Exception:
            threshold = saved_thr
        # Optional: force-classify as fake above a minimum probability (demo safety net)
        try:
            force_min = _os.environ.get("ML_FORCE_MIN_FAKE", "")
            force_min = float(force_min) if force_min else None
        except Exception:
            force_min = None
        # Heuristic gating knobs
        try:
            heur_min_prob = float(_os.environ.get("ML_HEURISTIC_MIN_PROB", "0.30"))
        except Exception:
            heur_min_prob = 0.30
        try:
            heur_min_signals = int(_os.environ.get("ML_HEURISTIC_MIN_SIGNALS", "2"))
        except Exception:
            heur_min_signals = 2
        try:
            official_override = _os.environ.get("ML_OFFICIAL_OVERRIDE", "1").lower() in {"1","true","yes"}
        except Exception:
            official_override = True
        try:
            official_override_cap = float(_os.environ.get("ML_OFFICIAL_OVERRIDE_CAP", "0.40"))
        except Exception:
            official_override_cap = 0.40
        # Optional per-SHA overrides (comma/space/semicolon separated lists)
        try:
            _force_fake = os.environ.get("ML_FORCE_FAKE_SHA256S", "")
            _force_legit = os.environ.get("ML_FORCE_LEGIT_SHA256S", "")
            def _parse_list(s: str):
                raw = [x.strip().lower() for x in s.replace(";", ",").replace(" ", ",").split(",")]
                return {x for x in raw if x}
            force_fake_set = _parse_list(_force_fake)
            force_legit_set = _parse_list(_force_legit)
        except Exception:
            force_fake_set, force_legit_set = set(), set()
        pred_initial = 1 if prob >= threshold else 0
        pred = pred_initial
        force_rule = None
        if sha:
            _sha_l = sha.lower()
            if _sha_l in force_legit_set:
                pred = 0
                force_rule = "force_legit"
            elif _sha_l in force_fake_set:
                pred = 1
                force_rule = "force_fake"
        # Aggressive mode: use domain heuristics to reduce false negatives
        try:
            aggressive = os.environ.get("ML_AGGRESSIVE", "0").lower() in {"1","true","yes"}
            margin = float(os.environ.get("ML_MARGIN", "0.08"))
        except Exception:
            aggressive = False
            margin = 0.08
        feat = v["feature_map"]
        try:
            hazard_sms = (feat.get("api_sendTextMessage",0)==1 or feat.get("api_SmsManager",0)==1) and (feat.get("READ_SMS",0)==1 or feat.get("RECEIVE_SMS",0)==1)
            overlay = feat.get("SYSTEM_ALERT_WINDOW",0)==1 or feat.get("api_TYPE_SYSTEM_ALERT_WINDOW",0)==1 or feat.get("api_addView",0)==1
            network = feat.get("INTERNET",0)==1 and (feat.get("num_http",0)>0 or feat.get("num_suspicious_tld",0)>0)
            impersonate = feat.get("impersonation_score",0) >= 80 and feat.get("pkg_official",0)==0 and (feat.get("label_contains_bank",0)==1 or feat.get("package_contains_bank",0)==1)
            is_official = feat.get("pkg_official",0)==1
            signals = int(hazard_sms) + int(overlay) + int(network) + int(impersonate)
        except Exception:
            signals = 0
            impersonate = False
            is_official = False
        if aggressive:
            if pred == 0 and (prob >= (threshold - margin) and signals >= 1):
                pred = 1
            elif pred == 0 and (prob >= heur_min_prob and signals >= heur_min_signals):
                pred = 1
        # Official package override (avoid false positives on verified apps unless probability is very high)
        # Only override if probability is very low (below cap) to avoid hiding moderate-risk fakes
        if official_override and is_official and prob <= official_override_cap:
            pred = 0
        if pred == 0 and force_min is not None and prob >= force_min:
            pred = 1
        risk = "Red" if prob >= max(0.8, threshold) else ("Amber" if (prob >= threshold or pred==1) else "Green")

        # Optional SHAP on the fly (best-effort)
        top = []
        try:
            import shap  # type: ignore

            try:
                explainer = shap.TreeExplainer(model)
                shap_values = explainer.shap_values(X)
                if isinstance(shap_values, list):
                    sv = shap_values[1][0]
                else:
                    sv = shap_values[0]
                idxs = np.argsort(np.abs(sv))[::-1][:3]
                for j in idxs:
                    top.append({"feature": feature_order[j], "value": float(sv[j])})
            except Exception:
                top = []
        except Exception:
            top = []

        label_map = {0: "legit", 1: "fake"}
        out = {
            "prediction": label_map.get(int(pred), str(pred)),
            "probability": prob,
            "risk": risk,
            "top_shap": top,
            "feature_vector": v["feature_map"],
        }
        if debug:
            out["debug"] = {
                "threshold_used": float(threshold),
                "saved_tuned_threshold": float(saved_thr),
                "pred_initial": int(pred_initial),
                "signals": int(signals),
                "is_official": bool(is_official),
                "official_override": bool(official_override),
                "official_override_cap": float(official_override_cap),
                "aggressive": bool(aggressive),
                "sha256": sha,
                "force_rule": force_rule or "",
            }
        return JSONResponse(out)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


@app.post("/scan-batch")
async def scan_batch(
    files: list[UploadFile] = File(...),
    quick: bool = Query(False),
    debug: bool = Query(False),
):
    ensure_dirs()
    model_obj = load_model(MODEL_PATH)
    model = model_obj["model"]
    feature_order = model_obj["feature_order"]
    saved_thr = float(model_obj.get("tuned_threshold", 0.61))

    results = []
    for uf in files:
        suffix = os.path.splitext(uf.filename or "sample.apk")[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            content = await uf.read()
            tmp.write(content)
            tmp_path = tmp.name
        try:
            try:
                sha = get_sha256(tmp_path)
            except Exception:
                sha = None
            ext = None
            if sha:
                cached = _try_load_cached_json(sha)
                if cached:
                    ext = cached
            if ext is None:
                try:
                    ext = static_extract.extract(tmp_path, quick=quick)
                except Exception:
                    if not quick:
                        try:
                            ext = static_extract.extract(tmp_path, quick=True)
                        except Exception:
                            ext = None
                if not isinstance(ext, dict):
                    results.append({"file": uf.filename, "error": "parse_failed"})
                    continue
                try:
                    if sha is None:
                        sha = ext.get("sha256")
                    if sha:
                        cache_dir = os.path.join("artifacts", "static_jsons")
                        os.makedirs(cache_dir, exist_ok=True)
                        cache_path = os.path.join(cache_dir, f"{sha}.json")
                        if not os.path.exists(cache_path):
                            with open(cache_path, "w", encoding="utf-8") as _f:
                                json.dump(ext, _f, ensure_ascii=False)
                except Exception:
                    pass
            v = _vectorize_from_extract(ext, feature_order)
            import numpy as _np
            X = _np.array([v["vector"]])
            try:
                prob = float(model.predict_proba(X)[0, 1])
            except Exception:
                raw = model.predict(X)[0]
                prob = float(int(raw))
            import os as _os
            try:
                threshold = float(_os.environ.get("ML_FAKE_THRESHOLD", str(saved_thr)))
            except Exception:
                threshold = saved_thr
            try:
                force_min = _os.environ.get("ML_FORCE_MIN_FAKE", "")
                force_min = float(force_min) if force_min else None
            except Exception:
                force_min = None
            try:
                heur_min_prob = float(_os.environ.get("ML_HEURISTIC_MIN_PROB", "0.30"))
            except Exception:
                heur_min_prob = 0.30
            try:
                heur_min_signals = int(_os.environ.get("ML_HEURISTIC_MIN_SIGNALS", "2"))
            except Exception:
                heur_min_signals = 2
            try:
                official_override = os.environ.get("ML_OFFICIAL_OVERRIDE", "1").lower() in {"1","true","yes"}
            except Exception:
                official_override = True
            try:
                official_override_cap = float(os.environ.get("ML_OFFICIAL_OVERRIDE_CAP", "0.40"))
            except Exception:
                official_override_cap = 0.40
            pred = 1 if prob >= threshold else 0
            try:
                aggressive = os.environ.get("ML_AGGRESSIVE", "1").lower() in {"1","true","yes"}
                margin = float(os.environ.get("ML_MARGIN", "0.08"))
            except Exception:
                aggressive = True
                margin = 0.08
            feat = v["feature_map"]
            try:
                hazard_sms = (feat.get("api_sendTextMessage",0)==1 or feat.get("api_SmsManager",0)==1) and (feat.get("READ_SMS",0)==1 or feat.get("RECEIVE_SMS",0)==1)
                overlay = feat.get("SYSTEM_ALERT_WINDOW",0)==1 or feat.get("api_TYPE_SYSTEM_ALERT_WINDOW",0)==1 or feat.get("api_addView",0)==1
                network = feat.get("INTERNET",0)==1 and (feat.get("num_http",0)>0 or feat.get("num_suspicious_tld",0)>0)
                impersonate = feat.get("impersonation_score",0) >= 80 and feat.get("pkg_official",0)==0 and (feat.get("label_contains_bank",0)==1 or feat.get("package_contains_bank",0)==1)
                is_official = feat.get("pkg_official",0)==1
                signals = int(hazard_sms) + int(overlay) + int(network) + int(impersonate)
            except Exception:
                signals = 0
                impersonate = False
                is_official = False
            if aggressive:
                if pred == 0 and (prob >= (threshold - margin) and signals >= 1):
                    pred = 1
                elif pred == 0 and (prob >= heur_min_prob and signals >= heur_min_signals):
                    pred = 1
            if official_override and is_official and prob <= official_override_cap:
                pred = 0
            if pred == 0 and force_min is not None and prob >= force_min:
                pred = 1
            risk = "Red" if prob >= max(0.8, threshold) else ("Amber" if (prob >= threshold or pred==1) else "Green")
            label_map = {0: "legit", 1: "fake"}
            item = {
                "file": uf.filename,
                "prediction": label_map.get(int(pred), str(pred)),
                "probability": prob,
                "risk": risk,
                "feature_vector": v["feature_map"],
            }
            if debug:
                item["debug"] = {
                    "threshold_used": float(threshold),
                    "saved_tuned_threshold": float(saved_thr),
                    "signals": int(signals),
                    "aggressive": bool(aggressive),
                }
            results.append(item)
        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
    return JSONResponse({"results": results})


@app.get("/")
async def root():
    return {"status": "ok", "message": "Use POST /scan with multipart file 'file'"}


def _render_html_report(result: Dict) -> str:
    fv = result.get("feature_vector", {})
    top = result.get("top_shap", [])
    pred = result.get("prediction")
    prob = result.get("probability")
    risk = result.get("risk")
    rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k,v in fv.items())
    shap_rows = "".join(f"<li>{it.get('feature')}: {round(it.get('value',0),4)}</li>" for it in top)
    return f"""
    <html><head><meta charset='utf-8'><title>APK Risk Report</title>
    <style>body{{font-family:Arial, sans-serif; margin:20px}} table{{border-collapse:collapse}} td,th{{border:1px solid #ddd;padding:6px}}</style>
    </head><body>
    <h2>Prediction: {pred} &nbsp; Risk: {risk} &nbsp; P(fake): {prob:.4f}</h2>
    <h3>Top contributors</h3>
    <ul>{shap_rows}</ul>
    <h3>Feature vector</h3>
    <table><tr><th>Feature</th><th>Value</th></tr>{rows}</table>
    </body></html>
    """


@app.post("/report")
async def report(file: UploadFile = File(...)):
    # Reuse the /scan logic to get a full result, then wrap HTML
    scan = await scan_apk(file)  # type: ignore
    if isinstance(scan, JSONResponse):
        data = scan.body
        # JSONResponse.body is bytes
        import json as _json
        result = _json.loads(data)
        html = _render_html_report(result)
        return JSONResponse({"result": result, "html": html})
    return scan


@app.post("/report-html")
async def report_html(file: UploadFile = File(...)):
    # Directly return HTML report for browser form uploads
    scan = await scan_apk(file)  # type: ignore
    if isinstance(scan, JSONResponse):
        import json as _json
        data = scan.body
        result = _json.loads(data)
        html = _render_html_report(result)
        return HTMLResponse(content=html)
    return scan


@app.get("/report")
async def report_form():
    # Simple upload form for browser use
    html = """
    <html><head><meta charset='utf-8'><title>Upload APK</title></head>
    <body style="font-family:Arial; margin:20px">
    <h3>Upload an APK to get an HTML risk report</h3>
    <form action="/report-html" method="post" enctype="multipart/form-data">
      <input type="file" name="file" accept=".apk,.apks,.xapk" required />
      <button type="submit">Scan</button>
    </form>
    <p>For API clients: POST /report with multipart field <code>file</code> to get JSON with an embedded <code>html</code> string.</p>
    </body></html>
    """
    return HTMLResponse(content=html)


