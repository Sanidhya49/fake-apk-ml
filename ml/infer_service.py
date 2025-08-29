"""FastAPI inference service for APK fake/legit detection.

Run locally:
    uvicorn ml.infer_service:app --host 0.0.0.0 --port 9000
"""

import os
import tempfile
from typing import Dict, List
import asyncio
import json
import base64
from datetime import datetime
import requests

import numpy as np
from fastapi import FastAPI, File, UploadFile, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from jinja2 import Template
import weasyprint

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
    allow_origins=[
        "*",  # Keep wildcard for development
        "http://localhost:3000",
        "http://localhost:5173",
        "https://fake-apk-detection-frontend.vercel.app",
        "http://fake-apk-detection-frontend.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


MODEL_PATH = os.path.join("models", "xgb_model.joblib")


async def generate_gemini_analysis(analysis_result: Dict, file_info: Dict) -> str:
    """Generate detailed AI analysis using Google Gemini API"""
    try:
        # Get Gemini API key from environment
        gemini_api_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_api_key:
            return "AI analysis unavailable: API key not configured."
        
        # Prepare analysis data for Gemini
        prediction = analysis_result.get("prediction", "unknown")
        probability = analysis_result.get("probability", 0)
        risk = analysis_result.get("risk", "unknown")
        features = analysis_result.get("feature_vector", {})
        top_shap = analysis_result.get("top_shap", [])
        
        # Create context for Gemini
        prompt_text = f"""
        You are a cybersecurity expert specializing in Android APK analysis. Analyze this APK security scan result and provide a detailed assessment.

        APK Analysis Results:
        - File: {file_info.get('filename', 'unknown')}
        - Prediction: {prediction}
        - Risk Level: {risk}
        - Malware Probability: {probability:.2%}
        
        Security Features Detected:
        - SMS Permissions: {'Yes' if features.get('READ_SMS') or features.get('SEND_SMS') else 'No'}
        - System Alert Window: {'Yes' if features.get('SYSTEM_ALERT_WINDOW') else 'No'}
        - Network Access: {'Yes' if features.get('INTERNET') else 'No'}
        - Suspicious APIs: {features.get('count_suspicious', 0)}
        - Certificate Present: {'Yes' if features.get('cert_present') else 'No'}
        - Official Package: {'Yes' if features.get('pkg_official') else 'No'}
        - Impersonation Score: {features.get('impersonation_score', 0)}
        
        Top Contributing Factors:
        {chr(10).join([f"- {item['feature']}: {item['value']:.3f}" for item in top_shap[:5]])}
        
        Please provide a comprehensive security analysis that includes:
        1. Overall threat assessment and explanation of the verdict
        2. Analysis of specific security concerns based on detected features
        3. Technical explanation of why this APK is classified as {prediction}
        4. Risk mitigation recommendations
        5. User-friendly explanation for non-technical users
        
        Keep the response professional, informative, and under 500 words.
        """
        
        # Gemini API request
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt_text
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.3,
                "topK": 40,
                "topP": 0.8,
                "maxOutputTokens": 1000,
            }
        }
        
        # Use Gemini Pro model
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={gemini_api_key}"
        
        response = requests.post(
            api_url,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            candidates = result.get("candidates", [])
            if candidates:
                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                if parts:
                    return parts[0].get("text", "Analysis generation failed.")
            return "AI analysis unavailable: No content generated."
        else:
            return f"AI analysis unavailable: API error ({response.status_code})"
            
    except Exception as e:
        return f"AI analysis unavailable: {str(e)}"


def generate_security_recommendations(analysis_result: Dict) -> tuple:
    """Generate security recommendations, warnings, and critical issues"""
    features = analysis_result.get("feature_vector", {})
    prediction = analysis_result.get("prediction", "unknown")
    probability = analysis_result.get("probability", 0)
    
    recommendations = []
    warnings = []
    dangers = []
    
    # Generate recommendations based on analysis
    if prediction == "legit":
        recommendations.append("This APK appears to be legitimate based on our analysis.")
        recommendations.append("However, always download apps from official stores like Google Play.")
        recommendations.append("Keep your device updated with the latest security patches.")
    else:
        dangers.append("This APK has been flagged as potentially malicious.")
        dangers.append("Do not install this application on your device.")
        dangers.append("Report this APK to your security team immediately.")
    
    # Check for specific security features
    if features.get("READ_SMS") or features.get("SEND_SMS"):
        warnings.append("App requests SMS permissions - verify if legitimate for banking app.")
    
    if features.get("SYSTEM_ALERT_WINDOW"):
        dangers.append("App can display system overlay windows - potential for UI hijacking.")
    
    if features.get("count_suspicious", 0) > 3:
        warnings.append(f"App contains {features.get('count_suspicious')} suspicious API calls.")
    
    if not features.get("cert_present"):
        warnings.append("APK lacks proper digital certificate - authentication concerns.")
    
    if features.get("impersonation_score", 0) > 70:
        dangers.append("High impersonation score - may be mimicking legitimate banking apps.")
    
    if not features.get("pkg_official"):
        warnings.append("APK is not from a verified official source.")
    
    # High probability warnings
    if probability > 0.8:
        dangers.append("Very high malware probability - extreme caution advised.")
    elif probability > 0.5:
        warnings.append("Moderate malware probability - additional verification recommended.")
    
    return recommendations, warnings, dangers


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


@app.get("/ws-url")
async def get_websocket_url():
    """Get the WebSocket URL for real-time APK scanning"""
    return {"websocket_url": "ws://localhost:9000/ws/scan"}


async def process_single_apk(file_data: bytes, filename: str, quick: bool = False, debug: bool = False):
    """Process a single APK and return analysis result"""
    ensure_dirs()
    
    # Save to a temp file
    suffix = os.path.splitext(filename or "sample.apk")[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_data)
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
                return {"error": "parse_failed", "detail": "Could not parse APK", "filename": filename}
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
            "filename": filename,
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
        return out
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


@app.websocket("/ws/scan")
async def websocket_scan_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    try:
        while True:
            # Receive message from client
            message = await websocket.receive_text()
            data = json.loads(message)
            
            message_type = data.get("type")
            
            if message_type == "scan_single":
                # Send progress update
                await websocket.send_text(json.dumps({
                    "type": "progress",
                    "stage": "received",
                    "message": "File received, starting analysis...",
                    "progress": 10
                }))
                
                # Decode file data
                file_data = base64.b64decode(data["file_data"])
                filename = data["filename"]
                quick = data.get("quick", False)
                debug = data.get("debug", False)
                
                # Send progress update
                await websocket.send_text(json.dumps({
                    "type": "progress",
                    "stage": "parsing",
                    "message": "Parsing APK structure...",
                    "progress": 30
                }))
                
                # Process the APK
                result = await process_single_apk(file_data, filename, quick, debug)
                
                # Send progress update
                await websocket.send_text(json.dumps({
                    "type": "progress",
                    "stage": "analysis",
                    "message": "Running ML analysis...",
                    "progress": 70
                }))
                
                # Small delay to show progress
                await asyncio.sleep(0.5)
                
                # Send final result
                await websocket.send_text(json.dumps({
                    "type": "result",
                    "stage": "complete",
                    "message": "Analysis complete",
                    "progress": 100,
                    "result": result
                }))
                
            elif message_type == "scan_batch":
                files_data = data["files"]
                quick = data.get("quick", False)
                debug = data.get("debug", False)
                
                total_files = len(files_data)
                results = []
                
                for i, file_info in enumerate(files_data):
                    # Send progress update
                    await websocket.send_text(json.dumps({
                        "type": "progress",
                        "stage": "batch_processing",
                        "message": f"Processing file {i+1} of {total_files}: {file_info['filename']}",
                        "progress": int((i / total_files) * 90)
                    }))
                    
                    # Decode and process file
                    file_data = base64.b64decode(file_info["file_data"])
                    result = await process_single_apk(file_data, file_info["filename"], quick, debug)
                    results.append(result)
                    
                    # Send individual result
                    await websocket.send_text(json.dumps({
                        "type": "file_result",
                        "stage": "file_complete",
                        "message": f"Completed analysis of {file_info['filename']}",
                        "progress": int(((i + 1) / total_files) * 90),
                        "file_index": i,
                        "result": result
                    }))
                
                # Send final batch result
                await websocket.send_text(json.dumps({
                    "type": "batch_result",
                    "stage": "complete",
                    "message": "Batch analysis complete",
                    "progress": 100,
                    "results": results
                }))
                
            elif message_type == "ping":
                # Simple ping/pong for connection health
                await websocket.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": data.get("timestamp")
                }))
                
    except WebSocketDisconnect:
        print("WebSocket connection closed")
    except Exception as e:
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": f"Error processing request: {str(e)}"
        }))
        await websocket.close()


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


@app.post("/report-pdf")
async def generate_pdf_report(file: UploadFile = File(...)):
    """Generate a comprehensive PDF report with AI analysis"""
    try:
        # First, analyze the APK
        analysis_result = await scan_apk(file, quick=False, debug=True)
        
        if isinstance(analysis_result, JSONResponse):
            # Extract the analysis data
            import json as _json
            analysis_data = _json.loads(analysis_result.body)
        else:
            analysis_data = analysis_result
        
        # Check if analysis failed
        if "error" in analysis_data:
            return JSONResponse({
                "success": False,
                "error": "Failed to analyze APK",
                "details": analysis_data.get("detail", "Unknown error")
            }, status_code=422)
        
        # Prepare file information
        file_info = {
            "filename": file.filename,
            "size": getattr(file, 'size', 'Unknown'),
        }
        
        # Generate AI analysis
        ai_analysis = await generate_gemini_analysis(analysis_data, file_info)
        
        # Generate recommendations
        recommendations, warnings, dangers = generate_security_recommendations(analysis_data)
        
        # Load HTML template
        template_path = os.path.join("templates", "report_template.html")
        if not os.path.exists(template_path):
            return JSONResponse({
                "success": False,
                "error": "PDF template not found"
            }, status_code=500)
        
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
        
        # Prepare template data
        template_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "filename": file.filename,
            "package_name": analysis_data.get("feature_vector", {}).get("package", "Unknown"),
            "app_name": analysis_data.get("feature_vector", {}).get("app_label", "Unknown"),
            "file_size": f"{file.size / (1024*1024):.1f} MB" if hasattr(file, 'size') else "Unknown",
            "sha256": analysis_data.get("debug", {}).get("sha256", "Unknown") if analysis_data.get("debug") else "Unknown",
            "prediction": analysis_data.get("prediction", "unknown"),
            "probability": analysis_data.get("probability", 0),
            "risk": analysis_data.get("risk", "Unknown"),
            "top_shap": analysis_data.get("top_shap", []),
            "feature_vector": analysis_data.get("feature_vector", {}),
            "ai_analysis": ai_analysis.replace('\n', '<br>'),
            "recommendations": recommendations,
            "warnings": warnings,
            "dangers": dangers,
        }
        
        # Render HTML template
        template = Template(template_content)
        rendered_html = template.render(**template_data)
        
        # Generate PDF from HTML
        pdf_bytes = weasyprint.HTML(string=rendered_html).write_pdf()
        
        # Convert to base64
        pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
        
        return JSONResponse({
            "success": True,
            "filename": f"{file.filename}_security_report.pdf",
            "pdf_data": pdf_base64,
            "analysis_summary": {
                "prediction": analysis_data.get("prediction"),
                "risk": analysis_data.get("risk"),
                "probability": analysis_data.get("probability")
            }
        })
        
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": f"PDF generation failed: {str(e)}"
        }, status_code=500)


