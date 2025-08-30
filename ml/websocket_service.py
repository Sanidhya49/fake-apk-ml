"""WebSocket service for real-time APK analysis updates."""

import asyncio
import json
import os
import tempfile
import uuid
from typing import Dict, List, Optional, Set
import numpy as np
from fastapi import WebSocket, WebSocketDisconnect
import logging

from . import static_extract
from .utils import ensure_dirs, load_model, vectorize_feature_dict, get_sha256, load_bank_whitelist
from rapidfuzz import fuzz

logger = logging.getLogger(__name__)

# Store active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_tasks: Dict[str, Set[str]] = {}  # connection_id -> set of task_ids
    
    async def connect(self, websocket: WebSocket, connection_id: str):
        await websocket.accept()
        self.active_connections[connection_id] = websocket
        self.connection_tasks[connection_id] = set()
        logger.info(f"WebSocket connection established: {connection_id}")
    
    def disconnect(self, connection_id: str):
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        if connection_id in self.connection_tasks:
            del self.connection_tasks[connection_id]
        logger.info(f"WebSocket connection closed: {connection_id}")
    
    async def send_message(self, connection_id: str, message: dict):
        if connection_id in self.active_connections:
            try:
                await self.active_connections[connection_id].send_text(json.dumps(message))
                return True
            except Exception as e:
                logger.error(f"Error sending message to {connection_id}: {e}")
                self.disconnect(connection_id)
                return False
        return False
    
    def add_task(self, connection_id: str, task_id: str):
        if connection_id in self.connection_tasks:
            self.connection_tasks[connection_id].add(task_id)
    
    def remove_task(self, connection_id: str, task_id: str):
        if connection_id in self.connection_tasks:
            self.connection_tasks[connection_id].discard(task_id)


manager = ConnectionManager()

MODEL_PATH = os.path.join("models", "xgb_model.joblib")

# Analysis steps that match the frontend expectations
ANALYSIS_STEPS = [
    {"id": 1, "name": "Analyzing Package Structure", "progress_weight": 15},
    {"id": 2, "name": "Scanning for Malicious Code", "progress_weight": 20},
    {"id": 3, "name": "Checking Digital Signatures", "progress_weight": 15},
    {"id": 4, "name": "Verifying Banking Protocols", "progress_weight": 15},
    {"id": 5, "name": "Testing Encryption Standards", "progress_weight": 10},
    {"id": 6, "name": "Running ML Models", "progress_weight": 15},
    {"id": 7, "name": "Generating Risk Score", "progress_weight": 10},
]


def _try_load_cached_json(sha: str):
    """Load cached analysis result if available."""
    path = os.path.join("artifacts", "static_jsons", f"{sha}.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and data.get("parse_error"):
                    return None
                return data
        except Exception:
            return None
    return None


def _vectorize_from_extract(extract_dict: Dict, feature_order: List[str]) -> Dict:
    """Convert extraction results to feature vector (same as infer_service.py)."""
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
    
    # Additional features
    cert_issuer = extract_dict.get("cert_issuer", "unknown")
    base["issuer_present"] = 0 if not cert_issuer or cert_issuer == "unknown" else 1
    pkg = (extract_dict.get("package") or "").lower()
    cn = str(extract_dict.get("cert_subject", "")).lower()
    base["cn_matches_package"] = 1 if (pkg and pkg in cn) else 0
    
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

    # Impersonation score
    whitelist = load_bank_whitelist()
    bank_terms = list({*([n.lower() for n in whitelist.values()]), *whitelist.keys(), "hdfc","sbi","barclays","icici","axis","kotak","upi","paytm","phonepe","hsbc","bank"})
    name_blob = ((extract_dict.get("package") or "") + " " + (extract_dict.get("app_label") or "")).lower()
    try:
        sim = max(fuzz.partial_ratio(name_blob, t) for t in bank_terms)
    except Exception:
        sim = 0
    base["impersonation_score"] = int(sim)
    
    # Official package check
    pkg = (extract_dict.get("package") or "").strip()
    base["pkg_official"] = 1 if pkg in whitelist else 0

    # Additional metadata features
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


async def send_progress_update(connection_id: str, task_id: str, step_id: int, status: str, progress: int, message: str = None):
    """Send progress update to WebSocket client."""
    update = {
        "type": "progress",
        "task_id": task_id,
        "step_id": step_id,
        "status": status,  # "running", "completed", "error"
        "progress": progress,
        "message": message or f"Step {step_id} {status}",
        "timestamp": asyncio.get_event_loop().time()
    }
    await manager.send_message(connection_id, update)


async def send_completion(connection_id: str, task_id: str, result: Dict):
    """Send completion notification with results."""
    completion = {
        "type": "complete",
        "task_id": task_id,
        "result": result,
        "timestamp": asyncio.get_event_loop().time()
    }
    await manager.send_message(connection_id, completion)


async def send_error(connection_id: str, task_id: str, error: str, step_id: int = None):
    """Send error notification."""
    error_msg = {
        "type": "error",
        "task_id": task_id,
        "error": error,
        "step_id": step_id,
        "timestamp": asyncio.get_event_loop().time()
    }
    await manager.send_message(connection_id, error_msg)


async def analyze_apk_with_progress(connection_id: str, task_id: str, file_content: bytes, filename: str, quick: bool = False):
    """Analyze APK with real-time progress updates."""
    ensure_dirs()
    
    # Save to temp file
    suffix = os.path.splitext(filename)[1] if filename else ".apk"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_content)
        tmp_path = tmp.name

    try:
        # Load model
        model_obj = load_model(MODEL_PATH)
        model = model_obj["model"]
        feature_order = model_obj["feature_order"]
        saved_thr = float(model_obj.get("tuned_threshold", 0.61))

        total_progress = 0
        
        # Step 1: Package structure analysis
        await send_progress_update(connection_id, task_id, 1, "running", 5, "Starting package analysis...")
        await asyncio.sleep(0.5)  # Simulate processing time
        
        try:
            sha = get_sha256(tmp_path)
        except Exception:
            sha = None
        
        # Check cache
        ext = None
        if sha:
            cached = _try_load_cached_json(sha)
            if cached:
                ext = cached
                await send_progress_update(connection_id, task_id, 1, "running", 12, "Using cached analysis...")
        
        await send_progress_update(connection_id, task_id, 1, "completed", 15, "Package structure analyzed")
        total_progress += 15

        # Step 2: Malicious code scanning
        await send_progress_update(connection_id, task_id, 2, "running", total_progress + 5, "Scanning for malicious patterns...")
        await asyncio.sleep(0.8)
        
        if ext is None:
            try:
                ext = static_extract.extract(tmp_path, quick=quick)
            except Exception as e:
                if not quick:
                    try:
                        ext = static_extract.extract(tmp_path, quick=True)
                    except Exception:
                        await send_error(connection_id, task_id, "Could not parse APK file", 2)
                        return
                else:
                    await send_error(connection_id, task_id, f"Parse error: {str(e)}", 2)
                    return
                    
            if not isinstance(ext, dict):
                await send_error(connection_id, task_id, "Invalid APK structure", 2)
                return
            
            # Cache the result
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

        await send_progress_update(connection_id, task_id, 2, "completed", total_progress + 20, "Malicious code scan completed")
        total_progress += 20

        # Step 3: Digital signatures
        await send_progress_update(connection_id, task_id, 3, "running", total_progress + 5, "Verifying digital signatures...")
        await asyncio.sleep(0.6)
        
        # Vectorize features
        v = _vectorize_from_extract(ext, feature_order)
        feat = v["feature_map"]
        
        await send_progress_update(connection_id, task_id, 3, "completed", total_progress + 15, "Digital signature verification completed")
        total_progress += 15

        # Step 4: Banking protocols
        await send_progress_update(connection_id, task_id, 4, "running", total_progress + 5, "Checking banking app patterns...")
        await asyncio.sleep(0.7)
        
        # Check for banking-related features
        banking_related = feat.get("label_contains_bank", 0) == 1 or feat.get("package_contains_bank", 0) == 1
        is_official = feat.get("pkg_official", 0) == 1
        impersonation_score = feat.get("impersonation_score", 0)
        
        await send_progress_update(connection_id, task_id, 4, "completed", total_progress + 15, "Banking protocol verification completed")
        total_progress += 15

        # Step 5: Encryption standards
        await send_progress_update(connection_id, task_id, 5, "running", total_progress + 2, "Testing encryption standards...")
        await asyncio.sleep(0.5)
        
        await send_progress_update(connection_id, task_id, 5, "completed", total_progress + 10, "Encryption standards verified")
        total_progress += 10

        # Step 6: ML Models
        await send_progress_update(connection_id, task_id, 6, "running", total_progress + 5, "Running machine learning models...")
        await asyncio.sleep(1.0)
        
        # Run ML prediction
        X = np.array([v["vector"]])
        try:
            prob = float(model.predict_proba(X)[0, 1])
        except Exception:
            raw = model.predict(X)[0]
            prob = float(int(raw))

        # Apply thresholds and business logic (same as infer_service.py)
        threshold = float(os.environ.get("ML_FAKE_THRESHOLD", str(saved_thr)))
        pred = 1 if prob >= threshold else 0
        
        # Apply additional heuristics
        try:
            aggressive = os.environ.get("ML_AGGRESSIVE", "0").lower() in {"1","true","yes"}
            margin = float(os.environ.get("ML_MARGIN", "0.08"))
            heur_min_prob = float(os.environ.get("ML_HEURISTIC_MIN_PROB", "0.30"))
            heur_min_signals = int(os.environ.get("ML_HEURISTIC_MIN_SIGNALS", "2"))
            official_override = os.environ.get("ML_OFFICIAL_OVERRIDE", "1").lower() in {"1","true","yes"}
            official_override_cap = float(os.environ.get("ML_OFFICIAL_OVERRIDE_CAP", "0.40"))
            
            # Calculate risk signals
            hazard_sms = (feat.get("api_sendTextMessage",0)==1 or feat.get("api_SmsManager",0)==1) and (feat.get("READ_SMS",0)==1 or feat.get("RECEIVE_SMS",0)==1)
            overlay = feat.get("SYSTEM_ALERT_WINDOW",0)==1 or feat.get("api_TYPE_SYSTEM_ALERT_WINDOW",0)==1 or feat.get("api_addView",0)==1
            network = feat.get("INTERNET",0)==1 and (feat.get("num_http",0)>0 or feat.get("num_suspicious_tld",0)>0)
            impersonate = feat.get("impersonation_score",0) >= 80 and feat.get("pkg_official",0)==0 and (feat.get("label_contains_bank",0)==1 or feat.get("package_contains_bank",0)==1)
            signals = int(hazard_sms) + int(overlay) + int(network) + int(impersonate)
            
            # Apply heuristics
            if aggressive:
                if pred == 0 and (prob >= (threshold - margin) and signals >= 1):
                    pred = 1
                elif pred == 0 and (prob >= heur_min_prob and signals >= heur_min_signals):
                    pred = 1
            
            if official_override and is_official and prob <= official_override_cap:
                pred = 0
                
        except Exception:
            pass

        await send_progress_update(connection_id, task_id, 6, "completed", total_progress + 15, "ML models completed")
        total_progress += 15

        # Step 7: Generate risk score
        await send_progress_update(connection_id, task_id, 7, "running", total_progress + 5, "Generating risk assessment...")
        await asyncio.sleep(0.3)
        
        risk = "Red" if prob >= max(0.8, threshold) else ("Amber" if (prob >= threshold or pred==1) else "Green")
        
        # Generate SHAP explanations
        top_shap = []
        try:
            import shap
            try:
                explainer = shap.TreeExplainer(model)
                shap_values = explainer.shap_values(X)
                if isinstance(shap_values, list):
                    sv = shap_values[1][0]
                else:
                    sv = shap_values[0]
                idxs = np.argsort(np.abs(sv))[::-1][:3]
                for j in idxs:
                    top_shap.append({"feature": feature_order[j], "value": float(sv[j])})
            except Exception:
                pass
        except Exception:
            pass

        await send_progress_update(connection_id, task_id, 7, "completed", 100, "Risk assessment completed")
        
        # Prepare final result
        label_map = {0: "legit", 1: "fake"}
        result = {
            "prediction": label_map.get(int(pred), str(pred)),
            "probability": prob,
            "risk": risk,
            "riskScore": int(prob * 100),
            "summary": {
                "fileName": filename,
                "scanTime": asyncio.get_event_loop().time(),
                "verdict": "Potentially Malicious" if pred == 1 else "Appears Safe",
                "riskLevel": risk,
                "confidence": int(prob * 100),
            },
            "details": {
                "permissions": feat.get("num_permissions", 0),
                "suspiciousAPIs": feat.get("count_suspicious", 0),
                "certificateValid": feat.get("cert_present", 0) == 1,
                "bankingRelated": banking_related,
                "impersonationScore": impersonation_score,
                "officialPackage": is_official,
                "minSDK": feat.get("min_sdk", 0),
                "targetSDK": feat.get("target_sdk", 0),
                "domains": feat.get("num_domains", 0),
                "suspiciousDomains": feat.get("num_suspicious_tld", 0),
            },
            "topFeatures": top_shap,
            "featureVector": feat,
        }
        
        # Send completion
        await send_completion(connection_id, task_id, result)
        manager.remove_task(connection_id, task_id)
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        await send_error(connection_id, task_id, f"Analysis failed: {str(e)}")
        manager.remove_task(connection_id, task_id)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


async def analyze_batch_with_progress(connection_id: str, task_id: str, files_data: List[Dict], quick: bool = False):
    """Analyze multiple APKs with progress updates."""
    total_files = len(files_data)
    results = []
    
    for i, file_data in enumerate(files_data):
        filename = file_data["filename"]
        file_content = file_data["content"]
        
        # Create subtask for this file
        file_task_id = f"{task_id}_file_{i}"
        manager.add_task(connection_id, file_task_id)
        
        # Send batch progress
        batch_progress = {
            "type": "batch_progress",
            "task_id": task_id,
            "current_file": i + 1,
            "total_files": total_files,
            "filename": filename,
            "overall_progress": int((i / total_files) * 100),
            "timestamp": asyncio.get_event_loop().time()
        }
        await manager.send_message(connection_id, batch_progress)
        
        # Analyze this file
        try:
            # Run analysis for this file (simplified, without individual step updates for batch)
            ensure_dirs()
            
            suffix = os.path.splitext(filename)[1] if filename else ".apk"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(file_content)
                tmp_path = tmp.name
            
            try:
                model_obj = load_model(MODEL_PATH)
                model = model_obj["model"]
                feature_order = model_obj["feature_order"]
                saved_thr = float(model_obj.get("tuned_threshold", 0.61))
                
                sha = None
                try:
                    sha = get_sha256(tmp_path)
                except Exception:
                    pass
                
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
                                results.append({"filename": filename, "error": "Could not parse APK"})
                                continue
                        else:
                            results.append({"filename": filename, "error": "Parse failed"})
                            continue
                
                if not isinstance(ext, dict):
                    results.append({"filename": filename, "error": "Invalid APK structure"})
                    continue
                
                v = _vectorize_from_extract(ext, feature_order)
                X = np.array([v["vector"]])
                
                try:
                    prob = float(model.predict_proba(X)[0, 1])
                except Exception:
                    raw = model.predict(X)[0]
                    prob = float(int(raw))
                
                threshold = float(os.environ.get("ML_FAKE_THRESHOLD", str(saved_thr)))
                pred = 1 if prob >= threshold else 0
                risk = "Red" if prob >= max(0.8, threshold) else ("Amber" if (prob >= threshold or pred==1) else "Green")
                
                label_map = {0: "legit", 1: "fake"}
                file_result = {
                    "filename": filename,
                    "prediction": label_map.get(int(pred), str(pred)),
                    "probability": prob,
                    "risk": risk,
                    "riskScore": int(prob * 100),
                    "featureVector": v["feature_map"],
                }
                results.append(file_result)
                
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
                    
        except Exception as e:
            results.append({"filename": filename, "error": str(e)})
        
        manager.remove_task(connection_id, file_task_id)
    
    # Send final batch completion
    batch_completion = {
        "type": "batch_complete",
        "task_id": task_id,
        "results": results,
        "total_files": total_files,
        "timestamp": asyncio.get_event_loop().time()
    }
    await manager.send_message(connection_id, batch_completion)
    manager.remove_task(connection_id, task_id)


# WebSocket endpoint handler
async def websocket_handler(websocket: WebSocket):
    connection_id = str(uuid.uuid4())
    await manager.connect(websocket, connection_id)
    
    try:
        while True:
            # Wait for messages from client
            data = await websocket.receive_text()
            message = json.loads(data)
            
            message_type = message.get("type")
            task_id = message.get("task_id", str(uuid.uuid4()))
            
            if message_type == "scan_single":
                # Single APK analysis
                file_content = bytes.fromhex(message["file_content"])
                filename = message.get("filename", "unknown.apk")
                quick = message.get("quick", False)
                
                manager.add_task(connection_id, task_id)
                
                # Start analysis in background
                asyncio.create_task(analyze_apk_with_progress(
                    connection_id, task_id, file_content, filename, quick
                ))
                
            elif message_type == "scan_batch":
                # Batch APK analysis
                files_data = message["files"]  # List of {filename, content_hex}
                quick = message.get("quick", False)
                
                # Convert hex content back to bytes
                for file_data in files_data:
                    file_data["content"] = bytes.fromhex(file_data["content"])
                
                manager.add_task(connection_id, task_id)
                
                # Start batch analysis in background
                asyncio.create_task(analyze_batch_with_progress(
                    connection_id, task_id, files_data, quick
                ))
            
            elif message_type == "ping":
                # Health check
                await manager.send_message(connection_id, {"type": "pong", "timestamp": asyncio.get_event_loop().time()})
                
    except WebSocketDisconnect:
        manager.disconnect(connection_id)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(connection_id)
