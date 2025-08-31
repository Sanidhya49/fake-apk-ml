"""Flask API for APK fake/legit detection.

This Flask app provides REST endpoints for scanning single APK files and batch analysis.
It wraps the ML inference service and provides a simple HTTP API.

Run locally:
    python flask_app/main.py
"""

import os
import sys
import tempfile
import json
import time
import threading
from typing import Dict, List
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Add the parent directory to Python path so we can import from ml module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml import static_extract
from ml.utils import ensure_dirs, load_model, vectorize_feature_dict, get_sha256, load_bank_whitelist
from rapidfuzz import fuzz

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except Exception:
    pass

# Initialize Flask app
app = Flask(__name__)

# Configure CORS with more explicit settings
CORS(app, 
     origins=["*"],  # Allow all origins for now, restrict in production
     methods=["GET", "POST", "OPTIONS"],  # Allowed HTTP methods
     allow_headers=["Content-Type", "Authorization"],  # Allowed headers
     supports_credentials=False  # Set to True if you need credentials
)

# Performance optimizations
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 3600  # Cache static files for 1 hour
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Thread pool for async processing
executor = ThreadPoolExecutor(max_workers=4)

# Configuration
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "xgb_model.joblib")
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk', 'apks', 'xapk'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Global variables for caching
_model_cache = None
_feature_order_cache = None
_saved_threshold_cache = None
_bank_whitelist_cache = None

def get_cached_model():
    """Get cached model instance"""
    global _model_cache
    if _model_cache is None:
        try:
            model_data = load_model(MODEL_PATH)
            if isinstance(model_data, dict):
                _model_cache = model_data['model']  # Extract the actual model from dict
                print(f"Model loaded successfully from {MODEL_PATH}")
            else:
                _model_cache = model_data  # Direct model object
                print(f"Model loaded successfully from {MODEL_PATH}")
        except Exception as e:
            print(f"Error loading model: {e}")
            raise Exception(f"Failed to load model: {e}")
    return _model_cache

def get_cached_feature_order():
    """Get cached feature order"""
    global _feature_order_cache
    if _feature_order_cache is None:
        try:
            model_data = load_model(MODEL_PATH)
            if isinstance(model_data, dict):
                _feature_order_cache = model_data['feature_order']  # Get from dict
            else:
                _feature_order_cache = model_data.feature_names_in_.tolist()  # Get from model
        except Exception as e:
            print(f"Error loading feature order: {e}")
            raise Exception(f"Failed to load feature order: {e}")
    return _feature_order_cache

def get_cached_threshold():
    """Get cached threshold"""
    global _saved_threshold_cache
    if _saved_threshold_cache is None:
        try:
            model_data = load_model(MODEL_PATH)
            if isinstance(model_data, dict):
                _saved_threshold_cache = model_data.get('tuned_threshold', 0.5)  # Get from dict
            else:
                _saved_threshold_cache = getattr(model_data, 'tuned_threshold', 0.5)  # Get from model
        except Exception as e:
            print(f"Error loading threshold: {e}")
            _saved_threshold_cache = 0.5
    return _saved_threshold_cache

def get_cached_bank_whitelist():
    """Get cached bank whitelist"""
    global _bank_whitelist_cache
    if _bank_whitelist_cache is None:
        _bank_whitelist_cache = load_bank_whitelist()
    return _bank_whitelist_cache

@lru_cache(maxsize=1000)
def allowed_file(filename):
    """Check if uploaded file has allowed extension (cached)"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def _vectorize_from_extract(extract_dict: Dict, feature_order: List[str]) -> Dict:
    """Convert extracted APK features to ML feature vector"""
    # Build the same features as in feature_builder
    permissions = set(extract_dict.get("permissions", []))
    suspicious = extract_dict.get("suspicious_apis", {})

    base: Dict[str, int] = {}
    
    # Permissions of interest (must match builder)
    for p in ["READ_SMS", "SEND_SMS", "RECEIVE_SMS", "SYSTEM_ALERT_WINDOW", "READ_CONTACTS", "INTERNET"]:
        base[p] = 1 if p in permissions else 0

    # Suspicious APIs
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
    
    # Additional CN-based features
    subject_cn = (extract_dict.get("cert_subject_cn") or "").lower()
    issuer_cn = (extract_dict.get("cert_issuer_cn") or "").lower()
    base["issuer_cn_google_android"] = 1 if ("google" in issuer_cn or "android" in issuer_cn) else 0
    base["subject_cn_contains_pkg"] = 1 if (pkg and pkg in subject_cn) else 0
    base["issuer_subject_cn_equal"] = 1 if (subject_cn and issuer_cn and subject_cn == issuer_cn) else 0
    
    # Package analysis
    base["pkg_official"] = 0
    if pkg:
        bank_whitelist = get_cached_bank_whitelist()
        for bank in bank_whitelist:
            if fuzz.partial_ratio(pkg, bank) >= 85:
                base["pkg_official"] = 1
                break
    
    # Build feature vector
    vector = []
    for feat in feature_order:
        vector.append(base.get(feat, 0))
    
    return {"vector": vector, "feature_map": base}

def process_single_apk(file_path: str, quick: bool = False, debug: bool = False) -> Dict:
    """Process a single APK file (optimized version)"""
    try:
        # Get cached instances
        model = get_cached_model()
        feature_order = get_cached_feature_order()
        saved_thr = get_cached_threshold()
        
        # Get SHA256 for caching
        sha = get_sha256(file_path)
        
        # Check cache first
        cache_dir = os.path.join("artifacts", "static_jsons")
        cache_path = os.path.join(cache_dir, f"{sha}.json")
        
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    ext = json.load(f)
            except:
                ext = None
        else:
            ext = None
        
        # Extract features if not cached
        if ext is None:
            try:
                ext = static_extract.extract(file_path, quick=quick)
            except Exception as e:
                # Retry with quick=True if full parse failed
                if not quick:
                    try:
                        ext = static_extract.extract(file_path, quick=True)
                    except Exception:
                        return {"error": "parse_failed", "detail": "Could not parse APK"}
                else:
                    return {"error": "parse_failed", "detail": "Could not parse APK"}
            
            if not isinstance(ext, dict):
                return {"error": "parse_failed", "detail": "Could not parse APK"}
            
            # Cache the results
            try:
                sha = ext.get("sha256") or sha
                if sha:
                    os.makedirs(cache_dir, exist_ok=True)
                    cache_path = os.path.join(cache_dir, f"{sha}.json")
                    if not os.path.exists(cache_path):
                        with open(cache_path, "w", encoding="utf-8") as _f:
                            json.dump(ext, _f, ensure_ascii=False)
            except Exception:
                pass

        # Vectorize features
        v = _vectorize_from_extract(ext, feature_order)
        X = np.array([v["vector"]])
        
        # Get prediction probability
        try:
            prob = float(model.predict_proba(X)[0, 1])
        except Exception:
            # Fallback if model lacks predict_proba
            raw = model.predict(X)[0]
            prob = float(int(raw))

        # Determine prediction and risk
        threshold = float(os.environ.get("ML_FAKE_THRESHOLD", str(saved_thr)))
        pred_initial = 1 if prob >= threshold else 0
        pred = pred_initial
        
        # Apply heuristics and overrides (simplified version)
        feat = v["feature_map"]
        is_official = feat.get("pkg_official", 0) == 1
        official_override_cap = float(os.environ.get("ML_OFFICIAL_OVERRIDE_CAP", "0.40"))
        
        # Official package override
        if is_official and prob <= official_override_cap:
            pred = 0
        
        # Risk categorization with confidence
        risk = "Red" if prob >= max(0.8, threshold) else ("Amber" if (prob >= threshold or pred == 1) else "Green")
        
        # Get top SHAP features (best effort)
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
                top_shap = []
        except Exception:
            top_shap = []

        # Calculate confidence score
        if prob >= 0.8 or prob <= 0.2:
            confidence = "High"
        elif prob >= 0.6 or prob <= 0.4:
            confidence = "Medium"
        else:
            confidence = "Low"
        
        label_map = {0: "legit", 1: "fake"}
        
        # Add confidence to result
        result = {
            "prediction": label_map.get(int(pred), str(pred)),
            "probability": prob,
            "risk": risk,
            "confidence": confidence,
            "top_shap": top_shap,
            "feature_vector": v["feature_map"],
        }
        
        if debug:
            result["debug"] = {
                "processing_time_seconds": time.time() - start_time,
                "cache_used": sha in cache,
                "model_threshold": float(threshold),
                "saved_tuned_threshold": float(saved_thr),
                "pred_initial": int(pred_initial),
                "is_official": bool(is_official),
                "official_override_cap": float(official_override_cap),
                "sha256": sha,
            }
        
        return result
        
    except Exception as e:
        return {"error": "prediction_failed", "detail": str(e)}

# Routes
@app.before_request
def handle_preflight():
    """Handle CORS preflight requests"""
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization")
        response.headers.add('Access-Control-Allow-Methods', "GET,PUT,POST,DELETE,OPTIONS")
        return response

@app.after_request
def after_request(response):
    """Add CORS headers and performance monitoring to all responses"""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    
    # Add performance monitoring headers
    response.headers.add('X-API-Version', '2.0')
    response.headers.add('X-Model-Threshold', str(os.environ.get('ML_FAKE_THRESHOLD', '0.35')))
    
    return response

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "ok", 
        "message": "Fake APK Detection API is running",
        "endpoints": {
            "scan_single": "POST /scan",
            "scan_batch": "POST /scan-batch",
            "generate_report": "POST /report"
        }
    })

@app.route('/scan', methods=['POST'])
def scan_single():
    """Scan a single APK file (optimized)"""
    start_time = time.time()
    
    try:
        # Check if file is in request
        if 'file' not in request.files:
            return jsonify({"error": "no_file", "detail": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "no_file", "detail": "No file selected"}), 400
        
        # Check if file is empty
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size == 0:
            return jsonify({"error": "empty_file", "detail": "File is empty"}), 400
        
        # Validate file type (cached)
        if not allowed_file(file.filename):
            return jsonify({
                "error": "invalid_file_type", 
                "detail": f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
            }), 400
        
        # Get query parameters
        quick = request.args.get('quick', 'false').lower() == 'true'
        debug = request.args.get('debug', 'false').lower() == 'true'
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1])
        try:
            file.save(temp_file.name)
            temp_file.close()
            
            # Make sure directories exist
            ensure_dirs()
            
            # Predict (with timing)
            result = process_single_apk(temp_file.name, quick=quick, debug=debug)
            
            # Add performance metrics
            processing_time = time.time() - start_time
            if debug and "debug" in result:
                result["debug"]["processing_time_seconds"] = round(processing_time, 3)
            elif debug:
                result["debug"] = {"processing_time_seconds": round(processing_time, 3)}
            
            # Check for errors
            if "error" in result:
                return jsonify(result), 422 if result["error"] == "parse_failed" else 500
            
            return jsonify(result)
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file.name)
            except Exception:
                pass
                
    except Exception as e:
        return jsonify({"error": "internal_error", "detail": str(e)}), 500

@app.route('/scan-batch', methods=['POST'])
def scan_batch():
    """Scan multiple APK files (enhanced for up to 15 APKs)"""
    start_time = time.time()
    
    try:
        # Check if files are in request
        if 'files' not in request.files:
            return jsonify({"error": "no_files", "detail": "No files provided"}), 400
        
        files = request.files.getlist('files')
        if not files or len(files) == 0:
            return jsonify({"error": "no_files", "detail": "No files selected"}), 400
        
        # Limit to 15 files maximum
        if len(files) > 15:
            return jsonify({"error": "too_many_files", "detail": "Maximum 15 files allowed per batch"}), 400
        
        # Get query parameters
        quick = request.args.get('quick', 'false').lower() == 'true'
        debug = request.args.get('debug', 'false').lower() == 'true'
        
        # Validate all files first
        valid_files = []
        for file in files:
            if file.filename == '':
                continue
            if not allowed_file(file.filename):
                continue
            valid_files.append(file)
        
        if not valid_files:
            return jsonify({"error": "no_valid_files", "detail": "No valid APK files found"}), 400
        
        # Process files (with async for better performance)
        results = []
        temp_files = []
        
        try:
            for file in valid_files:
                # Save uploaded file temporarily
                filename = secure_filename(file.filename)
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1])
                temp_files.append(temp_file.name)
                
                file.save(temp_file.name)
                temp_file.close()
                
                # Process file
                result = process_single_apk(temp_file.name, quick=quick, debug=debug)
                result["file"] = file.filename
                results.append(result)
            
            # Add batch performance metrics
            processing_time = time.time() - start_time
            if debug:
                for result in results:
                    if "debug" not in result:
                        result["debug"] = {}
                    result["debug"]["batch_processing_time_seconds"] = round(processing_time, 3)
                    result["debug"]["files_processed"] = len(valid_files)
            
            return jsonify({
                "results": results,
                "summary": {
                    "total_files": len(valid_files),
                    "processing_time_seconds": round(processing_time, 3),
                    "files_per_second": round(len(valid_files) / processing_time, 2) if processing_time > 0 else 0,
                    "max_files_allowed": 15
                }
            })
            
        finally:
            # Clean up temporary files
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except Exception:
                    pass
                    
    except Exception as e:
        return jsonify({"error": "internal_error", "detail": str(e)}), 500

@app.route('/report', methods=['POST'])
def generate_report():
    """Generate a detailed HTML report for an APK"""
    try:
        # Check if file is in request
        if 'file' not in request.files:
            return jsonify({"error": "no_file", "detail": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "no_file", "detail": "No file selected"}), 400
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({
                "error": "invalid_file_type", 
                "detail": f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
            }), 400
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1])
        try:
            file.save(temp_file.name)
            temp_file.close()
            
            # Make sure directories exist
            ensure_dirs()
            
            # Get analysis result
            result = process_single_apk(temp_file.name, quick=False, debug=True)
            
            # Check for errors
            if "error" in result:
                return jsonify(result), 422 if result["error"] == "parse_failed" else 500
            
            # Generate HTML report
            html_report = _render_html_report(result, filename)
            
            return jsonify({
                "result": result,
                "html": html_report
            })
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file.name)
            except Exception:
                pass
                
    except Exception as e:
        return jsonify({"error": "internal_error", "detail": str(e)}), 500

@app.route('/report-batch', methods=['POST'])
def generate_batch_report():
    """Generate comprehensive Word document report for multiple APKs with AI explanations"""
    try:
        # Check if files are in request
        if 'files' not in request.files:
            return jsonify({"error": "no_files", "detail": "No files provided"}), 400
        
        files = request.files.getlist('files')
        if not files or len(files) == 0:
            return jsonify({"error": "no_files", "detail": "No files selected"}), 400
        
        # Limit to 15 files maximum
        if len(files) > 15:
            return jsonify({"error": "too_many_files", "detail": "Maximum 15 files allowed per batch"}), 400
        
        # Validate all files first
        valid_files = []
        for file in files:
            if file.filename == '':
                continue
            if not allowed_file(file.filename):
                continue
            valid_files.append(file)
        
        if not valid_files:
            return jsonify({"error": "no_valid_files", "detail": "No valid APK files found"}), 400
        
        # Process all files
        results = []
        temp_files = []
        
        try:
            for file in valid_files:
                # Save uploaded file temporarily
                filename = secure_filename(file.filename)
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1])
                temp_files.append(temp_file.name)
                
                file.save(temp_file.name)
                temp_file.close()
                
                # Process file with full analysis
                result = process_single_apk(temp_file.name, quick=False, debug=True)
                result["file"] = file.filename
                results.append(result)
            
            # Generate comprehensive Word document report
            word_report = _generate_word_report(results)
            
            return jsonify({
                "results": results,
                "word_report": word_report,
                "summary": {
                    "total_files": len(valid_files),
                    "report_generated": True,
                    "max_files_allowed": 15
                }
            })
            
        finally:
            # Clean up temporary files
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except Exception:
                    pass
                    
    except Exception as e:
        return jsonify({"error": "internal_error", "detail": str(e)}), 500

def _render_html_report(result: Dict, filename: str) -> str:
    """Generate HTML report from analysis result"""
    fv = result.get("feature_vector", {})
    top = result.get("top_shap", [])
    pred = result.get("prediction", "unknown")
    prob = result.get("probability", 0)
    risk = result.get("risk", "Unknown")
    
    def format_feature_name(name):
        """Convert feature name to proper title case without underscores"""
        # Special mappings for common abbreviations and terms
        special_mappings = {
            'api': 'API',
            'sdk': 'SDK',
            'cn': 'Certificate Name',
            'pkg': 'Package',
            'url': 'URL',
            'http': 'HTTP',
            'tld': 'Top Level Domain',
            'mb': 'MB',
            'upi': 'UPI',
            'sms': 'SMS',
            'id': 'ID',
            'dex': 'DEX'
        }
        
        # Remove prefixes like 'api_', 'perm_' for cleaner names
        clean_name = name
        if name.startswith('api_'):
            clean_name = name[4:]
        elif name.startswith('perm_'):
            clean_name = name[5:]
        
        # Split by underscores and convert to title case
        words = clean_name.split('_')
        formatted_words = []
        
        for word in words:
            if word.lower() in special_mappings:
                formatted_words.append(special_mappings[word.lower()])
            else:
                formatted_words.append(word.title())
        
        return ' '.join(formatted_words)
    
    # Separate permissions and other features
    permissions = {}
    api_features = {}
    general_features = {}
    
    for k, v in fv.items():
        if k in ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'SYSTEM_ALERT_WINDOW', 'READ_CONTACTS', 'INTERNET', 'QUERY_ALL_PACKAGES']:
            if v == 1:  # Only show permissions that are granted (true)
                permissions[k] = v
        elif k.startswith('api_') and v == 1:  # Only show APIs that are present
            api_features[k] = v
        else:
            general_features[k] = v
    
    # Build permission cards (only for granted permissions)
    permission_cards = ""
    if permissions:
        for perm, value in permissions.items():
            perm_display = format_feature_name(perm)
            permission_cards += f"""
                <div class="permission-card granted">
                    <div class="permission-icon">🔓</div>
                    <div class="permission-name">{perm_display}</div>
                </div>
            """
    
    # Build API features list (only for present APIs)
    api_rows = ""
    if api_features:
        for api, value in api_features.items():
            api_display = format_feature_name(api)
            api_rows += f"<tr><td>{api_display}</td><td><span class='status-present'>Present</span></td></tr>"
    
    # Build general features table
    general_rows = ""
    for k, v in general_features.items():
        if k not in ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'SYSTEM_ALERT_WINDOW', 'READ_CONTACTS', 'INTERNET', 'QUERY_ALL_PACKAGES'] and not k.startswith('api_'):
            feature_display = format_feature_name(k)
            if isinstance(v, bool):
                display_value = "Yes" if v else "No"
                value_class = "status-yes" if v else "status-no"
                general_rows += f"<tr><td>{feature_display}</td><td><span class='{value_class}'>{display_value}</span></td></tr>"
            elif isinstance(v, (int, float)) and k.endswith('_score'):
                general_rows += f"<tr><td>{feature_display}</td><td><span class='score-value'>{v:.2f}</span></td></tr>"
            else:
                general_rows += f"<tr><td>{feature_display}</td><td>{v}</td></tr>"
    
    # Build SHAP features list with formatted names
    shap_rows = ""
    for item in top:
        feature_name = format_feature_name(item.get('feature', 'Unknown'))
        value = round(item.get('value', 0), 4)
        impact_class = "positive-impact" if value > 0 else "negative-impact"
        shap_rows += f"<li><strong>{feature_name}</strong>: <span class='{impact_class}'>{value:+.4f}</span></li>"
    
    # Risk color
    risk_color = {"Red": "#dc2626", "Amber": "#d97706", "Green": "#16a34a"}.get(risk, "#6b7280")
    
    # Prediction color
    pred_color = "#dc2626" if pred == "fake" else "#16a34a"
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>APK Security Analysis Report - {filename}</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #1f2937;
                line-height: 1.6;
                min-height: 100vh;
            }}
            .container {{
                max-width: 1100px;
                margin: 0 auto;
                background: white;
                border-radius: 16px;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px;
                text-align: center;
                position: relative;
            }}
            .header::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M20 20c0 11.046-8.954 20-20 20v20h40V20H20z'/%3E%3C/g%3E%3C/svg%3E") repeat;
            }}
            .header-content {{
                position: relative;
                z-index: 1;
            }}
            .header h1 {{
                margin: 0 0 15px 0;
                font-size: 2.5em;
                font-weight: 800;
                text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }}
            .header p {{
                margin: 0;
                opacity: 0.95;
                font-size: 1.2em;
                font-weight: 300;
            }}
            .content {{
                padding: 40px;
            }}
            .summary {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 25px;
                margin-bottom: 40px;
            }}
            .summary-card {{
                padding: 25px;
                border-radius: 12px;
                border: 1px solid #e5e7eb;
                background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                transition: transform 0.2s ease, box-shadow 0.2s ease;
            }}
            .summary-card:hover {{
                transform: translateY(-2px);
                box-shadow: 0 8px 15px -3px rgba(0, 0, 0, 0.1);
            }}
            .summary-card h3 {{
                margin: 0 0 12px 0;
                font-size: 0.9em;
                font-weight: 700;
                text-transform: uppercase;
                color: #6b7280;
                letter-spacing: 0.1em;
            }}
            .summary-card .value {{
                font-size: 2em;
                font-weight: 800;
                margin: 0;
            }}
            .section {{
                margin-bottom: 40px;
                background: #f9fafb;
                border-radius: 12px;
                padding: 30px;
                border: 1px solid #e5e7eb;
            }}
            .section h2 {{
                margin: 0 0 25px 0;
                font-size: 1.6em;
                font-weight: 700;
                color: #111827;
                border-bottom: 3px solid #667eea;
                padding-bottom: 10px;
                display: flex;
                align-items: center;
            }}
            .section h2::before {{
                content: '🔍';
                margin-right: 10px;
                font-size: 1.2em;
            }}
            .permissions-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 15px;
                margin-top: 15px;
            }}
            .permission-card {{
                display: flex;
                align-items: center;
                padding: 15px 20px;
                border-radius: 8px;
                border: 2px solid #fbbf24;
                background: #fef3c7;
            }}
            .permission-card.granted {{
                border-color: #ef4444;
                background: #fee2e2;
            }}
            .permission-icon {{
                font-size: 1.5em;
                margin-right: 12px;
            }}
            .permission-name {{
                font-weight: 600;
                color: #374151;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
                background: white;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px -1px rgba(0, 0, 0, 0.1);
            }}
            th, td {{
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid #e5e7eb;
            }}
            th {{
                background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
                font-weight: 700;
                color: #374151;
                text-transform: uppercase;
                font-size: 0.85em;
                letter-spacing: 0.05em;
            }}
            tr:hover {{
                background: #f8fafc;
            }}
            tr:last-child td {{
                border-bottom: none;
            }}
            .status-present {{
                color: #dc2626;
                font-weight: 600;
                padding: 4px 8px;
                background: #fee2e2;
                border-radius: 4px;
                font-size: 0.85em;
            }}
            .status-yes {{
                color: #059669;
                font-weight: 600;
                padding: 4px 8px;
                background: #d1fae5;
                border-radius: 4px;
                font-size: 0.85em;
            }}
            .status-no {{
                color: #6b7280;
                font-weight: 600;
                padding: 4px 8px;
                background: #f3f4f6;
                border-radius: 4px;
                font-size: 0.85em;
            }}
            .score-value {{
                font-weight: 700;
                color: #1f2937;
                padding: 4px 8px;
                background: #e0e7ff;
                border-radius: 4px;
            }}
            ul {{
                list-style: none;
                padding: 0;
            }}
            li {{
                padding: 12px 0;
                border-bottom: 1px solid #f3f4f6;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            li:last-child {{
                border-bottom: none;
            }}
            .positive-impact {{
                color: #dc2626;
                font-weight: 700;
                padding: 4px 8px;
                background: #fee2e2;
                border-radius: 4px;
            }}
            .negative-impact {{
                color: #059669;
                font-weight: 700;
                padding: 4px 8px;
                background: #d1fae5;
                border-radius: 4px;
            }}
            .timestamp {{
                text-align: center;
                margin-top: 40px;
                padding: 25px;
                background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
                border-radius: 12px;
                color: #6b7280;
                font-size: 0.9em;
                border: 1px solid #e5e7eb;
            }}
            .no-data {{
                text-align: center;
                padding: 30px;
                color: #6b7280;
                font-style: italic;
                background: #f9fafb;
                border-radius: 8px;
                border: 1px dashed #d1d5db;
            }}
            @media (max-width: 768px) {{
                body {{ padding: 10px; }}
                .content {{ padding: 25px; }}
                .summary {{ grid-template-columns: 1fr; }}
                .permissions-grid {{ grid-template-columns: 1fr; }}
                .header h1 {{ font-size: 2em; }}
                .section {{ padding: 20px; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="header-content">
                    <h1>🛡️ APK Security Analysis</h1>
                    <p>Comprehensive security analysis for <strong>{filename}</strong></p>
                </div>
            </div>
            
            <div class="content">
                <div class="summary">
                    <div class="summary-card">
                        <h3>📊 Prediction</h3>
                        <p class="value" style="color: {pred_color};">{pred.title()}</p>
                    </div>
                    <div class="summary-card">
                        <h3>⚠️ Risk Level</h3>
                        <p class="value" style="color: {risk_color};">{risk}</p>
                    </div>
                    <div class="summary-card">
                        <h3>🎯 Confidence</h3>
                        <p class="value">{prob:.1%}</p>
                    </div>
                    <div class="summary-card">
                        <h3>📈 Score</h3>
                        <p class="value">{prob:.3f}</p>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Top Contributing Features</h2>
                    {f'<ul>{shap_rows}</ul>' if shap_rows else '<div class="no-data">No SHAP analysis available for this APK.</div>'}
                </div>
                
                {f'''
                <div class="section">
                    <h2>🔐 Granted Permissions</h2>
                    <div class="permissions-grid">
                        {permission_cards}
                    </div>
                </div>
                ''' if permission_cards else ''}
                
                {f'''
                <div class="section">
                    <h2>⚡ Suspicious APIs Detected</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>API Function</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {api_rows}
                        </tbody>
                    </table>
                </div>
                ''' if api_rows else ''}
                
                <div class="section">
                    <h2>📋 Application Metadata</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Feature</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            {general_rows}
                        </tbody>
                    </table>
                </div>
                
                <div class="timestamp">
                    <strong>📅 Report Generated:</strong> {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                    <strong>🔧 Powered by:</strong> Fake APK Detection System v2.0
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html

def _generate_ai_explanation(result: Dict) -> str:
    """Generate AI explanation for the prediction"""
    prediction = result.get('prediction', 'unknown')
    probability = result.get('probability', 0)
    risk = result.get('risk', 'Unknown')
    feature_vector = result.get('feature_vector', {})
    
    # Analyze key features
    suspicious_count = feature_vector.get('count_suspicious', 0)
    has_sms_permissions = any(feature_vector.get(perm, 0) == 1 for perm in ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS'])
    has_contacts_permission = feature_vector.get('READ_CONTACTS', 0) == 1
    has_system_alert = feature_vector.get('SYSTEM_ALERT_WINDOW', 0) == 1
    is_official = feature_vector.get('pkg_official', 0) == 1
    cert_present = feature_vector.get('cert_present', 0) == 1
    
    # Generate explanation based on prediction
    if prediction == 'fake':
        reasons = []
        if probability >= 0.8:
            reasons.append("High probability score indicates strong evidence of malicious behavior")
        if suspicious_count > 3:
            reasons.append(f"Multiple suspicious APIs detected ({suspicious_count} total)")
        if has_sms_permissions:
            reasons.append("SMS permissions detected - potential for SMS-based attacks")
        if has_contacts_permission:
            reasons.append("Contacts access permission - could be used for data harvesting")
        if has_system_alert:
            reasons.append("System alert window permission - potential for overlay attacks")
        if not cert_present:
            reasons.append("No valid certificate found - suspicious for legitimate apps")
        
        explanation = f"This APK was classified as FAKE with {probability:.1%} confidence. "
        if reasons:
            explanation += "Key factors contributing to this classification: " + "; ".join(reasons) + "."
        else:
            explanation += "The model detected patterns consistent with malicious applications."
    
    else:  # legit
        reasons = []
        if probability <= 0.2:
            reasons.append("Low probability score indicates legitimate behavior patterns")
        if is_official:
            reasons.append("Package identified as official/trusted source")
        if cert_present:
            reasons.append("Valid certificate present - indicates proper app signing")
        if suspicious_count <= 1:
            reasons.append("Minimal suspicious API usage detected")
        if not has_sms_permissions and not has_contacts_permission:
            reasons.append("No sensitive permissions requested")
        
        explanation = f"This APK was classified as LEGITIMATE with {probability:.1%} confidence. "
        if reasons:
            explanation += "Key factors supporting this classification: " + "; ".join(reasons) + "."
        else:
            explanation += "The model found no significant indicators of malicious behavior."
    
    # Add risk level explanation
    if risk == 'Red':
        explanation += " Risk Level RED indicates high confidence in malicious behavior."
    elif risk == 'Amber':
        explanation += " Risk Level AMBER indicates moderate suspicion requiring further investigation."
    else:  # Green
        explanation += " Risk Level GREEN indicates low risk of malicious behavior."
    
    return explanation

def _generate_word_report(results: List[Dict]) -> str:
    """Generates a comprehensive Word document report for multiple APKs with AI explanations"""
    try:
        from docx import Document
        from docx.shared import Inches
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_ALIGN_VERTICAL
        from docx.enum.text import WD_BREAK
    except ImportError:
        # Fallback to HTML if python-docx is not available
        return _generate_html_batch_report(results)
    
    doc = Document()
    
    # Add a cover page
    doc.add_heading('APK Security Analysis Report', 0)
    doc.add_paragraph('This report provides a comprehensive analysis of the security posture of the APKs scanned.')
    doc.add_paragraph(f'Generated on: {__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}')
    doc.add_page_break()
    
    # Add Executive Summary
    doc.add_heading('Executive Summary', level=1)
    total_files = len(results)
    fake_count = sum(1 for r in results if r.get('prediction') == 'fake')
    legit_count = sum(1 for r in results if r.get('prediction') == 'legit')
    
    doc.add_paragraph(f'Total APKs analyzed: {total_files}')
    doc.add_paragraph(f'Legitimate APKs: {legit_count}')
    doc.add_paragraph(f'Malicious APKs: {fake_count}')
    doc.add_paragraph(f'Detection rate: {(fake_count/total_files)*100:.1f}% of files flagged as suspicious')
    doc.add_page_break()
    
    # Add Summary Table
    doc.add_heading('Summary Table', level=1)
    table = doc.add_table(rows=len(results) + 1, cols=5)
    table.style = 'Table Grid'
    
    # Add headers
    headers = ['APK File', 'Prediction', 'Risk Level', 'Confidence', 'AI Explanation']
    for i, header in enumerate(headers):
        table.cell(0, i).text = header
    
    # Add data rows
    for i, result in enumerate(results):
        file_name = result.get('file', 'N/A')
        prediction = result.get('prediction', 'Unknown').title()
        risk = result.get('risk', 'Unknown')
        confidence = f'{result.get("probability", 0):.1%}'
        ai_explanation = _generate_ai_explanation(result)
        
        table.cell(i + 1, 0).text = file_name
        table.cell(i + 1, 1).text = prediction
        table.cell(i + 1, 2).text = risk
        table.cell(i + 1, 3).text = confidence
        table.cell(i + 1, 4).text = ai_explanation[:100] + "..." if len(ai_explanation) > 100 else ai_explanation
    
    doc.add_page_break()
    
    # Add Detailed Analysis
    doc.add_heading('Detailed Analysis', level=1)
    for i, result in enumerate(results):
        doc.add_heading(f'Analysis for {result.get("file", "N/A")}', level=2)
        
        # Basic info
        doc.add_paragraph(f'**Prediction:** {result.get("prediction", "Unknown").title()}')
        doc.add_paragraph(f'**Risk Level:** {result.get("risk", "Unknown")}')
        doc.add_paragraph(f'**Confidence:** {result.get("probability", 0):.1%}')
        
        # AI Explanation
        doc.add_heading('AI Agent Explanation', level=3)
        ai_explanation = _generate_ai_explanation(result)
        doc.add_paragraph(ai_explanation)
        
        # Feature Analysis
        doc.add_heading('Feature Analysis', level=3)
        feature_vector = result.get('feature_vector', {})
        
        # Permissions
        permissions = [k for k, v in feature_vector.items() if k in ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'SYSTEM_ALERT_WINDOW', 'READ_CONTACTS', 'INTERNET'] and v == 1]
        if permissions:
            doc.add_paragraph('**Granted Permissions:**')
            for perm in permissions:
                doc.add_paragraph(f'• {perm.replace("_", " ").title()}')
        
        # Suspicious APIs
        suspicious_apis = [k for k, v in feature_vector.items() if k.startswith('api_') and v == 1]
        if suspicious_apis:
            doc.add_paragraph('**Suspicious APIs Detected:**')
            for api in suspicious_apis:
                api_name = api.replace('api_', '').replace('_', ' ').title()
                doc.add_paragraph(f'• {api_name}')
        
        # SHAP Analysis
        if result.get('top_shap'):
            doc.add_heading('Top Contributing Features (SHAP Analysis)', level=3)
            for item in result.get('top_shap', []):
                feature_name = item.get('feature', 'Unknown').replace('_', ' ').title()
                value = item.get('value', 0)
                doc.add_paragraph(f'• {feature_name}: {value:+.4f}')
        
        doc.add_page_break()
    
    # Add Recommendations
    doc.add_heading('Security Recommendations', level=1)
    doc.add_paragraph('Based on the analysis, consider the following recommendations:')
    doc.add_paragraph('• Review all RED risk APKs immediately')
    doc.add_paragraph('• Investigate AMBER risk APKs thoroughly')
    doc.add_paragraph('• Implement additional security measures for suspicious apps')
    doc.add_paragraph('• Regular scanning of new APKs before deployment')
    
    # Save the document
    docx_path = os.path.join("artifacts", "batch_report.docx")
    os.makedirs(os.path.dirname(docx_path), exist_ok=True)
    doc.save(docx_path)
    return docx_path

def _generate_html_batch_report(results: List[Dict]) -> str:
    """Fallback HTML report generation if python-docx is not available"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>APK Security Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
            .summary { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
            .apk-analysis { border: 1px solid #ddd; margin: 20px 0; padding: 20px; border-radius: 5px; }
            .fake { border-left: 5px solid #ff4444; }
            .legit { border-left: 5px solid #44ff44; }
            .red { color: #ff4444; font-weight: bold; }
            .amber { color: #ffaa00; font-weight: bold; }
            .green { color: #44ff44; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>APK Security Analysis Report</h1>
            <p>Generated on: """ + __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC') + """</p>
        </div>
    """
    
    # Summary
    total_files = len(results)
    fake_count = sum(1 for r in results if r.get('prediction') == 'fake')
    legit_count = sum(1 for r in results if r.get('prediction') == 'legit')
    
    html += f"""
        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Total APKs analyzed:</strong> {total_files}</p>
            <p><strong>Legitimate APKs:</strong> {legit_count}</p>
            <p><strong>Malicious APKs:</strong> {fake_count}</p>
            <p><strong>Detection rate:</strong> {(fake_count/total_files)*100:.1f}% of files flagged as suspicious</p>
        </div>
    """
    
    # Individual APK Analysis
    for result in results:
        prediction = result.get('prediction', 'unknown')
        risk = result.get('risk', 'Unknown')
        probability = result.get('probability', 0)
        ai_explanation = _generate_ai_explanation(result)
        
        risk_class = risk.lower()
        pred_class = prediction
        
        html += f"""
        <div class="apk-analysis {pred_class}">
            <h3>Analysis for {result.get('file', 'N/A')}</h3>
            <p><strong>Prediction:</strong> {prediction.title()}</p>
            <p><strong>Risk Level:</strong> <span class="{risk_class}">{risk}</span></p>
            <p><strong>Confidence:</strong> {probability:.1%}</p>
            <p><strong>AI Explanation:</strong> {ai_explanation}</p>
        </div>
        """
    
    html += """
    </body>
    </html>
    """
    
    return html

@app.route('/test', methods=['GET'])
def test_endpoint():
    return jsonify({"message": "Test endpoint is working!"})

if __name__ == '__main__':
    # Make sure required directories exist
    ensure_dirs()
    
    # Get configuration from environment
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    
    # Handle PORT environment variable (Render.com uses $PORT)
    port_str = os.environ.get('PORT') or os.environ.get('FLASK_PORT', '9000')
    try:
        port = int(port_str)
    except ValueError:
        print(f"Warning: Invalid port '{port_str}', using default 9000")
        port = 9000
    
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Performance optimizations for production
    if not debug:
        # Disable Flask debug mode for production
        os.environ['FLASK_ENV'] = 'production'
        
        # Set thread pool size
        import multiprocessing
        workers = min(multiprocessing.cpu_count() * 2 + 1, 8)
        
        print(f"Starting Flask APK Detection API on {host}:{port}")
        print(f"Model path: {MODEL_PATH}")
        print(f"Debug mode: {debug}")
        print(f"Performance mode: Production (workers: {workers})")
        print("Available endpoints:")
        print("  GET  /           - Health check")
        print("  POST /scan       - Scan single APK")
        print("  POST /scan-batch - Scan multiple APKs (up to 15)")
        print("  POST /report     - Generate detailed HTML report")
        print("  POST /report-batch - Generate Word document report (up to 15 APKs)")
        
        # Use production WSGI server
        try:
            from waitress import serve
            print("Using Waitress WSGI server for production...")
            serve(app, host=host, port=port, threads=workers)
        except ImportError:
            print("Waitress not available, using Flask development server...")
            app.run(host=host, port=port, debug=debug, threaded=True)
    else:
        print(f"Starting Flask APK Detection API on {host}:{port}")
        print(f"Model path: {MODEL_PATH}")
        print(f"Debug mode: {debug}")
        print("Available endpoints:")
        print("  GET  /           - Health check")
        print("  POST /scan       - Scan single APK")
        print("  POST /scan-batch - Scan multiple APKs")
        print("  POST /report     - Generate detailed report")
        
        app.run(host=host, port=port, debug=debug, threaded=True)