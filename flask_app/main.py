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

import logging

# Configure logging to show everything
logging.basicConfig(level=logging.DEBUG)

@app.before_request
def log_request():
    app.logger.info(f"[REQ] {request.remote_addr} {request.method} {request.full_path}")
    app.logger.info(f"Headers: {dict(request.headers)}")
    if request.content_length:
        app.logger.info(f"Body size: {request.content_length} bytes")
    if request.data and request.content_length < 5000:  # prevent logging huge APK files
        try:
            app.logger.info(f"Body: {request.data.decode('utf-8', errors='ignore')}")
        except Exception:
            app.logger.warning("[Body could not be decoded]")

@app.after_request
def log_response(response):
    app.logger.info(
        f"[RESP] {request.remote_addr} {request.method} {request.full_path} "
        f"-> {response.status} ({len(response.data)} bytes)"
    )
    try:
        if len(response.data) < 5000:  # don’t spam with huge responses
            app.logger.debug(f"Response body: {response.data.decode('utf-8', errors='ignore')}")
    except Exception:
        app.logger.warning("[Response body could not be decoded]")
    return response

@app.teardown_request
def log_teardown(error=None):
    if error:
        app.logger.error(f"[ERROR] {request.remote_addr} {request.method} {request.full_path} -> {error}", exc_info=True)

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
        start_time = time.time()  # Add start time for debug
        
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
        if prob >= max(0.8, threshold):
            risk = "Red"
        elif prob >= threshold or pred == 1:
            risk = "Amber"
        else:
            risk = "Green"

        # Get top SHAP features (best effort)
        top_shap = []
        try:
            import shap
            print("✅ SHAP imported successfully")
            try:
                print(f"🔍 SHAP Debug: Model type: {type(model)}")
                print(f"🔍 SHAP Debug: X shape: {X.shape}")
                print(f"🔍 SHAP Debug: Feature order length: {len(feature_order)}")
                
                # Handle CalibratedClassifierCV by extracting base model
                if hasattr(model, 'estimator'):
                    base_model = model.estimator
                    print(f"🔍 SHAP Debug: Using estimator: {type(base_model)}")
                elif hasattr(model, 'base_estimator'):
                    base_model = model.base_estimator
                    print(f"🔍 SHAP Debug: Using base model: {type(base_model)}")
                else:
                    base_model = model
                    print(f"🔍 SHAP Debug: Using original model: {type(base_model)}")
                
                explainer = shap.TreeExplainer(base_model)
                shap_values = explainer.shap_values(X)
                print(f"🔍 SHAP Debug: SHAP values type: {type(shap_values)}")
                
                if isinstance(shap_values, list):
                    sv = shap_values[1][0]
                    print(f"🔍 SHAP Debug: Using list index 1, shape: {sv.shape}")
                else:
                    sv = shap_values[0]
                    print(f"🔍 SHAP Debug: Using direct index 0, shape: {sv.shape}")
                
                idxs = np.argsort(np.abs(sv))[::-1][:3]
                print(f"🔍 SHAP Debug: Top indices: {idxs}")
                
                for j in idxs:
                    if j < len(feature_order):
                        top_shap.append({"feature": feature_order[j], "value": float(sv[j])})
                    else:
                        print(f"🔍 SHAP Debug: Index {j} out of range for feature_order")
                
                print(f"✅ SHAP analysis completed: {len(top_shap)} features")
            except Exception as e:
                print(f"❌ SHAP analysis failed: {e}")
                import traceback
                traceback.print_exc()
                top_shap = []
        except ImportError as e:
            print(f"❌ SHAP import failed: {e}")
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
            "risk_level": risk,  # Changed from "risk" to "risk_level" to match expected format
            "confidence": confidence,
            "top_shap": top_shap,
            "feature_vector": v["feature_map"],
            "processing_time": time.time() - start_time,
            "model_threshold": threshold,
            "cache_used": os.path.exists(cache_path) if 'cache_path' in locals() else False,
        }
        
        # Add AI explanation
        try:
            result["ai_explanation"] = _generate_ai_explanation(result)
        except Exception as e:
            print(f"❌ AI explanation generation failed: {e}")
            result["ai_explanation"] = "AI explanation could not be generated"
        
        if debug:
            result["debug"] = {
                "processing_time_seconds": time.time() - start_time,
                "cache_used": os.path.exists(cache_path) if 'cache_path' in locals() else False,
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
            
            # Add original filename
            result["file"] = file.filename
            
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
    """Generate comprehensive Word document report for multiple APKs with AI explanations
    
    Returns JSON with:
    - results: Array of analysis results for each APK
    - word_report: Base64-encoded Word document content for download
    - summary: Metadata about the batch processing
    """
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
    """Generate AI explanation for the prediction using Gemini API"""
    try:
        import requests
        import json
        import re
        
        # Load API key from environment variable (recommended)
        API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyAI32Wr0w0cLHNx-X10fG7f_fCDZ4SPIpk")
        ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
        
        def extract_json_from_text(text):
            """Extract JSON content from text that might contain markdown code blocks or other text."""
            json_pattern = r'```(?:json)?\n([\s\S]*?)```'
            match = re.search(json_pattern, text)
            
            if match:
                return match.group(1).strip()
            return text.strip()
        
        def call_gemini(system_prompt, user_prompt):
            payload = {
                "contents": [{
                    "parts": [{
                        "text": f"System: {system_prompt}\nUser: {user_prompt}"
                    }]
                }]
            }
            
            if not API_KEY:
                raise ValueError("API key is missing. Please check your environment variables.")
            
            headers = {
                "Content-Type": "application/json",
                "X-goog-api-key": API_KEY
            }
            
            response = requests.post(
                ENDPOINT,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            response_data = response.json()
            
            if 'candidates' not in response_data or not response_data['candidates']:
                raise ValueError("No candidates found in response")
            
            raw_text = response_data['candidates'][0]['content']['parts'][0]['text']
            clean_response = extract_json_from_text(raw_text)
            
            try:
                return json.loads(clean_response)  # if valid JSON
            except json.JSONDecodeError:
                return {"raw_text": clean_response}
        
        # Prepare data for AI analysis
        prediction = result.get('prediction', 'unknown')
        probability = result.get('probability', 0)
        risk_level = result.get('risk_level', 'Unknown')
        confidence = result.get('confidence', 'Unknown')
        feature_vector = result.get('feature_vector', {})
        top_shap = result.get('top_shap', [])
        
        # Analyze key features
        suspicious_count = feature_vector.get('count_suspicious', 0)
        has_sms_permissions = any(feature_vector.get(perm, 0) == 1 for perm in ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS'])
        has_contacts_permission = feature_vector.get('READ_CONTACTS', 0) == 1
        has_system_alert = feature_vector.get('SYSTEM_ALERT_WINDOW', 0) == 1
        is_official = feature_vector.get('pkg_official', 0) == 1
        cert_present = feature_vector.get('cert_present', 0) == 1
        
        # Build prompts for Gemini
        system_prompt = """You are a senior cybersecurity analyst specializing in Android application security and malware analysis. You have extensive experience in reverse engineering, threat intelligence, and mobile security assessment. Provide expert-level, professional cybersecurity analysis using industry-standard terminology, technical depth, and actionable security insights. Your analysis should be comprehensive, technically accurate, and suitable for cybersecurity professionals and security teams."""
        
        user_prompt = f"""
        Conduct a comprehensive cybersecurity analysis of this Android APK security scan result. Provide a detailed, professional assessment suitable for security teams and cybersecurity professionals.

        **APK Security Analysis Results:**
        - **Classification:** {prediction.upper()}
        - **Confidence Score:** {probability:.1%}
        - **Risk Assessment:** {risk_level} Level
        - **Analysis Confidence:** {confidence}

        **Security Indicators Analysis:**
        - **Suspicious API Count:** {suspicious_count} (threshold-based detection)
        - **SMS Permissions:** {'DETECTED' if has_sms_permissions else 'Not Present'} (potential SMS-based attacks)
        - **Contacts Access:** {'DETECTED' if has_contacts_permission else 'Not Present'} (data harvesting risk)
        - **System Alert Window:** {'DETECTED' if has_system_alert else 'Not Present'} (overlay attack capability)
        - **Package Verification:** {'Official' if is_official else 'Unofficial'} (trustworthiness indicator)
        - **Code Signing:** {'Valid Certificate' if cert_present else 'No Certificate'} (integrity verification)

        **Feature Importance Analysis (SHAP Values):**
        {chr(10).join([f"- **{item.get('feature', 'Unknown').replace('_', ' ').title()}:** {item.get('value', 0):.4f} (contribution weight)" for item in top_shap])}

        **Required Analysis Components:**
        1. **Threat Assessment:** Detailed analysis of the classification with technical reasoning
        2. **Risk Analysis:** Specific security risks, attack vectors, and potential impact
        3. **Technical Indicators:** Deep dive into suspicious patterns, API usage, and behavioral analysis
        4. **Security Recommendations:** Actionable mitigation strategies and security measures
        5. **Professional Context:** Industry-standard cybersecurity terminology and expert insights

        **Analysis Requirements:**
        - Use professional cybersecurity terminology (malware, threat vectors, attack surfaces, etc.)
        - Provide technical depth suitable for security professionals
        - Include specific security recommendations and mitigation strategies
        - Reference industry best practices and security frameworks
        - Maintain professional tone suitable for security reports
        - Focus on actionable intelligence for threat response teams

        Provide a comprehensive cybersecurity analysis (200-300 words) that demonstrates expert-level understanding of mobile security threats and professional security assessment capabilities.
        """
        
        response_data = call_gemini(system_prompt, user_prompt)
        
        if 'raw_text' in response_data:
            return response_data['raw_text'].strip()
        else:
            return str(response_data).strip()
            
    except Exception as e:
        print(f"❌ Gemini API failed: {e}, falling back to rule-based explanation")
        return _generate_rule_based_explanation(result)

def _generate_rule_based_explanation(result: Dict) -> str:
    """Fallback rule-based explanation when Gemini API is not available"""
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
        from docx.shared import Inches, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_ALIGN_VERTICAL
        from docx.enum.text import WD_BREAK
        from docx.oxml.shared import OxmlElement, qn
        import re
    except ImportError:
        # Fallback to HTML if python-docx is not available
        return _generate_html_batch_report(results)
    
    def format_markdown_to_docx(paragraph_text, paragraph):
        """Convert markdown formatting to Word document formatting"""
        # Handle bold text (**text** or __text__)
        bold_pattern = r'\*\*(.*?)\*\*|__(.*?)__'
        parts = re.split(bold_pattern, paragraph_text)
        
        current_run = None
        for i, part in enumerate(parts):
            if part is None:
                continue
            
            # Check if this part should be bold (every 2nd and 3rd captured group)
            is_bold = (i % 3 == 1 or i % 3 == 2) and part
            
            if part:
                if current_run is None:
                    current_run = paragraph.add_run(part)
                else:
                    current_run = paragraph.add_run(part)
                
                if is_bold:
                    current_run.bold = True
    
    def add_formatted_paragraph(doc, text):
        """Add a paragraph with proper markdown formatting conversion"""
        # Split text into lines and handle different formatting
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                doc.add_paragraph('')  # Empty line
                continue
            
            # Handle headers (# ## ###)
            if line.startswith('###'):
                doc.add_heading(line[3:].strip(), level=3)
            elif line.startswith('##'):
                doc.add_heading(line[2:].strip(), level=2)
            elif line.startswith('#'):
                doc.add_heading(line[1:].strip(), level=1)
            # Handle bullet points
            elif line.startswith('- ') or line.startswith('* '):
                p = doc.add_paragraph(style='List Bullet')
                format_markdown_to_docx(line[2:].strip(), p)
            # Handle numbered lists
            elif re.match(r'^\d+\.', line):
                p = doc.add_paragraph(style='List Number')
                format_markdown_to_docx(re.sub(r'^\d+\.\s*', '', line), p)
            # Regular paragraph
            else:
                p = doc.add_paragraph()
                format_markdown_to_docx(line, p)
    
    doc = Document()
    
    # Add a cover page with better formatting
    title = doc.add_heading('APK Security Analysis Report', 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    cover_para = doc.add_paragraph('This report provides a comprehensive analysis of the security posture of the APKs scanned.')
    cover_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    date_para = doc.add_paragraph(f'Generated on: {__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}')
    date_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    doc.add_page_break()
    
    # Add Executive Summary with better formatting
    doc.add_heading('Executive Summary', level=1)
    total_files = len(results)
    fake_count = sum(1 for r in results if r.get('prediction') == 'fake')
    legit_count = sum(1 for r in results if r.get('prediction') == 'legit')
    
    # Create summary with proper formatting
    summary_text = f"""
**Analysis Overview:**
- Total APKs analyzed: {total_files}
- Legitimate APKs: {legit_count}
- Malicious APKs: {fake_count}
- Detection rate: {(fake_count/total_files)*100:.1f}% of files flagged as suspicious

**Risk Distribution:**"""
    
    # Count risk levels
    red_count = sum(1 for r in results if r.get('risk_level', r.get('risk', 'Unknown')) == 'Red')
    amber_count = sum(1 for r in results if r.get('risk_level', r.get('risk', 'Unknown')) == 'Amber')
    green_count = sum(1 for r in results if r.get('risk_level', r.get('risk', 'Unknown')) == 'Green')
    
    summary_text += f"""
- Red Risk (High): {red_count} APKs
- Amber Risk (Medium): {amber_count} APKs  
- Green Risk (Low): {green_count} APKs
"""
    
    add_formatted_paragraph(doc, summary_text)
    doc.add_page_break()
    
    # Add Summary Table with better formatting
    doc.add_heading('Summary Table', level=1)
    table = doc.add_table(rows=len(results) + 1, cols=5)
    table.style = 'Table Grid'
    
    # Add headers with formatting
    headers = ['APK File', 'Prediction', 'Risk Level', 'Confidence', 'Summary']
    for i, header in enumerate(headers):
        cell = table.cell(0, i)
        cell.text = header
        # Make header bold
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.bold = True
    
    # Add data rows with proper formatting
    for i, result in enumerate(results):
        file_name = result.get('file', 'N/A')
        prediction = result.get('prediction', 'Unknown').title()
        risk = result.get('risk_level', result.get('risk', 'Unknown'))
        confidence = f'{result.get("probability", 0):.1%}'
        
        # Generate AI explanation and truncate for table
        ai_explanation = result.get('ai_explanation', '') or _generate_ai_explanation(result)
        # Clean up the explanation and truncate
        clean_explanation = re.sub(r'\*\*(.*?)\*\*', r'\1', ai_explanation)  # Remove bold markdown
        clean_explanation = re.sub(r'[#*-]', '', clean_explanation)  # Remove other markdown
        summary = clean_explanation[:150] + "..." if len(clean_explanation) > 150 else clean_explanation
        
        table.cell(i + 1, 0).text = file_name
        table.cell(i + 1, 1).text = prediction
        table.cell(i + 1, 2).text = risk
        table.cell(i + 1, 3).text = confidence
        table.cell(i + 1, 4).text = summary.strip()
    
    doc.add_page_break()
    
    # Add Detailed Analysis with improved formatting
    doc.add_heading('Detailed Analysis', level=1)
    for i, result in enumerate(results):
        file_name = result.get("file", "N/A")
        doc.add_heading(f'Analysis for {file_name}', level=2)
        
        # Basic info with better formatting
        basic_info = f"""
**Prediction:** {result.get("prediction", "Unknown").title()}
**Risk Level:** {result.get("risk_level", result.get("risk", "Unknown"))}
**Confidence Score:** {result.get("probability", 0):.1%}
**Confidence Level:** {result.get("confidence", "Unknown")}
        """
        add_formatted_paragraph(doc, basic_info.strip())
        
        # AI Explanation with proper formatting
        doc.add_heading('AI Security Analysis', level=3)
        ai_explanation = result.get('ai_explanation', '') or _generate_ai_explanation(result)
        
        # Process and format the AI explanation
        if ai_explanation:
            add_formatted_paragraph(doc, ai_explanation)
        else:
            doc.add_paragraph("AI explanation not available for this APK.")
        
        # Feature Analysis with better organization
        doc.add_heading('Technical Analysis', level=3)
        feature_vector = result.get('feature_vector', {})
        
        # Permissions with improved formatting
        permissions = [k for k, v in feature_vector.items() 
                      if k in ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'SYSTEM_ALERT_WINDOW', 'READ_CONTACTS', 'INTERNET', 'QUERY_ALL_PACKAGES'] 
                      and v == 1]
        
        if permissions:
            perm_text = "**Granted Permissions:**\n"
            for perm in permissions:
                perm_display = perm.replace("_", " ").title()
                perm_text += f"- {perm_display}\n"
            add_formatted_paragraph(doc, perm_text.strip())
        
        # Suspicious APIs with better formatting
        suspicious_apis = [k for k, v in feature_vector.items() if k.startswith('api_') and v == 1]
        if suspicious_apis:
            api_text = "**Suspicious APIs Detected:**\n"
            for api in suspicious_apis:
                api_name = api.replace('api_', '').replace('_', ' ').title()
                api_text += f"- {api_name}\n"
            add_formatted_paragraph(doc, api_text.strip())
        
        # SHAP Analysis with enhanced formatting
        if result.get('top_shap'):
            doc.add_heading('Top Contributing Features (SHAP Analysis)', level=4)
            shap_text = "**Feature Impact Analysis:**\n"
            for item in result.get('top_shap', []):
                feature_name = item.get('feature', 'Unknown').replace('_', ' ').title()
                value = item.get('value', 0)
                impact = "increases risk" if value > 0 else "decreases risk"
                shap_text += f"- **{feature_name}**: {value:+.4f} ({impact})\n"
            add_formatted_paragraph(doc, shap_text.strip())
        
        # Additional technical details
        if result.get('debug'):
            doc.add_heading('Technical Details', level=4)
            debug_info = result['debug']
            tech_text = f"""**Processing Information:**
- Processing Time: {debug_info.get('processing_time_seconds', 0):.3f} seconds
- Cache Used: {"Yes" if debug_info.get('cache_used', False) else "No"}
- Model Threshold: {debug_info.get('model_threshold', 0):.3f}
- SHA256: {debug_info.get('sha256', 'N/A')[:16]}...
            """
            add_formatted_paragraph(doc, tech_text.strip())
        
        # Add separator between APK analyses
        if i < len(results) - 1:
            doc.add_page_break()
    
    # Add comprehensive Security Recommendations
    doc.add_heading('Security Recommendations', level=1)
    recommendations_text = """
**Immediate Actions:**
- Review all RED risk APKs immediately and consider blocking/quarantining
- Investigate AMBER risk APKs thoroughly before deployment
- Verify the source and authenticity of all suspicious applications

**Security Best Practices:**
- Implement regular APK scanning before deployment
- Establish a security review process for all mobile applications
- Monitor for new threats and update security policies accordingly
- Consider implementing additional runtime protection measures

**Risk Mitigation Strategies:**
- For high-risk APKs: Perform detailed manual analysis and sandbox testing
- For medium-risk APKs: Implement additional monitoring and access controls  
- For all APKs: Verify digital signatures and certificate chains
- Maintain an updated whitelist of trusted application sources
    """
    
    add_formatted_paragraph(doc, recommendations_text.strip())
    
    # Add footer with metadata
    doc.add_paragraph()
    footer_text = f"""
**Report Metadata:**
- Generated by: APK Security Analysis System v2.0
- Analysis Engine: XGBoost with SHAP explainability
- Total Processing Time: {sum(r.get('debug', {}).get('processing_time_seconds', 0) for r in results):.2f} seconds
- Report Generation: {__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}
    """
    add_formatted_paragraph(doc, footer_text.strip())
    
    # Save the document to a BytesIO object and return as base64
    import io
    import base64
    
    # Save to BytesIO instead of file
    doc_buffer = io.BytesIO()
    doc.save(doc_buffer)
    doc_buffer.seek(0)
    
    # Convert to base64
    doc_base64 = base64.b64encode(doc_buffer.read()).decode('utf-8')
    doc_buffer.close()
    
    return doc_base64

def _generate_html_batch_report(results: List[Dict]) -> str:
    """Fallback HTML report generation if python-docx is not available"""
    import re
    
    def format_markdown_to_html(text):
        """Convert markdown formatting to HTML"""
        if not text:
            return ""
            
        # Convert bold text (**text** or __text__)
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'__(.*?)__', r'<strong>\1</strong>', text)
        
        # Convert headers
        text = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)  
        text = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', text, flags=re.MULTILINE)
        
        # Convert bullet points
        lines = text.split('\n')
        in_list = False
        formatted_lines = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('- ') or line.startswith('* '):
                if not in_list:
                    formatted_lines.append('<ul>')
                    in_list = True
                formatted_lines.append(f'<li>{line[2:]}</li>')
            else:
                if in_list:
                    formatted_lines.append('</ul>')
                    in_list = False
                if line:
                    formatted_lines.append(f'<p>{line}</p>')
                else:
                    formatted_lines.append('<br>')
        
        if in_list:
            formatted_lines.append('</ul>')
            
        return '\n'.join(formatted_lines)
    
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>APK Security Analysis Report</title>
        <style>
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; 
                margin: 0; 
                padding: 20px; 
                background: #f8fafc;
                color: #1f2937;
                line-height: 1.6;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 12px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }
            .header { 
                text-align: center; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px; 
            }
            .header h1 {
                margin: 0 0 15px 0;
                font-size: 2.5em;
                font-weight: 800;
            }
            .content {
                padding: 40px;
            }
            .summary { 
                background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); 
                padding: 30px; 
                margin: 30px 0; 
                border-radius: 12px; 
                border: 1px solid #e5e7eb;
            }
            .summary h2 {
                color: #111827;
                border-bottom: 3px solid #667eea;
                padding-bottom: 10px;
            }
            .apk-analysis { 
                border: 1px solid #e5e7eb; 
                margin: 30px 0; 
                padding: 30px; 
                border-radius: 12px; 
                background: #fff;
            }
            .fake { border-left: 5px solid #ef4444; }
            .legit { border-left: 5px solid #10b981; }
            .red { color: #ef4444; font-weight: bold; }
            .amber { color: #f59e0b; font-weight: bold; }
            .green { color: #10b981; font-weight: bold; }
            .analysis-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .stat-card {
                background: #f9fafb;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                border: 1px solid #e5e7eb;
            }
            .stat-value {
                font-size: 2em;
                font-weight: bold;
                margin-bottom: 5px;
            }
            .ai-explanation {
                background: #f0f9ff;
                padding: 20px;
                border-left: 4px solid #0ea5e9;
                margin: 15px 0;
                border-radius: 0 8px 8px 0;
            }
            .technical-details {
                background: #fafafa;
                padding: 20px;
                border-radius: 8px;
                margin: 15px 0;
            }
            .feature-list {
                columns: 2;
                column-gap: 30px;
            }
            .feature-item {
                break-inside: avoid;
                margin-bottom: 8px;
                padding: 8px;
                background: #f3f4f6;
                border-radius: 4px;
            }
            @media (max-width: 768px) {
                body { padding: 10px; }
                .content { padding: 20px; }
                .analysis-grid { grid-template-columns: 1fr; }
                .feature-list { columns: 1; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ APK Security Analysis Report</h1>
                <p>Comprehensive security analysis with AI-powered insights</p>
                <p>Generated on: """ + __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC') + """</p>
            </div>
            <div class="content">
    """
    
    # Executive Summary with enhanced formatting
    total_files = len(results)
    fake_count = sum(1 for r in results if r.get('prediction') == 'fake')
    legit_count = sum(1 for r in results if r.get('prediction') == 'legit')
    red_count = sum(1 for r in results if r.get('risk_level', r.get('risk', 'Unknown')) == 'Red')
    amber_count = sum(1 for r in results if r.get('risk_level', r.get('risk', 'Unknown')) == 'Amber')
    green_count = sum(1 for r in results if r.get('risk_level', r.get('risk', 'Unknown')) == 'Green')
    
    html += f"""
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="analysis-grid">
                <div class="stat-card">
                    <div class="stat-value">{total_files}</div>
                    <div>Total APKs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value legit">{legit_count}</div>
                    <div>Legitimate</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value fake">{fake_count}</div>
                    <div>Malicious</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{(fake_count/total_files)*100:.1f}%</div>
                    <div>Detection Rate</div>
                </div>
            </div>
            
            <h3>Risk Distribution</h3>
            <div class="analysis-grid">
                <div class="stat-card">
                    <div class="stat-value red">{red_count}</div>
                    <div>High Risk (Red)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value amber">{amber_count}</div>
                    <div>Medium Risk (Amber)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value green">{green_count}</div>
                    <div>Low Risk (Green)</div>
                </div>
            </div>
        </div>
    """
    
    # Individual APK Analysis with enhanced formatting
    for i, result in enumerate(results, 1):
        prediction = result.get('prediction', 'unknown')
        risk = result.get('risk_level', result.get('risk', 'Unknown'))
        probability = result.get('probability', 0)
        confidence = result.get('confidence', 'Unknown')
        
        # Get AI explanation with proper formatting
        ai_explanation = result.get('ai_explanation', '') or _generate_ai_explanation(result)
        formatted_ai_explanation = format_markdown_to_html(ai_explanation)
        
        risk_class = risk.lower()
        pred_class = prediction
        
        html += f"""
        <div class="apk-analysis {pred_class}">
            <h2>📱 Analysis #{i}: {result.get('file', 'N/A')}</h2>
            
            <div class="analysis-grid">
                <div class="stat-card">
                    <div class="stat-value {pred_class}">{prediction.title()}</div>
                    <div>Prediction</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value {risk_class}">{risk}</div>
                    <div>Risk Level</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{probability:.1%}</div>
                    <div>Confidence</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{confidence}</div>
                    <div>Certainty</div>
                </div>
            </div>
            
            <div class="ai-explanation">
                <h3>🤖 AI Security Analysis</h3>
                {formatted_ai_explanation}
            </div>
        """
        
        # Technical details
        feature_vector = result.get('feature_vector', {})
        
        # Permissions
        permissions = [k for k, v in feature_vector.items() 
                      if k in ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'SYSTEM_ALERT_WINDOW', 'READ_CONTACTS', 'INTERNET', 'QUERY_ALL_PACKAGES'] 
                      and v == 1]
        
        # Suspicious APIs
        suspicious_apis = [k for k, v in feature_vector.items() if k.startswith('api_') and v == 1]
        
        if permissions or suspicious_apis or result.get('top_shap'):
            html += f"""
            <div class="technical-details">
                <h3>🔍 Technical Analysis</h3>
            """
            
            if permissions:
                html += f"""
                <h4>Granted Permissions</h4>
                <div class="feature-list">
                """
                for perm in permissions:
                    perm_display = perm.replace("_", " ").title()
                    html += f'<div class="feature-item">🔓 {perm_display}</div>'
                html += "</div>"
            
            if suspicious_apis:
                html += f"""
                <h4>Suspicious APIs Detected</h4>
                <div class="feature-list">
                """
                for api in suspicious_apis:
                    api_name = api.replace('api_', '').replace('_', ' ').title()
                    html += f'<div class="feature-item">⚠️ {api_name}</div>'
                html += "</div>"
            
            if result.get('top_shap'):
                html += f"""
                <h4>Top Contributing Features (SHAP Analysis)</h4>
                <ul>
                """
                for item in result.get('top_shap', []):
                    feature_name = item.get('feature', 'Unknown').replace('_', ' ').title()
                    value = item.get('value', 0)
                    impact = "increases risk" if value > 0 else "decreases risk"
                    impact_class = "red" if value > 0 else "green"
                    html += f'<li><strong>{feature_name}</strong>: <span class="{impact_class}">{value:+.4f}</span> ({impact})</li>'
                html += "</ul>"
            
            html += "</div>"
        
        html += "</div>"
    
    # Security Recommendations
    html += f"""
        <div class="summary">
            <h2>🛡️ Security Recommendations</h2>
            
            <h3>Immediate Actions</h3>
            <ul>
                <li><strong>Review all RED risk APKs immediately</strong> and consider blocking/quarantining</li>
                <li><strong>Investigate AMBER risk APKs thoroughly</strong> before deployment</li>
                <li><strong>Verify the source and authenticity</strong> of all suspicious applications</li>
            </ul>
            
            <h3>Security Best Practices</h3>
            <ul>
                <li>Implement regular APK scanning before deployment</li>
                <li>Establish a security review process for all mobile applications</li>
                <li>Monitor for new threats and update security policies accordingly</li>
                <li>Consider implementing additional runtime protection measures</li>
            </ul>
            
            <h3>Risk Mitigation Strategies</h3>
            <ul>
                <li><strong>High-risk APKs:</strong> Perform detailed manual analysis and sandbox testing</li>
                <li><strong>Medium-risk APKs:</strong> Implement additional monitoring and access controls</li>
                <li><strong>All APKs:</strong> Verify digital signatures and certificate chains</li>
                <li>Maintain an updated whitelist of trusted application sources</li>
            </ul>
        </div>
        
        <div class="summary">
            <h2>📋 Report Metadata</h2>
            <p><strong>Generated by:</strong> APK Security Analysis System v2.0</p>
            <p><strong>Analysis Engine:</strong> XGBoost with SHAP explainability</p>
            <p><strong>Total Processing Time:</strong> {sum(r.get('debug', {}).get('processing_time_seconds', 0) for r in results):.2f} seconds</p>
            <p><strong>Report Generation:</strong> {__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Convert HTML to base64 for consistent handling with Word documents
    import base64
    html_base64 = base64.b64encode(html.encode('utf-8')).decode('utf-8')
    return html_base64

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