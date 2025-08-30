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
from typing import Dict, List

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

# Configuration
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "xgb_model.joblib")
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk', 'apks', 'xapk'}
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    """Check if uploaded file has allowed extension"""
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

    # Metadata features
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
    """Try to load cached extraction results"""
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

def _predict_apk(file_path: str, quick: bool = False, debug: bool = False):
    """Predict if APK is fake or legit"""
    try:
        # Load model
        model_obj = load_model(MODEL_PATH)
        model = model_obj["model"]
        feature_order = model_obj["feature_order"]
        saved_thr = float(model_obj.get("tuned_threshold", 0.61))

        # Get SHA256 for caching
        try:
            sha = get_sha256(file_path)
        except Exception:
            sha = None

        # Try cached extraction first
        ext = None
        if sha:
            cached = _try_load_cached_json(sha)
            if cached:
                ext = cached

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
                    cache_dir = os.path.join("artifacts", "static_jsons")
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
        
        # Risk categorization
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

        label_map = {0: "legit", 1: "fake"}
        result = {
            "prediction": label_map.get(int(pred), str(pred)),
            "probability": prob,
            "risk": risk,
            "top_shap": top_shap,
            "feature_vector": v["feature_map"],
        }
        
        if debug:
            result["debug"] = {
                "threshold_used": float(threshold),
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
    """Add CORS headers to all responses"""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
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
    """Scan a single APK file"""
    try:
        # Debug: Print all request information
        print('=== DEBUG: Request received ===')
        print(f'Content-Type: {request.content_type}')
        print(f'Method: {request.method}')
        print(f'Headers: {dict(request.headers)}')
        print(f'Files keys: {list(request.files.keys())}')
        print(f'Form keys: {list(request.form.keys())}')
        print('================================')
        
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
            
            # Predict
            result = _predict_apk(temp_file.name, quick=quick, debug=debug)
            
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
    """Scan multiple APK files"""
    try:
        # Check if files are in request
        if 'files' not in request.files:
            return jsonify({"error": "no_files", "detail": "No files provided"}), 400
        
        files = request.files.getlist('files')
        if not files or len(files) == 0:
            return jsonify({"error": "no_files", "detail": "No files selected"}), 400
        
        # Get query parameters
        quick = request.args.get('quick', 'false').lower() == 'true'
        debug = request.args.get('debug', 'false').lower() == 'true'
        
        # Make sure directories exist
        ensure_dirs()
        
        results = []
        
        for file in files:
            if file.filename == '':
                results.append({"file": "unknown", "error": "empty_filename"})
                continue
                
            # Validate file type
            if not allowed_file(file.filename):
                results.append({
                    "file": file.filename, 
                    "error": "invalid_file_type",
                    "detail": f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
                })
                continue
            
            # Save uploaded file temporarily
            filename = secure_filename(file.filename)
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1])
            try:
                file.save(temp_file.name)
                temp_file.close()
                
                # Predict
                result = _predict_apk(temp_file.name, quick=quick, debug=debug)
                result["file"] = file.filename
                results.append(result)
                
            except Exception as e:
                results.append({
                    "file": file.filename,
                    "error": "processing_failed",
                    "detail": str(e)
                })
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_file.name)
                except Exception:
                    pass
        
        return jsonify({"results": results})
        
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
            result = _predict_apk(temp_file.name, quick=False, debug=True)
            
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

@app.route('/test', methods=['GET'])
def test_endpoint():
    return jsonify({"message": "Test endpoint is working!"})

if __name__ == '__main__':
    # Make sure required directories exist
    ensure_dirs()
    
    # Get configuration from environment
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 9000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"Starting Flask APK Detection API on {host}:{port}")
    print(f"Model path: {MODEL_PATH}")
    print(f"Debug mode: {debug}")
    print("Available endpoints:")
    print("  GET  /           - Health check")
    print("  POST /scan       - Scan single APK")
    print("  POST /scan-batch - Scan multiple APKs")
    print("  POST /report     - Generate detailed report")
    
    app.run(host=host, port=port, debug=debug)