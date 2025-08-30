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
CORS(app, origins="*")  # Enable CORS for all origins

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
    
    # Build feature table rows
    rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in fv.items())
    
    # Build SHAP features list
    shap_rows = "".join(f"<li><strong>{item.get('feature', 'Unknown')}</strong>: {round(item.get('value', 0), 4)}</li>" for item in top)
    
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
                background: #f8fafc;
                color: #1f2937;
                line-height: 1.6;
            }}
            .container {{
                max-width: 900px;
                margin: 0 auto;
                background: white;
                border-radius: 12px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0 0 10px 0;
                font-size: 2.2em;
                font-weight: 700;
            }}
            .header p {{
                margin: 0;
                opacity: 0.9;
                font-size: 1.1em;
            }}
            .content {{
                padding: 30px;
            }}
            .summary {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .summary-card {{
                padding: 20px;
                border-radius: 8px;
                border: 1px solid #e5e7eb;
                background: #f9fafb;
            }}
            .summary-card h3 {{
                margin: 0 0 8px 0;
                font-size: 0.9em;
                font-weight: 600;
                text-transform: uppercase;
                color: #6b7280;
                letter-spacing: 0.05em;
            }}
            .summary-card .value {{
                font-size: 1.8em;
                font-weight: 700;
                margin: 0;
            }}
            .section {{
                margin-bottom: 30px;
            }}
            .section h2 {{
                margin: 0 0 20px 0;
                font-size: 1.5em;
                font-weight: 700;
                color: #111827;
                border-bottom: 2px solid #e5e7eb;
                padding-bottom: 8px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #e5e7eb;
            }}
            th {{
                background: #f9fafb;
                font-weight: 600;
                color: #374151;
            }}
            tr:hover {{
                background: #f9fafb;
            }}
            ul {{
                list-style: none;
                padding: 0;
            }}
            li {{
                padding: 8px 0;
                border-bottom: 1px solid #f3f4f6;
            }}
            li:last-child {{
                border-bottom: none;
            }}
            .timestamp {{
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #e5e7eb;
                color: #6b7280;
                font-size: 0.9em;
            }}
            @media (max-width: 768px) {{
                body {{ padding: 10px; }}
                .content {{ padding: 20px; }}
                .summary {{ grid-template-columns: 1fr; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>APK Security Analysis Report</h1>
                <p>Comprehensive security analysis for <strong>{filename}</strong></p>
            </div>
            
            <div class="content">
                <div class="summary">
                    <div class="summary-card">
                        <h3>Prediction</h3>
                        <p class="value" style="color: {pred_color};">{pred.title()}</p>
                    </div>
                    <div class="summary-card">
                        <h3>Risk Level</h3>
                        <p class="value" style="color: {risk_color};">{risk}</p>
                    </div>
                    <div class="summary-card">
                        <h3>Confidence</h3>
                        <p class="value">{prob:.1%}</p>
                    </div>
                    <div class="summary-card">
                        <h3>Score</h3>
                        <p class="value">{prob:.3f}</p>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Top Contributing Features</h2>
                    {f'<ul>{shap_rows}</ul>' if shap_rows else '<p>No SHAP analysis available.</p>'}
                </div>
                
                <div class="section">
                    <h2>Complete Feature Analysis</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Feature</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </table>
                </div>
                
                <div class="timestamp">
                    Report generated on {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
                    <br>
                    Powered by Fake APK Detection System
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