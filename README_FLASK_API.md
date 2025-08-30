# Flask APK Detection API Setup Guide

## Overview

This guide shows how to set up and use the Flask API for APK security analysis. The Flask API provides endpoints for:

- Single APK file analysis
- Batch processing of multiple APK files
- HTML report generation

## Prerequisites

1. **Python Environment**: Python 3.8+ with pip
2. **ML Models**: Trained XGBoost model files in the `models/` directory
3. **Dependencies**: All required Python packages (see installation below)

## Quick Start

### 1. Install Dependencies

```bash
cd fake-apk-ml
pip install -r flask_requirements.txt
```

### 2. Start the Flask Server

**Option A: Using the batch script (Windows)**
```cmd
start_flask_api.bat
```

**Option B: Manual startup**
```bash
cd fake-apk-ml
python flask_app/main.py
```

**Option C: With custom configuration**
```bash
set FLASK_HOST=127.0.0.1
set FLASK_PORT=9000
set FLASK_DEBUG=true
python flask_app/main.py
```

### 3. Test the API

Run the test script to verify everything works:
```bash
cd fake-apk-ml
python test_flask_api.py
```

### 4. Start the Frontend

```bash
cd fake-apk-detection
npm install
npm run dev
```

The frontend should now connect to the Flask API at http://localhost:9000

## API Endpoints

### Health Check
```http
GET /
```

**Response:**
```json
{
  "status": "ok",
  "message": "Fake APK Detection API is running",
  "endpoints": {
    "scan_single": "POST /scan",
    "scan_batch": "POST /scan-batch", 
    "generate_report": "POST /report"
  }
}
```

### Single APK Analysis
```http
POST /scan
Content-Type: multipart/form-data

file: <APK_FILE>
quick: false (optional)
debug: false (optional)
```

**Response:**
```json
{
  "prediction": "fake|legit",
  "probability": 0.85,
  "risk": "Red|Amber|Green",
  "top_shap": [
    {
      "feature": "impersonation_score",
      "value": 0.15
    }
  ],
  "feature_vector": {
    "READ_SMS": 1,
    "cert_present": 0,
    "pkg_official": 0,
    ...
  }
}
```

### Batch APK Analysis
```http
POST /scan-batch
Content-Type: multipart/form-data

files: <APK_FILE_1>
files: <APK_FILE_2>
files: <APK_FILE_N>
quick: false (optional)
debug: false (optional)
```

**Response:**
```json
{
  "results": [
    {
      "file": "app1.apk",
      "prediction": "fake",
      "probability": 0.85,
      "risk": "Red",
      "feature_vector": {...}
    },
    {
      "file": "app2.apk", 
      "prediction": "legit",
      "probability": 0.15,
      "risk": "Green",
      "feature_vector": {...}
    }
  ]
}
```

### HTML Report Generation
```http
POST /report
Content-Type: multipart/form-data

file: <APK_FILE>
```

**Response:**
```json
{
  "result": {
    "prediction": "fake",
    "probability": 0.85,
    "risk": "Red",
    ...
  },
  "html": "<html>...detailed report...</html>"
}
```

## Error Handling

The API returns appropriate HTTP status codes:

- `200`: Success
- `400`: Bad request (missing file, invalid parameters)
- `422`: Unprocessable entity (invalid APK file, parsing failed)
- `500`: Internal server error

**Error Response Format:**
```json
{
  "error": "error_code",
  "detail": "Human readable error message"
}
```

Common error codes:
- `no_file`: No file provided in request
- `invalid_file_type`: File is not an APK
- `parse_failed`: Could not parse the APK file
- `prediction_failed`: ML model prediction failed
- `internal_error`: Server error

## Frontend Integration

The frontend is already configured to use the Flask API. Key files:

### API Service (`src/services/api.js`)
```javascript
export class APKAnalysisService {
  static async scanSingle(file, quick = false, debug = false) {
    // Makes POST request to /scan
  }
  
  static async scanBatch(files, quick = false, debug = false) {
    // Makes POST request to /scan-batch
  }
  
  static async generateReport(file) {
    // Makes POST request to /report
  }
}
```

### Store Integration (`src/store/useAppStore.js`)
The store's `startAnalysis()` function automatically calls `APKAnalysisService.scanSingle()` and processes the response to match the frontend's expected format.

### Environment Configuration (`.env`)
```properties
VITE_API_BASE_URL=http://localhost:9000
```

## Configuration Options

### Environment Variables

- `FLASK_HOST`: Host to bind to (default: 0.0.0.0)
- `FLASK_PORT`: Port to listen on (default: 9000) 
- `FLASK_DEBUG`: Enable debug mode (default: false)
- `ML_FAKE_THRESHOLD`: Prediction threshold (default: 0.61)
- `ML_OFFICIAL_OVERRIDE`: Override predictions for official apps (default: true)
- `ML_AGGRESSIVE`: Use aggressive heuristics (default: false)

### Model Configuration
The Flask app expects the XGBoost model file at:
```
models/xgb_model.joblib
```

This file should contain:
- `model`: Trained XGBoost classifier
- `feature_order`: List of feature names in correct order
- `tuned_threshold`: Optimal decision threshold

## Batch Processing Example

Here's how to use the batch analysis from JavaScript:

```javascript
import { APKAnalysisService } from './services/api';

const files = document.querySelector('#file-input').files;
const results = await APKAnalysisService.scanBatch(files, false, true);

results.data.results.forEach(result => {
  if (result.error) {
    console.error(`${result.file}: ${result.error}`);
  } else {
    console.log(`${result.file}: ${result.prediction} (${result.probability})`);
  }
});
```

## Troubleshooting

### Common Issues

1. **"Import could not be resolved" errors**
   - Install dependencies: `pip install -r flask_requirements.txt`

2. **"Could not parse APK" errors**
   - Ensure file is a valid APK
   - Check file size (max 100MB)
   - Try with `quick=true` parameter

3. **Connection refused errors**
   - Ensure Flask server is running on correct host/port
   - Check firewall settings
   - Verify frontend .env file has correct API URL

4. **Model not found errors**
   - Ensure `models/xgb_model.joblib` exists
   - Run the training pipeline to generate models

5. **CORS errors**
   - Flask-CORS is configured for all origins
   - Check browser developer tools for details

### Debugging

Enable debug mode for detailed logging:
```bash
set FLASK_DEBUG=true
python flask_app/main.py
```

Check the console output for detailed error messages and request logging.

### Performance Notes

- First analysis may be slower due to model loading
- Subsequent analyses are cached when possible
- Batch processing is more efficient for multiple files
- Use `quick=true` for faster basic analysis

## Production Deployment

For production deployment, consider:

1. **Use a WSGI server** like Gunicorn instead of Flask's development server
2. **Configure proper CORS** origins instead of allowing all
3. **Set up proper logging** and monitoring
4. **Use environment variables** for sensitive configuration
5. **Implement rate limiting** and authentication as needed
6. **Set up reverse proxy** (nginx) for static file serving

Example Gunicorn command:
```bash
gunicorn --bind 0.0.0.0:9000 --workers 4 flask_app.main:app
```

## File Structure

```
fake-apk-ml/
├── flask_app/
│   └── main.py              # Flask application
├── ml/                      # ML modules (imported by Flask)
│   ├── static_extract.py    # APK feature extraction
│   ├── utils.py            # Utility functions
│   └── ...
├── models/
│   └── xgb_model.joblib    # Trained model
├── artifacts/
│   └── static_jsons/       # Cached extraction results
├── flask_requirements.txt   # Flask-specific dependencies
├── start_flask_api.bat     # Windows startup script
└── test_flask_api.py       # API testing script
```

This setup provides a complete APK analysis API that integrates seamlessly with your React frontend!
