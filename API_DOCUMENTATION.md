# 🔒 APK Risk Scanner - API Documentation

## Overview
This API provides machine learning-based static analysis for detecting fake banking APKs. It analyzes APK files for suspicious permissions, APIs, certificates, and domain patterns.

## Base URL
- **Local Development:** `http://localhost:9000`
- **Production:** `https://your-deployed-url.com`

## Authentication
Currently, no authentication is required. For production, consider adding API keys.

## Endpoints

### 1. Health Check
**GET** `/`

**Response:**
```json
{
  "status": "ok",
  "message": "Use POST /scan with multipart file 'file'"
}
```

### 2. Scan APK File
**POST** `/scan`

**Description:** Analyze a single APK file for fake/legitimate classification.

**Parameters:**
- `file` (multipart/form-data): APK file to scan
- `quick` (query, optional): Boolean - Quick mode (manifest + cert only). Default: `false`
- `debug` (query, optional): Boolean - Include debug information. Default: `false`
- `bypass_cache` (query, optional): Boolean - Force fresh analysis. Default: `false`

**Example Request (cURL):**
```bash
curl -X POST "http://localhost:9000/scan?debug=true&bypass_cache=false" \
  -F "file=@path/to/your/app.apk"
```

**Response:**
```json
{
  "prediction": "legit",
  "probability": 0.1234,
  "risk": "Green",
  "top_shap": [
    {"feature": "api_sendTextMessage", "value": -0.0456},
    {"feature": "READ_SMS", "value": -0.0234},
    {"feature": "impersonation_score", "value": -0.0123}
  ],
  "feature_vector": {
    "READ_SMS": 0,
    "SEND_SMS": 0,
    "api_sendTextMessage": 0,
    "impersonation_score": 0,
    // ... more features
  },
  "debug": {
    "threshold_used": 0.35,
    "cache_bypassed": false,
    "cache_used": true,
    "sha256": "abc123...",
    "signals": 0,
    "is_official": false
  }
}
```

### 3. Batch Scan
**POST** `/scan-batch`

**Description:** Analyze multiple APK files in a single request.

**Parameters:**
- `files` (multipart/form-data): Multiple APK files
- `quick` (query, optional): Boolean - Quick mode. Default: `false`
- `debug` (query, optional): Boolean - Include debug information. Default: `false`

**Response:**
```json
{
  "results": [
    {
      "file": "app1.apk",
      "prediction": "legit",
      "probability": 0.1234,
      "risk": "Green",
      "feature_vector": {...}
    },
    {
      "file": "app2.apk",
      "prediction": "fake",
      "probability": 0.8765,
      "risk": "Red",
      "feature_vector": {...}
    }
  ]
}
```

### 4. HTML Report
**POST** `/report`

**Description:** Get an HTML report for an APK file.

**Parameters:**
- `file` (multipart/form-data): APK file to analyze

**Response:**
```json
{
  "result": {
    "prediction": "legit",
    "probability": 0.1234,
    "risk": "Green",
    // ... other fields
  },
  "html": "<html>...</html>"
}
```

## Response Fields

### Main Fields
- `prediction`: `"legit"` or `"fake"`
- `probability`: Float between 0-1 (probability of being fake)
- `risk`: `"Green"`, `"Amber"`, or `"Red"`
- `top_shap`: Array of top contributing features with SHAP values
- `feature_vector`: Complete feature vector used for prediction

### Debug Fields (when debug=true)
- `threshold_used`: Decision threshold used
- `cache_bypassed`: Whether cache was bypassed
- `cache_used`: Whether cached results were used
- `sha256`: File hash
- `signals`: Number of suspicious signals detected
- `is_official`: Whether package is in official whitelist

## Risk Levels
- **Green**: Low risk (likely legitimate)
- **Amber**: Medium risk (suspicious)
- **Red**: High risk (likely fake)

## Error Responses

### File Parse Error
```json
{
  "error": "parse_failed",
  "detail": "Could not parse APK"
}
```

### Invalid File
```json
{
  "detail": "File is required"
}
```

## Frontend Integration Examples

### JavaScript/Fetch
```javascript
async function scanAPK(file) {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await fetch('http://localhost:9000/scan?debug=true', {
    method: 'POST',
    body: formData
  });
  
  const result = await response.json();
  
  if (result.error) {
    console.error('Scan failed:', result.error);
    return;
  }
  
  console.log('Prediction:', result.prediction);
  console.log('Risk Level:', result.risk);
  console.log('Probability:', result.probability);
  
  return result;
}
```

### React Example
```jsx
import React, { useState } from 'react';

function APKScanner() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setLoading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:9000/scan?debug=true', {
        method: 'POST',
        body: formData
      });
      
      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error('Error scanning APK:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <input type="file" accept=".apk,.apks,.xapk" onChange={handleFileUpload} />
      {loading && <p>Scanning...</p>}
      {result && (
        <div>
          <h3>Result: {result.prediction}</h3>
          <p>Risk: {result.risk}</p>
          <p>Probability: {(result.probability * 100).toFixed(1)}%</p>
        </div>
      )}
    </div>
  );
}
```

### Python Requests
```python
import requests

def scan_apk(file_path):
    with open(file_path, 'rb') as f:
        files = {'file': f}
        params = {'debug': 'true', 'bypass_cache': 'false'}
        
        response = requests.post(
            'http://localhost:9000/scan',
            files=files,
            params=params
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code}")
            return None

# Usage
result = scan_apk('path/to/app.apk')
if result:
    print(f"Prediction: {result['prediction']}")
    print(f"Risk: {result['risk']}")
    print(f"Probability: {result['probability']:.2%}")
```

## Configuration Options

### Environment Variables
- `ML_FAKE_THRESHOLD`: Decision threshold (default: 0.35)
- `ML_AGGRESSIVE`: Aggressive mode (default: 0)
- `ML_OFFICIAL_OVERRIDE`: Official package override (default: 1)
- `ML_OFFICIAL_OVERRIDE_CAP`: Official override cap (default: 0.40)

### Query Parameters
- `quick`: Faster scan with fewer features
- `debug`: Include detailed debug information
- `bypass_cache`: Force fresh analysis (useful for testing)

## Rate Limits
Currently no rate limits are implemented. For production, consider adding rate limiting.

## CORS
CORS is enabled for all origins in development. Configure appropriately for production.

## File Size Limits
- Maximum file size: No explicit limit (handled by server configuration)
- Supported formats: `.apk`, `.apks`, `.xapk`

## Best Practices
1. Use `debug=true` during development for detailed information
2. Use `bypass_cache=false` for production (faster)
3. Handle errors gracefully in your frontend
4. Consider implementing retry logic for failed requests
5. Cache results on the frontend when appropriate
