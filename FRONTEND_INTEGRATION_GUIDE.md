# Frontend Integration Guide - APK Risk Scanner API

## 🚀 **Deployed API Information**

### **Production URL**
```
https://fake-apk-ml-api.onrender.com
```

### **Local Development URL**
```
http://localhost:9000
```

## 📋 **API Endpoints**

### **1. Health Check**
```javascript
GET /api/health
// or
GET /
```

**Response:**
```json
{
  "status": "ok",
  "message": "Use POST /scan with multipart file 'file'"
}
```

### **2. Model Information**
```javascript
GET /api/model-info
// or
GET /model-info
```

**Response:**
```json
{
  "model_version": "20250830_232741",
  "threshold": 0.35,
  "feature_count": 43,
  "is_consistent": true,
  "predictions_consistent": true
}
```

### **3. Single APK Scan**
```javascript
POST /api/scan
// or
POST /scan
```

**Parameters:**
- `file`: APK file (multipart/form-data)
- `debug`: "true" or "false" (optional, default: false)
- `bypass_cache`: "true" or "false" (optional, default: false)
- `quick`: "true" or "false" (optional, default: false)

**Response:**
```json
{
  "prediction": "legit",
  "probability": 0.0417,
  "risk": "Green",
  "confidence": 0.9583,
  "debug": {
    "threshold_used": 0.35,
    "cache_bypassed": false,
    "cache_used": true,
    "processing_time": 1.23
  }
}
```

### **4. Batch APK Scan**
```javascript
POST /api/scan-batch
// or
POST /scan-batch
```

**Parameters:**
- `files`: Array of APK files (multipart/form-data)
- `debug`: "true" or "false" (optional)
- `bypass_cache`: "true" or "false" (optional)

**Response:**
```json
{
  "results": [
    {
      "file_name": "app1.apk",
      "prediction": "legit",
      "probability": 0.0417,
      "risk": "Green"
    },
    {
      "file_name": "app2.apk",
      "prediction": "fake",
      "probability": 0.571,
      "risk": "Amber"
    }
  ],
  "summary": {
    "total": 2,
    "legit": 1,
    "fake": 1
  }
}
```

## 🔧 **Frontend Integration Examples**

### **React.js Example**
```jsx
import React, { useState } from 'react';

const APKScanner = () => {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const API_URL = 'https://fake-apk-ml-api.onrender.com';

  const scanAPK = async () => {
    if (!file) return;

    setLoading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error('Scan failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <input
        type="file"
        accept=".apk"
        onChange={(e) => setFile(e.target.files[0])}
      />
      <button onClick={scanAPK} disabled={!file || loading}>
        {loading ? 'Scanning...' : 'Scan APK'}
      </button>

      {result && (
        <div>
          <h3>Result:</h3>
          <p>Prediction: {result.prediction}</p>
          <p>Probability: {(result.probability * 100).toFixed(1)}%</p>
          <p>Risk: {result.risk}</p>
        </div>
      )}
    </div>
  );
};

export default APKScanner;
```

### **JavaScript (Vanilla) Example**
```javascript
class APKScanner {
  constructor(apiUrl = 'https://fake-apk-ml-api.onrender.com') {
    this.apiUrl = apiUrl;
  }

  async scanSingleAPK(file, options = {}) {
    const formData = new FormData();
    formData.append('file', file);

    // Add optional parameters
    if (options.debug) formData.append('debug', 'true');
    if (options.bypassCache) formData.append('bypass_cache', 'true');
    if (options.quick) formData.append('quick', 'true');

    const response = await fetch(`${this.apiUrl}/scan`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  }

  async scanMultipleAPKs(files, options = {}) {
    const formData = new FormData();
    
    files.forEach(file => {
      formData.append('files', file);
    });

    if (options.debug) formData.append('debug', 'true');
    if (options.bypassCache) formData.append('bypass_cache', 'true');

    const response = await fetch(`${this.apiUrl}/scan-batch`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  }

  async getModelInfo() {
    const response = await fetch(`${this.apiUrl}/model-info`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
  }

  async checkHealth() {
    const response = await fetch(`${this.apiUrl}/`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
  }
}

// Usage
const scanner = new APKScanner();

// Scan single APK
document.getElementById('fileInput').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (file) {
    try {
      const result = await scanner.scanSingleAPK(file, { debug: true });
      console.log('Scan result:', result);
    } catch (error) {
      console.error('Scan failed:', error);
    }
  }
});
```

### **cURL Examples**
```bash
# Health check
curl -X GET "https://fake-apk-ml-api.onrender.com/"

# Get model info
curl -X GET "https://fake-apk-ml-api.onrender.com/model-info"

# Scan single APK
curl -X POST "https://fake-apk-ml-api.onrender.com/scan" \
  -F "file=@path/to/your/app.apk" \
  -F "debug=true"

# Scan multiple APKs
curl -X POST "https://fake-apk-ml-api.onrender.com/scan-batch" \
  -F "files=@app1.apk" \
  -F "files=@app2.apk" \
  -F "debug=true"
```

## 🎯 **Risk Levels & Thresholds**

### **Current Configuration**
- **Threshold**: 0.35 (35%)
- **Model Version**: 20250830_232741
- **Features**: 43 numeric features

### **Risk Classification**
- **Green**: Probability < 35% (Legitimate)
- **Amber**: Probability ≥ 35% (Suspicious/Fake)

### **Response Format**
```json
{
  "prediction": "legit" | "fake",
  "probability": 0.0-1.0,
  "risk": "Green" | "Amber",
  "confidence": 0.0-1.0
}
```

## 🔍 **Debug Information**

When `debug=true` is included, the response includes additional information:

```json
{
  "debug": {
    "threshold_used": 0.35,
    "cache_bypassed": false,
    "cache_used": true,
    "processing_time": 1.23,
    "shap_values": {
      "feature1": 0.123,
      "feature2": -0.456
    }
  }
}
```

## ⚠️ **Error Handling**

### **Common HTTP Status Codes**
- `200`: Success
- `400`: Bad Request (invalid file, missing parameters)
- `413`: Payload Too Large (file too big)
- `500`: Internal Server Error

### **Error Response Format**
```json
{
  "error": "Error description",
  "detail": "Additional error details"
}
```

## 🚀 **Deployment Notes**

### **Production Environment**
- **URL**: https://fake-apk-ml-api.onrender.com
- **Threshold**: 0.35 (35%)
- **Model**: XGBoost with fallback to RandomForest
- **Features**: Static analysis of APK permissions, APIs, certificates

### **Rate Limits**
- Free tier: 750 hours/month
- Request timeout: 30 seconds
- File size limit: 100MB per APK

### **Caching**
- Results are cached by file SHA256
- Use `bypass_cache=true` to force fresh analysis
- Cache improves response time for repeated scans

## 📞 **Support**

For issues or questions:
1. Check the health endpoint first
2. Verify model info endpoint
3. Test with debug mode enabled
4. Check file format and size

---

**Last Updated**: August 30, 2024
**Model Version**: 20250830_232741
**Threshold**: 0.35
