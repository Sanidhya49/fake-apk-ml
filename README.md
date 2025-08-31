# Fake APK Detection API

A machine learning-powered API for detecting fake/malicious Android APK files using static analysis and XGBoost classification.

## 🚀 Live API

**Production API**: https://fake-apk-ml-api01.onrender.com

## ✨ Features

- **Single APK Analysis**: Scan individual APK files for malicious content
- **Batch Processing**: Upload up to 15 APKs simultaneously
- **Word Document Reports**: Generate professional reports with AI explanations
- **AI Agent Explanations**: Get intelligent insights into why APKs are classified
- **Risk Level Assessment**: Red/Amber/Green risk categorization
- **Performance Optimized**: Fast processing with caching and production WSGI server
- **Production Ready**: Deployed on Render.com with automatic scaling

## 🏗️ Architecture

- **Backend**: Flask API with Waitress WSGI server
- **ML Model**: XGBoost classifier with SHAP explanations
- **Features**: 200+ static analysis features extracted from APK files
- **Deployment**: Docker container on Render.com
- **Caching**: SHA256-based caching for improved performance

## 📋 API Endpoints

### Health Check
```http
GET /
```
Returns API status and available endpoints.

### Single APK Scan
```http
POST /scan
```
Scan a single APK file for malicious content.

**Parameters:**
- `file`: APK file (multipart/form-data)
- `debug` (optional): Enable debug information

**Response:**
```json
{
  "prediction": "legit|fake",
  "probability": 0.374,
  "risk_level": "Green|Amber|Red",
  "confidence": "Low|Medium|High",
  "top_shap": [...],
  "feature_vector": {...},
  "debug": {
    "model_threshold": 0.385,
    "processing_time_seconds": 0.3,
    "cache_used": false
  }
}
```

### Batch APK Scan (Up to 15 files)
```http
POST /scan-batch
```
Scan multiple APK files simultaneously.

**Parameters:**
- `files`: Multiple APK files (multipart/form-data)
- `debug` (optional): Enable debug information

**Response:**
```json
{
  "results": [
    {
      "file": "app1.apk",
      "prediction": "legit",
      "probability": 0.25,
      "risk_level": "Green",
      "confidence": "High"
    }
  ],
  "summary": {
    "total_files": 5,
    "processing_time_seconds": 2.5,
    "files_per_second": 2.0,
    "max_files_allowed": 15
  }
}
```

### Word Document Report Generation
```http
POST /report-batch
```
Generate comprehensive Word document reports with AI explanations.

**Parameters:**
- `files`: APK files (multipart/form-data, up to 15)

**Response:**
```json
{
  "results": [...],
  "summary": {
    "total_files": 5,
    "report_generated": true
  },
  "word_report": "artifacts/batch_report.docx"
}
```

## 🎯 Frontend Integration

### Basic Single APK Upload
```javascript
const formData = new FormData();
formData.append('file', apkFile);

const response = await fetch('https://fake-apk-ml-api01.onrender.com/scan', {
  method: 'POST',
  body: formData
});

const result = await response.json();
console.log(result.prediction); // "legit" or "fake"
```

### Batch Upload (Up to 15 APKs)
```javascript
const formData = new FormData();
apkFiles.forEach(file => {
  formData.append('files', file);
});

const response = await fetch('https://fake-apk-ml-api01.onrender.com/scan-batch', {
  method: 'POST',
  body: formData
});

const result = await response.json();
console.log(result.results); // Array of scan results
```

### Word Report Generation
```javascript
const formData = new FormData();
apkFiles.forEach(file => {
  formData.append('files', file);
});

const response = await fetch('https://fake-apk-ml-api01.onrender.com/report-batch', {
  method: 'POST',
  body: formData
});

const result = await response.json();
// Word document is generated on server
// You can provide download link or email functionality
```

### Error Handling
```javascript
try {
  const response = await fetch('https://fake-apk-ml-api01.onrender.com/scan', {
    method: 'POST',
    body: formData
  });
  
  if (!response.ok) {
    const error = await response.json();
    console.error('API Error:', error.detail);
    return;
  }
  
  const result = await response.json();
  // Handle success
} catch (error) {
  console.error('Network Error:', error);
}
```

## 🔧 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ML_FAKE_THRESHOLD` | 0.385 | Classification threshold |
| `ML_AGGRESSIVE` | 0 | Aggressive detection mode |
| `ML_OFFICIAL_OVERRIDE` | 1 | Enable official package override |
| `ML_OFFICIAL_OVERRIDE_CAP` | 0.40 | Official package override cap |
| `ML_HEURISTIC_MIN_PROB` | 0.35 | Minimum probability for heuristics |
| `ML_HEURISTIC_MIN_SIGNALS` | 2 | Minimum signals for heuristics |
| `ML_MARGIN` | 0.08 | Classification margin |
| `ML_DISABLE_CACHE_BYPASS` | 1 | Disable cache bypass in production |
| `FLASK_ENV` | production | Flask environment |
| `FLASK_DEBUG` | false | Flask debug mode |
| `PYTHONHASHSEED` | 42 | Python hash seed for consistency |

## 🚀 Local Development

### Prerequisites
- Python 3.10+
- Virtual environment

### Setup
```bash
# Clone repository
git clone <repository-url>
cd fake-apk-ml

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export ML_FAKE_THRESHOLD=0.385
export FLASK_DEBUG=true

# Start Flask API
python flask_app/main.py
```

### Testing
```bash
# Test single APK
python test_optimized_flask.py

# Test with real APKs
python test_real_apks.py
```

## 📊 Model Information

- **Algorithm**: XGBoost Classifier
- **Features**: 200+ static analysis features
- **Training Data**: 1000+ legitimate and malicious APKs
- **Performance**: 95%+ accuracy on test set
- **Threshold**: 0.385 (optimized for legitimate APK detection)

### Feature Categories
- **Package Information**: App name, package name, version
- **Permissions**: Android permissions analysis
- **Activities**: App activities and components
- **Services**: Background services
- **Receivers**: Broadcast receivers
- **Providers**: Content providers
- **Native Libraries**: Native code analysis
- **Certificate**: App signing certificate
- **File Analysis**: APK structure analysis

## 🔒 Security Features

- **Input Validation**: File type and size validation
- **Rate Limiting**: Built-in request throttling
- **Error Handling**: Comprehensive error responses
- **CORS Support**: Cross-origin resource sharing
- **Production Hardening**: Security headers and configurations

## 📈 Performance

- **Single APK**: ~0.3 seconds processing time
- **Batch Processing**: ~2 files per second
- **Caching**: SHA256-based feature caching
- **Memory Efficient**: Optimized for production workloads
- **Scalable**: Horizontal scaling support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For issues and questions:
- Check the API documentation
- Review error responses
- Test with sample APK files
- Contact the development team

## 🔄 Updates

- **v2.0**: Flask API with batch processing and Word reports
- **v1.0**: FastAPI with single APK scanning
- **v0.9**: Initial ML model development

---

**API Status**: ✅ Production Ready  
**Last Updated**: August 2024  
**Version**: 2.0.0



