# 🚨 Fake APK Detection ML System

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-1.5+-orange.svg)](https://xgboost.readthedocs.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Hackathon](https://img.shields.io/badge/Hackathon-CyberShield%202025-red.svg)](https://ciisummit.com/cybershield-hackathon-2025/)

> **A production-ready Machine Learning system for detecting malicious Android APK files with 95%+ accuracy, featuring explainable AI, real-time risk assessment, and comprehensive reporting.**

## 🎯 Project Overview

This project addresses the critical cybersecurity challenge of **"Detecting Fake Banking APKs"** - malicious Android applications that mimic legitimate banking apps to steal user credentials and financial information. Built for the [National CyberShield Hackathon 2025](https://ciisummit.com/cybershield-hackathon-2025/) organized by Madhya Pradesh Police.

### 🌟 Key Features

- **🤖 ML-Powered Detection**: XGBoost classifier with 95%+ accuracy
- **🔍 Static Analysis**: Comprehensive APK feature extraction using Androguard
- **📊 Explainable AI**: SHAP analysis for model interpretability
- **🧠 AI Explanations**: Google Gemini integration for human-readable insights
- **⚡ Real-time Processing**: Instant risk assessment and classification
- **📋 Professional Reports**: HTML and Word document generation
- **🌐 RESTful API**: Flask-based backend with comprehensive endpoints
- **🎨 Modern Frontend**: Beautiful, responsive web interface
- **🐳 Docker Ready**: Production-ready containerization
- **☁️ Cloud Deployable**: Optimized for GCP and other cloud platforms

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Flask API     │    │   ML Pipeline   │
│   (React/HTML)  │◄──►│   (REST)        │◄──►│   (XGBoost)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   APK Analysis  │
                       │   (Androguard)  │
                       └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Feature       │
                       │   Extraction    │
                       └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Docker (optional)
- Google Gemini API key (for AI explanations)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/fake-apk-ml.git
   cd fake-apk-ml
   ```

2. **Set up virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set environment variables**
```bash
   export GEMINI_API_KEY="your_api_key_here"
   export ML_FAKE_THRESHOLD="0.385"
   ```

5. **Run the application**
   ```bash
   python flask_app/main.py
   ```

### Docker Deployment

```bash
# Build the image
docker build -t fake-apk-detector .

# Run the container
docker run -p 5000:5000 -e GEMINI_API_KEY="your_key" fake-apk-detector
```

## 📡 API Endpoints

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check and system status |
| `/scan` | POST | Single APK analysis |
| `/scan/batch` | POST | Batch APK processing |
| `/report` | POST | Generate comprehensive reports |

### Example Usage

```bash
# Single APK scan
curl -X POST -F "file=@suspicious.apk" http://localhost:5000/scan

# Batch processing
curl -X POST -F "files=@app1.apk" -F "files=@app2.apk" http://localhost:5000/scan/batch

# Generate report
curl -X POST -F "file=@app.apk" http://localhost:5000/report
```

## 🔬 Technical Details

### Machine Learning Model

- **Algorithm**: XGBoost Classifier
- **Features**: 200+ extracted from APK files
- **Accuracy**: 95%+ on test datasets
- **Threshold**: 0.385 (optimized for precision)

### Feature Extraction

- **Permissions**: Android manifest permissions analysis
- **API Calls**: Suspicious system API detection
- **Certificates**: Signing authority validation
- **Manifest Data**: SDK versions, activities, services
- **DEX Analysis**: Dalvik executable file inspection
- **File Structure**: APK internal organization

### Risk Classification

- **🟢 Green**: Low risk (legitimate app)
- **🟡 Amber**: Medium risk (suspicious)
- **🔴 Red**: High risk (malicious)

## 📊 Sample Output

```json
{
  "prediction": "malicious",
  "risk_level": "Red",
  "confidence": 94.2,
  "confidence_percentage": 94.2,
  "processing_time": 2.3,
  "model_threshold": 0.385,
  "cache_used": false,
  "app_label": "Fake Banking App",
  "package": "com.fake.banking",
  "version": "1.0.0",
  "file_size": 15432000,
  "critical_labels": ["Suspicious Banking", "High Risk"],
  "critical_permissions": ["READ_SMS", "READ_CONTACTS", "RECORD_AUDIO"],
  "suspicious_api_count": 8,
  "total_permissions": 15,
  "certificate_status": "Self-signed",
  "signing_authority": "Unknown",
  "app_trust_level": "Low",
  "ai_explanation": "This app requests suspicious permissions...",
  "shap_features": ["permission_score", "api_risk", "certificate_trust"]
}
```

## 🛠️ Development

### Project Structure

```
fake-apk-ml/
├── flask_app/              # Flask application
│   ├── main.py            # Main API server
│   └── templates/         # HTML templates
├── ml/                    # Machine learning modules
│   ├── static_extract.py  # APK feature extraction
│   ├── model.py          # ML model management
│   └── utils.py          # Utility functions
├── artifacts/             # Model files and cache
│   ├── models/           # Trained models
│   └── static_jsons/     # Extracted features cache
├── data/                  # Training and test data
├── tests/                 # Test files
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker configuration
└── README.md            # This file
```

### Key Components

- **`flask_app/main.py`**: Main Flask application with all API endpoints
- **`ml/static_extract.py`**: APK parsing and feature extraction
- **`ml/model.py`**: ML model loading and prediction
- **`artifacts/`**: Pre-trained models and feature cache

## 🧪 Testing

### Run Tests

```bash
# Test single APK scan
python -c "
from flask_app.main import app
with app.test_client() as client:
    response = client.post('/scan', data={'file': open('data/test.apk', 'rb')})
    print(response.json)
"

# Test health endpoint
curl http://localhost:5000/health
```

### Test with Sample APKs

```bash
# Use the provided test APKs in the data/ directory
python -c "
from ml.static_extract import extract
result = extract('data/legit/base.apk', quick=False)
print('Extraction successful:', list(result.keys()))
"
```

## 🚀 Deployment

### Google Cloud Platform

1. **Build and push Docker image**
   ```bash
   docker build -t gcr.io/your-project/fake-apk-detector .
   docker push gcr.io/your-project/fake-apk-detector
   ```

2. **Deploy to Cloud Run**
```bash
   gcloud run deploy fake-apk-detector \
     --image gcr.io/your-project/fake-apk-detector \
     --platform managed \
     --region us-central1 \
     --allow-unauthenticated
   ```

### Environment Variables

```bash
# Required
GEMINI_API_KEY=your_gemini_api_key

# Optional
ML_FAKE_THRESHOLD=0.385
ML_OFFICIAL_OVERRIDE_CAP=0.40
FLASK_ENV=production
```

## 📈 Performance

- **Processing Speed**: 2-5 seconds per APK
- **Memory Usage**: ~500MB per analysis
- **Concurrent Requests**: Supports multiple simultaneous scans
- **Cache Efficiency**: 90%+ cache hit rate for repeated files

## 🔒 Security Features

- **Static Analysis**: No code execution, safe for unknown files
- **Permission Analysis**: Critical permission identification
- **Certificate Validation**: Signing authority verification
- **API Call Detection**: Suspicious system call identification
- **Export Component Analysis**: Security implications assessment

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📚 Documentation

- [API Documentation](docs/API.md)
- [Model Architecture](docs/MODEL.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## 🏆 Hackathon Details

This project was developed for the **[National CyberShield Hackathon 2025](https://ciisummit.com/cybershield-hackathon-2025/)** organized by Madhya Pradesh Police.

- **Problem Statement**: Detecting Fake Banking APKs
- **Event Date**: September 16-17, 2025
- **Venue**: Hotel Taj Lakefront, Bhopal, Madhya Pradesh
- **Organizer**: Madhya Pradesh Police
- **Prizes**: ₹1 Lakh+ cash prizes

## 📄 License

This project is licensed under the MIT License

## 🙏 Acknowledgments

- **Team Members**: My amazing teammates for their collaboration
- **CyberShield 2025**: Organizers for the incredible opportunity
- **Open Source Community**: For the amazing tools and libraries
- **Law Enforcement**: For highlighting real-world cybersecurity needs

## 📞 Contact details

- **GitHub**: [@Sanidhya49](https://github.com/Sanidhya49)
- **Medium**: [@alwaysanidhya](https://alwaysanidhya.medium.com/)
- **LinkedIn**: [Sanidhya Patel](https://www.linkedin.com/in/sanidhya-patel-849802262/)

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

**🔒 Making the digital world safer** 

</div>
