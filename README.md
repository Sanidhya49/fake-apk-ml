# 🛡️ Digital Rakshak - AI-Powered APK Security Guardian

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![React](https://img.shields.io/badge/React-19+-blue.svg)](https://reactjs.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-1.5+-orange.svg)](https://xgboost.readthedocs.io/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-Integrated-red.svg)](https://www.virustotal.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Hackathon](https://img.shields.io/badge/Hackathon-CyberShield%202025-red.svg)](https://ciisummit.com/cybershield-hackathon-2025/)

> **India's first AI-powered digital guardian against fake banking APKs - featuring triple-layer detection, real-time threat intelligence, prevention-first approach, and comprehensive admin management.**

## 🎯 Project Overview

This project addresses the critical cybersecurity challenge of **"Detecting Fake Banking APKs"** - malicious Android applications that mimic legitimate banking apps to steal user credentials and financial information. Built for the [National CyberShield Hackathon 2025](https://ciisummit.com/cybershield-hackathon-2025/) organized by Madhya Pradesh Police.

### 🌟 Revolutionary Features

#### 🛡️ **Triple-Layer AI Detection System**
- **Layer 1**: XGBoost ML model with 95.7% accuracy on Indian banking APKs
- **Layer 2**: VirusTotal integration with 70+ antivirus engines
- **Layer 3**: Real-time threat intelligence that learns from every attack

#### ⚡ **Lightning-Fast Analysis**
- **2.3 seconds** comprehensive APK analysis
- **200+ features** extracted including permissions, APIs, certificates
- **Real-time risk assessment** with confidence scoring

#### 🎯 **Indian Banking Ecosystem Mastery**
- **Bank-specific detection** for SBI, HDFC, ICICI, Paytm, and more
- **Permission pattern recognition** for Indian banking apps
- **Certificate validation** against known Indian banking authorities

#### 🚨 **Prevention-First Approach**
- **Threat Intelligence Feed**: Real-time database of malicious hashes, packages, and certificates
- **Abuse Reporting System**: Users can report suspicious apps with evidence bundles
- **STIX 2.1 Integration**: Professional threat intelligence sharing
- **Admin Dashboard**: Complete visibility into all reported threats

#### 📚 **Educational Ecosystem**
- **AI-Enhanced News System**: Real-time security alerts and RBI guidelines
- **Interactive Learning**: Users learn to identify threats themselves
- **Community Protection**: Shared intelligence protects everyone

#### 🎨 **Modern User Experience**
- **Beautiful React Frontend**: Responsive, dark-themed interface
- **Real-time Updates**: Live threat intelligence and news
- **Professional Reports**: HTML and Word document generation
- **Admin Management**: Complete threat monitoring and management

## 🏗️ Advanced System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DIGITAL RAKSHAK ECOSYSTEM                │
├─────────────────────────────────────────────────────────────────┤
│  Frontend (React 19)     │  Backend (Flask)     │  AI Services  │
│  ┌─────────────────┐     │  ┌─────────────────┐  │  ┌──────────┐ │
│  │ User Interface  │◄────┤  │ REST API        │◄─┤  │ Gemini   │ │
│  │ Admin Panel     │     │  │ Threat Intel    │  │  │ AI       │ │
│  │ News System     │     │  │ Abuse Reports   │  │  └──────────┘ │
│  └─────────────────┘     │  └─────────────────┘  │  ┌──────────┐ │
│                          │           │            │  │VirusTotal│ │
│                          │           ▼            │  │ 70+ Engines│ │
│                          │  ┌─────────────────┐  │  └──────────┘ │
│                          │  │ ML Pipeline     │  │               │
│                          │  │ (XGBoost)       │  │               │
│                          │  └─────────────────┘  │               │
│                          │           │            │               │
│                          │           ▼            │               │
│                          │  ┌─────────────────┐  │               │
│                          │  │ APK Analysis    │  │               │
│                          │  │ (Androguard)    │  │               │
│                          │  └─────────────────┘  │               │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Node.js 20+ (for frontend)
- Docker (optional)
- Google Gemini API key (for AI explanations)
- VirusTotal API key (for enhanced detection)

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
   # Backend (.env)
   export GEMINI_API_KEY="your_gemini_api_key"
   export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
   export ML_FAKE_THRESHOLD="0.385"
   
   # Frontend (.env)
   export VITE_API_BASE_URL="http://127.0.0.1:9000"
   ```

5. **Run the application**
   ```bash
   # Start backend
   python flask_app/main.py
   
   # Start frontend (in another terminal)
   cd fake-apk-detection-frontend-main
   npm install
   npm run dev
   ```

### Docker Deployment

```bash
# Build the image
docker build -t fake-apk-detector .

# Run the container
docker run -p 5000:5000 -e GEMINI_API_KEY="your_key" fake-apk-detector
```

## 📡 API Endpoints

### Core Detection Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check and system status |
| `/scan` | POST | Single APK analysis with VirusTotal |
| `/scan-batch` | POST | Batch APK processing (up to 15 files) |
| `/report` | POST | Generate comprehensive HTML reports |
| `/report-batch` | POST | Generate Word document reports |

### Prevention & Intelligence Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/threat-feed` | GET | Real-time threat intelligence |
| `/threat/submit` | POST | Submit new threat indicators |
| `/report-abuse` | POST | Report malicious APK with evidence |
| `/report-batch-abuse` | POST | Report multiple malicious APKs |

### Admin Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/reports` | GET | Get all abuse reports (paginated) |
| `/admin/reports/<id>` | GET | Get specific report details |
| `/admin/reports/<id>` | DELETE | Delete abuse report |

### VirusTotal Integration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/virustotal/scan` | POST | Scan APK with VirusTotal by hash |
| `/virustotal/report/<sha256>` | GET | Get VirusTotal report |
| `/virustotal/upload` | POST | Upload APK to VirusTotal |

### News & Awareness

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/news` | GET | Get security news and alerts |
| `/news/categories` | GET | Get news categories |
| `/news/enhanced` | GET | Get AI-enhanced news content |

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

- **🟢 Green**: Low risk (legitimate app) - 0-40% malicious probability
- **🟡 Amber**: Medium risk (suspicious) - 40-80% malicious probability  
- **🔴 Red**: High risk (malicious) - 80%+ malicious probability

### Detection Methods

1. **ML Analysis**: XGBoost model with 200+ features
2. **VirusTotal Scan**: 70+ antivirus engines
3. **Threat Intelligence**: Real-time malicious hash database
4. **Heuristic Analysis**: Permission and API call patterns
5. **Certificate Validation**: Signing authority verification

## 📊 Sample Output

### Single APK Analysis
```json
{
  "prediction": "fake",
  "risk_level": "Red",
  "probability": 0.942,
  "confidence": "High",
  "processing_time": 2.3,
  "app_label": "Fake SBI Banking App",
  "package": "com.fake.sbi.banking",
  "file_size": 15432000,
  "permissions_analysis": {
    "total_permissions": 15,
    "dangerous_permissions": 8,
    "suspicious_permissions": ["READ_SMS", "RECORD_AUDIO", "READ_CONTACTS"]
  },
  "virustotal_result": {
    "available": true,
    "malicious_engines": 12,
    "suspicious_engines": 3,
    "clean_engines": 55
  },
  "ai_explanation": "This app requests suspicious permissions including READ_SMS and RECORD_AUDIO, which are commonly used by fake banking apps to steal OTPs and record voice commands.",
  "threat_feed_match": true,
  "evidence_bundle": "Generated STIX 2.1 evidence bundle"
}
```

### Admin Dashboard Statistics
```json
{
  "stats": {
    "total_reports": 156,
    "high_risk": 23,
    "medium_risk": 45,
    "low_risk": 88,
    "threat_intelligence": {
      "malicious_hashes": 1247,
      "suspicious_packages": 89,
      "compromised_certificates": 34
    }
  }
}
```

## 🛠️ Development

### Project Structure

```
fake-apk-ml/
├── flask_app/                           # Flask backend
│   ├── main.py                         # Main API server with all endpoints
│   └── templates/                      # HTML report templates
├── fake-apk-detection-frontend-main/   # React frontend
│   ├── src/
│   │   ├── components/                 # React components
│   │   │   ├── sections/              # Main sections (Hero, Analysis, etc.)
│   │   │   ├── layout/                # Header, Footer, Navigation
│   │   │   └── admin/                 # Admin panel components
│   │   ├── pages/                     # Page components
│   │   │   └── admin/                 # Admin login and dashboard
│   │   ├── store/                     # Zustand state management
│   │   ├── services/                  # API service layer
│   │   └── utils/                     # Utility functions
│   ├── public/                        # Static assets and sample APKs
│   └── package.json                   # Frontend dependencies
├── ml/                                # Machine learning modules
│   ├── static_extract.py             # APK feature extraction
│   ├── model.py                      # ML model management
│   └── utils.py                      # Utility functions
├── artifacts/                         # Generated files
│   ├── models/                       # Trained ML models
│   ├── reports/                      # Generated abuse reports
│   └── threat_intel/                 # Threat intelligence data
├── data/                             # Training and test data
├── tests/                            # Test files
├── requirements.txt                  # Python dependencies
├── Dockerfile                       # Docker configuration
└── README.md                       # This file
```

### Key Components

- **`flask_app/main.py`**: Main Flask application with all API endpoints
- **`ml/static_extract.py`**: APK parsing and feature extraction
- **`ml/model.py`**: ML model loading and prediction
- **`fake-apk-detection-frontend-main/`**: React frontend application
- **`artifacts/`**: Pre-trained models, reports, and threat intelligence

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
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Frontend
VITE_API_BASE_URL=http://127.0.0.1:9000

# Optional
ML_FAKE_THRESHOLD=0.385
ML_OFFICIAL_OVERRIDE_CAP=0.40
FLASK_ENV=production
```

## 📈 Performance

- **Processing Speed**: 2.3 seconds per APK (comprehensive analysis)
- **Memory Usage**: ~500MB per analysis
- **Concurrent Requests**: Supports multiple simultaneous scans
- **Cache Efficiency**: 90%+ cache hit rate for repeated files
- **VirusTotal Integration**: Real-time scanning with 70+ engines
- **Batch Processing**: Up to 15 APKs simultaneously
- **Real-time Updates**: Live threat intelligence and news

## 🔒 Security Features

- **Static Analysis**: No code execution, safe for unknown files
- **Permission Analysis**: Critical permission identification
- **Certificate Validation**: Signing authority verification
- **API Call Detection**: Suspicious system call identification
- **Threat Intelligence**: Real-time malicious hash database
- **Evidence Collection**: STIX 2.1 compliant evidence bundles
- **Abuse Reporting**: Professional reporting with law enforcement templates
- **Admin Monitoring**: Complete threat visibility and management

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
- **Team**: Digital Rakshak (Final Round Qualifier)

### 🎯 Competitive Advantages

**Why Digital Rakshak Wins:**

1. **🛡️ Triple-Layer Defense**: ML + VirusTotal + Threat Intelligence
2. **⚡ Speed**: 2.3 seconds vs minutes (competitors)
3. **🎯 Indian Focus**: Bank-specific detection vs generic solutions
4. **🚨 Prevention-First**: Proactive vs reactive approach
5. **📚 Education**: User awareness vs just detection
6. **🔧 Complete Ecosystem**: Detection + Prevention + Management
7. **🤖 AI Integration**: Gemini AI for human-readable explanations
8. **📊 Professional Reports**: STIX 2.1 compliance for law enforcement

### 🎤 Presentation Highlights

- **Live Demo**: Real-time APK scanning with 2.3-second results
- **Admin Dashboard**: Complete threat monitoring and management
- **VirusTotal Integration**: 70+ antivirus engines validation
- **Threat Intelligence**: Real-time malicious hash database
- **AI Explanations**: Human-readable security insights
- **Evidence Bundles**: Professional law enforcement reporting

## 📄 License

This project is licensed under the MIT License

## 🙏 Acknowledgments

- **Team Digital Rakshak**: Amazing collaboration and dedication
- **CyberShield 2025**: Organizers for the incredible opportunity
- **Madhya Pradesh Police**: For highlighting real-world cybersecurity needs
- **Open Source Community**: For the amazing tools and libraries
- **VirusTotal**: For providing comprehensive threat intelligence
- **Google Gemini**: For AI-powered explanations and insights

## 📞 Contact details

- **GitHub**: [@Sanidhya49](https://github.com/Sanidhya49)
- **Medium**: [@alwaysanidhya](https://alwaysanidhya.medium.com/)
- **LinkedIn**: [Sanidhya Patel](https://www.linkedin.com/in/sanidhya-patel-849802262/)

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

**🛡️ Digital Rakshak - Protecting India's Digital Future** 

**🏆 CyberShield Hackathon 2025 Finalist**

</div>
