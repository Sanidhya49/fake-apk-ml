### Fake APK ML - Static Analysis Pipeline (Monorepo with Django backend)

This repository implements a beginner-friendly, fully runnable static-analysis + ML pipeline to detect fake banking APKs. It focuses on offline/static features only (no dynamic analysis or sandboxing).

Repository layout:

```
fake-apk-ml/
├─ data/                  # (empty) you will unzip: data/legit/ and data/fake/
├─ artifacts/
│  ├─ static_jsons/
│  └─ features.csv
├─ ml/
│  ├─ static_extract.py
│  ├─ feature_builder.py
│  ├─ train.py
│  ├─ infer_service.py
│  └─ utils.py
├─ models/
├─ Dockerfile
├─ requirements.txt
├─ README.md
├─ backend/              # Django project (proxy to ML API)
│  ├─ manage.py
│  ├─ fake_apk_backend/
│  └─ scanbridge/        # app exposing POST /api/scan/
├─ docker-compose.yml    # optional: run ML API + Streamlit
├─ env.sample            # copy to .env for defaults
└─ .gitignore
```

### Quickstart (ML pipeline)

0) Python 3.10+ is recommended. On Windows PowerShell, run commands without the leading `$`.

1) Install dependencies:

```bash
pip install -r requirements.txt
```

**Note:** If you encounter compilation errors on Windows, try installing packages individually:
```bash
pip install androguard==4.1.3
pip install pandas==2.2.2
pip install scikit-learn==1.5.1
pip install xgboost==2.1.0
# ... continue with other packages
```

2) Prepare data:

- Place APKs under `data/legit/` and `data/fake/` (create these folders if they do not exist). Example:

```
data/
  legit/
    bank1.apk
  fake/
    trojan1.apk
```

Verified packages (whitelist)
- We ship a small `ml/bank_whitelist.json` mapping official package IDs → bank names. During featurization/inference we add:
  - `pkg_official`: 1 if the package is in the whitelist
  - `impersonation_score`: fuzzy match against whitelist names and known terms
You can extend `ml/bank_whitelist.json` safely; no code changes needed.

3) Static extraction to JSON per APK:

```bash
python -m ml.static_extract data
```

This writes one JSON per APK into `artifacts/static_jsons/`. Any parse error is logged and processing continues.
Re-running the command is incremental: it skips APKs that already have a JSON (keyed by the file's sha256), so adding new files later will be fast.

4) Build features CSV:

```bash
python -m ml.feature_builder
```

Saves `artifacts/features.csv` and prints class balance.

5) Train model (XGBoost with fallback to RandomForest) and compute SHAP summary for held-out test set:

```bash
python -m ml.train
```

Saves model to `models/xgb_model.joblib` and SHAP top-3 per-sample contributions to `artifacts/shap_summary.csv`.

6) Configure AI Analysis (optional):

Create a `.env` file based on `.env.example` and add your Google Gemini API key:

```bash
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

Get your Gemini API key from: https://makersuite.google.com/app/apikey

7) Run inference API (FastAPI + Uvicorn) and optional Streamlit UI:

```bash
uvicorn ml.infer_service:app --host 0.0.0.0 --port 9000
streamlit run ml/streamlit_app.py
```

8) Test the API with an APK file:

```bash
curl -X POST "http://localhost:9000/scan" -F "file=@data/legit/bank1.apk"
```

Example JSON response contains the predicted class (`fake` or `legit`), probability, top SHAP contributors, and the feature vector used.

### AI-Powered Analysis Reports

The service integrates with Google's Gemini AI to provide detailed security analysis:

- **PDF Reports**: Generate comprehensive security reports with AI analysis via `/report-pdf` endpoint
- **Real-time Analysis**: WebSocket support for live progress updates during APK scanning
- **Detailed Insights**: AI-powered explanations of security threats and recommendations

Features include:
- Professional PDF reports with security breakdowns
- AI-generated threat assessments using Google Gemini
- Base64 PDF encoding for easy frontend integration
- Comprehensive security recommendations

### Backend (Django bridge)

The backend proxies uploads to the ML API so any frontend can call one stable endpoint.

Install once:

```powershell
# from repo root
pip install -r requirements.txt

cd backend
python -m venv .venv
.\.venv\Scripts\pip install -r ..\requirements.txt
.\.venv\Scripts\python manage.py migrate
```

Run backend:

```powershell
cd backend
.\.venv\Scripts\python manage.py runserver 0.0.0.0:8000
```

Config:
- Set `ML_SERVICE_URL` in `backend/fake_apk_backend/settings.py` or as an environment variable. Default: `http://localhost:9000`.
- CORS is enabled for development (`CORS_ALLOW_ALL_ORIGINS=True`). Tighten for production.

Endpoint:
- `POST http://localhost:8000/api/scan/` with multipart field `file` (APK).
- Optional query params are forwarded to the ML API: `quick`, `debug`.

Example (PowerShell):

```powershell
$file = "C:\path\to\app.apk"
curl.exe -s -X POST "http://localhost:8000/api/scan/?quick=false&debug=true" -F "file=@$file"
```

### Docker

Build and run the API service with Docker (model and artifacts should exist or be mounted):

```bash
docker build -t fake-apk-ml .
docker run -p 9000:9000 -v $(pwd)/artifacts:/app/artifacts -v $(pwd)/models:/app/models fake-apk-ml
```

Or with Compose to run API + UI together:

```bash
docker compose up --build
```

### Safety note

This project is for research and education. APKs may be malicious. Handle all files with care and do not execute unknown apps. This pipeline performs static analysis only and does not run APK code.

### Frontend integration

- Call the Django endpoint: `POST /api/scan/` with multipart `file`.
- Response JSON fields: `prediction` (fake|legit), `probability` (0..1), `risk` (Green|Amber|Red), `top_shap`, `feature_vector`.
- For batch UI, reuse the Streamlit logic or your own queue; the backend simply forwards each request.

### Features & advanced roadmap

- Full static extraction with APK/APKS/XAPK support and JSON cache by sha256.
- ML features: permission flags, suspicious API flags, cert presence/issuer, CN vs package match, impersonation score (bank whitelist + fuzzy match), domain/TLD IOCs.
- Model: XGBoost (fallback RF), SHAP explanations, novelty detector.
- Inference: FastAPI `/scan` (JSON), `/report` (JSON+HTML), `/report-html` (browser form), Streamlit multi-file UI (concurrent scanning, CSV/Excel export).
- MLflow tracking: set `MLFLOW_TRACKING_URI=file:./mlruns` and run `mlflow ui` to view runs/artifacts.
- Next upgrades: family-aware split, probability calibration + business thresholds, verified-store cross-checks, richer risk report, Docker Compose for Django+ML.



