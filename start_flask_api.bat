@echo off
echo Starting Fake APK Detection Flask API (Production Optimized)...
echo.

REM Change to the flask_app directory
cd /d "%~dp0"

REM Set environment variables for production
set FLASK_HOST=0.0.0.0
set FLASK_PORT=9000
set FLASK_DEBUG=false
set FLASK_ENV=production

REM Set ML environment variables (your production settings)
set ML_FAKE_THRESHOLD=0.35
set ML_HEURISTIC_MIN_PROB=0.35
set ML_AGGRESSIVE=0
set ML_MARGIN=0.08
set ML_HEURISTIC_MIN_SIGNALS=2
set ML_OFFICIAL_OVERRIDE=1
set ML_OFFICIAL_OVERRIDE_CAP=0.40
set ML_FORCE_MIN_FAKE=0.45

echo Configuration:
echo   Host: %FLASK_HOST%
echo   Port: %FLASK_PORT%
echo   Debug: %FLASK_DEBUG%
echo   Environment: %FLASK_ENV%
echo   ML Threshold: %ML_FAKE_THRESHOLD%
echo.

REM Check if virtual environment exists
if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
)

REM Install production dependencies if needed
echo Installing production dependencies...
pip install -q waitress flask flask-cors numpy pandas scikit-learn xgboost joblib rapidfuzz python-dotenv shap

echo.
echo Starting Flask server (Production Mode)...
echo API will be available at: http://%FLASK_HOST%:%FLASK_PORT%
echo.
echo Available endpoints:
echo   GET  /           - Health check
echo   POST /scan       - Scan single APK file
echo   POST /scan-batch - Scan multiple APK files  
echo   POST /report     - Generate detailed HTML report
echo.
echo Performance optimizations enabled:
echo   - Model caching
echo   - Feature caching
echo   - Thread pool optimization
echo   - Production WSGI server (Waitress)
echo   - Static file caching
echo.
echo Press Ctrl+C to stop the server
echo.

REM Start the Flask app
python flask_app\main.py

pause
