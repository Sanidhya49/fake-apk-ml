@echo off
echo Starting Fake APK Detection Flask API...
echo.

REM Change to the flask_app directory
cd /d "%~dp0"

REM Set environment variables
set FLASK_HOST=0.0.0.0
set FLASK_PORT=9000
set FLASK_DEBUG=true

echo Configuration:
echo   Host: %FLASK_HOST%
echo   Port: %FLASK_PORT%
echo   Debug: %FLASK_DEBUG%
echo.

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
)

REM Install dependencies if needed
echo Checking dependencies...
pip install -q flask flask-cors numpy pandas scikit-learn xgboost joblib rapidfuzz python-dotenv shap

echo.
echo Starting Flask server...
echo API will be available at: http://%FLASK_HOST%:%FLASK_PORT%
echo.
echo Available endpoints:
echo   GET  /           - Health check
echo   POST /scan       - Scan single APK file
echo   POST /scan-batch - Scan multiple APK files  
echo   POST /report     - Generate detailed HTML report
echo.
echo Press Ctrl+C to stop the server
echo.

REM Start the Flask app
python flask_app\main.py

pause
