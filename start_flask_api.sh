#!/bin/bash

echo "Starting Fake APK Detection Flask API (Production Optimized)..."
echo

# Change to the project directory
cd "$(dirname "$0")"

# Set environment variables for production
export FLASK_HOST=0.0.0.0
export FLASK_PORT=9000
export FLASK_DEBUG=false
export FLASK_ENV=production

# Set ML environment variables (your production settings)
export ML_FAKE_THRESHOLD=0.35
export ML_HEURISTIC_MIN_PROB=0.35
export ML_AGGRESSIVE=0
export ML_MARGIN=0.08
export ML_HEURISTIC_MIN_SIGNALS=2
export ML_OFFICIAL_OVERRIDE=1
export ML_OFFICIAL_OVERRIDE_CAP=0.40
export ML_FORCE_MIN_FAKE=0.45

echo "Configuration:"
echo "  Host: $FLASK_HOST"
echo "  Port: $FLASK_PORT"
echo "  Debug: $FLASK_DEBUG"
echo "  Environment: $FLASK_ENV"
echo "  ML Threshold: $ML_FAKE_THRESHOLD"
echo

# Check if virtual environment exists
if [ -f ".venv/Scripts/activate" ]; then
    echo "Activating virtual environment..."
    source .venv/Scripts/activate
elif [ -f ".venv/bin/activate" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
fi

# Install production dependencies if needed
echo "Installing production dependencies..."
pip install -q waitress flask flask-cors numpy pandas scikit-learn xgboost joblib rapidfuzz python-dotenv shap

echo
echo "Starting Flask server (Production Mode)..."
echo "API will be available at: http://$FLASK_HOST:$FLASK_PORT"
echo
echo "Available endpoints:"
echo "  GET  /           - Health check"
echo "  POST /scan       - Scan single APK file"
echo "  POST /scan-batch - Scan multiple APK files"
echo "  POST /report     - Generate detailed HTML report"
echo
echo "Performance optimizations enabled:"
echo "  - Model caching"
echo "  - Feature caching"
echo "  - Thread pool optimization"
echo "  - Production WSGI server (Waitress)"
echo "  - Static file caching"
echo
echo "Press Ctrl+C to stop the server"
echo

# Start the Flask app
python flask_app/main.py
