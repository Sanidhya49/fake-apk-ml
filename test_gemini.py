#!/usr/bin/env python3
"""
Test script to verify Gemini API integration for APK analysis.

Usage:
    python test_gemini.py

Make sure to set GEMINI_API_KEY in your .env file first.
"""

import os
import asyncio
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def test_gemini_integration():
    """Test the Gemini API integration with sample data"""
    
    # Check if API key is configured
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("❌ GEMINI_API_KEY not found in environment variables")
        print("Please add your Gemini API key to the .env file")
        print("Get your key from: https://makersuite.google.com/app/apikey")
        return False
    
    print("✅ Gemini API key found")
    
    # Import the function we want to test
    try:
        from ml.infer_service import generate_gemini_analysis
    except ImportError as e:
        print(f"❌ Failed to import generate_gemini_analysis: {e}")
        return False
    
    # Sample test data
    sample_analysis = {
        "prediction": "fake",
        "probability": 0.85,
        "risk": "Red",
        "feature_vector": {
            "READ_SMS": 1,
            "SYSTEM_ALERT_WINDOW": 1,
            "INTERNET": 1,
            "count_suspicious": 5,
            "cert_present": 0,
            "pkg_official": 0,
            "impersonation_score": 85
        },
        "top_shap": [
            {"feature": "impersonation_score", "value": 0.45},
            {"feature": "SYSTEM_ALERT_WINDOW", "value": 0.32},
            {"feature": "count_suspicious", "value": 0.28}
        ]
    }
    
    sample_file_info = {
        "filename": "test_banking_app.apk",
        "size": "2.5 MB"
    }
    
    print("🔍 Testing Gemini API integration...")
    
    try:
        # Test the Gemini analysis function
        analysis = await generate_gemini_analysis(sample_analysis, sample_file_info)
        
        if "AI analysis unavailable" in analysis:
            print(f"⚠️  Gemini API test resulted in error: {analysis}")
            return False
        
        print("✅ Gemini API integration test successful!")
        print("\n📄 Sample AI Analysis:")
        print("-" * 50)
        print(analysis[:300] + "..." if len(analysis) > 300 else analysis)
        print("-" * 50)
        
        return True
        
    except Exception as e:
        print(f"❌ Gemini API test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🚀 Testing Gemini API Integration")
    print("=" * 40)
    
    success = asyncio.run(test_gemini_integration())
    
    if success:
        print("\n✅ All tests passed! Gemini integration is working correctly.")
    else:
        print("\n❌ Tests failed. Please check your configuration.")
    
    print("\nNext steps:")
    print("- Start the ML service: uvicorn ml.infer_service:app --host 0.0.0.0 --port 9000")
    print("- Test PDF generation: POST /report-pdf with an APK file")