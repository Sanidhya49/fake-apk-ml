#!/usr/bin/env python3
"""
Comprehensive API Testing Script
Tests both FastAPI and Flask endpoints to ensure everything is working correctly.
"""

import requests
import json
import time
import os
from pathlib import Path

# Configuration
FASTAPI_URL = "http://localhost:9000"
FLASK_URL = "http://localhost:9001"
TEST_APK_PATH = "data/legit/base.apk"  # Adjust path as needed

def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*60)
    print(f"🧪 {title}")
    print("="*60)

def print_success(message):
    """Print success message"""
    print(f"✅ {message}")

def print_error(message):
    """Print error message"""
    print(f"❌ {message}")

def print_info(message):
    """Print info message"""
    print(f"ℹ️  {message}")

def test_health_check(url, api_name):
    """Test health check endpoint"""
    print_header(f"Testing {api_name} Health Check")
    
    try:
        response = requests.get(f"{url}/", timeout=10)
        print_info(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"{api_name} is healthy!")
            print_info(f"Response: {json.dumps(data, indent=2)}")
            return True
        else:
            print_error(f"{api_name} health check failed: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print_error(f"{api_name} connection failed: {e}")
        return False

def test_model_info(url, api_name):
    """Test model info endpoint"""
    print_header(f"Testing {api_name} Model Info")
    
    try:
        response = requests.get(f"{url}/model-info", timeout=10)
        print_info(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"{api_name} model info retrieved!")
            print_info(f"Threshold: {data.get('threshold', 'N/A')}")
            print_info(f"Model Version: {data.get('model_version', 'N/A')}")
            print_info(f"Features: {data.get('feature_count', 'N/A')}")
            return True
        else:
            print_error(f"{api_name} model info failed: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print_error(f"{api_name} connection failed: {e}")
        return False

def test_apk_scan(url, api_name, test_file=None):
    """Test APK scan endpoint"""
    print_header(f"Testing {api_name} APK Scan")
    
    if not test_file or not os.path.exists(test_file):
        print_error(f"Test APK file not found: {test_file}")
        print_info("Skipping APK scan test...")
        return False
    
    try:
        with open(test_file, 'rb') as f:
            files = {'file': f}
            params = {'debug': 'true'}
            
            response = requests.post(f"{url}/scan", files=files, params=params, timeout=30)
            print_info(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print_success(f"{api_name} APK scan successful!")
                print_info(f"Prediction: {data.get('prediction', 'N/A')}")
                print_info(f"Probability: {data.get('probability', 'N/A')}")
                print_info(f"Risk: {data.get('risk', 'N/A')}")
                
                # Check threshold
                if 'debug' in data:
                    threshold = data['debug'].get('threshold_used', 'N/A')
                    print_info(f"Threshold Used: {threshold}")
                    if threshold == 0.35:
                        print_success("✅ Correct threshold (0.35) is being used!")
                    else:
                        print_error(f"❌ Wrong threshold: {threshold} (expected 0.35)")
                
                return True
            else:
                print_error(f"{api_name} APK scan failed: {response.status_code}")
                try:
                    error_data = response.json()
                    print_error(f"Error: {error_data}")
                except:
                    print_error(f"Response: {response.text}")
                return False
                
    except requests.exceptions.RequestException as e:
        print_error(f"{api_name} connection failed: {e}")
        return False
    except Exception as e:
        print_error(f"{api_name} scan error: {e}")
        return False

def test_batch_scan(url, api_name, test_file=None):
    """Test batch scan endpoint"""
    print_header(f"Testing {api_name} Batch Scan")
    
    if not test_file or not os.path.exists(test_file):
        print_error(f"Test APK file not found: {test_file}")
        print_info("Skipping batch scan test...")
        return False
    
    try:
        with open(test_file, 'rb') as f:
            files = [('files', f), ('files', f)]  # Send same file twice
            params = {'debug': 'true'}
            
            response = requests.post(f"{url}/scan-batch", files=files, params=params, timeout=30)
            print_info(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print_success(f"{api_name} batch scan successful!")
                print_info(f"Results count: {len(data.get('results', []))}")
                return True
            else:
                print_error(f"{api_name} batch scan failed: {response.status_code}")
                return False
                
    except requests.exceptions.RequestException as e:
        print_error(f"{api_name} connection failed: {e}")
        return False
    except Exception as e:
        print_error(f"{api_name} batch scan error: {e}")
        return False

def test_report_generation(url, api_name, test_file=None):
    """Test report generation endpoint"""
    print_header(f"Testing {api_name} Report Generation")
    
    if not test_file or not os.path.exists(test_file):
        print_error(f"Test APK file not found: {test_file}")
        print_info("Skipping report test...")
        return False
    
    try:
        with open(test_file, 'rb') as f:
            files = {'file': f}
            
            response = requests.post(f"{url}/report", files=files, timeout=30)
            print_info(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print_success(f"{api_name} report generation successful!")
                print_info(f"HTML length: {len(data.get('html', ''))}")
                return True
            else:
                print_error(f"{api_name} report generation failed: {response.status_code}")
                return False
                
    except requests.exceptions.RequestException as e:
        print_error(f"{api_name} connection failed: {e}")
        return False
    except Exception as e:
        print_error(f"{api_name} report error: {e}")
        return False

def find_test_apk():
    """Find a test APK file"""
    possible_paths = [
        "data/legit/base.apk",
        "data/fake/base.apk", 
        "data/legit/",
        "data/fake/",
        "test_data/",
        "samples/"
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            if os.path.isfile(path) and path.endswith('.apk'):
                return path
            elif os.path.isdir(path):
                # Look for APK files in directory
                for file in os.listdir(path):
                    if file.endswith('.apk'):
                        return os.path.join(path, file)
    
    return None

def main():
    """Main test function"""
    print_header("🚀 COMPREHENSIVE API TESTING")
    
    # Find test APK
    test_apk = find_test_apk()
    if test_apk:
        print_success(f"Found test APK: {test_apk}")
    else:
        print_error("No test APK found. Please place an APK file in data/legit/ or data/fake/")
        print_info("Tests will be skipped for scan endpoints...")
    
    # Test FastAPI
    print_header("🔵 TESTING FASTAPI (Primary API)")
    fastapi_results = []
    
    fastapi_results.append(test_health_check(FASTAPI_URL, "FastAPI"))
    fastapi_results.append(test_model_info(FASTAPI_URL, "FastAPI"))
    fastapi_results.append(test_apk_scan(FASTAPI_URL, "FastAPI", test_apk))
    fastapi_results.append(test_batch_scan(FASTAPI_URL, "FastAPI", test_apk))
    fastapi_results.append(test_report_generation(FASTAPI_URL, "FastAPI", test_apk))
    
    # Test Flask
    print_header("🟡 TESTING FLASK (Alternative API)")
    flask_results = []
    
    flask_results.append(test_health_check(FLASK_URL, "Flask"))
    flask_results.append(test_apk_scan(FLASK_URL, "Flask", test_apk))
    flask_results.append(test_batch_scan(FLASK_URL, "Flask", test_apk))
    flask_results.append(test_report_generation(FLASK_URL, "Flask", test_apk))
    
    # Summary
    print_header("📊 TEST RESULTS SUMMARY")
    
    fastapi_success = sum(fastapi_results)
    flask_success = sum(flask_results)
    
    print_info(f"FastAPI Tests: {fastapi_success}/{len(fastapi_results)} passed")
    print_info(f"Flask Tests: {flask_success}/{len(flask_results)} passed")
    
    if fastapi_success == len(fastapi_results):
        print_success("🎉 FastAPI is working perfectly!")
    else:
        print_error(f"⚠️  FastAPI has {len(fastapi_results) - fastapi_success} issues")
    
    if flask_success == len(flask_results):
        print_success("🎉 Flask is working perfectly!")
    else:
        print_error(f"⚠️  Flask has {len(flask_results) - flask_success} issues")
    
    if fastapi_success == len(fastapi_results) and flask_success == len(flask_results):
        print_success("🎉 ALL TESTS PASSED! Both APIs are working correctly!")
    else:
        print_error("❌ Some tests failed. Check the logs above for details.")

if __name__ == "__main__":
    main()
