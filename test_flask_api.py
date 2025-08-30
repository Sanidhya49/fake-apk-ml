"""
Test script for the Flask APK analysis API.
Run this after starting the Flask server to verify the API is working.
"""

import requests
import os
import sys

API_BASE_URL = "http://localhost:9000"

def test_health_check():
    """Test the health check endpoint"""
    print("Testing health check endpoint...")
    try:
        response = requests.get(f"{API_BASE_URL}/")
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"Response: {response.json()}")
            return True
        else:
            print(f"❌ Health check failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

def test_scan_endpoint():
    """Test the scan endpoint with a sample file"""
    print("\nTesting scan endpoint...")
    
    # Create a dummy APK file for testing
    test_file_path = "test_sample.apk"
    
    # Create a minimal test file (not a real APK, just for endpoint testing)
    with open(test_file_path, 'wb') as f:
        f.write(b'PK\x03\x04' + b'0' * 100)  # Minimal ZIP-like header
    
    try:
        with open(test_file_path, 'rb') as f:
            files = {'file': ('test_sample.apk', f, 'application/vnd.android.package-archive')}
            response = requests.post(f"{API_BASE_URL}/scan", files=files, timeout=60)
        
        print(f"Response status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        
        if response.status_code in [200, 422]:  # 422 expected for invalid APK
            print("✅ Scan endpoint is reachable")
            try:
                json_response = response.json()
                print(f"Response body: {json_response}")
                if response.status_code == 422 and "parse_failed" in json_response.get("error", ""):
                    print("✅ Expected parse_failed error for dummy file")
                    return True
                elif response.status_code == 200:
                    print("✅ Scan completed successfully (unexpected but good!)")
                    return True
            except Exception as e:
                print(f"❌ Failed to parse JSON response: {e}")
                print(f"Raw response: {response.text}")
                return False
        else:
            print(f"❌ Scan endpoint failed with status {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Scan endpoint test failed: {e}")
        return False
    finally:
        # Clean up test file
        try:
            os.remove(test_file_path)
        except:
            pass

def test_batch_scan_endpoint():
    """Test the batch scan endpoint"""
    print("\nTesting batch scan endpoint...")
    
    # Create dummy APK files for testing
    test_files = []
    file_paths = []
    
    try:
        for i in range(2):
            file_path = f"test_sample_{i}.apk"
            file_paths.append(file_path)
            with open(file_path, 'wb') as f:
                f.write(b'PK\x03\x04' + b'0' * 100)  # Minimal ZIP-like header
            
            test_files.append(('files', (f'test_sample_{i}.apk', open(file_path, 'rb'), 'application/vnd.android.package-archive')))
        
        response = requests.post(f"{API_BASE_URL}/scan-batch", files=test_files, timeout=120)
        
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Batch scan endpoint is reachable")
            try:
                json_response = response.json()
                print(f"Response body: {json_response}")
                if "results" in json_response:
                    print("✅ Batch scan returned results array")
                    return True
            except Exception as e:
                print(f"❌ Failed to parse JSON response: {e}")
                return False
        else:
            print(f"❌ Batch scan endpoint failed with status {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Batch scan endpoint test failed: {e}")
        return False
    finally:
        # Clean up test files
        for file_tuple in test_files:
            try:
                file_tuple[1][1].close()  # Close file handle
            except:
                pass
        for file_path in file_paths:
            try:
                os.remove(file_path)
            except:
                pass

def main():
    print("🧪 Testing Flask APK Analysis API")
    print("=" * 50)
    
    # Test health check
    health_ok = test_health_check()
    
    if not health_ok:
        print("\n❌ Basic connectivity failed. Make sure Flask server is running on http://localhost:9000")
        return
    
    # Test scan endpoint
    scan_ok = test_scan_endpoint()
    
    # Test batch scan endpoint
    batch_ok = test_batch_scan_endpoint()
    
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    print(f"  Health Check: {'✅ PASS' if health_ok else '❌ FAIL'}")
    print(f"  Single Scan:  {'✅ PASS' if scan_ok else '❌ FAIL'}")
    print(f"  Batch Scan:   {'✅ PASS' if batch_ok else '❌ FAIL'}")
    
    if health_ok and scan_ok and batch_ok:
        print("\n🎉 All tests passed! API is ready for frontend integration.")
    else:
        print("\n⚠️  Some tests failed. Check the Flask server logs for details.")

if __name__ == "__main__":
    main()
