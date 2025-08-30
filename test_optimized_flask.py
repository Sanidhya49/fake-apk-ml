#!/usr/bin/env python3
"""
Comprehensive Test Script for Optimized Flask API
Tests performance, functionality, and error handling.
"""

import requests
import json
import time
import os
import sys
from pathlib import Path

# Configuration
API_BASE_URL = "http://localhost:9000"
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
    print(f"ℹ️ {message}")

def test_health_check():
    """Test the health check endpoint"""
    print_header("Testing Health Check")
    
    try:
        start_time = time.time()
        response = requests.get(f"{API_BASE_URL}/", timeout=10)
        response_time = time.time() - start_time
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"Health check passed in {response_time:.3f}s")
            print_info(f"Status: {data.get('status')}")
            print_info(f"Message: {data.get('message')}")
            return True
        else:
            print_error(f"Health check failed with status {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Health check failed: {e}")
        return False

def test_single_scan_performance():
    """Test single APK scan with performance metrics"""
    print_header("Testing Single APK Scan Performance")
    
    if not os.path.exists(TEST_APK_PATH):
        print_error(f"Test APK not found: {TEST_APK_PATH}")
        return False
    
    try:
        with open(TEST_APK_PATH, 'rb') as f:
            files = {'file': ('test.apk', f, 'application/vnd.android.package-archive')}
            
            start_time = time.time()
            response = requests.post(
                f"{API_BASE_URL}/scan?debug=true", 
                files=files, 
                timeout=60
            )
            total_time = time.time() - start_time
        
        if response.status_code == 200:
            data = response.json()
            processing_time = data.get('debug', {}).get('processing_time_seconds', 0)
            
            print_success(f"Scan completed in {total_time:.3f}s total")
            print_info(f"Processing time: {processing_time:.3f}s")
            print_info(f"Prediction: {data.get('prediction')}")
            print_info(f"Probability: {data.get('probability', 0):.3f}")
            print_info(f"Risk: {data.get('risk')}")
            
            # Performance analysis
            if processing_time < 5.0:
                print_success("Excellent performance (< 5s)")
            elif processing_time < 10.0:
                print_info("Good performance (< 10s)")
            else:
                print_error("Slow performance (> 10s)")
            
            return True
        else:
            print_error(f"Scan failed with status {response.status_code}")
            print_error(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print_error(f"Scan test failed: {e}")
        return False

def test_batch_scan_performance():
    """Test batch APK scan with performance metrics"""
    print_header("Testing Batch APK Scan Performance")
    
    if not os.path.exists(TEST_APK_PATH):
        print_error(f"Test APK not found: {TEST_APK_PATH}")
        return False
    
    try:
        # Create multiple file uploads (same file for testing)
        files = []
        for i in range(3):  # Test with 3 files
            with open(TEST_APK_PATH, 'rb') as f:
                files.append(('files', (f'test_{i}.apk', f.read(), 'application/vnd.android.package-archive')))
        
        start_time = time.time()
        response = requests.post(
            f"{API_BASE_URL}/scan-batch?debug=true", 
            files=files, 
            timeout=120
        )
        total_time = time.time() - start_time
        
        if response.status_code == 200:
            data = response.json()
            summary = data.get('summary', {})
            results = data.get('results', [])
            
            print_success(f"Batch scan completed in {total_time:.3f}s")
            print_info(f"Files processed: {summary.get('total_files', 0)}")
            print_info(f"Processing time: {summary.get('processing_time_seconds', 0):.3f}s")
            print_info(f"Files per second: {summary.get('files_per_second', 0):.2f}")
            
            # Performance analysis
            files_per_second = summary.get('files_per_second', 0)
            if files_per_second > 1.0:
                print_success("Excellent batch performance (> 1 file/sec)")
            elif files_per_second > 0.5:
                print_info("Good batch performance (> 0.5 files/sec)")
            else:
                print_error("Slow batch performance (< 0.5 files/sec)")
            
            # Check results
            for i, result in enumerate(results):
                if 'error' not in result:
                    print_info(f"File {i+1}: {result.get('prediction')} ({result.get('probability', 0):.3f})")
                else:
                    print_error(f"File {i+1}: {result.get('error')}")
            
            return True
        else:
            print_error(f"Batch scan failed with status {response.status_code}")
            print_error(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print_error(f"Batch scan test failed: {e}")
        return False

def test_error_handling():
    """Test error handling with invalid inputs"""
    print_header("Testing Error Handling")
    
    # Test 1: No file
    try:
        response = requests.post(f"{API_BASE_URL}/scan", timeout=10)
        if response.status_code == 400:
            print_success("Correctly handled missing file")
        else:
            print_error(f"Expected 400 for missing file, got {response.status_code}")
    except Exception as e:
        print_error(f"Error handling test failed: {e}")
    
    # Test 2: Invalid file type
    try:
        files = {'file': ('test.txt', b'not an apk', 'text/plain')}
        response = requests.post(f"{API_BASE_URL}/scan", files=files, timeout=10)
        if response.status_code == 400:
            print_success("Correctly handled invalid file type")
        else:
            print_error(f"Expected 400 for invalid file type, got {response.status_code}")
    except Exception as e:
        print_error(f"Invalid file type test failed: {e}")
    
    # Test 3: Empty file
    try:
        files = {'file': ('empty.apk', b'', 'application/vnd.android.package-archive')}
        response = requests.post(f"{API_BASE_URL}/scan", files=files, timeout=10)
        if response.status_code in [400, 422]:
            print_success("Correctly handled empty file")
        else:
            print_error(f"Expected 400/422 for empty file, got {response.status_code}")
    except Exception as e:
        print_error(f"Empty file test failed: {e}")

def test_caching():
    """Test caching functionality"""
    print_header("Testing Caching Performance")
    
    if not os.path.exists(TEST_APK_PATH):
        print_error(f"Test APK not found: {TEST_APK_PATH}")
        return False
    
    try:
        # First scan (should be slower)
        with open(TEST_APK_PATH, 'rb') as f:
            files = {'file': ('test.apk', f, 'application/vnd.android.package-archive')}
            
            start_time = time.time()
            response1 = requests.post(f"{API_BASE_URL}/scan?debug=true", files=files, timeout=60)
            time1 = time.time() - start_time
        
        # Second scan (should be faster due to caching)
        with open(TEST_APK_PATH, 'rb') as f:
            files = {'file': ('test.apk', f, 'application/vnd.android.package-archive')}
            
            start_time = time.time()
            response2 = requests.post(f"{API_BASE_URL}/scan?debug=true", files=files, timeout=60)
            time2 = time.time() - start_time
        
        if response1.status_code == 200 and response2.status_code == 200:
            print_info(f"First scan: {time1:.3f}s")
            print_info(f"Second scan: {time2:.3f}s")
            
            if time2 < time1:
                improvement = ((time1 - time2) / time1) * 100
                print_success(f"Caching working! {improvement:.1f}% improvement")
            else:
                print_info("Caching may not be working as expected")
            
            return True
        else:
            print_error("Caching test failed - scan requests failed")
            return False
            
    except Exception as e:
        print_error(f"Caching test failed: {e}")
        return False

def main():
    """Run all tests"""
    print_header("Flask API Performance & Functionality Test Suite")
    
    # Check if API is running
    print_info("Checking if Flask API is running...")
    try:
        response = requests.get(f"{API_BASE_URL}/", timeout=5)
        if response.status_code == 200:
            print_success("Flask API is running!")
        else:
            print_error("Flask API is not responding correctly")
            return
    except Exception as e:
        print_error(f"Cannot connect to Flask API: {e}")
        print_info("Please start the Flask API first using: start_flask_api.bat")
        return
    
    # Run tests
    tests = [
        test_health_check,
        test_single_scan_performance,
        test_batch_scan_performance,
        test_error_handling,
        test_caching
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print_error(f"Test {test.__name__} failed with exception: {e}")
    
    # Summary
    print_header("Test Summary")
    print_info(f"Tests passed: {passed}/{total}")
    if passed == total:
        print_success("All tests passed! Flask API is working optimally.")
    else:
        print_error(f"{total - passed} tests failed. Check the issues above.")

if __name__ == "__main__":
    main()
