#!/usr/bin/env python3
"""
Test script for new batch features:
- Up to 15 APK uploads
- Word document report generation
- AI explanations
"""

import requests
import json
import time
import os
import glob

# Configuration
API_BASE_URL = "http://localhost:9000"

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

def test_batch_scan_15_apks():
    """Test batch scan with up to 15 APKs"""
    print_header("Testing Batch Scan (Up to 15 APKs)")
    
    # Get test APK files
    legit_dir = "data/legit"
    fake_dir = "data/fake"
    
    test_files = []
    
    # Add some legitimate APKs
    if os.path.exists(legit_dir):
        legit_files = glob.glob(os.path.join(legit_dir, "*.apk"))
        legit_files.sort(key=lambda x: os.path.getsize(x))  # Smallest first
        test_files.extend(legit_files[:8])  # 8 legitimate APKs
    
    # Add some fake APKs
    if os.path.exists(fake_dir):
        fake_files = glob.glob(os.path.join(fake_dir, "*.apk"))
        fake_files.sort(key=lambda x: os.path.getsize(x))  # Smallest first
        test_files.extend(fake_files[:7])  # 7 fake APKs
    
    if len(test_files) < 5:
        print_error("Not enough test files found")
        return False
    
    print(f"Testing with {len(test_files)} APK files...")
    
    try:
        # Prepare files for upload
        files = []
        for apk_file in test_files:
            with open(apk_file, 'rb') as f:
                files.append(('files', (os.path.basename(apk_file), f.read(), 'application/vnd.android.package-archive')))
        
        # Test batch scan
        start_time = time.time()
        response = requests.post(
            f"{API_BASE_URL}/scan-batch?debug=true", 
            files=files, 
            timeout=300  # 5 minutes timeout for large batch
        )
        total_time = time.time() - start_time
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            summary = data.get('summary', {})
            
            print_success(f"Batch scan completed in {total_time:.2f}s")
            print_info(f"Files processed: {summary.get('total_files', 0)}")
            print_info(f"Processing time: {summary.get('processing_time_seconds', 0):.2f}s")
            print_info(f"Files per second: {summary.get('files_per_second', 0):.2f}")
            print_info(f"Max files allowed: {summary.get('max_files_allowed', 0)}")
            
            # Show results summary
            fake_count = sum(1 for r in results if r.get('prediction') == 'fake')
            legit_count = sum(1 for r in results if r.get('prediction') == 'legit')
            
            print_info(f"Results: {legit_count} legitimate, {fake_count} fake")
            
            return True
        else:
            print_error(f"Batch scan failed: {response.status_code}")
            print_error(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print_error(f"Batch scan test failed: {e}")
        return False

def test_word_report_generation():
    """Test Word document report generation"""
    print_header("Testing Word Document Report Generation")
    
    # Get a few test APK files
    legit_dir = "data/legit"
    fake_dir = "data/fake"
    
    test_files = []
    
    # Add 2 legitimate APKs
    if os.path.exists(legit_dir):
        legit_files = glob.glob(os.path.join(legit_dir, "*.apk"))
        legit_files.sort(key=lambda x: os.path.getsize(x))
        test_files.extend(legit_files[:2])
    
    # Add 2 fake APKs
    if os.path.exists(fake_dir):
        fake_files = glob.glob(os.path.join(fake_dir, "*.apk"))
        fake_files.sort(key=lambda x: os.path.getsize(x))
        test_files.extend(fake_files[:2])
    
    if len(test_files) < 2:
        print_error("Not enough test files found")
        return False
    
    print(f"Testing Word report generation with {len(test_files)} APK files...")
    
    try:
        # Prepare files for upload
        files = []
        for apk_file in test_files:
            with open(apk_file, 'rb') as f:
                files.append(('files', (os.path.basename(apk_file), f.read(), 'application/vnd.android.package-archive')))
        
        # Test batch report generation
        start_time = time.time()
        response = requests.post(
            f"{API_BASE_URL}/report-batch", 
            files=files, 
            timeout=300
        )
        total_time = time.time() - start_time
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            summary = data.get('summary', {})
            word_report = data.get('word_report', '')
            
            print_success(f"Word report generation completed in {total_time:.2f}s")
            print_info(f"Files processed: {summary.get('total_files', 0)}")
            print_info(f"Report generated: {summary.get('report_generated', False)}")
            print_info(f"Word report path: {word_report}")
            
            # Check if Word document was created
            if word_report and os.path.exists(word_report):
                file_size = os.path.getsize(word_report)
                print_success(f"Word document created: {word_report} ({file_size} bytes)")
            else:
                print_info("Word document not created (fallback to HTML)")
            
            # Show AI explanations
            print_info("AI Explanations generated:")
            for result in results:
                file_name = result.get('file', 'N/A')
                prediction = result.get('prediction', 'Unknown')
                confidence = result.get('probability', 0)
                print(f"  • {file_name}: {prediction.title()} ({confidence:.1%})")
            
            return True
        else:
            print_error(f"Word report generation failed: {response.status_code}")
            print_error(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print_error(f"Word report test failed: {e}")
        return False

def test_15_apk_limit():
    """Test the 15 APK limit enforcement"""
    print_header("Testing 15 APK Limit Enforcement")
    
    # Create 16 dummy files to test the limit
    dummy_files = []
    for i in range(16):
        dummy_files.append(('files', (f'test_{i}.apk', b'dummy content', 'application/vnd.android.package-archive')))
    
    try:
        response = requests.post(
            f"{API_BASE_URL}/scan-batch", 
            files=dummy_files, 
            timeout=30
        )
        
        if response.status_code == 400:
            data = response.json()
            if data.get('error') == 'too_many_files':
                print_success("15 APK limit correctly enforced")
                print_info(f"Error message: {data.get('detail', '')}")
                return True
            else:
                print_error("Unexpected error response")
                return False
        else:
            print_error(f"Expected 400 error, got {response.status_code}")
            return False
            
    except Exception as e:
        print_error(f"Limit test failed: {e}")
        return False

def main():
    """Run all batch feature tests"""
    print_header("Batch Features Test Suite")
    
    # Check if API is running
    try:
        response = requests.get(f"{API_BASE_URL}/", timeout=5)
        if response.status_code != 200:
            print_error("Flask API is not responding correctly")
            return
    except Exception as e:
        print_error(f"Cannot connect to Flask API: {e}")
        print_info("Please start the Flask API first")
        return
    
    print_success("Flask API is running and ready for testing!")
    
    # Run tests
    tests = [
        test_batch_scan_15_apks,
        test_word_report_generation,
        test_15_apk_limit
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
        print_success("All batch features working correctly!")
    else:
        print_error(f"{total - passed} tests failed. Check the issues above.")

if __name__ == "__main__":
    main()

