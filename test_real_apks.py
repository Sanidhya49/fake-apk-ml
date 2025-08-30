#!/usr/bin/env python3
"""
Real APK Testing Script for Flask API
Tests the API with actual legitimate and fake APK files to verify predictions.
"""

import requests
import json
import time
import os
import glob
from pathlib import Path

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

def test_single_apk(apk_path, expected_category="unknown"):
    """Test a single APK file"""
    try:
        with open(apk_path, 'rb') as f:
            files = {'file': (os.path.basename(apk_path), f, 'application/vnd.android.package-archive')}
            
            start_time = time.time()
            response = requests.post(
                f"{API_BASE_URL}/scan?debug=true", 
                files=files, 
                timeout=120
            )
            total_time = time.time() - start_time
        
        if response.status_code == 200:
            data = response.json()
            prediction = data.get('prediction', 'unknown')
            probability = data.get('probability', 0)
            risk = data.get('risk', 'unknown')
            processing_time = data.get('debug', {}).get('processing_time_seconds', 0)
            
            # Determine if prediction matches expectation
            is_correct = True
            if expected_category == "legit" and prediction == "fake":
                is_correct = False
            elif expected_category == "fake" and prediction == "legit":
                is_correct = False
            
            status = "✅" if is_correct else "❌"
            
            print(f"{status} {os.path.basename(apk_path):<40} | {prediction:>5} | {probability:.3f} | {risk:>5} | {processing_time:.2f}s | {total_time:.2f}s")
            
            return {
                'file': os.path.basename(apk_path),
                'prediction': prediction,
                'probability': probability,
                'risk': risk,
                'processing_time': processing_time,
                'total_time': total_time,
                'is_correct': is_correct,
                'expected': expected_category
            }
        else:
            print(f"❌ {os.path.basename(apk_path):<40} | ERROR | {response.status_code} | {response.text[:50]}")
            return None
            
    except Exception as e:
        print(f"❌ {os.path.basename(apk_path):<40} | ERROR | {str(e)[:50]}")
        return None

def test_legitimate_apks():
    """Test legitimate APK files"""
    print_header("Testing Legitimate APK Files")
    
    # Find legitimate APK files (smaller ones for faster testing)
    legit_files = []
    legit_dir = "data/legit"
    
    if os.path.exists(legit_dir):
        # Get smaller APK files for faster testing
        apk_files = glob.glob(os.path.join(legit_dir, "*.apk"))
        apk_files.sort(key=lambda x: os.path.getsize(x))  # Sort by size (smallest first)
        
        # Take first 5 legitimate APKs for testing
        legit_files = apk_files[:5]
    
    if not legit_files:
        print_error("No legitimate APK files found")
        return []
    
    print(f"Testing {len(legit_files)} legitimate APK files...")
    print(f"{'File':<40} | {'Pred':>5} | {'Prob':>6} | {'Risk':>5} | {'Proc':>5} | {'Total':>5}")
    print("-" * 80)
    
    results = []
    for apk_file in legit_files:
        result = test_single_apk(apk_file, expected_category="legit")
        if result:
            results.append(result)
    
    return results

def test_fake_apks():
    """Test fake APK files"""
    print_header("Testing Fake APK Files")
    
    # Find fake APK files
    fake_files = []
    fake_dir = "data/fake"
    
    if os.path.exists(fake_dir):
        # Get smaller APK files for faster testing
        apk_files = glob.glob(os.path.join(fake_dir, "*.apk"))
        apk_files.sort(key=lambda x: os.path.getsize(x))  # Sort by size (smallest first)
        
        # Take first 5 fake APKs for testing
        fake_files = apk_files[:5]
    
    if not fake_files:
        print_error("No fake APK files found")
        return []
    
    print(f"Testing {len(fake_files)} fake APK files...")
    print(f"{'File':<40} | {'Pred':>5} | {'Prob':>6} | {'Risk':>5} | {'Proc':>5} | {'Total':>5}")
    print("-" * 80)
    
    results = []
    for apk_file in fake_files:
        result = test_single_apk(apk_file, expected_category="fake")
        if result:
            results.append(result)
    
    return results

def analyze_results(legit_results, fake_results):
    """Analyze and summarize test results"""
    print_header("Test Results Analysis")
    
    all_results = legit_results + fake_results
    
    if not all_results:
        print_error("No test results to analyze")
        return
    
    # Calculate statistics
    total_tests = len(all_results)
    correct_predictions = sum(1 for r in all_results if r['is_correct'])
    accuracy = (correct_predictions / total_tests) * 100 if total_tests > 0 else 0
    
    # Legitimate APK statistics
    legit_tests = len(legit_results)
    legit_correct = sum(1 for r in legit_results if r['is_correct'])
    legit_accuracy = (legit_correct / legit_tests) * 100 if legit_tests > 0 else 0
    
    # Fake APK statistics
    fake_tests = len(fake_results)
    fake_correct = sum(1 for r in fake_results if r['is_correct'])
    fake_accuracy = (fake_correct / fake_tests) * 100 if fake_tests > 0 else 0
    
    # Performance statistics
    avg_processing_time = sum(r['processing_time'] for r in all_results) / len(all_results)
    avg_total_time = sum(r['total_time'] for r in all_results) / len(all_results)
    
    # Risk distribution
    risk_counts = {}
    for r in all_results:
        risk = r['risk']
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    
    # Print summary
    print(f"📊 Overall Accuracy: {accuracy:.1f}% ({correct_predictions}/{total_tests})")
    print(f"📊 Legitimate APK Accuracy: {legit_accuracy:.1f}% ({legit_correct}/{legit_tests})")
    print(f"📊 Fake APK Accuracy: {fake_accuracy:.1f}% ({fake_correct}/{fake_tests})")
    print(f"⚡ Average Processing Time: {avg_processing_time:.2f}s")
    print(f"⚡ Average Total Time: {avg_total_time:.2f}s")
    
    print(f"\n🎯 Risk Distribution:")
    for risk, count in risk_counts.items():
        percentage = (count / total_tests) * 100
        print(f"   {risk}: {count} ({percentage:.1f}%)")
    
    # Show incorrect predictions
    incorrect_results = [r for r in all_results if not r['is_correct']]
    if incorrect_results:
        print(f"\n❌ Incorrect Predictions ({len(incorrect_results)}):")
        for r in incorrect_results:
            print(f"   {r['file']}: Expected {r['expected']}, Got {r['prediction']} ({r['probability']:.3f})")
    
    # Performance assessment
    print(f"\n🚀 Performance Assessment:")
    if avg_processing_time < 5.0:
        print_success("Excellent processing speed (< 5s average)")
    elif avg_processing_time < 10.0:
        print_info("Good processing speed (< 10s average)")
    else:
        print_error("Slow processing speed (> 10s average)")
    
    if accuracy >= 90:
        print_success("Excellent accuracy (≥ 90%)")
    elif accuracy >= 80:
        print_info("Good accuracy (≥ 80%)")
    elif accuracy >= 70:
        print_info("Acceptable accuracy (≥ 70%)")
    else:
        print_error("Poor accuracy (< 70%)")

def main():
    """Run the real APK tests"""
    print_header("Real APK Testing for Flask API")
    
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
    
    # Test legitimate APKs
    legit_results = test_legitimate_apks()
    
    # Test fake APKs
    fake_results = test_fake_apks()
    
    # Analyze results
    analyze_results(legit_results, fake_results)
    
    print_header("Test Complete")
    print_success("Real APK testing completed successfully!")

if __name__ == "__main__":
    main()
