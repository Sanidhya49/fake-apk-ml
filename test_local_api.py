import requests
import os
import time
import random

# Test with local Flask API
API_URL = "http://localhost:9000"

def get_random_apks(legit_count=3, fake_count=3):
    """Get random APK files from both directories"""
    apks = []
    
    # Get legitimate APKs
    if os.path.exists("data/legit"):
        legit_files = [f for f in os.listdir("data/legit") if f.endswith('.apk')]
        legit_files = [f for f in legit_files if not f.startswith('._')]
        selected_legit = random.sample(legit_files, min(legit_count, len(legit_files)))
        
        for file in selected_legit:
            apks.append({
                'path': os.path.join("data/legit", file),
                'expected': 'legit',
                'file': file
            })
    
    # Get fake APKs
    if os.path.exists("data/fake"):
        fake_files = [f for f in os.listdir("data/fake") if f.endswith('.apk')]
        fake_files = [f for f in fake_files if not f.startswith('._')]
        selected_fake = random.sample(fake_files, min(fake_count, len(fake_files)))
        
        for file in selected_fake:
            apks.append({
                'path': os.path.join("data/fake", file),
                'expected': 'fake',
                'file': file
            })
    
    return apks

def test_single_apk(apk_info):
    """Test a single APK file"""
    try:
        with open(apk_info['path'], 'rb') as f:
            files = {'file': (apk_info['file'], f, 'application/vnd.android.package-archive')}
            
            start_time = time.time()
            response = requests.post(
                f"{API_URL}/scan", 
                files=files, 
                params={'debug': 'true'},
                timeout=60
            )
            total_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'file': apk_info['file'],
                    'expected': apk_info['expected'],
                    'prediction': data.get('prediction', 'unknown'),
                    'probability': data.get('probability', 0),
                    'risk_level': data.get('risk_level', 'unknown'),
                    'confidence': data.get('confidence', 'unknown'),
                    'processing_time': total_time,
                    'debug': data.get('debug', {})
                }
            else:
                return {
                    'success': False,
                    'file': apk_info['file'],
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
    except Exception as e:
        return {
            'success': False,
            'file': apk_info['file'],
            'error': str(e)
        }

def print_results(results):
    """Print test results"""
    print("\n" + "="*60)
    print("LOCAL API TESTING RESULTS")
    print("="*60)
    
    successful_tests = [r for r in results if r['success']]
    failed_tests = [r for r in results if not r['success']]
    
    print(f"Total APKs tested: {len(results)}")
    print(f"Successful tests: {len(successful_tests)}")
    print(f"Failed tests: {len(failed_tests)}")
    
    if successful_tests:
        print("\nSUCCESSFUL TESTS:")
        print("-" * 40)
        
        correct_predictions = 0
        legit_tests = 0
        fake_tests = 0
        
        for result in successful_tests:
            file_name = result['file']
            expected = result['expected']
            prediction = result['prediction']
            probability = result['probability']
            risk_level = result['risk_level']
            confidence = result['confidence']
            processing_time = result['processing_time']
            model_threshold = result['debug'].get('model_threshold', 'N/A')
            
            # Count statistics
            if expected == 'legit':
                legit_tests += 1
            else:
                fake_tests += 1
                
            if prediction == expected:
                correct_predictions += 1
                status = "✅ CORRECT"
            else:
                status = "❌ WRONG"
            
            print(f"{status} | {file_name}")
            print(f"  Expected: {expected.upper()}, Predicted: {prediction.upper()}")
            print(f"  Probability: {probability:.1%}, Risk: {risk_level}, Confidence: {confidence}")
            print(f"  Processing: {processing_time:.2f}s, Threshold: {model_threshold}")
            print()
        
        # Calculate accuracy
        if successful_tests:
            accuracy = (correct_predictions / len(successful_tests)) * 100
            print(f"Overall Accuracy: {accuracy:.1f}% ({correct_predictions}/{len(successful_tests)})")
            
            if legit_tests > 0:
                legit_correct = sum(1 for r in successful_tests if r['expected'] == 'legit' and r['prediction'] == 'legit')
                legit_accuracy = (legit_correct / legit_tests) * 100
                print(f"Legitimate APK Accuracy: {legit_accuracy:.1f}% ({legit_correct}/{legit_tests})")
            
            if fake_tests > 0:
                fake_correct = sum(1 for r in successful_tests if r['expected'] == 'fake' and r['prediction'] == 'fake')
                fake_accuracy = (fake_correct / fake_tests) * 100
                print(f"Fake APK Accuracy: {fake_accuracy:.1f}% ({fake_correct}/{fake_tests})")
    
    if failed_tests:
        print("\nFAILED TESTS:")
        print("-" * 40)
        for result in failed_tests:
            print(f"❌ {result['file']}: {result['error']}")

def main():
    """Main test function"""
    print("="*60)
    print("LOCAL FLASK API TESTING")
    print("="*60)
    print(f"API URL: {API_URL}")
    print(f"Current Threshold: 0.385")
    
    # Check if local API is running
    try:
        health_response = requests.get(f"{API_URL}/", timeout=5)
        print(f"✅ Local API is running (Status: {health_response.status_code})")
    except Exception as e:
        print(f"❌ Local API is not running: {e}")
        print("Please start the local Flask API first using:")
        print("python flask_app/main.py")
        return
    
    # Get random APKs
    print("\nSelecting random APK files...")
    apks = get_random_apks(legit_count=3, fake_count=3)
    
    if not apks:
        print("❌ No APK files found in data directories!")
        return
    
    print(f"Selected {len(apks)} APK files for testing:")
    for apk in apks:
        print(f"  - {apk['file']} (Expected: {apk['expected']})")
    
    # Test each APK
    print(f"\nTesting {len(apks)} APK files...")
    results = []
    
    for i, apk in enumerate(apks, 1):
        print(f"\n[{i}/{len(apks)}] Testing: {apk['file']}")
        result = test_single_apk(apk)
        results.append(result)
        
        if result['success']:
            prediction = result['prediction']
            expected = result['expected']
            status = "✅" if prediction == expected else "❌"
            print(f"  {status} Predicted: {prediction}, Expected: {expected}")
        else:
            print(f"  ❌ Failed: {result['error']}")
    
    # Print summary
    print_results(results)
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()
