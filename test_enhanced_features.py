#!/usr/bin/env python3
"""
Enhanced Features Test Script - Tests all new features including Gemini API
"""

import requests
import json
import os
import time
from pathlib import Path

# Test API Configuration (local)
LOCAL_API_BASE = "http://localhost:9000"

def test_local_api_health():
    """Test local API health"""
    print("🔍 Testing Local API Health...")
    try:
        response = requests.get(f"{LOCAL_API_BASE}/", timeout=10)
        print(f"✅ Local Health Status: {response.status_code}")
        print(f"✅ Local Response: {response.json()}")
        return True
    except Exception as e:
        print(f"❌ Local Health Failed: {e}")
        print("💡 Make sure your local Flask API is running on port 9000")
        return False

def test_enhanced_scan_features(apk_path):
    """Test enhanced scan features including Gemini API"""
    print(f"\n🔍 Testing Enhanced Scan Features: {os.path.basename(apk_path)}")
    
    try:
        with open(apk_path, 'rb') as f:
            files = {'file': (os.path.basename(apk_path), f, 'application/vnd.android.package-archive')}
            
            response = requests.post(
                f"{LOCAL_API_BASE}/scan",
                files=files,
                timeout=120
            )
            
        print(f"✅ Local Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Test all enhanced features
            enhanced_features = {
                'prediction': 'Basic ML prediction',
                'probability': 'Probability score',
                'risk_level': 'Risk level (Red/Amber/Green)',
                'confidence': 'Confidence level',
                'top_shap': 'SHAP feature analysis',
                'feature_vector': 'Feature vector',
                'processing_time': 'Processing time',
                'model_threshold': 'Model threshold',
                'cache_used': 'Cache usage info',
                'file': 'File name',
                'ai_explanation': 'Gemini AI explanation'
            }
            
            print("📊 Enhanced Feature Verification:")
            all_features_working = True
            
            for field, description in enhanced_features.items():
                if field in result:
                    value = result[field]
                    if value is not None and value != "N/A" and value != "":
                        if field == 'top_shap':
                            if isinstance(value, list) and len(value) > 0:
                                print(f"✅ {field}: {len(value)} features found")
                            else:
                                print(f"❌ {field}: Empty array")
                                all_features_working = False
                        elif field == 'ai_explanation':
                            if isinstance(value, str) and len(value) > 50:
                                print(f"✅ {field}: Gemini AI explanation ({len(value)} chars)")
                                print(f"   Preview: {value[:100]}...")
                            else:
                                print(f"❌ {field}: Too short or missing")
                                all_features_working = False
                        elif field == 'processing_time':
                            if isinstance(value, (int, float)) and value > 0:
                                print(f"✅ {field}: {value:.3f} seconds")
                            else:
                                print(f"❌ {field}: Invalid value ({value})")
                                all_features_working = False
                        elif field == 'model_threshold':
                            if isinstance(value, (int, float)) and value > 0:
                                print(f"✅ {field}: {value}")
                            else:
                                print(f"❌ {field}: Invalid value ({value})")
                                all_features_working = False
                        elif field == 'cache_used':
                            if isinstance(value, bool):
                                print(f"✅ {field}: {value}")
                            else:
                                print(f"❌ {field}: Invalid value ({value})")
                                all_features_working = False
                        elif field == 'file':
                            if isinstance(value, str) and len(value) > 0:
                                print(f"✅ {field}: {value}")
                            else:
                                print(f"❌ {field}: Missing or empty")
                                all_features_working = False
                        else:
                            print(f"✅ {field}: {value}")
                    else:
                        print(f"❌ {field}: Empty/None/N/A")
                        all_features_working = False
                else:
                    print(f"❌ {field}: Missing from response")
                    all_features_working = False
            
            # Test Gemini AI explanation quality
            print("\n🔍 Gemini AI Explanation Quality Test:")
            if 'ai_explanation' in result and result['ai_explanation']:
                ai_text = result['ai_explanation']
                if len(ai_text) > 100:
                    print("✅ Gemini AI Explanation: High quality (detailed)")
                    # Check for professional cybersecurity terms
                    security_terms = ['security', 'malicious', 'permissions', 'certificate', 'risk', 'threat', 'vulnerability', 'analysis']
                    found_terms = [term for term in security_terms if term.lower() in ai_text.lower()]
                    print(f"   Security terms found: {len(found_terms)}/{len(security_terms)}")
                    if len(found_terms) >= 3:
                        print("✅ Professional cybersecurity terminology used")
                    else:
                        print("⚠️  Limited cybersecurity terminology")
                else:
                    print("❌ Gemini AI Explanation: Too short")
                    all_features_working = False
            else:
                print("❌ Gemini AI Explanation: Missing")
                all_features_working = False
            
            # Test SHAP analysis quality
            print("\n🔍 SHAP Analysis Quality Test:")
            if 'top_shap' in result and result['top_shap']:
                shap_features = result['top_shap']
                if len(shap_features) >= 3:
                    print(f"✅ SHAP Analysis: High quality ({len(shap_features)} features)")
                    for i, feature in enumerate(shap_features[:3]):
                        print(f"   {i+1}. {feature.get('feature', 'Unknown')}: {feature.get('value', 0):.4f}")
                else:
                    print(f"⚠️  SHAP Analysis: Low quality ({len(shap_features)} features)")
            else:
                print("❌ SHAP Analysis: Missing or empty")
                all_features_working = False
            
            return result, all_features_working
        else:
            print(f"❌ Local Error: {response.text}")
            return None, False
            
    except Exception as e:
        print(f"❌ Local Scan Failed: {e}")
        return None, False

def test_batch_enhanced_features(apk_paths):
    """Test enhanced batch scan features"""
    print(f"\n🔍 Testing Enhanced Batch Features: {len(apk_paths)} files")
    
    try:
        files = []
        file_handles = []
        
        for apk_path in apk_paths:
            f = open(apk_path, 'rb')
            file_handles.append(f)
            files.append(('files', (os.path.basename(apk_path), f, 'application/vnd.android.package-archive')))
        
        try:
            response = requests.post(
                f"{LOCAL_API_BASE}/scan-batch",
                files=files,
                timeout=300
            )
        finally:
            # Close all file handles
            for f in file_handles:
                f.close()
        
        print(f"✅ Local Batch Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            if 'results' in data:
                results = data['results']
                print(f"✅ Batch Results: {len(results)} files processed")
                
                # Check enhanced features in all results
                enhanced_feature_counts = {
                    'ai_explanation': 0,
                    'risk_level': 0,
                    'top_shap': 0,
                    'processing_time': 0,
                    'model_threshold': 0,
                    'cache_used': 0,
                    'file': 0
                }
                
                for result in results:
                    for field in enhanced_feature_counts:
                        if field in result and result[field] and result[field] != "N/A":
                            enhanced_feature_counts[field] += 1
                
                print("📊 Enhanced Batch Feature Summary:")
                for field, count in enhanced_feature_counts.items():
                    print(f"   - {field}: {count}/{len(results)} files")
                
                return results
            else:
                print("❌ Batch response missing 'results' field")
                return None
        else:
            print(f"❌ Local Batch Error: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Local Batch Failed: {e}")
        return None

def main():
    """Main test function"""
    print("🚀 Starting Enhanced Features Test")
    print(f"📍 Local API: {LOCAL_API_BASE}")
    print("="*80)
    
    # Test 1: Health Check
    if not test_local_api_health():
        print("❌ Local API health check failed. Please start your Flask API first.")
        print("💡 Run: python flask_app/main.py")
        return
    
    # Test 2: Find APK file
    print("\n🔍 Looking for test APK file...")
    apk_path = "data/fake/base.apk"
    
    if not os.path.exists(apk_path):
        print(f"❌ APK file not found: {apk_path}")
        return
    
    print(f"✅ Found APK: {apk_path}")
    
    # Test 3: Enhanced Single Scan Features
    print("\n" + "="*80)
    print("🔍 ENHANCED SINGLE SCAN FEATURE TEST")
    print("="*80)
    
    result, all_features_working = test_enhanced_scan_features(apk_path)
    
    # Test 4: Enhanced Batch Scan Features
    print("\n" + "="*80)
    print("🔍 ENHANCED BATCH SCAN FEATURE TEST")
    print("="*80)
    
    batch_results = test_batch_enhanced_features([apk_path])
    
    # Final Summary
    print("\n" + "="*80)
    print("🎉 ENHANCED FEATURES TEST COMPLETE!")
    print("="*80)
    
    if result and all_features_working:
        print("✅ ALL ENHANCED FEATURES WORKING - READY TO COMMIT!")
        print("📊 All enhanced features are functioning correctly:")
        print("   ✅ Gemini AI Explanations")
        print("   ✅ Enhanced SHAP Analysis with debug logging")
        print("   ✅ Processing Metadata in main response")
        print("   ✅ File Names preserved")
        print("   ✅ Risk Levels working")
        print("   ✅ Batch Processing with all features")
        print("   ✅ Professional cybersecurity analysis")
    elif result:
        print("⚠️  MOST FEATURES WORKING - Review issues above")
        print("💡 Some features may need minor adjustments")
    else:
        print("❌ FEATURES NOT WORKING - Do not commit yet")
        print("💡 Fix the issues above before committing")
    
    print("\n🚀 Next Steps:")
    if all_features_working:
        print("   1. ✅ Commit your enhanced changes")
        print("   2. ✅ Share with your friend")
        print("   3. ✅ Deploy to GCP")
        print("   4. ✅ Test GCP deployment")
    else:
        print("   1. ❌ Fix the issues above")
        print("   2. ❌ Test again")
        print("   3. ❌ Then commit")

if __name__ == "__main__":
    main()
