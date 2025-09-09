#!/usr/bin/env python3
"""
Test script for admin endpoints
"""

import requests
import json

BASE_URL = "http://localhost:9000"

def test_admin_reports():
    """Test the admin reports endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/admin/reports")
        print(f"GET /admin/reports: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Found {len(data.get('reports', []))} reports")
            print(f"Stats: {data.get('stats', {})}")
            return data
        else:
            print(f"Error: {response.text}")
            return None
            
    except Exception as e:
        print(f"Error testing admin reports: {e}")
        return None

def test_health_check():
    """Test the health check endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"GET /: {response.status_code}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error testing health check: {e}")
        return False

if __name__ == "__main__":
    print("Testing admin endpoints...")
    
    # Test health check first
    if test_health_check():
        print("✅ Server is running")
        
        # Test admin reports
        reports = test_admin_reports()
        if reports is not None:
            print("✅ Admin reports endpoint working")
        else:
            print("❌ Admin reports endpoint failed")
    else:
        print("❌ Server is not running or not accessible")
        print("Make sure to start the Flask server first:")
        print("cd fake-apk-ml && python flask_app/main.py")
