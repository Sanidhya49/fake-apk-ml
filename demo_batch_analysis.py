"""
Demonstration script showing batch APK analysis functionality.

This script shows how to use the Flask API for batch processing of multiple APK files.
It includes examples for both programmatic use and web frontend integration.
"""

import requests
import json
import time
from pathlib import Path

API_BASE_URL = "http://localhost:9000"

def create_sample_apk_files():
    """Create some sample APK files for testing"""
    print("📁 Creating sample APK files for testing...")
    
    sample_files = []
    
    for i in range(3):
        filename = f"sample_app_{i+1}.apk"
        filepath = Path(filename)
        
        # Create a minimal APK-like file (not a real APK, just for API testing)
        content = b'PK\x03\x04' + f'Sample APK content {i+1}'.encode() + b'\x00' * 200
        
        with open(filepath, 'wb') as f:
            f.write(content)
        
        sample_files.append(filepath)
        print(f"  ✓ Created {filename}")
    
    return sample_files

def test_single_analysis(files):
    """Test single file analysis"""
    print("\n🔍 Testing Single File Analysis...")
    
    if not files:
        print("  ❌ No files to test")
        return
    
    test_file = files[0]
    print(f"  📄 Analyzing: {test_file.name}")
    
    try:
        with open(test_file, 'rb') as f:
            files_param = {'file': (test_file.name, f, 'application/vnd.android.package-archive')}
            response = requests.post(f"{API_BASE_URL}/scan", files=files_param, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            print(f"  ✅ Analysis completed:")
            print(f"     Prediction: {result.get('prediction', 'unknown')}")
            print(f"     Probability: {result.get('probability', 0):.3f}")
            print(f"     Risk Level: {result.get('risk', 'unknown')}")
        elif response.status_code == 422:
            error = response.json()
            print(f"  ⚠️  Expected error (invalid APK): {error.get('error', 'unknown')}")
        else:
            print(f"  ❌ Request failed: {response.status_code}")
            print(f"     Response: {response.text}")
            
    except Exception as e:
        print(f"  ❌ Error: {e}")

def test_batch_analysis(files):
    """Test batch file analysis"""
    print(f"\n📚 Testing Batch Analysis ({len(files)} files)...")
    
    if not files:
        print("  ❌ No files to test")
        return
    
    try:
        # Prepare files for batch request
        files_param = []
        file_handles = []
        
        for file_path in files:
            print(f"  📄 Adding to batch: {file_path.name}")
            f = open(file_path, 'rb')
            file_handles.append(f)
            files_param.append(('files', (file_path.name, f, 'application/vnd.android.package-archive')))
        
        print("  🚀 Sending batch request...")
        start_time = time.time()
        
        response = requests.post(f"{API_BASE_URL}/scan-batch", files=files_param, timeout=180)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Close file handles
        for f in file_handles:
            f.close()
        
        if response.status_code == 200:
            result = response.json()
            results = result.get('results', [])
            
            print(f"  ✅ Batch analysis completed in {duration:.2f} seconds")
            print(f"  📊 Results summary:")
            
            for i, file_result in enumerate(results):
                filename = file_result.get('file', f'file_{i+1}')
                
                if 'error' in file_result:
                    print(f"     {filename}: ❌ Error - {file_result['error']}")
                else:
                    pred = file_result.get('prediction', 'unknown')
                    prob = file_result.get('probability', 0)
                    risk = file_result.get('risk', 'unknown')
                    print(f"     {filename}: {pred} ({prob:.3f}, {risk})")
            
            # Statistics
            total_files = len(results)
            successful = len([r for r in results if 'error' not in r])
            errors = total_files - successful
            
            if successful > 0:
                fake_count = len([r for r in results if r.get('prediction') == 'fake'])
                legit_count = len([r for r in results if r.get('prediction') == 'legit'])
                
                print(f"  📈 Statistics:")
                print(f"     Total files: {total_files}")
                print(f"     Successful: {successful}")
                print(f"     Errors: {errors}")
                print(f"     Fake/Malicious: {fake_count}")
                print(f"     Legitimate: {legit_count}")
                print(f"     Avg time per file: {duration/total_files:.2f}s")
        else:
            print(f"  ❌ Batch request failed: {response.status_code}")
            print(f"     Response: {response.text}")
            
    except Exception as e:
        print(f"  ❌ Error: {e}")
    finally:
        # Ensure file handles are closed
        for f in file_handles:
            try:
                f.close()
            except:
                pass

def test_html_report(files):
    """Test HTML report generation"""
    print("\n📋 Testing HTML Report Generation...")
    
    if not files:
        print("  ❌ No files to test")
        return
    
    test_file = files[0]
    print(f"  📄 Generating report for: {test_file.name}")
    
    try:
        with open(test_file, 'rb') as f:
            files_param = {'file': (test_file.name, f, 'application/vnd.android.package-archive')}
            response = requests.post(f"{API_BASE_URL}/report", files=files_param, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            
            if 'html' in result and 'result' in result:
                html_content = result['html']
                analysis_result = result['result']
                
                print(f"  ✅ Report generated successfully")
                print(f"     HTML size: {len(html_content)} characters")
                print(f"     Analysis: {analysis_result.get('prediction', 'unknown')}")
                
                # Save HTML report to file
                report_filename = f"report_{test_file.stem}.html"
                with open(report_filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                print(f"  💾 Report saved as: {report_filename}")
                print(f"     You can open this file in a web browser to view the detailed report")
            else:
                print(f"  ❌ Invalid response format")
        elif response.status_code == 422:
            error = response.json()
            print(f"  ⚠️  Expected error (invalid APK): {error.get('error', 'unknown')}")
        else:
            print(f"  ❌ Request failed: {response.status_code}")
            print(f"     Response: {response.text}")
            
    except Exception as e:
        print(f"  ❌ Error: {e}")

def cleanup_files(files):
    """Clean up test files"""
    print("\n🧹 Cleaning up test files...")
    
    for file_path in files:
        try:
            file_path.unlink()
            print(f"  🗑️  Deleted: {file_path.name}")
        except Exception as e:
            print(f"  ❌ Could not delete {file_path.name}: {e}")
    
    # Also clean up any generated reports
    for report_file in Path(".").glob("report_*.html"):
        try:
            report_file.unlink()
            print(f"  🗑️  Deleted report: {report_file.name}")
        except:
            pass

def show_frontend_integration_example():
    """Show how to integrate batch functionality in the frontend"""
    
    js_example = '''
// JavaScript example for frontend integration

// 1. Single file analysis (existing functionality)
async function analyzeSingleFile(file) {
  try {
    const response = await APKAnalysisService.scanSingle(file);
    console.log('Single analysis result:', response.data);
    return response.data;
  } catch (error) {
    console.error('Single analysis failed:', error);
    throw error;
  }
}

// 2. Batch analysis (new functionality)
async function analyzeBatchFiles(files) {
  try {
    const response = await APKAnalysisService.scanBatch(files);
    console.log('Batch analysis results:', response.data.results);
    
    // Process results
    const results = response.data.results;
    const summary = {
      total: results.length,
      successful: results.filter(r => !r.error).length,
      fake: results.filter(r => r.prediction === 'fake').length,
      legit: results.filter(r => r.prediction === 'legit').length,
      errors: results.filter(r => r.error).length
    };
    
    return { results, summary };
  } catch (error) {
    console.error('Batch analysis failed:', error);
    throw error;
  }
}

// 3. Usage in React component
function BatchAnalysisComponent() {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [results, setResults] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleFilesSelected = (files) => {
    setSelectedFiles(Array.from(files));
  };

  const handleBatchAnalysis = async () => {
    if (selectedFiles.length === 0) return;
    
    setIsAnalyzing(true);
    try {
      const batchResults = await analyzeBatchFiles(selectedFiles);
      setResults(batchResults);
    } catch (error) {
      console.error('Batch analysis error:', error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div>
      <input 
        type="file" 
        multiple 
        accept=".apk" 
        onChange={(e) => handleFilesSelected(e.target.files)}
      />
      
      {selectedFiles.length > 0 && (
        <button 
          onClick={handleBatchAnalysis} 
          disabled={isAnalyzing}
        >
          {isAnalyzing ? 'Analyzing...' : `Analyze ${selectedFiles.length} files`}
        </button>
      )}
      
      {results && (
        <div>
          <h3>Results Summary</h3>
          <p>Total: {results.summary.total}</p>
          <p>Successful: {results.summary.successful}</p>
          <p>Threats detected: {results.summary.fake}</p>
          <p>Safe apps: {results.summary.legit}</p>
          <p>Errors: {results.summary.errors}</p>
        </div>
      )}
    </div>
  );
}
'''
    
    print("\n💻 Frontend Integration Example:")
    print("="*60)
    print(js_example)
    print("="*60)

def main():
    """Main demonstration function"""
    print("🎬 Flask APK Analysis API - Batch Processing Demo")
    print("="*60)
    
    # Check if API is running
    try:
        response = requests.get(f"{API_BASE_URL}/", timeout=5)
        if response.status_code == 200:
            print("✅ Flask API is running and accessible")
        else:
            print(f"❌ Flask API returned status {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Cannot connect to Flask API at {API_BASE_URL}")
        print(f"   Error: {e}")
        print(f"   Make sure to start the Flask server first:")
        print(f"   python flask_app/main.py")
        return
    
    # Create test files
    test_files = create_sample_apk_files()
    
    try:
        # Run tests
        test_single_analysis(test_files)
        test_batch_analysis(test_files)
        test_html_report(test_files)
        
        # Show integration example
        show_frontend_integration_example()
        
        print("\n🎉 Demo completed successfully!")
        print("📝 Key takeaways:")
        print("   • Flask API supports both single and batch analysis")
        print("   • Batch processing is more efficient for multiple files")
        print("   • HTML reports provide detailed analysis results")
        print("   • Frontend integration is straightforward")
        print("   • Error handling works for invalid/malformed APK files")
        
    finally:
        # Clean up
        cleanup_files(test_files)
    
    print("\n🚀 Next steps:")
    print("   1. Try the API with real APK files")
    print("   2. Integrate batch functionality in the frontend")
    print("   3. Customize analysis parameters (quick, debug modes)")
    print("   4. Set up production deployment with proper security")

if __name__ == "__main__":
    main()
