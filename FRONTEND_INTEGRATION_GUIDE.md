# Frontend Integration Guide

Complete guide for integrating the Fake APK Detection API into your frontend application.

## 🚀 API Base URL

```
https://fake-apk-ml-api01.onrender.com
```

## 📋 Available Endpoints

### 1. Health Check
```http
GET /
```

### 2. Single APK Scan
```http
POST /scan
```

### 3. Batch APK Scan (Up to 15 files)
```http
POST /scan-batch
```

### 4. Word Document Report Generation
```http
POST /report-batch
```

## 🎯 Frontend Implementation Examples

### React.js Example

```jsx
import React, { useState } from 'react';

const APKScanner = () => {
  const [files, setFiles] = useState([]);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleFileChange = (e) => {
    setFiles(Array.from(e.target.files));
  };

  const scanSingleAPK = async (file) => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('https://fake-apk-ml-api01.onrender.com/scan', {
      method: 'POST',
      body: formData
    });

    return await response.json();
  };

  const scanBatchAPKs = async () => {
    if (files.length > 15) {
      alert('Maximum 15 files allowed');
      return;
    }

    setLoading(true);
    const formData = new FormData();
    
    files.forEach(file => {
      formData.append('files', file);
    });

    try {
      const response = await fetch('https://fake-apk-ml-api01.onrender.com/scan-batch', {
        method: 'POST',
        body: formData
      });

      const result = await response.json();
      setResults(result);
    } catch (error) {
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateWordReport = async () => {
    if (files.length > 15) {
      alert('Maximum 15 files allowed');
      return;
    }

    setLoading(true);
    const formData = new FormData();
    
    files.forEach(file => {
      formData.append('files', file);
    });

    try {
      const response = await fetch('https://fake-apk-ml-api01.onrender.com/report-batch', {
        method: 'POST',
        body: formData
      });

      const result = await response.json();
      
      if (result.summary.report_generated) {
        // Handle Word document download or email
        alert('Word report generated successfully!');
      }
    } catch (error) {
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <input 
        type="file" 
        multiple 
        accept=".apk" 
        onChange={handleFileChange}
      />
      
      <button onClick={scanBatchAPKs} disabled={loading}>
        {loading ? 'Scanning...' : `Scan ${files.length} APKs`}
      </button>
      
      <button onClick={generateWordReport} disabled={loading}>
        Generate Word Report
      </button>

      {results && (
        <div>
          <h3>Results:</h3>
          {results.results.map((result, index) => (
            <div key={index}>
              <p>File: {result.file}</p>
              <p>Prediction: {result.prediction}</p>
              <p>Risk Level: {result.risk_level}</p>
              <p>Confidence: {result.confidence}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
```

### Vanilla JavaScript Example

```javascript
class APKScanner {
  constructor() {
    this.apiUrl = 'https://fake-apk-ml-api01.onrender.com';
  }

  async scanSingleAPK(file) {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${this.apiUrl}/scan`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Scan failed:', error);
      throw error;
    }
  }

  async scanBatchAPKs(files) {
    if (files.length > 15) {
      throw new Error('Maximum 15 files allowed');
    }

    const formData = new FormData();
    files.forEach(file => {
      formData.append('files', file);
    });

    try {
      const response = await fetch(`${this.apiUrl}/scan-batch`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Batch scan failed:', error);
      throw error;
    }
  }

  async generateWordReport(files) {
    if (files.length > 15) {
      throw new Error('Maximum 15 files allowed');
    }

    const formData = new FormData();
    files.forEach(file => {
      formData.append('files', file);
    });

    try {
      const response = await fetch(`${this.apiUrl}/report-batch`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Report generation failed:', error);
      throw error;
    }
  }
}

// Usage
const scanner = new APKScanner();

// Single APK scan
document.getElementById('singleFile').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  try {
    const result = await scanner.scanSingleAPK(file);
    console.log('Single scan result:', result);
  } catch (error) {
    console.error('Error:', error);
  }
});

// Batch APK scan
document.getElementById('batchFiles').addEventListener('change', async (e) => {
  const files = Array.from(e.target.files);
  try {
    const result = await scanner.scanBatchAPKs(files);
    console.log('Batch scan result:', result);
  } catch (error) {
    console.error('Error:', error);
  }
});
```

### Vue.js Example

```vue
<template>
  <div>
    <input 
      type="file" 
      multiple 
      accept=".apk" 
      @change="handleFileChange"
    />
    
    <button @click="scanBatch" :disabled="loading">
      {{ loading ? 'Scanning...' : `Scan ${files.length} APKs` }}
    </button>
    
    <button @click="generateReport" :disabled="loading">
      Generate Word Report
    </button>

    <div v-if="results">
      <h3>Results:</h3>
      <div v-for="(result, index) in results.results" :key="index">
        <div :class="getRiskClass(result.risk_level)">
          <h4>{{ result.file }}</h4>
          <p>Prediction: {{ result.prediction }}</p>
          <p>Risk Level: {{ result.risk_level }}</p>
          <p>Confidence: {{ result.confidence }}</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      files: [],
      results: null,
      loading: false
    };
  },
  methods: {
    handleFileChange(event) {
      this.files = Array.from(event.target.files);
    },
    
    async scanBatch() {
      if (this.files.length > 15) {
        alert('Maximum 15 files allowed');
        return;
      }

      this.loading = true;
      const formData = new FormData();
      
      this.files.forEach(file => {
        formData.append('files', file);
      });

      try {
        const response = await fetch('https://fake-apk-ml-api01.onrender.com/scan-batch', {
          method: 'POST',
          body: formData
        });

        this.results = await response.json();
      } catch (error) {
        console.error('Error:', error);
      } finally {
        this.loading = false;
      }
    },

    async generateReport() {
      if (this.files.length > 15) {
        alert('Maximum 15 files allowed');
        return;
      }

      this.loading = true;
      const formData = new FormData();
      
      this.files.forEach(file => {
        formData.append('files', file);
      });

      try {
        const response = await fetch('https://fake-apk-ml-api01.onrender.com/report-batch', {
          method: 'POST',
          body: formData
        });

        const result = await response.json();
        
        if (result.summary.report_generated) {
          alert('Word report generated successfully!');
        }
      } catch (error) {
        console.error('Error:', error);
      } finally {
        this.loading = false;
      }
    },

    getRiskClass(riskLevel) {
      return {
        'risk-red': riskLevel === 'Red',
        'risk-amber': riskLevel === 'Amber',
        'risk-green': riskLevel === 'Green'
      };
    }
  }
};
</script>

<style scoped>
.risk-red {
  border-left: 4px solid #dc3545;
  padding: 10px;
  margin: 10px 0;
  background-color: #f8d7da;
}

.risk-amber {
  border-left: 4px solid #ffc107;
  padding: 10px;
  margin: 10px 0;
  background-color: #fff3cd;
}

.risk-green {
  border-left: 4px solid #28a745;
  padding: 10px;
  margin: 10px 0;
  background-color: #d4edda;
}
</style>
```

## 📊 Response Format

### Single APK Scan Response
```json
{
  "prediction": "legit",
  "probability": 0.374,
  "risk_level": "Green",
  "confidence": "Medium",
  "top_shap": [
    {
      "feature": "pkg_official",
      "value": 1.0
    }
  ],
  "feature_vector": {
    "pkg_official": 1,
    "impersonation_score": 0.0
  },
  "debug": {
    "model_threshold": 0.385,
    "processing_time_seconds": 0.3,
    "cache_used": false
  }
}
```

### Batch Scan Response
```json
{
  "results": [
    {
      "file": "app1.apk",
      "prediction": "legit",
      "probability": 0.25,
      "risk_level": "Green",
      "confidence": "High"
    },
    {
      "file": "app2.apk",
      "prediction": "fake",
      "probability": 0.85,
      "risk_level": "Red",
      "confidence": "High"
    }
  ],
  "summary": {
    "total_files": 2,
    "processing_time_seconds": 1.2,
    "files_per_second": 1.67,
    "max_files_allowed": 15
  }
}
```

### Word Report Response
```json
{
  "results": [...],
  "summary": {
    "total_files": 5,
    "report_generated": true
  },
  "word_report": "artifacts/batch_report.docx"
}
```

## 🎨 UI/UX Best Practices

### File Upload
- **File Type Validation**: Only accept `.apk` files
- **File Size Limits**: Show warning for files > 100MB
- **Multiple File Support**: Allow drag-and-drop for batch uploads
- **Progress Indicators**: Show upload and processing progress

### Results Display
- **Risk Level Colors**: 
  - Red: High risk (probability ≥ 0.8)
  - Amber: Medium risk (probability ≥ 0.385)
  - Green: Low risk (probability < 0.385)
- **Confidence Indicators**: Show confidence level (High/Medium/Low)
- **AI Explanations**: Display why the APK was classified as fake/legit
- **Feature Details**: Show top contributing features

### Error Handling
- **Network Errors**: Retry mechanism for failed requests
- **File Validation**: Clear error messages for invalid files
- **Rate Limiting**: Handle 429 responses gracefully
- **Server Errors**: User-friendly error messages

### Performance Optimization
- **Caching**: Cache results for previously scanned files
- **Lazy Loading**: Load results progressively for large batches
- **Background Processing**: Process files in background for better UX

## 🔒 Security Considerations

### File Upload Security
- **File Type Validation**: Server-side validation of APK files
- **File Size Limits**: Prevent large file uploads
- **Virus Scanning**: Consider scanning uploaded files
- **Temporary Storage**: Clean up temporary files

### API Security
- **HTTPS Only**: Always use HTTPS for API calls
- **CORS Configuration**: Configure CORS for your domain
- **Rate Limiting**: Implement client-side rate limiting
- **Error Handling**: Don't expose sensitive information in errors

## 📱 Mobile Considerations

### File Upload
- **Camera Integration**: Allow taking photos of APK files
- **File Picker**: Use native file picker for better UX
- **Offline Support**: Queue uploads when offline

### UI/UX
- **Touch-Friendly**: Large touch targets for mobile
- **Responsive Design**: Adapt layout for different screen sizes
- **Loading States**: Clear loading indicators
- **Error Messages**: Mobile-friendly error displays

## 🧪 Testing

### Unit Testing
```javascript
// Test single APK scan
test('should scan single APK successfully', async () => {
  const file = new File(['test'], 'test.apk', { type: 'application/vnd.android.package-archive' });
  const result = await scanner.scanSingleAPK(file);
  expect(result.prediction).toBeDefined();
});

// Test batch scan
test('should scan multiple APKs successfully', async () => {
  const files = [
    new File(['test1'], 'test1.apk', { type: 'application/vnd.android.package-archive' }),
    new File(['test2'], 'test2.apk', { type: 'application/vnd.android.package-archive' })
  ];
  const result = await scanner.scanBatchAPKs(files);
  expect(result.results).toHaveLength(2);
});
```

### Integration Testing
- Test with real APK files
- Test error scenarios (network errors, invalid files)
- Test performance with large files
- Test batch processing limits

## 🚀 Deployment Checklist

- [ ] Configure CORS for your domain
- [ ] Set up error monitoring
- [ ] Implement rate limiting
- [ ] Add file size validation
- [ ] Test with real APK files
- [ ] Monitor API performance
- [ ] Set up logging and analytics

## 📞 Support

For integration support:
- Check API documentation
- Review error responses
- Test with sample APK files
- Contact the development team

---

**Last Updated**: August 2024  
**API Version**: 2.0.0
