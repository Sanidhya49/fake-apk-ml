# 🎨 Frontend Integration Guide for Digital Rakshak Prevention Features

## 🚀 New API Endpoints to Integrate

### 1. **Threat Feed Status** (GET)
```javascript
// Get current threat feed statistics
const getThreatFeed = async () => {
  const response = await fetch('/threat-feed');
  const data = await response.json();
  return data.feed; // { hash_count, package_count, cert_fingerprint_count, last_updated }
};
```

### 2. **Submit Threat Intelligence** (POST)
```javascript
// Submit new threat indicators
const submitThreatIntel = async (hashes, packages, certs) => {
  const response = await fetch('/threat/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      hashes: hashes || [],
      packages: packages || [],
      cert_fingerprints: certs || []
    })
  });
  return response.json();
};
```

### 3. **Report Abuse** (POST)
```javascript
// Report malicious APK with evidence bundle
const reportAbuse = async (file, reporterEmail, reporterName, notes) => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('reporter_email', reporterEmail);
  formData.append('reporter_name', reporterName);
  formData.append('additional_notes', notes);
  
  const response = await fetch('/report-abuse', {
    method: 'POST',
    body: formData
  });
  return response.json();
};
```

## 🎯 Frontend UI Components to Add

### 1. **Threat Feed Dashboard**
```html
<div class="threat-feed-dashboard">
  <h3>🛡️ Threat Intelligence Feed</h3>
  <div class="feed-stats">
    <div class="stat">
      <span class="number" id="hash-count">0</span>
      <span class="label">Known Bad Hashes</span>
    </div>
    <div class="stat">
      <span class="number" id="package-count">0</span>
      <span class="label">Malicious Packages</span>
    </div>
    <div class="stat">
      <span class="number" id="cert-count">0</span>
      <span class="label">Bad Certificates</span>
    </div>
  </div>
  <div class="last-updated">
    Last Updated: <span id="last-updated">Never</span>
  </div>
</div>
```

### 2. **Abuse Reporting Form**
```html
<div class="abuse-report-form">
  <h3>🚨 Report Malicious APK</h3>
  <form id="abuse-report-form">
    <div class="form-group">
      <label>APK File:</label>
      <input type="file" id="abuse-file" accept=".apk,.apks,.xapk" required>
    </div>
    <div class="form-group">
      <label>Your Email:</label>
      <input type="email" id="reporter-email" required>
    </div>
    <div class="form-group">
      <label>Your Name:</label>
      <input type="text" id="reporter-name" required>
    </div>
    <div class="form-group">
      <label>Additional Notes:</label>
      <textarea id="additional-notes" rows="3"></textarea>
    </div>
    <button type="submit">Submit Abuse Report</button>
  </form>
</div>
```

### 3. **Enhanced Scan Results**
```html
<div class="scan-result-enhanced">
  <!-- Existing scan result display -->
  
  <!-- New: Threat Feed Match Indicator -->
  <div class="threat-feed-match" id="threat-match" style="display: none;">
    <div class="alert alert-danger">
      <h4>🚨 KNOWN MALICIOUS APK DETECTED!</h4>
      <p>This APK matches a known bad indicator in our threat feed.</p>
      <div class="match-details">
        <strong>Match Type:</strong> <span id="match-type"></span><br>
        <strong>Indicator:</strong> <span id="match-value"></span>
      </div>
    </div>
  </div>
  
  <!-- New: Report Abuse Button -->
  <div class="action-buttons">
    <button class="btn btn-danger" id="report-abuse-btn">
      🚨 Report This APK
    </button>
  </div>
</div>
```

## 🔧 JavaScript Integration

### **Update Scan Result Handler**
```javascript
// Update your existing scan result handler
const handleScanResult = (result) => {
  // Existing result display code...
  
  // NEW: Check for threat feed match
  if (result.threat_feed_match && result.threat_feed_match.match) {
    document.getElementById('threat-match').style.display = 'block';
    document.getElementById('match-type').textContent = result.threat_feed_match.type;
    document.getElementById('match-value').textContent = result.threat_feed_match.value;
  }
  
  // NEW: Show report button for high-risk APKs
  if (result.prediction === 'fake' || result.probability > 0.7) {
    document.getElementById('report-abuse-btn').style.display = 'block';
  }
};
```

### **Threat Feed Status Update**
```javascript
// Update threat feed status periodically
const updateThreatFeedStatus = async () => {
  try {
    const feed = await getThreatFeed();
    document.getElementById('hash-count').textContent = feed.hash_count;
    document.getElementById('package-count').textContent = feed.package_count;
    document.getElementById('cert-count').textContent = feed.cert_fingerprint_count;
    
    const lastUpdated = new Date(feed.last_updated * 1000);
    document.getElementById('last-updated').textContent = lastUpdated.toLocaleString();
  } catch (error) {
    console.error('Failed to update threat feed status:', error);
  }
};

// Update every 30 seconds
setInterval(updateThreatFeedStatus, 30000);
```

### **Abuse Report Handler**
```javascript
// Handle abuse report submission
document.getElementById('abuse-report-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const file = document.getElementById('abuse-file').files[0];
  const email = document.getElementById('reporter-email').value;
  const name = document.getElementById('reporter-name').value;
  const notes = document.getElementById('additional-notes').value;
  
  try {
    const result = await reportAbuse(file, email, name, notes);
    
    if (result.status === 'success') {
      alert('✅ Abuse report submitted successfully!');
      
      // Show evidence bundle details
      if (result.evidence_bundle) {
        const bundle = result.evidence_bundle;
        console.log('Evidence Bundle:', bundle);
        
        // You can display STIX pattern, email template, etc.
        showEvidenceBundle(bundle);
      }
      
      // Update threat feed status
      updateThreatFeedStatus();
    } else {
      alert('❌ Failed to submit abuse report: ' + result.detail);
    }
  } catch (error) {
    alert('❌ Error submitting abuse report: ' + error.message);
  }
});
```

## 🎨 CSS Styling

```css
.threat-feed-dashboard {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 20px;
  border-radius: 10px;
  margin: 20px 0;
}

.feed-stats {
  display: flex;
  justify-content: space-around;
  margin: 20px 0;
}

.stat {
  text-align: center;
}

.stat .number {
  display: block;
  font-size: 2em;
  font-weight: bold;
}

.threat-feed-match {
  background: #ff4444;
  color: white;
  padding: 15px;
  border-radius: 5px;
  margin: 10px 0;
}

.abuse-report-form {
  background: #f8f9fa;
  padding: 20px;
  border-radius: 10px;
  margin: 20px 0;
}

.form-group {
  margin: 15px 0;
}

.form-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: bold;
}

.form-group input,
.form-group textarea {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
}

.btn {
  padding: 10px 20px;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  font-weight: bold;
}

.btn-danger {
  background: #dc3545;
  color: white;
}

.btn-danger:hover {
  background: #c82333;
}
```

## 🔄 Integration Steps

1. **Add new API functions** to your existing JavaScript
2. **Update scan result display** to show threat feed matches
3. **Add threat feed dashboard** to your main page
4. **Add abuse reporting form** (can be in a modal or separate page)
5. **Update CSS** with the new styling
6. **Test integration** with your existing scan workflow

## 🎯 User Experience Flow

1. **User uploads APK** → Normal scan process
2. **If threat feed match** → Show prominent warning + report button
3. **If high risk** → Show report button
4. **User clicks report** → Open abuse report form
5. **Form submission** → Generate evidence bundle + update threat feed
6. **Dashboard updates** → Show new threat indicators

This creates a seamless prevention workflow that goes beyond just detection!
