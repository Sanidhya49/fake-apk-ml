import io
import os
import concurrent.futures as cf
import requests
import pandas as pd
import streamlit as st
import json
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Page configuration
st.set_page_config(
    page_title="APK Risk Scanner - Drag & Drop",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .result-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 10px;
        border-left: 4px solid #007bff;
        margin: 1rem 0;
    }
    .risk-high {
        border-left-color: #dc3545 !important;
        background: #f8d7da !important;
    }
    .risk-medium {
        border-left-color: #ffc107 !important;
        background: #fff3cd !important;
    }
    .risk-low {
        border-left-color: #28a745 !important;
        background: #d4edda !important;
    }
    .upload-area {
        border: 2px dashed #007bff;
        border-radius: 10px;
        padding: 2rem;
        text-align: center;
        background: #f8f9fa;
        margin: 1rem 0;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar configuration
with st.sidebar:
    st.title("⚙️ Configuration")
    
    # API Configuration
    st.subheader("API Settings")
    api_url = st.text_input(
        "API URL", 
        value=os.environ.get("ML_SERVICE_URL", "http://localhost:9000"),
        help="URL of the ML inference service"
    )
    
    # Scan Options
    st.subheader("Scan Options")
    quick_mode = st.checkbox(
        "Quick Mode", 
        value=False, 
        help="Faster scan with manifest + certificate only (fewer features)"
    )
    debug_mode = st.checkbox(
        "Debug Mode", 
        value=False, 
        help="Include detailed debug information in results"
    )
    bypass_cache = st.checkbox(
        "Bypass Cache", 
        value=False, 
        help="Force fresh analysis (ignore cached results) - useful for testing"
    )
    
    # Batch Processing
    st.subheader("Batch Processing")
    max_workers = st.slider(
        "Max Concurrent Scans", 
        min_value=1, 
        max_value=10, 
        value=5,
        help="Number of files to scan simultaneously"
    )
    
    # Model Info
    st.subheader("Model Information")
    
    # Get current threshold from environment or API
    try:
        import requests
        model_info_response = requests.get(f"{api_url}/model-info", timeout=5)
        if model_info_response.status_code == 200:
            model_info = model_info_response.json()
            current_threshold = model_info.get('threshold', 0.61)
        else:
            current_threshold = 0.61
    except:
        current_threshold = 0.61
    
    st.info(f"""
    **Model Type:** XGBoost with fallback to RandomForest
    **Features:** Static analysis of APK permissions, APIs, certificates, and domain analysis
    **Threshold:** {current_threshold} (configurable via ML_FAKE_THRESHOLD)
    """)
    
    # Cache bypass info
    if bypass_cache:
        st.warning("⚠️ Cache bypass enabled - files will be analyzed fresh")

# Main content
st.markdown('<div class="main-header"><h1>🔒 APK Risk Scanner - Drag & Drop Interface</h1></div>', unsafe_allow_html=True)

# File upload section with drag and drop styling
st.subheader("📁 Upload APK Files")

# Option to test local files
test_local_files = st.checkbox("Test Local Files", value=False, help="Test files from your data directory")

if test_local_files:
    # Local file selection
    st.subheader("🗂️ Select Local Files")
    
    # Get files from data directory
    data_dirs = ["data/legit", "data/fake"]
    available_files = []
    
    for data_dir in data_dirs:
        if os.path.exists(data_dir):
            for file in os.listdir(data_dir):
                if file.endswith(('.apk', '.apks', '.xapk')):
                    available_files.append(os.path.join(data_dir, file))
    
    if available_files:
        selected_files = st.multiselect(
            "Choose files to test:",
            options=available_files,
            format_func=lambda x: os.path.basename(x),
            help="Select files from your data directory to test"
        )
        
        if selected_files:
            st.info(f"Selected {len(selected_files)} local file(s) for testing")
            
            # Convert local files to file-like objects for processing
            class LocalFileWrapper:
                def __init__(self, file_path):
                    self.name = os.path.basename(file_path)
                    self.path = file_path
                
                def getvalue(self):
                    with open(self.path, 'rb') as f:
                        return f.read()
            
            local_file_objects = [LocalFileWrapper(f) for f in selected_files]
            uploaded_files = local_file_objects
        else:
            uploaded_files = None
    else:
        st.warning("No APK files found in data/legit or data/fake directories")
        uploaded_files = None
else:
    # Regular file upload
    st.markdown("""
    <div class="upload-area">
        <h3>Drag and drop your APK files here</h3>
        <p>Supported formats: .apk, .apks, .xapk</p>
        <p>You can upload multiple files at once</p>
    </div>
    """, unsafe_allow_html=True)

    uploaded_files = st.file_uploader(
        "Choose APK files", 
        type=["apk", "apks", "xapk"], 
        accept_multiple_files=True,
        help="Select one or more APK files to scan"
    )

# Function to scan a single file
def scan_single_file(file_obj):
    """Scan a single APK file and return results"""
    try:
        files = {"file": (file_obj.name, file_obj.getvalue())}
        params = {
            "quick": str(quick_mode).lower(),
            "debug": str(debug_mode).lower(),
            "bypass_cache": str(bypass_cache).lower()
        }
        
        response = requests.post(
            f"{api_url}/scan", 
            params=params, 
            files=files, 
            timeout=600
        )
        response.raise_for_status()
        
        result = response.json()
        result["file_name"] = file_obj.name
        result["file_size"] = len(file_obj.getvalue())
        result["scan_timestamp"] = datetime.now().isoformat()
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            "file_name": file_obj.name,
            "prediction": "error",
            "probability": 0.0,
            "risk": "Error",
            "error": str(e),
            "file_size": len(file_obj.getvalue()),
            "scan_timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "file_name": file_obj.name,
            "prediction": "error", 
            "probability": 0.0,
            "risk": "Error",
            "error": str(e),
            "file_size": len(file_obj.getvalue()),
            "scan_timestamp": datetime.now().isoformat()
        }

# Scan button and processing
if st.button("🚀 Start Scanning", type="primary", use_container_width=True) and uploaded_files:
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Scan files
    results = []
    total_files = len(uploaded_files)
    
    with cf.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {executor.submit(scan_single_file, file): file for file in uploaded_files}
        
        # Process completed tasks
        completed = 0
        for future in cf.as_completed(future_to_file):
            try:
                result = future.result()
                results.append(result)
                completed += 1
                
                # Update progress
                progress = completed / total_files
                progress_bar.progress(progress)
                status_text.text(f"Scanned {completed}/{total_files} files...")
                
            except Exception as e:
                st.error(f"Error processing file: {e}")
                completed += 1
                progress_bar.progress(completed / total_files)
    
    progress_bar.progress(1.0)
    status_text.text("✅ Scanning completed!")
    
    if results:
        # Create DataFrame
        df = pd.DataFrame(results)
        
        # Display summary metrics
        st.subheader("📊 Scan Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_scanned = len(df)
            st.metric("Total Files", total_scanned)
        
        with col2:
            fake_count = len(df[df['prediction'] == 'fake'])
            st.metric("Fake APKs", fake_count, delta=f"{fake_count/total_scanned*100:.1f}%" if total_scanned > 0 else 0)
        
        with col3:
            legit_count = len(df[df['prediction'] == 'legit'])
            st.metric("Legitimate APKs", legit_count, delta=f"{legit_count/total_scanned*100:.1f}%" if total_scanned > 0 else 0)
        
        with col4:
            error_count = len(df[df['prediction'] == 'error'])
            st.metric("Errors", error_count, delta=f"{error_count/total_scanned*100:.1f}%" if total_scanned > 0 else 0)
        
        # Risk distribution chart
        if 'risk' in df.columns and len(df) > 0:
            st.subheader("🎯 Risk Distribution")
            
            risk_counts = df['risk'].value_counts()
            fig = px.pie(
                values=risk_counts.values, 
                names=risk_counts.index, 
                title="Risk Level Distribution",
                color_discrete_map={
                    'Green': '#28a745',
                    'Amber': '#ffc107', 
                    'Red': '#dc3545',
                    'Error': '#6c757d'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Probability distribution
        if 'probability' in df.columns and len(df) > 0:
            st.subheader("📈 Probability Distribution")
            
            # Filter out errors for probability analysis
            prob_df = df[df['prediction'] != 'error'].copy()
            
            if len(prob_df) > 0:
                fig = px.histogram(
                    prob_df, 
                    x='probability',
                    nbins=20,
                    title="Fake Probability Distribution",
                    labels={'probability': 'Probability of being Fake', 'count': 'Number of APKs'}
                )
                
                # Get current threshold for visualization
                try:
                    model_info_response = requests.get(f"{api_url}/model-info", timeout=5)
                    if model_info_response.status_code == 200:
                        model_info = model_info_response.json()
                        viz_threshold = model_info.get('threshold', 0.61)
                    else:
                        viz_threshold = 0.61
                except:
                    viz_threshold = 0.61
                
                fig.add_vline(x=viz_threshold, line_dash="dash", line_color="red", annotation_text=f"Threshold ({viz_threshold})")
                st.plotly_chart(fig, use_container_width=True)
        
        # Detailed results table
        st.subheader("📋 Detailed Results")
        
        # Prepare display columns
        display_columns = ['file_name', 'prediction', 'probability', 'risk']
        if debug_mode and 'top_shap' in df.columns:
            display_columns.append('top_shap')
        
        # Create a styled dataframe
        def color_risk(val):
            if val == 'Red':
                return 'background-color: #f8d7da; color: #721c24'
            elif val == 'Amber':
                return 'background-color: #fff3cd; color: #856404'
            elif val == 'Green':
                return 'background-color: #d4edda; color: #155724'
            return ''
        
        def color_prediction(val):
            if val == 'fake':
                return 'background-color: #f8d7da; color: #721c24; font-weight: bold'
            elif val == 'legit':
                return 'background-color: #d4edda; color: #155724; font-weight: bold'
            return ''
        
        # Display the dataframe with styling
        display_df = df[display_columns].copy()
        
        # Format probability as percentage
        if 'probability' in display_df.columns:
            display_df['probability'] = display_df['probability'].apply(lambda x: f"{x*100:.1f}%" if isinstance(x, (int, float)) else x)
        
        # Apply styling
        styled_df = display_df.style.applymap(color_prediction, subset=['prediction'])
        if 'risk' in display_df.columns:
            styled_df = styled_df.applymap(color_risk, subset=['risk'])
        
        st.dataframe(styled_df, use_container_width=True)
        
        # Individual file details
        st.subheader("🔍 Individual File Details")
        
        for idx, row in df.iterrows():
            risk_class = ""
            if row.get('risk') == 'Red':
                risk_class = "risk-high"
            elif row.get('risk') == 'Amber':
                risk_class = "risk-medium"
            elif row.get('risk') == 'Green':
                risk_class = "risk-low"
            
            with st.expander(f"📱 {row['file_name']} - {row.get('prediction', 'Unknown')} ({row.get('risk', 'Unknown')} Risk)"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**File Name:** {row['file_name']}")
                    st.write(f"**Prediction:** {row.get('prediction', 'Unknown')}")
                    st.write(f"**Risk Level:** {row.get('risk', 'Unknown')}")
                    st.write(f"**Probability:** {row.get('probability', 0)*100:.1f}%" if isinstance(row.get('probability'), (int, float)) else f"**Probability:** {row.get('probability', 'Unknown')}")
                    
                    if 'file_size' in row:
                        file_size_mb = row['file_size'] / (1024 * 1024)
                        st.write(f"**File Size:** {file_size_mb:.2f} MB")
                
                with col2:
                    if 'top_shap' in row and row['top_shap']:
                        st.write("**Top SHAP Contributors:**")
                        try:
                            shap_data = row['top_shap']
                            if isinstance(shap_data, str):
                                shap_data = json.loads(shap_data)
                            
                            for i, (feature, value) in enumerate(shap_data[:5], 1):
                                color = "🔴" if value > 0 else "🟢"
                                st.write(f"{i}. {color} {feature}: {value:.3f}")
                        except:
                            st.write("Unable to parse SHAP data")
                    
                    if 'error' in row and row['error']:
                        st.error(f"**Error:** {row['error']}")
        
        # Download options
        st.subheader("💾 Download Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # CSV Download
            csv_data = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📄 Download CSV",
                data=csv_data,
                file_name=f"apk_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col2:
            # Excel Download
            try:
                from pandas import ExcelWriter
                excel_buffer = io.BytesIO()
                with ExcelWriter(excel_buffer, engine="xlsxwriter") as writer:
                    df.to_excel(writer, index=False, sheet_name="scan_results")
                    # Add summary sheet
                    summary_data = {
                        'Metric': ['Total Files', 'Fake APKs', 'Legitimate APKs', 'Errors', 'Average Probability'],
                        'Value': [
                            len(df),
                            len(df[df['prediction'] == 'fake']),
                            len(df[df['prediction'] == 'legit']),
                            len(df[df['prediction'] == 'error']),
                            f"{df[df['prediction'] != 'error']['probability'].mean()*100:.1f}%" if len(df[df['prediction'] != 'error']) > 0 else "N/A"
                        ]
                    }
                    pd.DataFrame(summary_data).to_excel(writer, index=False, sheet_name="summary")
                
                st.download_button(
                    label="📊 Download Excel",
                    data=excel_buffer.getvalue(),
                    file_name=f"apk_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )
            except ImportError:
                st.warning("ExcelWriter not available. Install xlsxwriter for Excel export.")

# Instructions and tips
with st.expander("ℹ️ Instructions & Tips"):
    st.markdown("""
         ### How to use this scanner:
     
     1. **Start the ML API Service:**
        ```bash
        uvicorn ml.infer_service:app --host 0.0.0.0 --port 9000
        ```
     
     2. **Choose File Source:**
        - **Upload Files:** Drag and drop APK files into the upload area
        - **Test Local Files:** Select files from your data/legit and data/fake directories
        - Supported formats: .apk, .apks, .xapk
        - You can upload/select multiple files at once
     
     3. **Configure Scan Options:**
        - **Quick Mode:** Faster scan with fewer features (manifest + certificate only)
        - **Debug Mode:** Include detailed SHAP explanations and feature vectors
        - **Bypass Cache:** Force fresh analysis (ignore cached results) - useful for testing
        - **Max Concurrent Scans:** Control parallel processing (1-10 files)
    
    4. **Review Results:**
       - Summary metrics and risk distribution
       - Detailed results table with color-coded risk levels
       - Individual file analysis with SHAP explanations
       - Download results in CSV or Excel format
    
    ### Understanding Results:
    
    - **Prediction:** `fake` or `legit` based on ML model
    - **Probability:** Confidence score (0-100%) of being fake
    - **Risk Level:** 
      - 🟢 **Green:** Low risk (legitimate)
      - 🟡 **Amber:** Medium risk (suspicious)
      - 🔴 **Red:** High risk (likely fake)
    
    ### Safety Note:
    This tool performs static analysis only. Handle all APK files with care and do not execute unknown applications.
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🔒 APK Risk Scanner - Static ML Analysis | Built with Streamlit & FastAPI</p>
</div>
""", unsafe_allow_html=True)
