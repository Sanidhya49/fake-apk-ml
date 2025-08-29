import io
import os
import concurrent.futures as cf
import requests
import pandas as pd
import streamlit as st


st.set_page_config(page_title="APK Risk Scanner", layout="wide")
st.title("APK Risk Scanner (Static ML)")

api_url = st.text_input("API URL", value=os.environ.get("ML_SERVICE_URL", "http://localhost:9000"))
quick = st.checkbox("Quick mode (manifest + cert only)", value=False, help="Faster but fewer signals")

uploaded = st.file_uploader("Upload APKs (.apk/.apks/.xapk)", type=["apk","apks","xapk"], accept_multiple_files=True)

def scan_one(file_obj):
    files = {"file": (file_obj.name, file_obj.getvalue())}
    r = requests.post(f"{api_url}/scan", params={"quick": str(quick).lower()}, files=files, timeout=600)
    r.raise_for_status()
    j = r.json()
    j["file_name"] = file_obj.name
    return j

if st.button("Scan") and uploaded:
    with st.spinner("Scanning..."):
        rows = []
        with cf.ThreadPoolExecutor(max_workers=min(10, len(uploaded))) as ex:
            futs = [ex.submit(scan_one, f) for f in uploaded]
            for fut in cf.as_completed(futs):
                try:
                    rows.append(fut.result())
                except Exception as e:
                    rows.append({"file_name": "<error>", "prediction": "error", "probability": 0.0, "risk": "", "error": str(e)})
        df = pd.DataFrame(rows)
        st.subheader("Results")
        st.dataframe(df[[c for c in df.columns if c not in ("feature_vector","top_shap")]], use_container_width=True)

        # Download CSV
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download CSV", data=csv, file_name="scan_results.csv", mime="text/csv")

        # Download Excel
        from pandas import ExcelWriter
        buf = io.BytesIO()
        with ExcelWriter(buf, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name="scans")
        st.download_button("Download Excel", data=buf.getvalue(), file_name="scan_results.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

st.markdown("""
Tips:
- Start the API: `uvicorn ml.infer_service:app --host 0.0.0.0 --port 9000`
- For the most complete features, leave quick mode off.
""")



