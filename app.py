import streamlit as st
import pandas as pd
import joblib
import tempfile
import os
from androguard.core.apk import APK

st.set_page_config(page_title="APKGuard Scanner", page_icon="🛡️", layout="wide")

@st.cache_resource
def load_models():
    if not os.path.exists("apkguard_models.pkl"):
        return None, None
    artifacts = joblib.load("apkguard_models.pkl")
    features = artifacts.pop("features")
    return artifacts, features

models_dict, model_features = load_models()

def parse_apk_permissions(apk_bytes):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        tmp.write(apk_bytes)
        tmp_path = tmp.name
    try:
        apk = APK(tmp_path)
        return apk.get_permissions(), apk.get_package(), apk.get_app_name()
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

st.title("🛡️ APKGuard: Static Malware Analyzer")
st.markdown("---")

if not models_dict:
    st.error("Missing `apkguard_models.pkl`. Ensure it is in the repository.")
    st.stop()

# Sidebar Configuration
st.sidebar.header("Scanner Configuration")
selected_model_name = st.sidebar.selectbox("Select Inference Model", list(models_dict.keys()))
active_model = models_dict[selected_model_name]

uploaded_file = st.sidebar.file_uploader("Upload an Android APK", type=["apk"])

if uploaded_file:
    with st.spinner("Decompiling APK and extracting permissions..."):
        permissions, pkg_name, app_name = parse_apk_permissions(uploaded_file.read())
        
        # Build 86-feature vector
        vector = {feat: (1 if feat in permissions else 0) for feat in model_features}
        X_input = pd.DataFrame([vector])
        
        # Inference
        malware_prob = active_model.predict_proba(X_input)[0, 1]
        is_malware = malware_prob >= 0.5

    # Top Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("App Name", app_name)
    col2.metric("Package", pkg_name)
    col3.metric("Permissions Matched", int(X_input.sum(axis=1).iloc[0]))

    # Risk Dashboard
    st.markdown("### Risk Evaluation")
    if is_malware:
        st.error(f"🚨 **MALWARE THREAT DETECTED** (Confidence: {malware_prob*100:.2f}%)")
    else:
        st.success(f"✅ **BENIGN APPLICATION** (Confidence: {(1-malware_prob)*100:.2f}%)")
    
    st.progress(float(malware_prob))
    st.caption(f"**Active Model:** {selected_model_name}")

    # Detailed Audit
    with st.expander("View Full Permission Audit"):
        audit_df = pd.DataFrame([
            {"Permission": feat, "Status": "🚩 Triggered" if feat in permissions else "Clean"}
            for feat in model_features
        ])
        st.dataframe(audit_df, use_container_width=True)
else:
    st.info("Upload an APK file in the sidebar to begin analysis.")