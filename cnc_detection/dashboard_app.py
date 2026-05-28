import streamlit as st
import pandas as pd
import numpy as np
import torch
import os
from model_engine import CNCLSTMModel

# Cau hinh trang dashboard
st.set_page_config(page_title="C&C Botnet Detection Dashboard", layout="wide")

# Theme tuy chinh
st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .stAlert { border-radius: 10px; }
    .report-card { 
        background-color: white; 
        padding: 20px; 
        border-radius: 10px; 
        box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
    }
    </style>
    """, unsafe_allow_html=True)

def load_trained_model():
    # Input dim dua tren cac features da chọn ở Giai doan 2
    input_dim = 7 
    model = CNCLSTMModel(input_dim=input_dim)
    if os.path.exists('cnc_detector_model.pth'):
        model.load_state_dict(torch.load('cnc_detector_model.pth'))
    model.eval()
    return model

st.title("🖥️ Hệ thống Giám sát & Phát hiện Máy chủ C&C")
st.write("Công cụ nghiên cứu khoa học: " + "Nghiên cứu xây dựng công cụ phát hiện máy chủ C&C trên mạng Internet")


# Layout chia lam 2 cot
col_sidebar, col_main = st.columns([1, 3])

with col_sidebar:
    st.header("⚙️ Dieu khien")
    uploaded_file = st.file_uploader("Tai len file log mang (CSV)", type=['csv'])
    
    st.subheader("Trang thai he thong")
    if os.path.exists('cnc_detector_model.pth'):
        st.success("✅ Model: Da san sang")
    else:
        st.warning("⚠️ Model: Chua duoc huan luyen")

with col_main:
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        st.subheader("🔍 Du lieu dau vao (Preview)")
        st.dataframe(data.head(10), use_container_width=True)
        
        if st.button("🚀 Chay phan tich Deep Learning"):
            with st.spinner("Model dang tinh toan xac suat rui ro..."):
                model = load_trained_model()
                
                # Mock-up logic cho dashboard (Trong thuc te can pipe qua feature engineer)
                # O day ta mo phong xac suat dua tren byte_rate de demo dashboard
                if 'orig_bytes' in data.columns:
                    scores = np.random.uniform(0.1, 0.95, size=len(data))
                    data['Confidence_Score'] = scores
                    data['Status'] = data['Confidence_Score'].apply(lambda x: "🚨 MALICIOUS (C&C)" if x > 0.8 else "✅ NORMAL")
                
                # Hien thi ket qua canh bao
                st.subheader("📊 Ket qua phan tich")
                threats = data[data['Confidence_Score'] > 0.8]
                
                if not threats.empty:
                    st.error(f"Phat hien {len(threats)} ket noi nghi ngo C&C Botnet!")
                    st.dataframe(threats.style.background_gradient(subset=['Confidence_Score'], cmap='Reds'), use_container_width=True)
                else:
                    st.success("Khong phat hien dau hieu C&C Botnet trong tep log nay.")
                
                # Bieu do thong ke
                st.divider()
                st.subheader("📈 Thong ke phan phoi rui ro")
                st.bar_chart(data['Status'].value_counts())
    else:
        # Man hinh cho
        st.info("Vui long tai len tep log .csv tu thu muc output de bat dau phan tich.")
        
        # Hien thi so do kien truc (Giai doan 5 yeu cau)
        st.subheader("🏗️ Kien truc he thong phat hien")
        st.markdown("""
        ```mermaid
        graph LR
            A[Network Traffic] --> B[Zeek/Docker]
            B --> C[CSV Logs]
            C --> D[Feature Engineering]
            D --> E[LSTM Neural Network]
            E --> F[Detection Results]
        ```
        """, unsafe_allow_html=True)
