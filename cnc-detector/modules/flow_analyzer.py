"""
==============================================================================
 C&C SERVER DETECTION TOOL - Module: XGBoost Flow Analyzer
 Mô tả: Phân tích hành vi mạng theo luồng (Flow-based) bằng XGBoost.
         Phát hiện beaconing, các kết nối bất thường từ mã độc.
==============================================================================
"""
import numpy as np
import pandas as pd
import joblib
import os
from pathlib import Path

# --- Định nghĩa đặc trưng (Feature names) khớp với CIC-IDS2017 ---
FLOW_FEATURES = [
    'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
    'fwd_packet_length_mean', 'bwd_packet_length_mean',
    'flow_bytes_per_sec', 'flow_packets_per_sec',
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
    'fwd_iat_mean', 'fwd_iat_std', 'bwd_iat_mean',
    'fwd_psh_flags', 'bwd_psh_flags',
    'fwd_header_length', 'bwd_header_length',
    'fwd_packets_per_sec', 'bwd_packets_per_sec',
    'min_packet_length', 'max_packet_length',
    'packet_length_mean', 'packet_length_std', 'packet_length_variance',
    'fin_flag_count', 'syn_flag_count', 'rst_flag_count',
    'ack_flag_count', 'urg_flag_count',
    'avg_fwd_segment_size', 'avg_bwd_segment_size',
    'active_mean', 'idle_mean',
]

MODEL_PATH = Path(__file__).parent.parent / "models" / "xgboost_flow_model.joblib"
SCALER_PATH = Path(__file__).parent.parent / "models" / "flow_scaler.joblib"


class FlowAnalyzer:
    """
    Phân tích luồng mạng bằng mô hình XGBoost đã được huấn luyện trên
    bộ dữ liệu CIC-IDS2017 (tập Botnet).
    """

    RISK_LABELS = {0: "BENIGN", 1: "C&C BOTNET"}
    RISK_COLORS = {0: "#2ecc71", 1: "#e74c3c"}

    def __init__(self):
        self.model = None
        self.scaler = None
        self._loaded = False

    def load(self):
        """Tải mô hình XGBoost từ file."""
        if self._loaded:
            return True
        try:
            if MODEL_PATH.exists() and SCALER_PATH.exists():
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                self._loaded = True
                return True
            else:
                # Tạo mô hình demo nếu chưa có
                self._create_demo_model()
                return True
        except Exception as e:
            print(f"[FlowAnalyzer] Lỗi tải mô hình: {e}")
            self._create_demo_model()
            return True

    def _create_demo_model(self):
        """
        Tạo mô hình XGBoost demo với các tham số giả lập.
        Trong thực tế, mô hình này được huấn luyện trên CIC-IDS2017.
        """
        try:
            from xgboost import XGBClassifier
            from sklearn.preprocessing import StandardScaler

            # Tạo dữ liệu huấn luyện giả lập mô phỏng đặc trưng C&C
            np.random.seed(42)
            n_benign = 1000
            n_malicious = 200  # mất cân bằng dữ liệu thực tế

            # Đặc trưng của lưu lượng sạch (benign)
            benign = np.random.randn(n_benign, len(FLOW_FEATURES))
            benign[:, 0] = np.abs(np.random.normal(50000, 20000, n_benign))  # flow_duration biến thiên
            benign[:, 7] = np.abs(np.random.normal(100, 80, n_benign))        # IAT mean
            benign[:, 32] = np.abs(np.random.normal(500, 200, n_benign))      # active_mean cao
            benign[:, 33] = np.abs(np.random.normal(150, 50, n_benign))       # idle_mean thấp

            # Đặc trưng của C&C (beaconing - IAT cực kỳ đều đặn, payload nhỏ)
            malicious = np.random.randn(n_malicious, len(FLOW_FEATURES)) * 0.3
            malicious[:, 0] = np.abs(np.random.normal(300000, 5000, n_malicious))   # Beaconing interval đều
            malicious[:, 7] = np.abs(np.random.normal(60000, 500, n_malicious))     # IAT mean rất đều
            malicious[:, 8] = np.abs(np.random.normal(100, 20, n_malicious))        # IAT std rất nhỏ
            malicious[:, 1] = np.abs(np.random.normal(5, 2, n_malicious))           # Ít packet
            malicious[:, 2] = np.abs(np.random.normal(3, 1, n_malicious))           # Ít bwd packet
            malicious[:, 32] = np.abs(np.random.normal(10, 5, n_malicious))         # active_mean cực thấp (chỉ gửi ping nhỏ)
            malicious[:, 33] = np.abs(np.random.normal(60000, 1000, n_malicious))   # idle_mean cực cao (thời gian ngủ đông)

            X = np.vstack([benign, malicious])
            y = np.array([0] * n_benign + [1] * n_malicious)

            # StandardScaler
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)

            # Huấn luyện XGBoost với scale_pos_weight để xử lý mất cân bằng
            self.model = XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                scale_pos_weight=n_benign / n_malicious,
                eval_metric='logloss',
                random_state=42,
                verbosity=0
            )
            self.model.fit(X_scaled, y)

            # Lưu mô hình
            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.model, MODEL_PATH)
            joblib.dump(self.scaler, SCALER_PATH)
            self._loaded = True
            print("[FlowAnalyzer] Đã tạo và lưu mô hình demo XGBoost.")
        except Exception as e:
            print(f"[FlowAnalyzer] Lỗi tạo mô hình demo: {e}")

    def predict(self, flow_features: dict) -> dict:
        """
        Dự đoán luồng mạng là BENIGN hay C&C.
        
        Args:
            flow_features: dict chứa các đặc trưng của luồng mạng
            
        Returns:
            dict với label, confidence, risk_score, feature_importance
        """
        if not self._loaded:
            self.load()

        try:
            # Tạo vector đặc trưng
            feat_vector = []
            for feat in FLOW_FEATURES:
                feat_vector.append(flow_features.get(feat, 0.0))

            X = np.array(feat_vector).reshape(1, -1)
            X_scaled = self.scaler.transform(X)

            # Dự đoán
            proba = self.model.predict_proba(X_scaled)[0]
            pred_class = int(np.argmax(proba))
            confidence = float(proba[pred_class])

            # Tính risk score (0-100)
            risk_score = float(proba[1]) * 100  # xác suất thuộc lớp malicious

            # Feature importance top 5
            importances = self.model.feature_importances_
            top_idx = np.argsort(importances)[::-1][:5]
            top_features = [
                {"feature": FLOW_FEATURES[i], "importance": float(importances[i])}
                for i in top_idx
            ]

            return {
                "label": self.RISK_LABELS[pred_class],
                "confidence": confidence,
                "risk_score": risk_score,
                "top_features": top_features,
                "probabilities": {
                    "benign": float(proba[0]),
                    "malicious": float(proba[1])
                }
            }

        except Exception as e:
            return {
                "label": "ERROR",
                "confidence": 0.0,
                "risk_score": 0.0,
                "top_features": [],
                "error": str(e)
            }

    def analyze_beaconing(self, intervals: list) -> dict:
        """
        Phát hiện beaconing dựa trên tính đều đặn của khoảng thời gian.
        Beaconing = mã độc giao tiếp định kỳ với C&C.
        """
        if len(intervals) < 3:
            return {"is_beaconing": False, "regularity_score": 0.0}

        arr = np.array(intervals)
        mean_interval = np.mean(arr)
        std_interval = np.std(arr)
        cv = std_interval / mean_interval if mean_interval > 0 else 1.0  # Coefficient of Variation

        # CV nhỏ = khoảng thời gian rất đều = beaconing
        is_beaconing = cv < 0.3
        regularity_score = max(0, (1 - cv)) * 100

        return {
            "is_beaconing": is_beaconing,
            "regularity_score": regularity_score,
            "mean_interval_sec": mean_interval / 1000,
            "std_interval_sec": std_interval / 1000,
            "coefficient_of_variation": cv,
            "sample_count": len(intervals)
        }

    def get_feature_importance_data(self) -> dict:
        """Trả về dữ liệu feature importance để vẽ biểu đồ."""
        if not self._loaded or self.model is None:
            return {}
        importances = self.model.feature_importances_
        return dict(zip(FLOW_FEATURES, importances.tolist()))
