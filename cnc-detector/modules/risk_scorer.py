"""
==============================================================================
 C&C SERVER DETECTION TOOL - Module: Ensemble Risk Scorer
 Mô tả: Tính điểm rủi ro tổng hợp từ tất cả các module phân tích.
         Thuật toán: Weighted Ensemble với các ngưỡng thích ứng.
==============================================================================
"""
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
import time


@dataclass
class AlertRecord:
    """Bản ghi cảnh báo C&C."""
    timestamp: str
    remote_ip: str
    remote_port: int
    domain: str
    process_name: str
    process_pid: int
    risk_score: float
    alert_level: str
    alert_color: str
    flow_score: float
    dga_score: float
    threat_intel_score: float
    process_score: float
    malware_family: str
    details: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)


# Trọng số của từng module (phải tổng = 1.0)
MODULE_WEIGHTS = {
    "flow_behavior": 0.35,      # XGBoost behavioral analysis
    "dga_detection": 0.30,      # Bi-LSTM domain analysis
    "threat_intel": 0.25,       # Threat Intelligence lookup
    "process_anomaly": 0.10,    # Process mapping anomaly
}

# Ngưỡng cảnh báo
ALERT_THRESHOLDS = {
    "CRITICAL": 80,   # Xác suất rất cao là C&C
    "HIGH":     60,   # Xác suất cao
    "MEDIUM":   40,   # Cần theo dõi
    "LOW":      20,   # Nghi ngờ thấp
}

ALERT_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#3498db",
    "SAFE":     "#2ecc71",
}


class RiskScorer:
    """
    Thuật toán tính điểm rủi ro tổng hợp (Ensemble Risk Scoring).
    Kết hợp đầu ra từ 4 module phân tích để đưa ra phán quyết cuối.
    """

    def __init__(self):
        self._alert_history = []
        self._stats = {
            "total_analyzed": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "safe_count": 0,
        }

    def calculate(self,
                  flow_result: dict = None,
                  dga_result: dict = None,
                  threat_intel_result: dict = None,
                  process_flags: list = None,
                  beaconing_result: dict = None,
                  context: dict = None) -> AlertRecord:
        """
        Tính điểm rủi ro tổng hợp từ tất cả các module.
        
        Args:
            flow_result: Kết quả từ FlowAnalyzer (XGBoost)
            dga_result: Kết quả từ DGADetector (Bi-LSTM)
            threat_intel_result: Kết quả từ ThreatIntelligence
            process_flags: Danh sách cờ đáng ngờ từ ProcessMapper
            beaconing_result: Kết quả phân tích beaconing
            context: Thông tin bổ sung (IP, port, domain, process...)
            
        Returns:
            AlertRecord với điểm rủi ro và cấp độ cảnh báo
        """
        context = context or {}
        details = []
        mitre_techniques = []

        # === Module 1: Flow Behavior Score (XGBoost) ===
        flow_score = 0.0
        if flow_result:
            flow_score = flow_result.get("risk_score", 0.0)
            if flow_result.get("label") == "C&C BOTNET":
                details.append(f"🔴 XGBoost: Phát hiện hành vi C&C (score: {flow_score:.1f})")
                mitre_techniques.append("T1071 (Application Layer Protocol)")
            
            # Bonus nếu phát hiện beaconing
            if beaconing_result and beaconing_result.get("is_beaconing"):
                bonus = beaconing_result.get("regularity_score", 0) * 0.2
                flow_score = min(100, flow_score + bonus)
                details.append(f"⏱️ Beaconing: Giao tiếp định kỳ (đều đặn {beaconing_result.get('regularity_score', 0):.0f}%)")
                mitre_techniques.append("T1071.001 (Web Protocols)")

        # === Module 2: DGA Detection Score (Bi-LSTM) ===
        dga_score = 0.0
        if dga_result and not dga_result.get("whitelisted", False):
            dga_score = dga_result.get("final_score", 0.0)
            if dga_result.get("is_dga"):
                details.append(f"🔴 DGA: Tên miền bất thường '{dga_result.get('domain', '')}' (score: {dga_score:.1f})")
                mitre_techniques.append("T1568.002 (Domain Generation Algorithm)")
            elif dga_score > 30:
                details.append(f"🟡 DGA: Tên miền đáng ngờ (score: {dga_score:.1f})")

        # === Module 3: Threat Intelligence Score ===
        threat_score = 0.0
        malware_family = "Unknown"
        if threat_intel_result:
            threat_score = float(threat_intel_result.get("confidence", 0.0))
            if threat_intel_result.get("is_malicious"):
                malware_family = threat_intel_result.get("malware_family", "Unknown")
                sources = ', '.join(threat_intel_result.get("sources", []))
                details.append(f"🔴 Threat Intel: '{malware_family}' từ {sources} (confidence: {threat_score:.0f}%)")
                mitre_techniques.extend(threat_intel_result.get("mitre_techniques", []))
            elif threat_score > 30:
                details.append(f"🟡 Threat Intel: IP đáng ngờ (score: {threat_score:.0f})")

        # === Module 4: Process Anomaly Score ===
        process_score = 0.0
        if process_flags:
            process_score = min(100, len(process_flags) * 25)
            for flag in process_flags:
                details.append(flag)
            if process_flags:
                mitre_techniques.append("T1055 (Process Injection)")

        # === Tính điểm tổng hợp có trọng số (Weighted Ensemble) ===
        raw_score = (
            flow_score * MODULE_WEIGHTS["flow_behavior"] +
            dga_score * MODULE_WEIGHTS["dga_detection"] +
            threat_score * MODULE_WEIGHTS["threat_intel"] +
            process_score * MODULE_WEIGHTS["process_anomaly"]
        )

        # Áp dụng hệ số khuếch đại nếu nhiều module cùng phát hiện (AND logic)
        positive_modules = sum([
            flow_score >= 50,
            dga_score >= 50,
            threat_score >= 50,
            process_score >= 50,
        ])
        if positive_modules >= 3:
            raw_score = min(100, raw_score * 1.4)  # Amplify khi nhiều bằng chứng
        elif positive_modules >= 2:
            raw_score = min(100, raw_score * 1.2)

        # Xác định cấp độ cảnh báo
        alert_level, alert_color = self._get_alert_level(raw_score)

        # Cập nhật thống kê
        self._stats["total_analyzed"] += 1
        self._stats[f"{alert_level.lower()}_count"] = self._stats.get(f"{alert_level.lower()}_count", 0) + 1

        # Tạo AlertRecord
        record = AlertRecord(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            remote_ip=context.get("remote_ip", "N/A"),
            remote_port=context.get("remote_port", 0),
            domain=context.get("domain", "N/A"),
            process_name=context.get("process_name", "N/A"),
            process_pid=context.get("process_pid", -1),
            risk_score=raw_score,
            alert_level=alert_level,
            alert_color=alert_color,
            flow_score=flow_score,
            dga_score=dga_score,
            threat_intel_score=threat_score,
            process_score=process_score,
            malware_family=malware_family,
            details=details,
            mitre_techniques=list(set(mitre_techniques)),
        )

        if alert_level in ("CRITICAL", "HIGH"):
            self._alert_history.append(record)

        return record

    def _get_alert_level(self, score: float) -> tuple:
        """Xác định cấp độ cảnh báo từ điểm số."""
        if score >= ALERT_THRESHOLDS["CRITICAL"]:
            return ("CRITICAL", ALERT_COLORS["CRITICAL"])
        elif score >= ALERT_THRESHOLDS["HIGH"]:
            return ("HIGH", ALERT_COLORS["HIGH"])
        elif score >= ALERT_THRESHOLDS["MEDIUM"]:
            return ("MEDIUM", ALERT_COLORS["MEDIUM"])
        elif score >= ALERT_THRESHOLDS["LOW"]:
            return ("LOW", ALERT_COLORS["LOW"])
        else:
            return ("SAFE", ALERT_COLORS["SAFE"])

    def get_statistics(self) -> dict:
        """Trả về thống kê tổng hợp."""
        return self._stats.copy()

    def get_alert_history(self) -> list:
        """Trả về lịch sử cảnh báo."""
        return self._alert_history.copy()

    def get_risk_breakdown(self, record: AlertRecord) -> dict:
        """Phân tích chi tiết đóng góp của từng module vào điểm rủi ro."""
        return {
            "total_score": record.risk_score,
            "breakdown": {
                "Behavioral (XGBoost)": {
                    "raw": record.flow_score,
                    "weighted": record.flow_score * MODULE_WEIGHTS["flow_behavior"],
                    "weight": MODULE_WEIGHTS["flow_behavior"] * 100
                },
                "DGA (Bi-LSTM)": {
                    "raw": record.dga_score,
                    "weighted": record.dga_score * MODULE_WEIGHTS["dga_detection"],
                    "weight": MODULE_WEIGHTS["dga_detection"] * 100
                },
                "Threat Intel": {
                    "raw": record.threat_intel_score,
                    "weighted": record.threat_intel_score * MODULE_WEIGHTS["threat_intel"],
                    "weight": MODULE_WEIGHTS["threat_intel"] * 100
                },
                "Process Anomaly": {
                    "raw": record.process_score,
                    "weighted": record.process_score * MODULE_WEIGHTS["process_anomaly"],
                    "weight": MODULE_WEIGHTS["process_anomaly"] * 100
                }
            }
        }
