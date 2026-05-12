"""
==============================================================================
 C&C SERVER DETECTION TOOL - Module: Threat Intelligence
 Mô tả: Đối chiếu IP/Domain với các nguồn tình báo đe dọa.
         Hỗ trợ VirusTotal API và AbuseIPDB.
==============================================================================
"""
import requests
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime

CACHE_PATH = Path(__file__).parent.parent / "data" / "threat_intel_cache.json"

# Các IOC đã biết (demo - thực tế lấy từ Threat Intel feeds)
KNOWN_C2_IPS = {
    "45.142.212.100": {"malware": "Emotet", "confidence": 95, "source": "Abuse.ch"},
    "194.165.16.10": {"malware": "Cobalt Strike", "confidence": 90, "source": "Shodan"},
    "185.220.101.34": {"malware": "TrickBot", "confidence": 88, "source": "MISP"},
    "91.219.236.166": {"malware": "QakBot", "confidence": 92, "source": "VirusTotal"},
    "5.188.87.40": {"malware": "Mirai", "confidence": 85, "source": "Shodan"},
    "23.95.97.59": {"malware": "Agent Tesla", "confidence": 78, "source": "AbuseIPDB"},
    "192.3.141.144": {"malware": "AsyncRAT", "confidence": 82, "source": "VirusTotal"},
    "107.175.150.113": {"malware": "NjRAT", "confidence": 87, "source": "Abuse.ch"},
    "103.43.75.120": {"malware": "BlackMatter", "confidence": 91, "source": "CISA"},
    "162.33.177.18": {"malware": "LockBit", "confidence": 93, "source": "FBI IC3"},
}

KNOWN_C2_DOMAINS = {
    "update-service.ddns.net": {"malware": "Generic RAT", "confidence": 80},
    "malware-c2.tk": {"malware": "DarkComet", "confidence": 95},
    "bot-controller.xyz": {"malware": "Mirai", "confidence": 88},
    "xjfhskjfhskjfhs.ru": {"malware": "DGA Malware", "confidence": 92},
    "aabbccddeeff1234.com": {"malware": "DGA - ZeuS", "confidence": 89},
    "svchost32update.net": {"malware": "Cobalt Strike", "confidence": 85},
}

THREAT_CATEGORIES = {
    "Emotet": "Banking Trojan / Botnet Loader",
    "Cobalt Strike": "Adversary Simulation / APT Tool",
    "TrickBot": "Banking Trojan",
    "QakBot": "Banking Trojan / Worm",
    "Mirai": "IoT Botnet",
    "Agent Tesla": "Spyware / Keylogger",
    "AsyncRAT": "Remote Access Trojan",
    "NjRAT": "Remote Access Trojan",
    "BlackMatter": "Ransomware",
    "LockBit": "Ransomware",
    "Generic RAT": "Remote Access Trojan",
    "DarkComet": "Remote Access Trojan",
    "DGA Malware": "DGA-based C&C",
    "DGA - ZeuS": "Banking Trojan",
}

MITRE_ATTACK_MAP = {
    "Cobalt Strike": ["T1071.001 (Web Protocols)", "T1090 (Proxy)", "T1105 (Ingress Tool Transfer)"],
    "Emotet": ["T1566.001 (Phishing)", "T1055 (Process Injection)", "T1021 (Remote Services)"],
    "Mirai": ["T1498 (DDoS)", "T1110 (Brute Force)", "T1071 (App Layer Protocol)"],
    "Generic RAT": ["T1095 (Non-App Layer Protocol)", "T1041 (Exfiltration over C2)"],
}


class ThreatIntelligence:
    """
    Module tình báo đe dọa - kiểm tra IP/domain với nhiều nguồn.
    Có cache để tránh gọi API liên tục.
    """

    def __init__(self, virustotal_api_key: str = "", abuseipdb_api_key: str = ""):
        self.vt_api_key = virustotal_api_key
        self.abuse_api_key = abuseipdb_api_key
        self._cache = {}
        self._load_cache()

    def _load_cache(self):
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            if CACHE_PATH.exists():
                with open(CACHE_PATH, 'r') as f:
                    self._cache = json.load(f)
        except Exception:
            self._cache = {}

    def _save_cache(self):
        try:
            with open(CACHE_PATH, 'w') as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass

    def check_ip(self, ip: str) -> dict:
        """Kiểm tra IP với local IOC database và API."""
        cache_key = f"ip:{ip}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            # Cache 1 giờ
            if time.time() - cached.get('timestamp', 0) < 3600:
                return cached['data']

        result = {
            "ip": ip,
            "is_malicious": False,
            "confidence": 0,
            "malware_family": "Unknown",
            "category": "Unknown",
            "mitre_techniques": [],
            "sources": [],
            "last_seen": "N/A",
            "vt_detections": 0,
            "abuse_score": 0,
        }

        # Kiểm tra local IOC database
        if ip in KNOWN_C2_IPS:
            info = KNOWN_C2_IPS[ip]
            result["is_malicious"] = True
            result["confidence"] = info["confidence"]
            result["malware_family"] = info["malware"]
            result["category"] = THREAT_CATEGORIES.get(info["malware"], "Unknown")
            result["mitre_techniques"] = MITRE_ATTACK_MAP.get(info["malware"], ["T1071 (App Layer Protocol)"])
            result["sources"].append(info["source"])
            result["last_seen"] = "2025-01-15"

        # Gọi VirusTotal API nếu có key
        if self.vt_api_key and not result["is_malicious"]:
            vt_result = self._query_virustotal_ip(ip)
            if vt_result:
                result["vt_detections"] = vt_result.get("malicious", 0)
                if vt_result.get("malicious", 0) > 5:
                    result["is_malicious"] = True
                    result["confidence"] = min(95, vt_result["malicious"] * 3)
                    result["sources"].append("VirusTotal")

        # Gọi AbuseIPDB API nếu có key
        if self.abuse_api_key:
            abuse_result = self._query_abuseipdb(ip)
            if abuse_result:
                result["abuse_score"] = abuse_result.get("abuseConfidenceScore", 0)
                if abuse_result.get("abuseConfidenceScore", 0) > 50:
                    result["is_malicious"] = True
                    result["sources"].append("AbuseIPDB")

        # Cache kết quả
        self._cache[cache_key] = {"data": result, "timestamp": time.time()}
        self._save_cache()
        return result

    def check_domain(self, domain: str) -> dict:
        """Kiểm tra domain với IOC database."""
        cache_key = f"domain:{domain}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - cached.get('timestamp', 0) < 3600:
                return cached['data']

        result = {
            "domain": domain,
            "is_malicious": False,
            "confidence": 0,
            "malware_family": "Unknown",
            "category": "Unknown",
            "sources": [],
        }

        domain_lower = domain.lower()
        for known_domain, info in KNOWN_C2_DOMAINS.items():
            if known_domain in domain_lower or domain_lower in known_domain:
                result["is_malicious"] = True
                result["confidence"] = info["confidence"]
                result["malware_family"] = info["malware"]
                result["category"] = THREAT_CATEGORIES.get(info["malware"], "Unknown")
                result["sources"].append("Local IOC DB")
                break

        # Gọi VirusTotal nếu có key
        if self.vt_api_key and not result["is_malicious"]:
            vt_result = self._query_virustotal_domain(domain)
            if vt_result:
                malicious = vt_result.get("malicious", 0)
                if malicious > 3:
                    result["is_malicious"] = True
                    result["confidence"] = min(95, malicious * 5)
                    result["sources"].append("VirusTotal")

        self._cache[cache_key] = {"data": result, "timestamp": time.time()}
        self._save_cache()
        return result

    def _query_virustotal_ip(self, ip: str) -> dict:
        """Truy vấn VirusTotal API v3 cho IP."""
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return stats
        except Exception as e:
            print(f"[ThreatIntel] VT API error: {e}")
        return {}

    def _query_virustotal_domain(self, domain: str) -> dict:
        """Truy vấn VirusTotal API v3 cho domain."""
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return stats
        except Exception as e:
            print(f"[ThreatIntel] VT Domain API error: {e}")
        return {}

    def _query_abuseipdb(self, ip: str) -> dict:
        """Truy vấn AbuseIPDB API."""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Accept": "application/json", "Key": self.abuse_api_key}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json().get("data", {})
        except Exception as e:
            print(f"[ThreatIntel] AbuseIPDB error: {e}")
        return {}

    def get_reputation_badge(self, confidence: int) -> tuple:
        """Trả về (badge_text, color) dựa trên confidence score."""
        if confidence >= 80:
            return ("🔴 NGUY HIỂM CAO", "#e74c3c")
        elif confidence >= 50:
            return ("🟡 ĐÁNG NGỜ", "#f39c12")
        elif confidence > 0:
            return ("🟠 CẦN THEO DÕI", "#e67e22")
        else:
            return ("🟢 AN TOÀN", "#2ecc71")
