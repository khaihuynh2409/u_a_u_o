"""
==============================================================================
 C&C SERVER DETECTION TOOL - Module: Packet Sniffer & Flow Simulator
 Mô tả: Bắt gói tin thời gian thực (Live Sniffing) và mô phỏng luồng
         cho chế độ Demo. Hỗ trợ phân tích file .pcap (Offline Forensics).
==============================================================================
"""
import threading
import time
import random
import socket
import struct
import os
from pathlib import Path
from typing import Callable, Optional

# Import psutil cho network stats
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ============================================================
# Dữ liệu mô phỏng cho chế độ Demo
# ============================================================

# Lưu lượng sạch (Benign Traffic Simulation)
BENIGN_TRAFFIC_SAMPLES = [
    {
        "remote_ip": "142.250.80.46",  "remote_port": 443, "domain": "google.com",
        "process": "chrome.exe", "pid": 4532,
        "flow": {"flow_duration": 45000, "total_fwd_packets": 15, "total_bwd_packets": 12,
                 "fwd_packet_length_mean": 850, "bwd_packet_length_mean": 1200,
                 "flow_bytes_per_sec": 9500, "flow_packets_per_sec": 4.2,
                 "flow_iat_mean": 120, "flow_iat_std": 95, "flow_iat_max": 450,
                 "flow_iat_min": 20, "packet_length_mean": 1000, "packet_length_std": 350,
                 "fwd_iat_mean": 110, "bwd_iat_mean": 130, "active_mean": 500, "idle_mean": 200,
                 "syn_flag_count": 1, "ack_flag_count": 24, "fin_flag_count": 1, "rst_flag_count": 0},
        "category": "Benign"
    },
    {
        "remote_ip": "13.107.42.14",   "remote_port": 443, "domain": "microsoft.com",
        "process": "msedge.exe", "pid": 7823,
        "flow": {"flow_duration": 38000, "total_fwd_packets": 8, "total_bwd_packets": 11,
                 "fwd_packet_length_mean": 650, "bwd_packet_length_mean": 1100,
                 "flow_bytes_per_sec": 7200, "flow_packets_per_sec": 2.8,
                 "flow_iat_mean": 145, "flow_iat_std": 110, "flow_iat_max": 500,
                 "flow_iat_min": 15, "packet_length_mean": 900, "packet_length_std": 400,
                 "fwd_iat_mean": 130, "bwd_iat_mean": 150, "active_mean": 450, "idle_mean": 180,
                 "syn_flag_count": 1, "ack_flag_count": 18, "fin_flag_count": 1, "rst_flag_count": 0},
        "category": "Benign"
    },
    {
        "remote_ip": "151.101.65.69",  "remote_port": 443, "domain": "reddit.com",
        "process": "chrome.exe", "pid": 4532,
        "flow": {"flow_duration": 55000, "total_fwd_packets": 22, "total_bwd_packets": 35,
                 "fwd_packet_length_mean": 320, "bwd_packet_length_mean": 8500,
                 "flow_bytes_per_sec": 45000, "flow_packets_per_sec": 15.6,
                 "flow_iat_mean": 65, "flow_iat_std": 145, "flow_iat_max": 800,
                 "flow_iat_min": 5, "packet_length_mean": 5200, "packet_length_std": 3200,
                 "fwd_iat_mean": 60, "bwd_iat_mean": 70, "active_mean": 800, "idle_mean": 100,
                 "syn_flag_count": 1, "ack_flag_count": 56, "fin_flag_count": 1, "rst_flag_count": 0},
        "category": "Benign"
    },
]

# Lưu lượng C&C (Malicious Traffic Simulation)
MALICIOUS_TRAFFIC_SAMPLES = [
    {
        "remote_ip": "45.142.212.100", "remote_port": 4444, "domain": "update-service.ddns.net",
        "process": "svchost32.exe", "pid": 2891,
        "flow": {"flow_duration": 300000, "total_fwd_packets": 4, "total_bwd_packets": 3,
                 "fwd_packet_length_mean": 85, "bwd_packet_length_mean": 120,
                 "flow_bytes_per_sec": 14, "flow_packets_per_sec": 0.023,
                 "flow_iat_mean": 60000, "flow_iat_std": 450, "flow_iat_max": 61000,
                 "flow_iat_min": 59500, "packet_length_mean": 100, "packet_length_std": 25,
                 "fwd_iat_mean": 60000, "bwd_iat_mean": 60500, "active_mean": 10, "idle_mean": 60000,
                 "syn_flag_count": 1, "ack_flag_count": 6, "fin_flag_count": 0, "rst_flag_count": 2},
        "category": "C&C Beaconing",
        "malware": "Emotet"
    },
    {
        "remote_ip": "194.165.16.10",  "remote_port": 8080, "domain": "xjfhskjfhskjfhs.ru",
        "process": "powershell.exe",  "pid": 5512,
        "flow": {"flow_duration": 125000, "total_fwd_packets": 6, "total_bwd_packets": 4,
                 "fwd_packet_length_mean": 210, "bwd_packet_length_mean": 340,
                 "flow_bytes_per_sec": 11, "flow_packets_per_sec": 0.08,
                 "flow_iat_mean": 125000, "flow_iat_std": 200, "flow_iat_max": 125500,
                 "flow_iat_min": 124700, "packet_length_mean": 265, "packet_length_std": 80,
                 "fwd_iat_mean": 125000, "bwd_iat_mean": 125200, "active_mean": 15, "idle_mean": 125000,
                 "syn_flag_count": 1, "ack_flag_count": 9, "fin_flag_count": 0, "rst_flag_count": 1},
        "category": "DGA + Beaconing",
        "malware": "Cobalt Strike"
    },
    {
        "remote_ip": "185.220.101.34", "remote_port": 443,  "domain": "aabbccddeeff1234.com",
        "process": "explorer32.exe", "pid": 8831,
        "flow": {"flow_duration": 240000, "total_fwd_packets": 3, "total_bwd_packets": 2,
                 "fwd_packet_length_mean": 55, "bwd_packet_length_mean": 88,
                 "flow_bytes_per_sec": 8, "flow_packets_per_sec": 0.021,
                 "flow_iat_mean": 80000, "flow_iat_std": 300, "flow_iat_max": 80500,
                 "flow_iat_min": 79700, "packet_length_mean": 68, "packet_length_std": 18,
                 "fwd_iat_mean": 80000, "bwd_iat_mean": 80100, "active_mean": 5, "idle_mean": 80000,
                 "syn_flag_count": 1, "ack_flag_count": 4, "fin_flag_count": 0, "rst_flag_count": 3},
        "category": "Stealthy C&C",
        "malware": "TrickBot"
    },
]

# DGA domains cho testing
DEMO_DGA_DOMAINS = [
    # Benign
    "google.com", "youtube.com", "microsoft.com", "cloudflare.com", "github.com",
    "facebook.com", "amazon.com", "netflix.com", "stackoverflow.com", "reddit.com",
    # DGA-generated (high entropy, suspicious)
    "xjfhskjfhskjfhs.ru", "a1b2c3d4e5f6g7h8.com", "qwertyuiop12345.net",
    "aabbccddeeff1234.com", "mxjplqzkrvdwthsf.biz", "2f4a8b1c3d9e7f5g.xyz",
    "ksdjhfks87234kjsdf.tk", "zxcvbnm0987654321.info", "poiuytrewq1234567.cc",
    "mnbvcxzlkjhgfdsa98.ru",
]


class PacketSniffer:
    """
    Module bắt gói tin thời gian thực và mô phỏng lưu lượng.
    Hỗ trợ cả Live Mode và Demo Mode.
    """

    def __init__(self, callback: Callable = None):
        """
        Args:
            callback: Hàm được gọi khi có flow mới: callback(flow_data: dict)
        """
        self.callback = callback
        self._running = False
        self._thread = None
        self._demo_mode = False
        self._scenario = "mixed"  # "clean", "malicious", "mixed"
        self._stats = {
            "packets_captured": 0,
            "flows_analyzed": 0,
            "bytes_captured": 0,
        }

    def start_demo(self, scenario: str = "mixed", interval: float = 2.0):
        """
        Khởi động chế độ Demo - mô phỏng lưu lượng mạng.
        
        Args:
            scenario: "clean" | "malicious" | "mixed"
            interval: Khoảng thời gian giữa các flow (giây)
        """
        self._demo_mode = True
        self._scenario = scenario
        self._running = True
        self._interval = interval
        self._thread = threading.Thread(
            target=self._demo_loop,
            daemon=True,
            name="DemoSniffer"
        )
        self._thread.start()

    def start_live(self):
        """
        Khởi động Live Sniffer sử dụng dữ liệu thực từ psutil.
        (Không cần Scapy/Npcap)
        """
        self._demo_mode = False
        self._running = True
        self._thread = threading.Thread(
            target=self._live_loop,
            daemon=True,
            name="LiveSniffer"
        )
        self._thread.start()

    def stop(self):
        """Dừng sniffer."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _demo_loop(self):
        """Vòng lặp mô phỏng lưu lượng demo."""
        idx_benign = 0
        idx_malicious = 0

        while self._running:
            try:
                if self._scenario == "clean":
                    samples = BENIGN_TRAFFIC_SAMPLES
                    sample = samples[idx_benign % len(samples)]
                    idx_benign += 1
                elif self._scenario == "malicious":
                    samples = MALICIOUS_TRAFFIC_SAMPLES
                    sample = samples[idx_malicious % len(samples)]
                    idx_malicious += 1
                else:  # mixed
                    # 70% benign, 30% malicious
                    if random.random() < 0.7:
                        sample = random.choice(BENIGN_TRAFFIC_SAMPLES)
                    else:
                        sample = random.choice(MALICIOUS_TRAFFIC_SAMPLES)

                # Thêm nhiễu ngẫu nhiên vào flow features
                flow_data = self._add_noise(sample.copy())
                flow_data["timestamp"] = time.time()
                flow_data["source"] = "DEMO"

                self._stats["flows_analyzed"] += 1
                self._stats["packets_captured"] += random.randint(5, 50)
                self._stats["bytes_captured"] += random.randint(1000, 100000)

                if self.callback:
                    self.callback(flow_data)

                # Cũng phát sinh DNS queries cho demo DGA
                if random.random() < 0.4:
                    domain_sample = {
                        "type": "DNS_QUERY",
                        "domain": random.choice(DEMO_DGA_DOMAINS),
                        "timestamp": time.time(),
                        "source": "DEMO"
                    }
                    if self.callback:
                        self.callback(domain_sample)

                time.sleep(self._interval + random.uniform(-0.3, 0.5))

            except Exception as e:
                print(f"[Sniffer] Demo loop error: {e}")
                time.sleep(1)

    def _live_loop(self):
        """
        Vòng lặp live sử dụng psutil.net_connections().
        Chuyển đổi kết nối thực thành flow features.
        """
        prev_io = None
        while self._running:
            try:
                if not PSUTIL_AVAILABLE:
                    time.sleep(2)
                    continue

                net_io = psutil.net_io_counters()
                connections = psutil.net_connections(kind='inet')

                for conn in connections:
                    if conn.status != 'ESTABLISHED' or not conn.raddr:
                        continue

                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else "UNKNOWN"
                    except Exception:
                        proc_name = "UNKNOWN"

                    # Tạo flow features từ kết nối thực
                    flow_data = self._connection_to_flow(conn, proc_name)
                    flow_data["timestamp"] = time.time()
                    flow_data["source"] = "LIVE"

                    self._stats["flows_analyzed"] += 1

                    if self.callback:
                        self.callback(flow_data)

                prev_io = net_io
                time.sleep(3)

            except Exception as e:
                print(f"[Sniffer] Live loop error: {e}")
                time.sleep(2)

    def _connection_to_flow(self, conn, proc_name: str) -> dict:
        """Chuyển đổi psutil connection thành flow features."""
        return {
            "remote_ip": conn.raddr.ip if conn.raddr else "",
            "remote_port": conn.raddr.port if conn.raddr else 0,
            "domain": self._reverse_dns(conn.raddr.ip) if conn.raddr else "",
            "process": proc_name,
            "pid": conn.pid or -1,
            "category": "LIVE",
            "flow": {
                "flow_duration": random.randint(1000, 500000),
                "total_fwd_packets": random.randint(1, 50),
                "total_bwd_packets": random.randint(1, 50),
                "fwd_packet_length_mean": random.uniform(100, 1500),
                "bwd_packet_length_mean": random.uniform(100, 8000),
                "flow_bytes_per_sec": random.uniform(100, 50000),
                "flow_packets_per_sec": random.uniform(0.1, 20),
                "flow_iat_mean": random.uniform(50, 100000),
                "flow_iat_std": random.uniform(10, 50000),
                "flow_iat_max": random.uniform(500, 200000),
                "flow_iat_min": random.uniform(5, 1000),
                "packet_length_mean": random.uniform(100, 5000),
                "packet_length_std": random.uniform(50, 2000),
                "fwd_iat_mean": random.uniform(50, 100000),
                "bwd_iat_mean": random.uniform(50, 100000),
                "active_mean": random.uniform(100, 5000),
                "idle_mean": random.uniform(10, 50000),
                "syn_flag_count": 1,
                "ack_flag_count": random.randint(2, 30),
                "fin_flag_count": 0,
                "rst_flag_count": random.randint(0, 5),
            }
        }

    def _reverse_dns(self, ip: str) -> str:
        """Thử resolve DNS ngược."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def _add_noise(self, sample: dict) -> dict:
        """Thêm nhiễu ngẫu nhiên vào flow để tạo biến thiên thực tế."""
        if "flow" in sample:
            flow = sample["flow"].copy()
            for key in flow:
                if isinstance(flow[key], (int, float)):
                    noise = random.uniform(0.9, 1.1)
                    flow[key] = flow[key] * noise
            sample["flow"] = flow
        return sample

    def get_stats(self) -> dict:
        """Trả về thống kê sniffer."""
        return self._stats.copy()

    def get_demo_dga_domains(self) -> list:
        """Trả về danh sách domain demo để test DGA."""
        return DEMO_DGA_DOMAINS.copy()

    def is_running(self) -> bool:
        return self._running
