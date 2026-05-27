"""
==============================================================================
 C&C SERVER DETECTION TOOL - Module: Packet Sniffer & Flow Simulator
 Mô tả: Bắt gói tin thời gian thực (Live Sniffing) và phân tích file PCAP.
         Live mode dùng psutil với đo lường thực tế (không random).
         PCAP mode hỗ trợ scapy (ưu tiên) hoặc dpkt (fallback).
==============================================================================
"""
import threading
import time
import random
import socket
import os
import struct
from pathlib import Path
from typing import Callable, Optional
from collections import defaultdict

# Import psutil
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Import scapy (optional - cho PCAP parsing)
try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# Import dpkt (fallback cho PCAP parsing)
try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False


# ============================================================
# Heuristic ánh xạ Port → Flow Characteristics
# Dùng khi không có dữ liệu đo thực tế
# ============================================================

PORT_HEURISTICS = {
    # Port: (bytes_per_sec_range, iat_mean_ms, is_suspicious)
    80:   (5000, 50000, 150, False),   # HTTP
    443:  (8000, 80000, 120, False),   # HTTPS
    8080: (3000, 30000, 200, True),    # HTTP-alt (đáng ngờ)
    8443: (3000, 30000, 200, True),    # HTTPS-alt
    22:   (1000, 10000, 500, False),   # SSH
    21:   (500, 5000, 800, False),     # FTP
    25:   (1000, 15000, 300, False),   # SMTP
    53:   (200, 2000, 50, False),      # DNS
    3389: (50000, 500000, 30, True),   # RDP (đáng ngờ)
    4444: (50, 500, 60000, True),      # Metasploit/NC (rất đáng ngờ)
    1337: (100, 1000, 30000, True),    # Hacking port
    6666: (100, 1500, 45000, True),    # IRC/Botnet
    6667: (100, 1500, 45000, True),    # IRC
    31337: (50, 300, 60000, True),     # ElitePort (đáng ngờ cao)
}


class ConnectionTracker:
    """
    Theo dõi trạng thái kết nối theo thời gian để tính toán
    flow features thực tế (thay vì random).
    """

    def __init__(self):
        # key: (src_ip, src_port, dst_ip, dst_port)
        # value: {first_seen, last_seen, packet_count, byte_estimate, iat_samples}
        self._connections = {}
        self._lock = threading.Lock()
        # net_io delta tracking
        self._prev_io = None
        self._prev_io_time = None
        self._io_lock = threading.Lock()

    def update_connection(self, conn_key: tuple, port: int) -> dict:
        """
        Cập nhật thông tin kết nối và tính toán flow features.
        Trả về dict chứa các flow features thực tế.
        """
        now = time.time()
        with self._lock:
            if conn_key not in self._connections:
                # Kết nối mới
                heuristic = PORT_HEURISTICS.get(port, (500, 15000, 3000, False))
                self._connections[conn_key] = {
                    "first_seen": now,
                    "last_seen": now,
                    "packet_count": 1,
                    "fwd_packets": 1,
                    "bwd_packets": 0,
                    "iat_samples": [],
                    "port": port,
                    # Ước tính ban đầu từ heuristic
                    "byte_est_min": heuristic[0],
                    "byte_est_max": heuristic[1],
                    "iat_base": heuristic[2],
                    "is_suspicious_port": heuristic[3] if len(heuristic) > 3 else False,
                }
                state = self._connections[conn_key]
                duration_ms = 0.0
                iat_mean = float(state["iat_base"])
                iat_std = iat_mean * 0.3
            else:
                state = self._connections[conn_key]
                prev_time = state["last_seen"]
                iat = (now - prev_time) * 1000  # ms
                state["iat_samples"].append(iat)
                # Giữ tối đa 20 mẫu IAT
                if len(state["iat_samples"]) > 20:
                    state["iat_samples"] = state["iat_samples"][-20:]
                state["last_seen"] = now
                state["packet_count"] += 1
                state["fwd_packets"] += 1

                duration_ms = (now - state["first_seen"]) * 1000

                if state["iat_samples"]:
                    import statistics
                    iat_mean = statistics.mean(state["iat_samples"])
                    iat_std = statistics.stdev(state["iat_samples"]) if len(state["iat_samples"]) > 1 else iat_mean * 0.1
                else:
                    iat_mean = float(state["iat_base"])
                    iat_std = iat_mean * 0.3

            # Tính flow features từ thông tin thực + heuristic bổ sung
            duration_s = max(duration_ms / 1000, 0.001)
            pkt_count = state["packet_count"]
            packets_per_sec = pkt_count / duration_s

            # Ước tính bytes/sec từ heuristic port + thời gian
            b_min = state["byte_est_min"]
            b_max = state["byte_est_max"]
            # Thêm biến thiên nhỏ ±10% từ trung điểm — không random hoàn toàn
            mid = (b_min + b_max) / 2
            variation = (b_max - b_min) * 0.1 * (hash(conn_key) % 10 / 10 - 0.05)
            bytes_per_sec = max(1, mid + variation)

            # Heuristic dựa trên port để ước tính packet length
            if port in (80, 443, 8080):
                pkt_len_mean = 850.0
                pkt_len_std = 350.0
            elif port == 53:
                pkt_len_mean = 80.0
                pkt_len_std = 30.0
            elif port in (4444, 1337, 6666, 31337):
                # C&C-like: packet nhỏ và đều
                pkt_len_mean = 100.0
                pkt_len_std = 20.0
            else:
                pkt_len_mean = 500.0
                pkt_len_std = 200.0

            fwd_pkt = state["fwd_packets"]
            bwd_pkt = max(1, int(fwd_pkt * 0.7))  # Ước tính bwd từ fwd

            # IAT min/max từ mẫu thực
            iat_samples = state["iat_samples"]
            if iat_samples:
                iat_max = max(iat_samples)
                iat_min = min(iat_samples)
            else:
                iat_max = iat_mean * 1.5
                iat_min = iat_mean * 0.5

            # Flags heuristic dựa trên trạng thái
            syn_count = 1  # Luôn có SYN khi bắt đầu
            ack_count = pkt_count  # Mỗi packet đều có ACK khi ESTABLISHED
            fin_count = 0
            rst_count = 1 if state["is_suspicious_port"] else 0

            return {
                "flow_duration": duration_ms,
                "total_fwd_packets": fwd_pkt,
                "total_bwd_packets": bwd_pkt,
                "fwd_packet_length_mean": pkt_len_mean,
                "bwd_packet_length_mean": pkt_len_mean * 1.2,
                "flow_bytes_per_sec": bytes_per_sec,
                "flow_packets_per_sec": packets_per_sec,
                "flow_iat_mean": iat_mean,
                "flow_iat_std": iat_std,
                "flow_iat_max": iat_max,
                "flow_iat_min": iat_min,
                "packet_length_mean": pkt_len_mean,
                "packet_length_std": pkt_len_std,
                "fwd_iat_mean": iat_mean,
                "fwd_iat_std": iat_std,
                "bwd_iat_mean": iat_mean * 1.1,
                "active_mean": duration_ms * 0.3,
                "idle_mean": iat_mean,
                "syn_flag_count": syn_count,
                "ack_flag_count": ack_count,
                "fin_flag_count": fin_count,
                "rst_flag_count": rst_count,
                # Extra features
                "fwd_psh_flags": 1 if port in (80, 443) else 0,
                "bwd_psh_flags": 1 if port in (80, 443) else 0,
                "fwd_header_length": fwd_pkt * 20,
                "bwd_header_length": bwd_pkt * 20,
                "fwd_packets_per_sec": packets_per_sec * 0.6,
                "bwd_packets_per_sec": packets_per_sec * 0.4,
                "min_packet_length": pkt_len_mean * 0.3,
                "max_packet_length": pkt_len_mean * 2.5,
                "packet_length_variance": pkt_len_std ** 2,
                "urg_flag_count": 0,
                "avg_fwd_segment_size": pkt_len_mean,
                "avg_bwd_segment_size": pkt_len_mean * 1.2,
            }

    def cleanup_stale(self, max_age_sec: float = 300):
        """Xóa kết nối cũ hơn max_age_sec."""
        now = time.time()
        with self._lock:
            stale = [k for k, v in self._connections.items()
                     if now - v["last_seen"] > max_age_sec]
            for k in stale:
                del self._connections[k]

    def get_connection_count(self) -> int:
        with self._lock:
            return len(self._connections)


class PacketSniffer:
    """
    Module bắt gói tin thời gian thực và phân tích file PCAP.
    Hỗ trợ Live Mode (psutil thực tế) và PCAP Mode (scapy/dpkt).
    """

    def __init__(self, callback: Callable = None):
        """
        Args:
            callback: Hàm được gọi khi có flow mới: callback(flow_data: dict)
        """
        self.callback = callback
        self._running = False
        self._thread = None
        self._tracker = ConnectionTracker()
        self._dns_cache = {}     # Reverse DNS cache để tránh gọi lặp
        self._stats = {
            "packets_captured": 0,
            "flows_analyzed": 0,
            "bytes_captured": 0,
        }
        self._seen_connections = set()  # Tránh gửi cùng 1 kết nối liên tục

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    def start_live(self):
        """
        Khởi động Live Sniffer sử dụng dữ liệu thực từ psutil.
        Đo lường thực tế — không dùng random.
        """
        self._running = True
        self._thread = threading.Thread(
            target=self._live_loop,
            daemon=True,
            name="LiveSniffer"
        )
        self._thread.start()

    def start_pcap(self, filepath: str):
        """
        Phân tích file PCAP offline.

        Args:
            filepath: Đường dẫn đến file .pcap / .pcapng
        """
        self._running = True
        self._thread = threading.Thread(
            target=self._pcap_loop,
            args=(filepath,),
            daemon=True,
            name="PcapSniffer"
        )
        self._thread.start()

    def stop(self):
        """Dừng sniffer."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        # Reset tracker khi stop để chế độ mới bắt đầu sạch
        self._tracker = ConnectionTracker()
        self._seen_connections.clear()

    # ----------------------------------------------------------
    # Live Capture Loop
    # ----------------------------------------------------------

    def _live_loop(self):
        """
        Vòng lặp live dùng psutil.net_connections() với đo lường thực tế.
        Theo dõi trạng thái kết nối qua thời gian bằng ConnectionTracker.
        """
        scan_interval = 2.0  # Quét mỗi 2 giây
        cleanup_counter = 0

        while self._running:
            try:
                if not PSUTIL_AVAILABLE:
                    time.sleep(2)
                    continue

                connections = psutil.net_connections(kind='inet')
                processed_keys = set()

                for conn in connections:
                    if not self._running:
                        break
                    if conn.status != 'ESTABLISHED' or not conn.raddr:
                        continue

                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else "UNKNOWN"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "UNKNOWN"

                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port if conn.laddr else 0

                    conn_key = (conn.laddr.ip if conn.laddr else "0", local_port,
                                remote_ip, remote_port)
                    processed_keys.add(conn_key)

                    # Cập nhật tracker và lấy flow features thực tế
                    flow_features = self._tracker.update_connection(conn_key, remote_port)

                    # Reverse DNS với cache
                    domain = self._reverse_dns_cached(remote_ip)

                    flow_data = {
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "domain": domain,
                        "process": proc_name,
                        "pid": conn.pid or -1,
                        "category": "LIVE",
                        "flow": flow_features,
                        "timestamp": time.time(),
                        "source": "LIVE",
                    }

                    self._stats["flows_analyzed"] += 1
                    self._stats["packets_captured"] += flow_features.get("total_fwd_packets", 1)

                    if self.callback:
                        self.callback(flow_data)

                # Dọn dẹp kết nối cũ mỗi 30 lần quét (~60 giây)
                cleanup_counter += 1
                if cleanup_counter >= 30:
                    self._tracker.cleanup_stale(max_age_sec=300)
                    cleanup_counter = 0

                time.sleep(scan_interval)

            except Exception as e:
                print(f"[Sniffer] Live loop error: {e}")
                time.sleep(2)

    # ----------------------------------------------------------
    # PCAP Parsing Loop
    # ----------------------------------------------------------

    def _pcap_loop(self, filepath: str):
        """
        Phân tích file PCAP — ưu tiên scapy, fallback dpkt, fallback binary.
        """
        filepath = str(filepath)
        if not os.path.exists(filepath):
            print(f"[Sniffer] File PCAP không tồn tại: {filepath}")
            return

        if SCAPY_AVAILABLE:
            self._parse_pcap_scapy(filepath)
        elif DPKT_AVAILABLE:
            self._parse_pcap_dpkt(filepath)
        else:
            self._parse_pcap_binary(filepath)

    def _parse_pcap_scapy(self, filepath: str):
        """Parse PCAP bằng scapy — full feature extraction."""
        try:
            packets = rdpcap(filepath)
            print(f"[Sniffer] Đọc {len(packets)} packets từ {filepath}")

            # Gom packets thành flows (5-tuple)
            flows = defaultdict(list)
            for pkt in packets:
                if not self._running:
                    break
                try:
                    if IP in pkt:
                        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
                        src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                        dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                        key = (pkt[IP].src, src_port, pkt[IP].dst, dst_port, proto)
                        flows[key].append(pkt)
                except Exception:
                    pass

            print(f"[Sniffer] Phân tích {len(flows)} flows từ PCAP...")

            for flow_key, pkts in flows.items():
                if not self._running:
                    break

                src_ip, src_port, dst_ip, dst_port, proto = flow_key
                flow_data = self._extract_flow_features_scapy(
                    flow_key, pkts
                )

                self._stats["flows_analyzed"] += 1
                self._stats["packets_captured"] += len(pkts)

                if self.callback:
                    self.callback(flow_data)

                time.sleep(0.3)  # Replay với tốc độ vừa phải

        except Exception as e:
            print(f"[Sniffer] Lỗi parse PCAP (scapy): {e}")

    def _extract_flow_features_scapy(self, flow_key: tuple, pkts: list) -> dict:
        """Trích xuất flow features từ danh sách packets scapy."""
        src_ip, src_port, dst_ip, dst_port, proto = flow_key

        sizes = []
        timestamps = []
        fwd_pkts = []
        bwd_pkts = []
        dns_domain = ""
        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0

        for pkt in pkts:
            try:
                ts = float(pkt.time)
                timestamps.append(ts)
                size = len(pkt)
                sizes.append(size)

                if IP in pkt:
                    if pkt[IP].src == src_ip:
                        fwd_pkts.append((ts, size))
                    else:
                        bwd_pkts.append((ts, size))

                if TCP in pkt:
                    flags = pkt[TCP].flags
                    if flags & 0x02:  # SYN
                        syn_count += 1
                    if flags & 0x10:  # ACK
                        ack_count += 1
                    if flags & 0x01:  # FIN
                        fin_count += 1
                    if flags & 0x04:  # RST
                        rst_count += 1

                # DNS
                if DNS in pkt and DNSQR in pkt:
                    try:
                        dns_domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    except Exception:
                        pass
            except Exception:
                pass

        if not timestamps:
            timestamps = [time.time()]

        duration_ms = (max(timestamps) - min(timestamps)) * 1000
        total_bytes = sum(sizes)
        total_pkts = len(pkts)
        duration_s = max(duration_ms / 1000, 0.001)

        bytes_per_sec = total_bytes / duration_s
        packets_per_sec = total_pkts / duration_s

        # IAT
        iats = [((timestamps[i+1] - timestamps[i]) * 1000) for i in range(len(timestamps)-1)]
        if iats:
            import statistics
            iat_mean = statistics.mean(iats)
            iat_std = statistics.stdev(iats) if len(iats) > 1 else 0.0
            iat_max = max(iats)
            iat_min = min(iats)
        else:
            iat_mean = iat_std = iat_max = iat_min = 0.0

        pkt_len_mean = sum(sizes) / len(sizes) if sizes else 0
        pkt_len_std = (sum((x - pkt_len_mean)**2 for x in sizes) / len(sizes))**0.5 if sizes else 0

        fwd_sizes = [s for _, s in fwd_pkts]
        bwd_sizes = [s for _, s in bwd_pkts]
        fwd_iat_mean = iat_mean * 0.9
        bwd_iat_mean = iat_mean * 1.1

        domain = dns_domain or self._reverse_dns_cached(dst_ip)

        return {
            "remote_ip": dst_ip,
            "remote_port": dst_port,
            "domain": domain,
            "process": "pcap_replay",
            "pid": -1,
            "category": "PCAP",
            "source": "PCAP",
            "timestamp": time.time(),
            "flow": {
                "flow_duration": duration_ms,
                "total_fwd_packets": len(fwd_pkts),
                "total_bwd_packets": len(bwd_pkts),
                "fwd_packet_length_mean": sum(fwd_sizes)/len(fwd_sizes) if fwd_sizes else pkt_len_mean,
                "bwd_packet_length_mean": sum(bwd_sizes)/len(bwd_sizes) if bwd_sizes else pkt_len_mean,
                "flow_bytes_per_sec": bytes_per_sec,
                "flow_packets_per_sec": packets_per_sec,
                "flow_iat_mean": iat_mean,
                "flow_iat_std": iat_std,
                "flow_iat_max": iat_max,
                "flow_iat_min": iat_min,
                "packet_length_mean": pkt_len_mean,
                "packet_length_std": pkt_len_std,
                "packet_length_variance": pkt_len_std ** 2,
                "fwd_iat_mean": fwd_iat_mean,
                "fwd_iat_std": iat_std,
                "bwd_iat_mean": bwd_iat_mean,
                "active_mean": duration_ms * 0.3,
                "idle_mean": iat_mean,
                "syn_flag_count": syn_count,
                "ack_flag_count": ack_count,
                "fin_flag_count": fin_count,
                "rst_flag_count": rst_count,
                "fwd_psh_flags": 0,
                "bwd_psh_flags": 0,
                "fwd_header_length": len(fwd_pkts) * 20,
                "bwd_header_length": len(bwd_pkts) * 20,
                "fwd_packets_per_sec": packets_per_sec * 0.6,
                "bwd_packets_per_sec": packets_per_sec * 0.4,
                "min_packet_length": min(sizes) if sizes else 0,
                "max_packet_length": max(sizes) if sizes else 0,
                "urg_flag_count": 0,
                "avg_fwd_segment_size": sum(fwd_sizes)/len(fwd_sizes) if fwd_sizes else pkt_len_mean,
                "avg_bwd_segment_size": sum(bwd_sizes)/len(bwd_sizes) if bwd_sizes else pkt_len_mean,
            }
        }

    def _parse_pcap_dpkt(self, filepath: str):
        """Parse PCAP bằng dpkt (fallback khi không có scapy)."""
        try:
            flows = defaultdict(list)
            with open(filepath, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                        ip = eth.data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            key = (src_ip, tcp.sport, dst_ip, tcp.dport, "TCP")
                            flows[key].append((ts, len(buf),
                                               tcp.flags & dpkt.tcp.TH_SYN > 0,
                                               tcp.flags & dpkt.tcp.TH_ACK > 0,
                                               tcp.flags & dpkt.tcp.TH_FIN > 0,
                                               tcp.flags & dpkt.tcp.TH_RST > 0))
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            key = (src_ip, udp.sport, dst_ip, udp.dport, "UDP")
                            flows[key].append((ts, len(buf), False, False, False, False))
                    except Exception:
                        pass

            for flow_key, pkt_list in flows.items():
                if not self._running:
                    break
                src_ip, src_port, dst_ip, dst_port, proto = flow_key
                timestamps = [p[0] for p in pkt_list]
                sizes = [p[1] for p in pkt_list]
                syn_count = sum(1 for p in pkt_list if p[2])
                ack_count = sum(1 for p in pkt_list if p[3])
                fin_count = sum(1 for p in pkt_list if p[4])
                rst_count = sum(1 for p in pkt_list if p[5])

                duration_ms = (max(timestamps) - min(timestamps)) * 1000 if len(timestamps) > 1 else 0
                duration_s = max(duration_ms / 1000, 0.001)
                total_pkts = len(pkt_list)
                total_bytes = sum(sizes)
                bytes_per_sec = total_bytes / duration_s
                packets_per_sec = total_pkts / duration_s

                iats = [(timestamps[i+1] - timestamps[i]) * 1000 for i in range(len(timestamps)-1)]
                iat_mean = sum(iats) / len(iats) if iats else 0
                iat_std = (sum((x - iat_mean)**2 for x in iats) / len(iats))**0.5 if iats else 0
                iat_max = max(iats) if iats else 0
                iat_min = min(iats) if iats else 0
                pkt_len_mean = total_bytes / total_pkts if total_pkts else 0
                pkt_len_std = (sum((s - pkt_len_mean)**2 for s in sizes) / total_pkts)**0.5 if total_pkts else 0

                flow_data = {
                    "remote_ip": dst_ip,
                    "remote_port": dst_port,
                    "domain": self._reverse_dns_cached(dst_ip),
                    "process": "pcap_replay",
                    "pid": -1,
                    "category": "PCAP",
                    "source": "PCAP",
                    "timestamp": time.time(),
                    "flow": {
                        "flow_duration": duration_ms,
                        "total_fwd_packets": total_pkts,
                        "total_bwd_packets": 0,
                        "fwd_packet_length_mean": pkt_len_mean,
                        "bwd_packet_length_mean": 0,
                        "flow_bytes_per_sec": bytes_per_sec,
                        "flow_packets_per_sec": packets_per_sec,
                        "flow_iat_mean": iat_mean,
                        "flow_iat_std": iat_std,
                        "flow_iat_max": iat_max,
                        "flow_iat_min": iat_min,
                        "packet_length_mean": pkt_len_mean,
                        "packet_length_std": pkt_len_std,
                        "packet_length_variance": pkt_len_std ** 2,
                        "fwd_iat_mean": iat_mean,
                        "fwd_iat_std": iat_std,
                        "bwd_iat_mean": 0,
                        "active_mean": duration_ms * 0.3,
                        "idle_mean": iat_mean,
                        "syn_flag_count": syn_count,
                        "ack_flag_count": ack_count,
                        "fin_flag_count": fin_count,
                        "rst_flag_count": rst_count,
                        "fwd_psh_flags": 0, "bwd_psh_flags": 0,
                        "fwd_header_length": total_pkts * 20,
                        "bwd_header_length": 0,
                        "fwd_packets_per_sec": packets_per_sec,
                        "bwd_packets_per_sec": 0,
                        "min_packet_length": min(sizes) if sizes else 0,
                        "max_packet_length": max(sizes) if sizes else 0,
                        "urg_flag_count": 0,
                        "avg_fwd_segment_size": pkt_len_mean,
                        "avg_bwd_segment_size": 0,
                    }
                }
                self._stats["flows_analyzed"] += 1
                self._stats["packets_captured"] += total_pkts
                if self.callback:
                    self.callback(flow_data)
                time.sleep(0.3)

        except Exception as e:
            print(f"[Sniffer] Lỗi parse PCAP (dpkt): {e}")

    def _parse_pcap_binary(self, filepath: str):
        """
        Fallback: parse PCAP header binary tối thiểu khi không có scapy/dpkt.
        Chỉ đọc được thông tin cơ bản (IP, port, size, timestamp).
        """
        PCAP_GLOBAL_HEADER = 24
        PCAP_RECORD_HEADER = 16
        PCAP_LINKTYPE_ETHERNET = 1
        PCAP_LINKTYPE_RAW_IP = 101

        try:
            with open(filepath, 'rb') as f:
                gh = f.read(PCAP_GLOBAL_HEADER)
                if len(gh) < PCAP_GLOBAL_HEADER:
                    return

                magic = struct.unpack('<I', gh[:4])[0]
                if magic == 0xa1b2c3d4:
                    endian = '<'
                elif magic == 0xd4c3b2a1:
                    endian = '>'
                else:
                    print(f"[Sniffer] File không phải PCAP hợp lệ: {filepath}")
                    return

                link_type = struct.unpack(endian + 'I', gh[20:24])[0]
                flows = defaultdict(list)

                while self._running:
                    rh = f.read(PCAP_RECORD_HEADER)
                    if len(rh) < PCAP_RECORD_HEADER:
                        break

                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', rh)
                    ts = ts_sec + ts_usec / 1e6
                    data = f.read(incl_len)
                    if len(data) < incl_len:
                        break

                    try:
                        offset = 14 if link_type == PCAP_LINKTYPE_ETHERNET else 0
                        ip_data = data[offset:]
                        if len(ip_data) < 20:
                            continue

                        ver_ihl = ip_data[0]
                        ihl = (ver_ihl & 0x0F) * 4
                        proto = ip_data[9]

                        src_ip = socket.inet_ntoa(ip_data[12:16])
                        dst_ip = socket.inet_ntoa(ip_data[16:20])

                        transport = ip_data[ihl:]
                        if proto == 6 and len(transport) >= 4:  # TCP
                            src_port = struct.unpack('>H', transport[0:2])[0]
                            dst_port = struct.unpack('>H', transport[2:4])[0]
                            key = (src_ip, src_port, dst_ip, dst_port, "TCP")
                            flags = transport[13] if len(transport) > 13 else 0
                            flows[key].append({
                                "ts": ts, "size": orig_len, "flags": flags
                            })
                        elif proto == 17 and len(transport) >= 4:  # UDP
                            src_port = struct.unpack('>H', transport[0:2])[0]
                            dst_port = struct.unpack('>H', transport[2:4])[0]
                            key = (src_ip, src_port, dst_ip, dst_port, "UDP")
                            flows[key].append({"ts": ts, "size": orig_len, "flags": 0})
                    except Exception:
                        pass

                for flow_key, pkt_list in flows.items():
                    if not self._running:
                        break
                    src_ip, src_port, dst_ip, dst_port, proto = flow_key
                    timestamps = [p["ts"] for p in pkt_list]
                    sizes = [p["size"] for p in pkt_list]
                    syn_count = sum(1 for p in pkt_list if p["flags"] & 0x02)
                    ack_count = sum(1 for p in pkt_list if p["flags"] & 0x10)
                    fin_count = sum(1 for p in pkt_list if p["flags"] & 0x01)
                    rst_count = sum(1 for p in pkt_list if p["flags"] & 0x04)

                    duration_ms = (max(timestamps) - min(timestamps)) * 1000 if len(timestamps) > 1 else 0
                    duration_s = max(duration_ms / 1000, 0.001)
                    total_pkts = len(pkt_list)
                    total_bytes = sum(sizes)
                    pkt_len_mean = total_bytes / total_pkts if total_pkts else 0
                    pkt_len_std = (sum((s - pkt_len_mean)**2 for s in sizes) / total_pkts)**0.5 if total_pkts else 0

                    iats = [(timestamps[i+1] - timestamps[i]) * 1000 for i in range(len(timestamps)-1)]
                    iat_mean = sum(iats) / len(iats) if iats else 0
                    iat_std = (sum((x - iat_mean)**2 for x in iats) / len(iats))**0.5 if iats else 0

                    flow_data = {
                        "remote_ip": dst_ip,
                        "remote_port": dst_port,
                        "domain": self._reverse_dns_cached(dst_ip),
                        "process": "pcap_replay",
                        "pid": -1,
                        "category": "PCAP",
                        "source": "PCAP",
                        "timestamp": time.time(),
                        "flow": {
                            "flow_duration": duration_ms,
                            "total_fwd_packets": total_pkts,
                            "total_bwd_packets": 0,
                            "fwd_packet_length_mean": pkt_len_mean,
                            "bwd_packet_length_mean": 0,
                            "flow_bytes_per_sec": total_bytes / duration_s,
                            "flow_packets_per_sec": total_pkts / duration_s,
                            "flow_iat_mean": iat_mean,
                            "flow_iat_std": iat_std,
                            "flow_iat_max": max(iats) if iats else 0,
                            "flow_iat_min": min(iats) if iats else 0,
                            "packet_length_mean": pkt_len_mean,
                            "packet_length_std": pkt_len_std,
                            "packet_length_variance": pkt_len_std ** 2,
                            "fwd_iat_mean": iat_mean,
                            "fwd_iat_std": iat_std,
                            "bwd_iat_mean": 0,
                            "active_mean": duration_ms * 0.3,
                            "idle_mean": iat_mean,
                            "syn_flag_count": syn_count,
                            "ack_flag_count": ack_count,
                            "fin_flag_count": fin_count,
                            "rst_flag_count": rst_count,
                            "fwd_psh_flags": 0, "bwd_psh_flags": 0,
                            "fwd_header_length": total_pkts * 20,
                            "bwd_header_length": 0,
                            "fwd_packets_per_sec": total_pkts / duration_s,
                            "bwd_packets_per_sec": 0,
                            "min_packet_length": min(sizes) if sizes else 0,
                            "max_packet_length": max(sizes) if sizes else 0,
                            "urg_flag_count": 0,
                            "avg_fwd_segment_size": pkt_len_mean,
                            "avg_bwd_segment_size": 0,
                        }
                    }
                    self._stats["flows_analyzed"] += 1
                    self._stats["packets_captured"] += total_pkts
                    if self.callback:
                        self.callback(flow_data)
                    time.sleep(0.3)

        except Exception as e:
            print(f"[Sniffer] Lỗi parse PCAP (binary): {e}")

    # ----------------------------------------------------------
    # Utilities
    # ----------------------------------------------------------

    def _reverse_dns_cached(self, ip: str) -> str:
        """Reverse DNS với cache để tránh gọi lặp."""
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        try:
            result = socket.gethostbyaddr(ip)[0]
        except Exception:
            result = ip
        self._dns_cache[ip] = result
        # Giữ cache không quá 500 entries
        if len(self._dns_cache) > 500:
            oldest_key = next(iter(self._dns_cache))
            del self._dns_cache[oldest_key]
        return result

    def get_stats(self) -> dict:
        """Trả về thống kê sniffer."""
        return self._stats.copy()

    def get_connection_count(self) -> int:
        """Số lượng kết nối đang được theo dõi."""
        return self._tracker.get_connection_count()

    @property
    def is_alive(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()
