"""
==============================================================================
 Tao 2 file PCAP mau de nghien cuu C&C Detection:
   1. data/clean_traffic.pcap   - Luu luong hop le (HTTP/HTTPS)
   2. data/malicious_traffic.pcap - Luu luong C&C (Beaconing, DGA, Port nguy hiem)

 Khong can Scapy - su dung Python thuan de tao PCAP binary hop le.
 Tuong thich voi Wireshark, tcpdump, va he thong phan tich.
==============================================================================
"""

import sys
import io
# Fix Windows console encoding
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import struct
import socket
import time
import random
import os
from pathlib import Path


# ============================================================
# PCAP Binary Builder (Libpcap format - 100% compatible)
# ============================================================

PCAP_GLOBAL_HEADER = struct.pack(
    '<IHHiIII',
    0xa1b2c3d4,   # magic number
    2,             # version major
    4,             # version minor
    0,             # timezone (UTC)
    0,             # timestamp accuracy
    65535,         # snaplen
    1,             # link type (Ethernet)
)


def make_ethernet_header(src_mac: bytes, dst_mac: bytes, ether_type: int = 0x0800) -> bytes:
    """Tạo Ethernet frame header (14 bytes)."""
    return dst_mac + src_mac + struct.pack('>H', ether_type)


def make_ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int,
                   ttl: int = 64, identification: int = None) -> bytes:
    """Tạo IPv4 header (20 bytes, không có option)."""
    if identification is None:
        identification = random.randint(1000, 65535)
    
    total_len = 20 + payload_len  # IP header + payload
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    
    # Tạo header với checksum = 0 trước
    header = struct.pack(
        '>BBHHHBBH4s4s',
        0x45,           # version=4, IHL=5 (20 bytes)
        0,              # DSCP/ECN
        total_len,      # total length
        identification, # identification
        0x4000,         # flags (DF) + fragment offset
        ttl,            # TTL
        proto,          # protocol (6=TCP, 17=UDP)
        0,              # checksum (placeholder)
        src,            # source IP
        dst,            # destination IP
    )
    
    # Tính checksum
    chksum = ip_checksum(header)
    # Gắn checksum vào đúng offset
    header = header[:10] + struct.pack('>H', chksum) + header[12:]
    return header


def ip_checksum(data: bytes) -> int:
    """Tính Internet checksum (RFC 1071)."""
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i] << 8) + data[i+1]
    if n:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def make_tcp_header(src_port: int, dst_port: int, seq: int, ack: int,
                    flags: int, window: int = 65535) -> bytes:
    """Tạo TCP header (20 bytes, không có option)."""
    return struct.pack(
        '>HHIIHHHH',
        src_port,     # source port
        dst_port,     # destination port
        seq,          # sequence number
        ack,          # acknowledgement number
        0x5000,       # data offset (5*4=20) + reserved
        flags,        # flags (SYN=0x02, ACK=0x10, FIN=0x01, PSH=0x08, RST=0x04)
        window,       # window size
        0,            # checksum (skip - Wireshark handles)
    ) + b'\x00\x00'  # urgent pointer


def make_udp_header(src_port: int, dst_port: int, data_len: int) -> bytes:
    """Tạo UDP header (8 bytes)."""
    return struct.pack('>HHHH', src_port, dst_port, data_len + 8, 0)


def make_dns_query(domain: str, query_id: int = None) -> bytes:
    """Tạo DNS query packet."""
    if query_id is None:
        query_id = random.randint(1, 65535)
    
    # DNS header
    header = struct.pack('>HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
    
    # DNS question
    question = b''
    for part in domain.split('.'):
        encoded = part.encode('ascii')
        question += struct.pack('B', len(encoded)) + encoded
    question += b'\x00'  # root label
    question += struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
    
    return header + question


def pcap_record(ts: float, data: bytes) -> bytes:
    """Tạo PCAP record header + data."""
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1e6)
    incl_len = orig_len = len(data)
    return struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len) + data


def build_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     flags: int, seq: int, ack: int, payload: bytes = b'') -> bytes:
    """Xây dựng Ethernet+IP+TCP packet hoàn chỉnh."""
    src_mac = bytes([0x00, 0x0c, 0x29, random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)])
    dst_mac = bytes([0x00, 0x50, 0x56, random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)])
    
    tcp = make_tcp_header(src_port, dst_port, seq, ack, flags)
    ip_payload = tcp + payload
    ip = make_ip_header(src_ip, dst_ip, 6, len(ip_payload))
    eth = make_ethernet_header(src_mac, dst_mac)
    
    return eth + ip + ip_payload


def build_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     payload: bytes) -> bytes:
    """Xây dựng Ethernet+IP+UDP packet hoàn chỉnh."""
    src_mac = bytes([0x00, 0x0c, 0x29, 0x01, 0x02, 0x03])
    dst_mac = bytes([0x00, 0x50, 0x56, 0x04, 0x05, 0x06])
    
    udp = make_udp_header(src_port, dst_port, len(payload))
    ip_payload = udp + payload
    ip = make_ip_header(src_ip, dst_ip, 17, len(ip_payload))
    eth = make_ethernet_header(src_mac, dst_mac)
    
    return eth + ip + ip_payload


# ============================================================
# Tạo Clean Traffic PCAP
# ============================================================

def create_clean_pcap(output_path: str):
    """
    Tạo file PCAP với lưu lượng hợp lệ:
    - HTTPS đến Google, Microsoft, GitHub (port 443)
    - HTTP đến các server web (port 80)
    - DNS queries hợp lệ
    - Flow đặc trưng: packet lớn, IAT ngẫu nhiên, nhiều dữ liệu
    """
    print(f"[+] Tạo clean_traffic.pcap...")
    records = []
    
    client_ip = "192.168.1.100"
    client_src_ports = [50000 + i for i in range(20)]
    
    # Các kết nối HTTPS hợp lệ
    https_connections = [
        ("142.250.80.46",   443, "google.com",      1200, 15),
        ("13.107.42.14",    443, "microsoft.com",   900,  12),
        ("140.82.121.3",    443, "github.com",      1500, 20),
        ("151.101.65.69",   443, "reddit.com",      8500, 35),
        ("157.240.195.35",  443, "facebook.com",    950,  18),
        ("54.239.28.85",    443, "amazon.com",      2000, 25),
        ("74.125.24.113",   80,  "googleapis.com",  850,  10),
        ("13.33.0.100",     443, "cloudflare.com",  1100, 14),
    ]
    
    base_ts = time.time() - 300  # 5 phút trước
    
    for server_ip, server_port, domain, payload_size, packet_count in https_connections:
        src_port = random.choice(client_src_ports)
        seq = random.randint(1000000, 4000000000)
        ack = random.randint(1000000, 4000000000)
        ts = base_ts + random.uniform(0, 280)
        
        # DNS query
        dns_payload = make_dns_query(domain)
        dns_pkt = build_udp_packet(client_ip, "8.8.8.8", random.randint(49152, 65535), 53, dns_payload)
        records.append((ts, dns_pkt))
        ts += random.uniform(0.01, 0.05)
        
        # TCP SYN
        pkt = build_tcp_packet(client_ip, server_ip, src_port, server_port,
                               0x02, seq, 0)  # SYN
        records.append((ts, pkt))
        ts += random.uniform(0.02, 0.08)
        
        # SYN-ACK
        pkt = build_tcp_packet(server_ip, client_ip, server_port, src_port,
                               0x12, ack, seq + 1)  # SYN+ACK
        records.append((ts, pkt))
        ts += random.uniform(0.001, 0.005)
        
        # ACK (3-way handshake complete)
        pkt = build_tcp_packet(client_ip, server_ip, src_port, server_port,
                               0x10, seq + 1, ack + 1)  # ACK
        records.append((ts, pkt))
        ts += random.uniform(0.005, 0.02)
        
        # Data transfer (TLS Client Hello + HTTP request)
        client_hello = bytes([0x16, 0x03, 0x01]) + os.urandom(min(payload_size, 300))
        pkt = build_tcp_packet(client_ip, server_ip, src_port, server_port,
                               0x18, seq + 1, ack + 1, client_hello)  # PSH+ACK
        records.append((ts, pkt))
        ts += random.uniform(0.02, 0.1)
        
        # Server response (multiple packets với payload lớn = HTTP response)
        for i in range(packet_count):
            response_data = os.urandom(random.randint(payload_size // 2, payload_size))
            pkt = build_tcp_packet(server_ip, client_ip, server_port, src_port,
                                   0x18, ack + 1 + i * payload_size,
                                   seq + len(client_hello) + 1, response_data)
            records.append((ts, pkt))
            ts += random.uniform(0.02, 0.15)  # IAT ngẫu nhiên = bình thường
        
        # FIN
        pkt = build_tcp_packet(client_ip, server_ip, src_port, server_port,
                               0x11, seq + len(client_hello) + 1,  # FIN+ACK
                               ack + 1 + packet_count * payload_size)
        records.append((ts, pkt))
        ts += random.uniform(0.001, 0.01)
    
    # Thêm một số UDP DNS queries thêm
    benign_domains = ["windows.com", "office.com", "bing.com", "youtube.com", "netflix.com"]
    for domain in benign_domains:
        ts = base_ts + random.uniform(0, 280)
        dns_payload = make_dns_query(domain)
        dns_pkt = build_udp_packet(client_ip, "1.1.1.1", random.randint(49152, 65535), 53, dns_payload)
        records.append((ts, dns_pkt))
    
    # Sắp xếp theo timestamp
    records.sort(key=lambda x: x[0])
    
    # Ghi file
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(PCAP_GLOBAL_HEADER)
        for ts, pkt in records:
            f.write(pcap_record(ts, pkt))
    
    total_size = os.path.getsize(output_path)
    print(f"[+] Đã tạo: {output_path}")
    print(f"    Packets: {len(records)}, Dung lượng: {total_size / 1024:.1f} KB")
    print(f"    Đặc trưng: HTTPS/HTTP traffic, IAT ngẫu nhiên, payload lớn")


# ============================================================
# Tạo Malicious Traffic PCAP
# ============================================================

def create_malicious_pcap(output_path: str):
    """
    Tạo file PCAP với lưu lượng C&C:
    - Beaconing định kỳ đến IP nguy hiểm (IAT rất đều đặn)
    - Kết nối đến port nguy hiểm (4444, 6666)
    - DNS queries cho DGA domains
    - Payload nhỏ, đều đặn = beaconing pattern
    - Sử dụng IP từ KNOWN_C2_IPS trong threat_intel.py
    """
    print(f"\n[+] Tạo malicious_traffic.pcap...")
    records = []
    
    client_ip = "192.168.1.100"
    base_ts = time.time() - 300
    
    # ----------------------------------------
    # Scenario 1: Emotet Beaconing (port 4444)
    # IP: 45.142.212.100 - trong KNOWN_C2_IPS
    # IAT cực kỳ đều đặn = dấu hiệu beaconing
    # ----------------------------------------
    cnc_ip_1 = "45.142.212.100"
    cnc_port_1 = 4444
    beacon_interval = 60.0  # 60 giây rất đều
    src_port_1 = 52000
    seq1 = 1234567
    ack1 = 9876543
    ts = base_ts + 10.0
    
    print(f"    Thêm Emotet beaconing (IP: {cnc_ip_1}:{cnc_port_1})...")
    for i in range(5):  # 5 beacon heartbeats
        # TCP SYN
        pkt = build_tcp_packet(client_ip, cnc_ip_1, src_port_1, cnc_port_1,
                               0x02, seq1, 0)
        records.append((ts, pkt))
        ts += 0.05
        
        # SYN-ACK
        pkt = build_tcp_packet(cnc_ip_1, client_ip, cnc_port_1, src_port_1,
                               0x12, ack1, seq1 + 1)
        records.append((ts, pkt))
        ts += 0.01
        
        # ACK
        pkt = build_tcp_packet(client_ip, cnc_ip_1, src_port_1, cnc_port_1,
                               0x10, seq1 + 1, ack1 + 1)
        records.append((ts, pkt))
        ts += 0.02
        
        # Beacon payload nhỏ (heartbeat message) - đặc trưng C&C
        beacon_payload = b'\x00\x01\x00\x00' + b'\xde\xad\xbe\xef' * 5 + os.urandom(20)
        pkt = build_tcp_packet(client_ip, cnc_ip_1, src_port_1, cnc_port_1,
                               0x18, seq1 + 1, ack1 + 1, beacon_payload)
        records.append((ts, pkt))
        ts += 0.03
        
        # C&C response nhỏ
        response = b'\x00\x01\x00\x01' + os.urandom(15)
        pkt = build_tcp_packet(cnc_ip_1, client_ip, cnc_port_1, src_port_1,
                               0x18, ack1 + 1, seq1 + len(beacon_payload) + 1, response)
        records.append((ts, pkt))
        ts += 0.02
        
        # RST (không close bình thường = đáng ngờ)
        pkt = build_tcp_packet(client_ip, cnc_ip_1, src_port_1, cnc_port_1,
                               0x04, seq1 + len(beacon_payload) + 1, ack1 + len(response) + 1)
        records.append((ts, pkt))
        
        # Chờ đúng beacon_interval (rất đều đặn!)
        ts += beacon_interval - 0.13  # trừ thời gian handshake

    # ----------------------------------------
    # Scenario 2: Cobalt Strike Beaconing (port 8080)
    # IP: 194.165.16.10 - trong KNOWN_C2_IPS
    # ----------------------------------------
    cnc_ip_2 = "194.165.16.10"
    cnc_port_2 = 8080
    src_port_2 = 53000
    ts2 = base_ts + 25.0
    seq2 = 5678901
    ack2 = 1234567
    beacon_interval_2 = 120.0  # 2 phút đều
    
    print(f"    Thêm Cobalt Strike beaconing (IP: {cnc_ip_2}:{cnc_port_2})...")
    for i in range(3):
        # SYN
        pkt = build_tcp_packet(client_ip, cnc_ip_2, src_port_2, cnc_port_2,
                               0x02, seq2, 0)
        records.append((ts2, pkt))
        ts2 += 0.08
        
        # SYN-ACK
        pkt = build_tcp_packet(cnc_ip_2, client_ip, cnc_port_2, src_port_2,
                               0x12, ack2, seq2 + 1)
        records.append((ts2, pkt))
        ts2 += 0.02
        
        # ACK
        pkt = build_tcp_packet(client_ip, cnc_ip_2, src_port_2, cnc_port_2,
                               0x10, seq2 + 1, ack2 + 1)
        records.append((ts2, pkt))
        ts2 += 0.03
        
        # Cobalt Strike giả lập HTTP GET beacon (disguised as HTTP)
        http_beacon = (
            b"GET /api/data HTTP/1.1\r\n"
            b"Host: " + cnc_ip_2.encode() + b"\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Cookie: MUID=" + os.urandom(8).hex().encode() + b"\r\n"
            b"\r\n"
        )
        pkt = build_tcp_packet(client_ip, cnc_ip_2, src_port_2, cnc_port_2,
                               0x18, seq2 + 1, ack2 + 1, http_beacon)
        records.append((ts2, pkt))
        ts2 += 0.15
        
        # C&C command response (nhỏ)
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 32\r\n\r\n"
        ) + os.urandom(32)
        pkt = build_tcp_packet(cnc_ip_2, client_ip, cnc_port_2, src_port_2,
                               0x18, ack2 + 1, seq2 + len(http_beacon) + 1, http_response)
        records.append((ts2, pkt))
        ts2 += 0.05
        
        # FIN
        pkt = build_tcp_packet(client_ip, cnc_ip_2, src_port_2, cnc_port_2,
                               0x11, seq2 + len(http_beacon) + 1, ack2 + len(http_response) + 1)
        records.append((ts2, pkt))
        ts2 += beacon_interval_2 - 0.3  # Beacon interval đều

    # ----------------------------------------
    # Scenario 3: DGA DNS Queries
    # Queries đến nhiều domain DGA ngẫu nhiên trong thời gian ngắn
    # ----------------------------------------
    dga_domains = [
        "xjfhskjfhskjfhs.ru",       # Trong KNOWN_C2_DOMAINS
        "aabbccddeeff1234.com",      # Trong KNOWN_C2_DOMAINS
        "mxjplqzkrvdwthsf.biz",
        "a1b2c3d4e5f6g7h8.com",
        "qwertyuiop12345.net",
        "ksdjhfks87234kjsdf.tk",
        "mnbvcxzlkjhgfdsa98.ru",
        "2f4a8b1c3d9e7f5g.xyz",
    ]
    
    ts3 = base_ts + 50.0
    print(f"    Thêm DGA DNS burst queries...")
    for domain in dga_domains:
        dns_payload = make_dns_query(domain)
        dns_pkt = build_udp_packet(client_ip, "8.8.8.8", random.randint(49152, 65535), 53, dns_payload)
        records.append((ts3, dns_pkt))
        ts3 += random.uniform(0.3, 1.5)  # Nhiều DNS trong thời gian ngắn

    # ----------------------------------------
    # Scenario 4: TrickBot (port 443 nhưng IP nguy hiểm)
    # IP: 185.220.101.34 - trong KNOWN_C2_IPS
    # Stealthy C&C dùng port 443 để trốn tránh
    # ----------------------------------------
    cnc_ip_3 = "185.220.101.34"
    cnc_port_3 = 443
    src_port_3 = 54000
    ts4 = base_ts + 80.0
    seq3 = 9876543
    ack3 = 5555555
    beacon_interval_3 = 80.0
    
    print(f"    Thêm TrickBot stealthy C&C (IP: {cnc_ip_3}:{cnc_port_3})...")
    for i in range(3):
        # 3-way handshake
        for flags, s, a in [(0x02, seq3, 0), (0x12, ack3, seq3+1), (0x10, seq3+1, ack3+1)]:
            src, dst = (client_ip, cnc_ip_3) if flags != 0x12 else (cnc_ip_3, client_ip)
            sport, dport = (src_port_3, cnc_port_3) if flags != 0x12 else (cnc_port_3, src_port_3)
            pkt = build_tcp_packet(src, dst, sport, dport, flags, s, a)
            records.append((ts4, pkt))
            ts4 += 0.02
        
        # Beacon (rất nhỏ - stealthy)
        stealthy_payload = struct.pack('>HH', 0x1603, 0x0301) + os.urandom(30)  # Fake TLS record
        pkt = build_tcp_packet(client_ip, cnc_ip_3, src_port_3, cnc_port_3,
                               0x18, seq3 + 1, ack3 + 1, stealthy_payload)
        records.append((ts4, pkt))
        ts4 += 0.04
        
        # RST sau khi gửi
        pkt = build_tcp_packet(cnc_ip_3, client_ip, cnc_port_3, src_port_3,
                               0x04, ack3 + 1, seq3 + len(stealthy_payload) + 1)
        records.append((ts4, pkt))
        ts4 += beacon_interval_3

    # Sắp xếp theo timestamp
    records.sort(key=lambda x: x[0])
    
    # Ghi file
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(PCAP_GLOBAL_HEADER)
        for ts, pkt in records:
            f.write(pcap_record(ts, pkt))
    
    total_size = os.path.getsize(output_path)
    print(f"[+] Đã tạo: {output_path}")
    print(f"    Packets: {len(records)}, Dung lượng: {total_size / 1024:.1f} KB")
    print(f"    Đặc trưng: Beaconing (IAT đều), DGA DNS burst, Port nguy hiểm (4444), IP trong C2 database")


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    base_dir = Path(__file__).parent
    
    clean_path = str(base_dir / "data" / "clean_traffic.pcap")
    malicious_path = str(base_dir / "data" / "malicious_traffic.pcap")
    
    print("=" * 60)
    print(" TẠO PCAP MẪU CHO NGHIÊN CỨU C&C DETECTION")
    print("=" * 60)
    
    create_clean_pcap(clean_path)
    create_malicious_pcap(malicious_path)
    
    print("\n" + "=" * 60)
    print(" HOÀN THÀNH!")
    print("=" * 60)
    print(f"\n📁 Files đã tạo:")
    print(f"   ✅ {clean_path}")
    print(f"   ⚠️  {malicious_path}")
    print(f"\n📖 Cách sử dụng:")
    print(f"   1. Mở phần mềm C&C Detector")
    print(f"   2. Bấm '📂 IMPORT PCAP'")
    print(f"   3. Chọn một trong 2 file PCAP trên")
    print(f"   4. Bấm '▶ BẮT ĐẦU GIÁM SÁT' để phân tích")
    print(f"\n🔬 Đặc trưng phân biệt:")
    print(f"   clean_traffic.pcap  - IAT ngẫu nhiên, payload lớn, domain uy tín")
    print(f"   malicious_traffic.pcap - Beaconing đều đặn, DGA domain, IP C2 database")
    print(f"\n💡 Bạn có thể xem các file này bằng Wireshark để nghiên cứu.")
