"""
==============================================================================
 C&C SERVER DETECTION TOOL - Module: Process Mapper
 Mô tả: Ánh xạ kết nối mạng với tiến trình hệ thống bằng psutil.
         Phát hiện mã độc đội lốt tiến trình hợp lệ (Process Masquerading).
==============================================================================
"""
import psutil
import socket
import os
import time
from pathlib import Path
from typing import Optional

# Tiến trình hệ thống hợp lệ (Windows)
LEGITIMATE_PROCESSES = {
    "svchost.exe", "chrome.exe", "firefox.exe", "msedge.exe",
    "explorer.exe", "winlogon.exe", "lsass.exe", "services.exe",
    "outlook.com", "teams.exe", "zoom.exe", "discord.exe",
    "python.exe", "pythonw.exe", "node.exe", "nginx.exe",
    "ssh.exe", "putty.exe", "winscp.exe",
    # Linux equivalents
    "systemd", "NetworkManager", "dhclient", "sshd",
    "nginx", "apache2", "python3", "node", "curl", "wget",
}

# Tiến trình đáng ngờ
SUSPICIOUS_PROCESS_NAMES = {
    "svchost32.exe", "svhost.exe", "scvhost.exe",  # Typosquatting
    "explorer32.exe", "lsass32.exe",               # Masquerading
    "mimikatz.exe", "psexec.exe", "mshta.exe",      # Hacking tools
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",  # Scripting
    "regsvr32.exe", "msiexec.exe", "rundll32.exe",  # LOLBins
}

# Đường dẫn hệ thống hợp lệ
LEGITIMATE_PATHS = [
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "/usr/bin", "/usr/sbin", "/usr/local/bin",
    "/bin", "/sbin", "/opt",
]


class ProcessMapper:
    """
    Ánh xạ kết nối mạng với tiến trình hệ thống.
    Phát hiện các dấu hiệu đáng ngờ trong tiến trình.
    """

    def __init__(self):
        self._process_cache = {}
        self._connection_cache = {}
        self._last_refresh = 0

    def get_all_connections(self) -> list:
        """Lấy tất cả kết nối mạng hiện tại kèm thông tin tiến trình."""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.status not in ('ESTABLISHED', 'SYN_SENT', 'CLOSE_WAIT'):
                        continue

                    proc_info = self._get_process_info(conn.pid)
                    local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

                    entry = {
                        "pid": conn.pid,
                        "local_address": local,
                        "remote_address": remote,
                        "remote_ip": conn.raddr.ip if conn.raddr else "",
                        "remote_port": conn.raddr.port if conn.raddr else 0,
                        "status": conn.status,
                        "process": proc_info,
                        "suspicious_flags": self._analyze_process_suspicion(proc_info, conn),
                    }
                    connections.append(entry)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print(f"[ProcessMapper] Lỗi lấy connections: {e}")
        return connections

    def _get_process_info(self, pid: Optional[int]) -> dict:
        """Lấy thông tin chi tiết của tiến trình."""
        if pid is None:
            return {"name": "UNKNOWN", "pid": -1, "exe": "", "cmdline": ""}

        if pid in self._process_cache:
            cached = self._process_cache[pid]
            if time.time() - cached.get('time', 0) < 5:
                return cached['data']

        try:
            proc = psutil.Process(pid)
            info = {
                "name": proc.name(),
                "pid": pid,
                "exe": proc.exe() if hasattr(proc, 'exe') else "",
                "cmdline": ' '.join(proc.cmdline()) if hasattr(proc, 'cmdline') else "",
                "create_time": proc.create_time(),
                "cpu_percent": proc.cpu_percent(),
                "memory_mb": proc.memory_info().rss / 1024 / 1024,
                "username": proc.username(),
                "parent_pid": proc.ppid(),
            }
            self._process_cache[pid] = {'data': info, 'time': time.time()}
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            return {"name": "ACCESS DENIED", "pid": pid, "exe": "", "cmdline": ""}

    def _analyze_process_suspicion(self, proc_info: dict, conn) -> list:
        """
        Phân tích các dấu hiệu đáng ngờ của tiến trình.
        Kỹ thuật: Process Masquerading Detection
        """
        flags = []
        name = proc_info.get("name", "").lower()
        exe = proc_info.get("exe", "").lower()
        remote_port = conn.raddr.port if conn.raddr else 0

        # 1. Tiến trình đáng ngờ
        if name in {p.lower() for p in SUSPICIOUS_PROCESS_NAMES}:
            flags.append(f"⚠️ Tiến trình đáng ngờ: {name}")

        # 2. Masquerading: tên hợp lệ nhưng đường dẫn sai
        if name in {"svchost.exe", "lsass.exe", "winlogon.exe", "services.exe"}:
            is_legit_path = any(
                exe.startswith(p.lower()) for p in LEGITIMATE_PATHS
            )
            if exe and not is_legit_path:
                flags.append(f"🔴 MASQUERADING: '{name}' chạy từ '{exe}'")

        # 3. Cổng không phổ biến
        if remote_port not in (0, 80, 443, 8080, 8443, 22, 21, 25, 53, 587):
            if remote_port > 1024:
                flags.append(f"⚠️ Cổng không phổ biến: {remote_port}")

        # 4. Kết nối outbound từ tiến trình hệ thống quan trọng
        critical_procs = {"lsass.exe", "winlogon.exe", "csrss.exe"}
        if name in critical_procs and conn.raddr:
            flags.append(f"🔴 CRITICAL: {name} có kết nối outbound bất thường")

        # 5. PowerShell/cmd với kết nối outbound
        if name in {"powershell.exe", "cmd.exe", "wscript.exe"}:
            flags.append(f"⚠️ Script shell ({name}) có kết nối mạng")

        return flags

    def get_process_tree(self, pid: int) -> dict:
        """Lấy cây tiến trình (parent-child) để phát hiện process injection."""
        try:
            proc = psutil.Process(pid)
            children = []
            for child in proc.children(recursive=True):
                try:
                    children.append({
                        "pid": child.pid,
                        "name": child.name(),
                        "exe": child.exe(),
                    })
                except Exception:
                    pass

            return {
                "pid": pid,
                "name": proc.name(),
                "exe": proc.exe(),
                "parent": proc.ppid(),
                "children": children,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_suspicious_connections(self) -> list:
        """Lấy danh sách các kết nối có dấu hiệu đáng ngờ."""
        all_conns = self.get_all_connections()
        return [c for c in all_conns if c.get("suspicious_flags")]

    def get_connection_summary(self) -> dict:
        """Tóm tắt thống kê kết nối."""
        all_conns = self.get_all_connections()
        suspicious = [c for c in all_conns if c.get("suspicious_flags")]

        # Top processes by connection count
        proc_counts = {}
        for conn in all_conns:
            name = conn["process"].get("name", "UNKNOWN")
            proc_counts[name] = proc_counts.get(name, 0) + 1

        return {
            "total_connections": len(all_conns),
            "suspicious_count": len(suspicious),
            "top_processes": sorted(proc_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            "connections": all_conns
        }
