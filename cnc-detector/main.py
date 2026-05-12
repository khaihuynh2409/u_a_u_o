import customtkinter as ctk
import threading
import time
from datetime import datetime
from PIL import Image, ImageTk
import sys
import os
from tkinter import ttk
import tkinter as tk
import csv
from tkinter import filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from modules.flow_analyzer import FlowAnalyzer
from modules.dga_detector import DGADetector
from modules.threat_intel import ThreatIntelligence
from modules.process_mapper import ProcessMapper
from modules.risk_scorer import RiskScorer
from modules.packet_sniffer import PacketSniffer

# Thiết lập theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CNCDetectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Init modules
        self.flow_analyzer = FlowAnalyzer()
        self.dga_detector = DGADetector()
        self.threat_intel = ThreatIntelligence()
        self.process_mapper = ProcessMapper()
        self.risk_scorer = RiskScorer()
        self.sniffer = PacketSniffer(callback=self.on_packet_captured)
        
        self.title("C&C Server Detection System - Advanced AI Edition")
        self.geometry("1280x720")
        
        # Giao diện chính siêu tối
        self.configure(fg_color="#020617")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Biến trạng thái
        self.is_running = False
        self.stats = {"flows": 0, "malicious": 0, "dga": 0}
        self.packet_features_map = {}
        self.all_alerts = []
        
        # Cấu trúc UI
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.create_sidebar()
        self.create_main_panel()
        
        # Tải mô hình bất đồng bộ
        threading.Thread(target=self.load_models, daemon=True).start()

    def load_models(self):
        self.log_message("System", "Đang tải mô hình XGBoost...")
        self.flow_analyzer.load()
        self.log_message("System", "Đang tải mô hình Bi-LSTM...")
        self.dga_detector.load()
        self.log_message("System", "Khởi tạo hệ thống hoàn tất. Sẵn sàng hoạt động.")
        self.btn_start.configure(state="normal")

    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkScrollableFrame(self, width=300, corner_radius=0, fg_color="#0f172a", border_width=0, scrollbar_button_color="#1e293b", scrollbar_button_hover_color="#334155")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ C&C DETECTOR", font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"), text_color="#38bdf8")
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 15))

        # Mode Selection
        self.mode_var = ctk.StringVar(value="demo_mixed")
        self.lbl_mode = ctk.CTkLabel(self.sidebar_frame, text="Chế độ hoạt động:")
        self.lbl_mode.grid(row=1, column=0, padx=20, pady=(5, 0), sticky="w")
        
        self.opt_mode = ctk.CTkOptionMenu(
            self.sidebar_frame, 
            variable=self.mode_var,
            values=["demo_mixed", "demo_clean", "demo_malicious", "live_capture"]
        )
        self.opt_mode.grid(row=2, column=0, padx=20, pady=(5, 5), sticky="ew")

        # Controls
        self.btn_start = ctk.CTkButton(
            self.sidebar_frame, text="▶ BẮT ĐẦU GIÁM SÁT", font=ctk.CTkFont(weight="bold"),
            command=self.toggle_sniffing, state="disabled", 
            fg_color="transparent", border_width=2, border_color="#10b981", text_color="#10b981", hover_color="#064e3b"
        )
        self.btn_start.grid(row=3, column=0, padx=20, pady=(15, 5), sticky="ew")

        self.btn_chart = ctk.CTkButton(
            self.sidebar_frame, text="📊 XEM BIỂU ĐỒ", font=ctk.CTkFont(weight="bold"),
            command=self.show_chart, 
            fg_color="transparent", border_width=2, border_color="#38bdf8", text_color="#38bdf8", hover_color="#0c4a6e"
        )
        self.btn_chart.grid(row=4, column=0, padx=20, pady=5, sticky="ew")

        self.btn_export = ctk.CTkButton(
            self.sidebar_frame, text="💾 XUẤT CSV", font=ctk.CTkFont(weight="bold"),
            command=self.export_csv, 
            fg_color="transparent", border_width=2, border_color="#c084fc", text_color="#c084fc", hover_color="#4c1d95"
        )
        self.btn_export.grid(row=5, column=0, padx=20, pady=(5, 10), sticky="ew")

        # Stats
        self.stats_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="#1e293b", corner_radius=8, border_width=1, border_color="#334155")
        self.stats_frame.grid(row=6, column=0, padx=15, pady=5, sticky="nsew")
        
        ctk.CTkLabel(self.stats_frame, text="THỐNG KÊ HỆ THỐNG", font=ctk.CTkFont(size=13, weight="bold"), text_color="#94a3b8").pack(pady=(5, 2))
        self.lbl_flows = ctk.CTkLabel(self.stats_frame, text="Luồng mạng: 0", font=ctk.CTkFont(size=13))
        self.lbl_flows.pack(anchor="w", padx=15, pady=0)
        
        self.lbl_malicious = ctk.CTkLabel(self.stats_frame, text="Nghi ngờ C&C: 0", text_color="#ef4444", font=ctk.CTkFont(size=13, weight="bold"))
        self.lbl_malicious.pack(anchor="w", padx=15, pady=0)
        
        self.lbl_dga = ctk.CTkLabel(self.stats_frame, text="Phát hiện DGA: 0", text_color="#f59e0b", font=ctk.CTkFont(size=13, weight="bold"))
        self.lbl_dga.pack(anchor="w", padx=15, pady=(0, 5))

        # Packet Params Stats
        self.packet_stats_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="#1e293b", corner_radius=8, border_width=1, border_color="#334155")
        self.packet_stats_frame.grid(row=7, column=0, padx=15, pady=(5, 10), sticky="nsew")
        
        ctk.CTkLabel(self.packet_stats_frame, text="THÔNG SỐ GÓI TIN", font=ctk.CTkFont(size=14, weight="bold"), text_color="#94a3b8").pack(pady=(10, 5))
        
        self.param_labels = {}
        self.params_to_show = [
            "Duration (ms)", "Bytes/sec", "Packets/sec", "Fwd Packets", 
            "Bwd Packets", "Pkt Len Mean", "Flow IAT Mean", "SYN Flags", "ACK Flags"
        ]
        for p in self.params_to_show:
            lbl = ctk.CTkLabel(self.packet_stats_frame, text=f"{p}: N/A", font=ctk.CTkFont(size=14))
            lbl.pack(anchor="w", padx=15, pady=3)
            self.param_labels[p] = lbl

    def update_packet_stats(self, flow_features):
        if not flow_features:
            return
            
        params = {
            "Duration (ms)": ("flow_duration", flow_features.get("flow_duration", 0), lambda x: "red" if x > 200000 else "yellow" if x > 100000 else "white"),
            "Bytes/sec": ("flow_bytes_per_sec", flow_features.get("flow_bytes_per_sec", 0), lambda x: "red" if x < 20 else "yellow" if x < 100 else "white"),
            "Packets/sec": ("flow_packets_per_sec", flow_features.get("flow_packets_per_sec", 0), lambda x: "red" if x < 0.1 else "yellow" if x < 1 else "white"),
            "Fwd Packets": ("total_fwd_packets", flow_features.get("total_fwd_packets", 0), lambda x: "white"),
            "Bwd Packets": ("total_bwd_packets", flow_features.get("total_bwd_packets", 0), lambda x: "white"),
            "Pkt Len Mean": ("packet_length_mean", flow_features.get("packet_length_mean", 0), lambda x: "white"),
            "Flow IAT Mean": ("flow_iat_mean", flow_features.get("flow_iat_mean", 0), lambda x: "red" if x > 50000 else "yellow" if x > 20000 else "white"),
            "SYN Flags": ("syn_flag_count", flow_features.get("syn_flag_count", 0), lambda x: "red" if x > 10 else "white"),
            "ACK Flags": ("ack_flag_count", flow_features.get("ack_flag_count", 0), lambda x: "white"),
        }
        
        for ui_name, (key, value, color_func) in params.items():
            if ui_name in self.param_labels:
                color = color_func(value)
                hex_color = "#f8fafc" # default white
                if color == "red": hex_color = "#ef4444"
                elif color == "yellow": hex_color = "#facc15"
                
                if isinstance(value, float):
                    val_str = f"{value:.2f}"
                else:
                    val_str = str(value)
                    
                self.param_labels[ui_name].configure(text=f"{ui_name}: {val_str}", text_color=hex_color)

    def on_packet_select(self, event):
        selected_items = self.packet_table.selection()
        if not selected_items:
            return
        item_id = selected_items[0]
        flow_features = self.packet_features_map.get(item_id)
        if flow_features is not None:
            self.update_packet_stats(flow_features)

    def create_main_panel(self):
        self.main_frame = ctk.CTkFrame(self, corner_radius=15, fg_color="#020617")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Header
        self.header_label = ctk.CTkLabel(self.main_frame, text="LIVE NETWORK MONITOR", font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"), text_color="#f8fafc")
        self.header_label.grid(row=0, column=0, padx=10, pady=(0, 20), sticky="w")

        # Packet Table Area (Treeview)
        self.table_frame = ctk.CTkFrame(self.main_frame, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#334155")
        self.table_frame.grid(row=1, column=0, padx=10, pady=(0, 20), sticky="nsew")
        self.table_frame.grid_columnconfigure(0, weight=1)
        self.table_frame.grid_rowconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("default")
        
        # Cấu hình thanh cuộn
        style.configure("Vertical.TScrollbar", background="#1e293b", bordercolor="#0f172a", arrowcolor="white", troughcolor="#0f172a")

        style.configure("Treeview", 
                        background="#0f172a", foreground="#cbd5e1", 
                        rowheight=35, fieldbackground="#0f172a", 
                        font=("Consolas", 11), borderwidth=0)
        style.configure("Treeview.Heading", background="#1e293b", foreground="#38bdf8", font=("Segoe UI", 12, "bold"), borderwidth=0, padding=5)
        style.map("Treeview.Heading", background=[("active", "#334155")])
        style.map("Treeview", background=[("selected", "#0ea5e9")])

        columns = ("Time", "Process", "Target IP", "Port", "Domain", "Risk", "Level")
        self.packet_table = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        for col in columns:
            self.packet_table.heading(col, text=col)
        
        self.packet_table.column("Time", width=90, anchor="center")
        self.packet_table.column("Process", width=140)
        self.packet_table.column("Target IP", width=120, anchor="center")
        self.packet_table.column("Port", width=60, anchor="center")
        self.packet_table.column("Domain", width=200)
        self.packet_table.column("Risk", width=60, anchor="center")
        self.packet_table.column("Level", width=100, anchor="center")

        scrollbar = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.packet_table.yview)
        self.packet_table.configure(yscrollcommand=scrollbar.set)
        
        self.packet_table.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Bắt sự kiện click vào Treeview
        self.packet_table.bind("<<TreeviewSelect>>", self.on_packet_select)
        
        self.packet_table.tag_configure('CRITICAL', background='#7f1d1d', foreground='#fca5a5') # Dark red / Light red
        self.packet_table.tag_configure('HIGH', background='#7c2d12', foreground='#fdba74') # Dark orange
        self.packet_table.tag_configure('MEDIUM', background='#713f12', foreground='#fde047') # Dark yellow
        self.packet_table.tag_configure('LOW', background='#1e3a8a', foreground='#93c5fd') # Dark blue
        self.packet_table.tag_configure('SAFE', background='#0f172a', foreground='#86efac') # Default / Light green
        self.packet_table.tag_configure('SYSTEM', background='#1e293b', foreground='#94a3b8') # Grayish

        # Alerts Panel (Bottom)
        self.alert_frame = ctk.CTkFrame(self.main_frame, height=220, fg_color="#1e293b", corner_radius=10, border_width=1, border_color="#ef4444")
        self.alert_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.alert_frame.grid_propagate(False)
        
        ctk.CTkLabel(self.alert_frame, text="🚨 CẢNH BÁO BẢO MẬT HỆ THỐNG (CRITICAL/HIGH)", text_color="#ef4444", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        self.alert_textbox = ctk.CTkTextbox(self.alert_frame, font=ctk.CTkFont(family="Consolas", size=14), fg_color="#0f172a", text_color="#f8fafc", border_width=0)
        self.alert_textbox.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.alert_textbox.configure(state="disabled")

    def toggle_sniffing(self):
        if not self.is_running:
            mode = self.mode_var.get()
            self.log_message("System", f"Bắt đầu giám sát (Mode: {mode})...")
            self.btn_start.configure(text="⏹ DỪNG GIÁM SÁT", fg_color="transparent", border_color="#ef4444", text_color="#ef4444", hover_color="#7f1d1d")
            self.is_running = True
            
            if mode.startswith("demo"):
                scenario = mode.split("_")[1]
                self.sniffer.start_demo(scenario=scenario, interval=1.5)
            else:
                self.sniffer.start_live()
        else:
            self.log_message("System", "Dừng giám sát.")
            self.btn_start.configure(text="▶ BẮT ĐẦU GIÁM SÁT", fg_color="transparent", border_color="#10b981", text_color="#10b981", hover_color="#064e3b")
            self.is_running = False
            self.sniffer.stop()

    def on_packet_captured(self, flow_data):
        # Hàm này được gọi từ thread khác, dùng after để update UI
        self.after(0, self.process_flow, flow_data)

    def process_flow(self, flow_data):
        self.stats["flows"] += 1
        self.lbl_flows.configure(text=f"Luồng mạng: {self.stats['flows']}")

        # 1. Phân tích XGBoost Flow
        flow_features = flow_data.get("flow", {})
        flow_res = self.flow_analyzer.predict(flow_features)
        
        # 2. Phân tích DGA Domain
        domain = flow_data.get("domain", "")
        dga_res = None
        if domain:
            dga_res = self.dga_detector.predict(domain)
            if dga_res["is_dga"]:
                self.stats["dga"] += 1
                self.lbl_dga.configure(text=f"Phát hiện DGA: {self.stats['dga']}")
                
        # 3. Phân tích Threat Intel
        ip = flow_data.get("remote_ip", "")
        ti_res = None
        if ip:
             ti_res = self.threat_intel.check_ip(ip)

        # 4. Phân tích Process (Masquerading)
        process_name = flow_data.get("process", "UNKNOWN")
        pid = flow_data.get("pid", -1)
        # Giả lập cờ process cho demo
        proc_flags = []
        if process_name in ["svchost32.exe", "explorer32.exe", "powershell.exe"]:
             proc_flags.append(f"⚠️ Process bất thường: {process_name}")

        # 5. Tổng hợp điểm rủi ro
        context = {
            "remote_ip": ip,
            "remote_port": flow_data.get("remote_port", 0),
            "domain": domain,
            "process_name": process_name,
            "process_pid": pid
        }
        
        # Tính toán Ensemble Score
        alert_record = self.risk_scorer.calculate(
            flow_result=flow_res,
            dga_result=dga_res,
            threat_intel_result=ti_res,
            process_flags=proc_flags,
            context=context
        )

        self.update_ui_logs(flow_data, alert_record)

    def update_ui_logs(self, flow_data, alert):
        ts = alert.timestamp
        ip = alert.remote_ip
        port = alert.remote_port
        domain = alert.domain if alert.domain else "N/A"
        proc = alert.process_name
        score = alert.risk_score
        
        # Thêm row vào Table thay vì in ra Textbox
        row_values = (ts, proc, ip, port, domain, f"{score:.1f}", alert.alert_level)
        item_id = self.packet_table.insert("", "end", values=row_values, tags=(alert.alert_level,))
        
        self.all_alerts.append({
            "Time": ts, "Process": proc, "IP": ip, "Port": port, 
            "Domain": domain, "Risk": score, "Level": alert.alert_level
        })
        
        # Lưu lại flow_features để hiển thị khi click
        flow_features = flow_data.get("flow", {})
        self.packet_features_map[item_id] = flow_features
        
        # Xóa dòng cũ nếu bảng quá dài (chống giật)
        if len(self.packet_table.get_children()) > 1000:
            old_item_id = self.packet_table.get_children()[0]
            self.packet_table.delete(old_item_id)
            self.packet_features_map.pop(old_item_id, None)
            
        # Cuộn bảng xuống cuối
        self.packet_table.yview_moveto(1)

        # Nếu có cảnh báo cao
        if alert.alert_level in ["CRITICAL", "HIGH"]:
            self.stats["malicious"] += 1
            self.lbl_malicious.configure(text=f"Nghi ngờ C&C: {self.stats['malicious']}")
            
            alert_msg = f"[{ts}] 🚨 PHÁT HIỆN C&C - MỨC {alert.alert_level} ({score:.1f}/100)\n"
            alert_msg += f"   ├── Target: {ip}:{port} ({domain})\n"
            alert_msg += f"   ├── Process: {proc} (PID: {alert.process_pid})\n"
            if alert.malware_family != "Unknown":
                alert_msg += f"   ├── Malware Family: {alert.malware_family}\n"
            for detail in alert.details:
                alert_msg += f"   ├── {detail}\n"
            alert_msg += "\n"
            
            self.alert_textbox.configure(state="normal")
            self.alert_textbox.insert("end", alert_msg)
            self.alert_textbox.see("end")
            self.alert_textbox.configure(state="disabled")

    def log_message(self, source, message):
        ts = datetime.now().strftime("%H:%M:%S")
        # Thêm system log vào bảng
        row_values = (ts, f"[{source}]", "N/A", "-", message, "0.0", "SYSTEM")
        self.packet_table.insert("", "end", values=row_values, tags=('SYSTEM',))
        self.packet_table.yview_moveto(1)

    def log_message_raw(self, msg):
        pass

    def export_csv(self):
        if not self.all_alerts:
            self.log_message("System", "Không có dữ liệu để xuất CSV.")
            return
            
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Lưu báo cáo C&C"
        )
        if not filepath:
            return
            
        try:
            with open(filepath, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["Time", "Process", "IP", "Port", "Domain", "Risk", "Level"])
                writer.writeheader()
                writer.writerows(self.all_alerts)
            self.log_message("System", f"Đã xuất file CSV thành công: {filepath}")
        except Exception as e:
            self.log_message("System", f"Lỗi xuất CSV: {e}")

    def show_chart(self):
        if not self.all_alerts:
            self.log_message("System", "Không có dữ liệu để vẽ biểu đồ.")
            return
            
        chart_window = ctk.CTkToplevel(self)
        chart_window.title("Biểu Đồ Phân Bố Mức Độ Rủi Ro")
        chart_window.geometry("600x450")
        chart_window.attributes("-topmost", True)
        
        scores = [item["Risk"] for item in self.all_alerts]
        
        fig, ax = plt.subplots(figsize=(6, 4))
        # Theme tối cho matplotlib
        fig.patch.set_facecolor('#2b2b2b')
        ax.set_facecolor('#2b2b2b')
        ax.tick_params(colors='white')
        ax.xaxis.label.set_color('white')
        ax.yaxis.label.set_color('white')
        ax.title.set_color('white')
        
        ax.hist(scores, bins=20, color='#e74c3c', edgecolor='black', alpha=0.8)
        ax.set_title("Phân Bố Điểm Rủi Ro (Risk Score)")
        ax.set_xlabel("Điểm Rủi Ro (0-100)")
        ax.set_ylabel("Số lượng kết nối")
        ax.grid(True, linestyle='--', alpha=0.3, color='gray')
        
        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

    def on_closing(self):
        if self.is_running:
            self.sniffer.stop()
        self.destroy()

if __name__ == "__main__":
    app = CNCDetectorApp()
    app.mainloop()
