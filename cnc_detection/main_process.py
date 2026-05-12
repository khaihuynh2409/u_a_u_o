import os
import subprocess
import pandas as pd
import numpy as np
import requests
import bz2
from tqdm import tqdm
import shutil

class BotnetDataPipeline:
    def __init__(self):
        self.pcap_dir = "./pcaps"
        self.output_dir = "/app/output"
        self.temp_dir = "./temp_logs"
        os.makedirs(self.pcap_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)

    def download_ctu13(self):
        """Tải kịch bản 1 và 2 của tập dữ liệu CTU-13."""
        urls = {
            "scenario_1": "https://mcfp.felk.cvut.cz/datasets/CTU-13-Dataset/1/capture20110810.pcap.bz2",
            "scenario_2": "https://mcfp.felk.cvut.cz/datasets/CTU-13-Dataset/2/capture20110811.pcap.bz2"
        }
        
        for name, url in urls.items():
            target = os.path.join(self.pcap_dir, f"{name}.pcap")
            if not os.path.exists(target):
                print(f"[*] Đang tải {name}...")
                bz2_file = target + ".bz2"
                
                # Tải file với stream để tiết kiệm RAM
                r = requests.get(url, stream=True)
                total_size = int(r.headers.get('content-length', 0))
                with open(bz2_file, 'wb') as f, tqdm(
                    total=total_size, unit='B', unit_scale=True, desc=name
                ) as pbar:
                    for chunk in r.iter_content(chunk_size=1024*1024):
                        f.write(chunk)
                        pbar.update(len(chunk))
                
                # Giải nén PCAP
                print(f"[*] Đang giải nén {name} (PCAP)...")
                with bz2.open(bz2_file, "rb") as f_in, open(target, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove(bz2_file)
            else:
                print(f"[!] File {name}.pcap đã tồn tại, bỏ qua bước tải.")

    def run_zeek_and_clean(self):
        """Sử dụng Zeek để phân tích và trích xuất đặc trưng số học."""
        pcap_files = [f for f in os.listdir(self.pcap_dir) if f.endswith(".pcap")]
        all_frames = []

        for pcap in pcap_files:
            pcap_path = os.path.join(self.pcap_dir, pcap)
            print(f"\n[*] Zeek đang phân tích gói tin: {pcap}")
            
            # Tạo thư mục tạm cho mỗi lần chạy Zeek
            if os.path.exists(self.temp_dir): shutil.rmtree(self.temp_dir)
            os.makedirs(self.temp_dir)
            
            # Thực thi Zeek
            try:
                subprocess.run(["zeek", "-r", pcap_path, "local"], cwd=self.temp_dir, check=True)
            except subprocess.CalledProcessError as e:
                print(f"  [!] Lỗi khi chạy Zeek cho {pcap}: {e}")
                continue

            # Đọc conn.log - Nhật ký kết nối chính
            conn_log = os.path.join(self.temp_dir, "conn.log")
            if os.path.exists(conn_log):
                # Zeek log có format TSV đặc thù, skip header lines
                df = pd.read_csv(conn_log, sep='\t', skiprows=8, skipfooter=1, engine='python')
                df.columns = [c.replace('#fields.', '') for c in df.columns]
                all_frames.append(df)

        if not all_frames:
            print("[!] Không có dữ liệu nào được trích xuất.")
            return

        # Tổng hợp dữ liệu từ tất cả các scenarios
        print("\n[*] Đang tổng hợp và làm sạch dữ liệu...")
        final_df = pd.concat(all_frames, ignore_index=True)

        # --- GIAI ĐOẠN VECTOR HÓA (Chuẩn bị cho Deep Learning) ---
        # 1. Xử lý giá trị thiếu
        final_df = final_df.replace('-', '0')

        # 2. Lựa chọn các đặc trưng số học quan trọng (Features)
        # Các đặc trưng này phản ánh hành vi mạng của Botnet
        numerical_features = [
            'duration', 'orig_bytes', 'resp_bytes', 
            'orig_pkts', 'resp_pkts', 
            'orig_ip_bytes', 'resp_ip_bytes'
        ]
        
        for col in numerical_features:
            final_df[col] = pd.to_numeric(final_df[col], errors='coerce').fillna(0)

        # 3. Mã hóa giao thức (Protocol Encoding)
        # Deep Learning yêu cầu đầu vào là số, không phải chuỗi "tcp/udp"
        proto_map = {'tcp': 1, 'udp': 2, 'icmp': 3}
        final_df['proto_num'] = final_df['proto'].map(proto_map).fillna(0)

        # 4. Xuất dữ liệu sạch ra thư mục chung với Windows
        output_file = os.path.join(self.output_dir, "clean_botnet_data.csv")
        final_cols = ['proto_num'] + numerical_features
        
        # Đảm bảo dữ liệu đầu ra là ma trận số thuần túy
        final_df[final_cols].to_csv(output_file, index=False)
        
        print("-" * 50)
        print(f" [SUCCESS] Pipeline hoàn thành xuất sắc!")
        print(f" [INFO] File kết quả: {output_file}")
        print(f" [INFO] Số lượng mẫu (Samples): {len(final_df)}")
        print("-" * 50)

if __name__ == "__main__":
    pipeline = BotnetDataPipeline()
    pipeline.download_ctu13()
    pipeline.run_zeek_and_clean()
