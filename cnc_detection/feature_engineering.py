import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split

# Đảm bảo tính tái lập cho báo cáo nghiên cứu khoa học
np.random.seed(42)

class CNCFeatureEngineer:
    def __init__(self, input_path='d:/NCKH/cnc_detection/output', output_path='./matrix'):
        self.input_path = input_path
        self.output_path = output_path
        self.scaler = MinMaxScaler()
        self.label_encoders = {}
        os.makedirs(self.output_path, exist_ok=True)

    def load_data(self):
        # Đọc dữ liệu đã được làm sạch từ Giai đoạn 1 (Docker/Zeek)
        csv_file = os.path.join(self.input_path, 'clean_botnet_data.csv')
        if not os.path.exists(csv_file):
            raise FileNotFoundError(f"Khong tim thay file {csv_file}. Vui long chay Giai doan 1 (Docker) truoc.")
        return pd.read_csv(csv_file)

    def extract_time_series_features(self, df):
        print("[*] Dang trich xuat dac trung Time-series (IAT & Byte Rates)...")
        # Gia dinh thoi diem (ts) da duoc xu ly hoac dung index lam thu tu thoi gian
        # Tinh toan IAT (Inter-Arrival Time) neu co cot ts
        if 'ts' in df.columns:
            df['iat'] = df['ts'].diff().fillna(0)
        else:
            # Neu khong co ts, ta dung duration lam dac trung thoi gian chinh
            df['iat'] = df['duration'].rolling(window=2).mean().fillna(0)
        
        # Byte rate - Mat do du lieu
        df['byte_rate'] = (df['orig_bytes'] + df['resp_bytes']) / (df['duration'] + 1e-6)
        return df

    def process_and_save(self):
        try:
            df = self.load_data()
            df = self.extract_time_series_features(df)

            # Tao nhãn gia dinh cho mục đích training (Trong thuc te lay tu ground truth CTU-13)
            # Label = 1 neu byte_rate > ngưỡng (gia dinh) hoac lay tu cot label goc
            if 'label' not in df.columns:
                df['label'] = np.where(df['byte_rate'] > df['byte_rate'].mean(), 1, 0)

            # Chon cac dac trung quan trong nhat cho LSTM
            features = ['proto_num', 'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'byte_rate']
            X = df[features].values
            y = df['label'].values

            # Chuan hoa ve khoang [0, 1] cho Neural Network
            X = self.scaler.fit_transform(X)

            # Reshape cho LSTM: (Samples, Time_steps, Features)
            # Thiet lap window_size = 1 (Stateful LSTM co the tang sau nay)
            X = X.reshape(X.shape[0], 1, X.shape[1])

            # Chia tap huan luyen va kiem thu
            X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

            # Luu ma tran NumPy de nạp nhanh vao PyTorch
            np.save(os.path.join(self.output_path, 'X_train.npy'), X_train.astype(np.float32))
            np.save(os.path.join(self.output_path, 'y_train.npy'), y_train.astype(np.float32))
            np.save(os.path.join(self.output_path, 'X_val.npy'), X_val.astype(np.float32))
            np.save(os.path.join(self.output_path, 'y_val.npy'), y_val.astype(np.float32))
            
            print(f"[SUCCESS] Da luu ma tran NumPy tai {self.output_path}")
        except Exception as e:
            print(f"[ERROR] Loi tai Giai doan 2: {e}")

if __name__ == "__main__":
    engineer = CNCFeatureEngineer()
    engineer.process_and_save()
