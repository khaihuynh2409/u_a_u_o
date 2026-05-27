import pandas as pd
import numpy as np
from pathlib import Path
import json

NB = Path("train_models.ipynb")
with open(NB, encoding="utf-8") as f:
    nb = json.load(f)

# Trích xuất constants
BOTNET_LABELS = ['Bot', 'BOTNET', 'Botnet', 'C&C', 'C2']
BENIGN_LABELS = ['BENIGN', 'Benign', 'benign']
FLOW_FEATURES = [
    'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
    'fwd_packet_length_mean', 'bwd_packet_length_mean',
    'flow_bytes_per_sec', 'flow_packets_per_sec',
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
    'fwd_iat_mean', 'fwd_iat_std', 'bwd_iat_mean',
    'fwd_psh_flags', 'bwd_psh_flags',
    'fwd_header_length', 'bwd_header_length',
    'fwd_packets_per_sec', 'bwd_packets_per_sec',
    'min_packet_length', 'max_packet_length',
    'packet_length_mean', 'packet_length_std', 'packet_length_variance',
    'fin_flag_count', 'syn_flag_count', 'rst_flag_count',
    'ack_flag_count', 'urg_flag_count',
    'avg_fwd_segment_size', 'avg_bwd_segment_size',
    'active_mean', 'idle_mean',
]
CICIDS_COLUMN_MAP = {
    'Flow Duration'          : 'flow_duration',
    'Total Fwd Packets'      : 'total_fwd_packets',
    'Total Backward Packets' : 'total_bwd_packets',
    'Fwd Packet Length Mean' : 'fwd_packet_length_mean',
    'Bwd Packet Length Mean' : 'bwd_packet_length_mean',
    'Flow Bytes/s'           : 'flow_bytes_per_sec',
    'Flow Packets/s'         : 'flow_packets_per_sec',
    'Flow IAT Mean'          : 'flow_iat_mean',
    'Flow IAT Std'           : 'flow_iat_std',
    'Flow IAT Max'           : 'flow_iat_max',
    'Flow IAT Min'           : 'flow_iat_min',
    'Fwd IAT Mean'           : 'fwd_iat_mean',
    'Fwd IAT Std'            : 'fwd_iat_std',
    'Bwd IAT Mean'           : 'bwd_iat_mean',
    'Fwd PSH Flags'          : 'fwd_psh_flags',
    'Bwd PSH Flags'          : 'bwd_psh_flags',
    'Fwd Header Length'      : 'fwd_header_length',
    'Bwd Header Length'      : 'bwd_header_length',
    'Fwd Packets/s'          : 'fwd_packets_per_sec',
    'Bwd Packets/s'          : 'bwd_packets_per_sec',
    'Min Packet Length'      : 'min_packet_length',
    'Max Packet Length'      : 'max_packet_length',
    'Packet Length Mean'     : 'packet_length_mean',
    'Packet Length Std'      : 'packet_length_std',
    'Packet Length Variance' : 'packet_length_variance',
    'FIN Flag Count'         : 'fin_flag_count',
    'SYN Flag Count'         : 'syn_flag_count',
    'RST Flag Count'         : 'rst_flag_count',
    'ACK Flag Count'         : 'ack_flag_count',
    'URG Flag Count'         : 'urg_flag_count',
    'Average Packet Size'    : 'packet_length_mean',
    'Avg Fwd Segment Size'   : 'avg_fwd_segment_size',
    'Avg Bwd Segment Size'   : 'avg_bwd_segment_size',
    'Active Mean'            : 'active_mean',
    'Idle Mean'              : 'idle_mean'
}

# Ham preprocess moi nhat
def preprocess_cicids(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()
    df = df.copy()
    df.columns = df.columns.str.strip()

    label_col = next((c for c in df.columns if 'label' in c.lower()), None)
    if label_col is None:
        raise ValueError('Không tìm thấy cột nhãn trong CICIDS2017')

    labels = df[label_col].apply(lambda x: 1 if str(x).strip() in BOTNET_LABELS else 0)

    renamed = df.rename(columns=CICIDS_COLUMN_MAP)
    renamed = renamed.loc[:, ~renamed.columns.duplicated(keep='first')]

    feat_dict = {}
    for f in FLOW_FEATURES:
        if f in renamed.columns:
            col = renamed[f]
            if isinstance(col, pd.DataFrame):
                col = col.iloc[:, 0]
            feat_dict[f] = pd.to_numeric(col, errors='coerce') \
                             .replace([np.inf, -np.inf], np.nan).fillna(0)
        else:
            feat_dict[f] = pd.Series(0.0, index=df.index)

    result = pd.DataFrame(feat_dict, index=df.index)
    result['label'] = labels.values
    return result

DATA_DIR = Path("dataset/CIC-IDS2017")
csv_files = sorted(DATA_DIR.glob('*.csv'))

print(f"Testing {len(csv_files)} files...")
for f in csv_files:
    try:
        df = pd.read_csv(f, low_memory=False, nrows=500)
        print(f"Testing {f.name} (shape: {df.shape})")
        df.columns = df.columns.str.strip()
        lc = next((c for c in df.columns if 'label' in c.lower()), None)
        if lc:
            mask = df[lc].isin(BOTNET_LABELS + BENIGN_LABELS)
            kept = mask.sum()
            if kept > 0:
                df = df[mask]
                df_proc = preprocess_cicids(df)
                print(f"  -> SUCCESS! Output shape: {df_proc.shape}")
            else:
                print("  -> SKIPPED (No Bot/Benign)")
    except Exception as e:
        print(f"  -> ERROR: {e}")
        import traceback
        traceback.print_exc()

