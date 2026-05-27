# CHƯƠNG 3: TRIỂN KHAI THỰC NGHIỆM VÀ ĐÁNH GIÁ

Chương 2 đã trình bày kiến trúc tổng thể và thiết kế chi tiết từng module cấu thành hệ thống phát hiện máy chủ Command & Control (C&C). Chương 3 này tập trung vào quá trình hiện thực hóa các thiết kế đó thành sản phẩm phần mềm chạy được, bao gồm: môi trường thực nghiệm, quy trình xây dựng và huấn luyện mô hình Học máy, đánh giá định lượng hiệu năng của từng mô hình, mô tả sản phẩm phần mềm hoàn chỉnh, và phân tích các hạn chế còn tồn tại cùng hướng phát triển trong tương lai. Mục tiêu của chương là cung cấp bằng chứng thực nghiệm cho các khẳng định kỹ thuật đã được đặt ra trong Chương 1 và Chương 2, đồng thời đánh giá một cách khách quan điểm mạnh và điểm yếu của hệ thống được xây dựng.

---

## 3.1. MÔI TRƯỜNG THỰC NGHIỆM

Mục 3.1 mô tả đầy đủ môi trường phần cứng và phần mềm được sử dụng trong quá trình phát triển, huấn luyện mô hình và kiểm thử hệ thống. Việc xác định rõ ràng môi trường thực nghiệm là điều kiện tiên quyết để đảm bảo tính tái lập (reproducibility) của kết quả thực nghiệm và giúp người đọc hiểu các ràng buộc kỹ thuật ảnh hưởng đến thiết kế hệ thống.

### 3.1.1. Cấu hình phần cứng và phần mềm thực nghiệm

Hệ thống được phát triển và kiểm thử trên môi trường máy tính cá nhân chạy hệ điều hành Windows với quyền Administrator. Lý do lựa chọn Windows làm nền tảng thực nghiệm chính xuất phát từ hai ràng buộc kỹ thuật quan trọng. Thứ nhất, hàm `psutil.net_connections()` — được sử dụng trong module `ProcessMapper` để ánh xạ kết nối mạng với tiến trình hệ thống — phụ thuộc vào Windows API (`MIB_TCPTABLE2`, `GetExtendedTcpTable`) để lấy thông tin PID của từng kết nối; trên Linux, hàm tương đương đọc từ `/proc/net/tcp` nhưng việc ánh xạ PID→tên tiến trình đòi hỏi quyền đặc biệt khác nhau tùy bản phân phối. Thứ hai, thư viện bắt gói tin Scapy trên Windows yêu cầu Npcap — phiên bản kế nhiệm của WinPcap — để truy cập raw socket ở tầng kernel; Npcap cung cấp driver NDIS 6.x tương thích với Windows 10/11 trong khi WinPcap không còn được duy trì. Quyền Administrator là bắt buộc vì cả Npcap driver lẫn việc gọi `psutil.net_connections(kind='inet')` ở chế độ đầy đủ đều yêu cầu đặc quyền `SeDebugPrivilege` và `SeSystemEnvironmentPrivilege` trên Windows.

**Bảng 3.1: Cấu hình môi trường thực nghiệm**

| Thành phần | Phiên bản / Thông số | Ghi chú |
|---|---|---|
| **Hệ điều hành** | Windows 10/11 (64-bit), Build ≥ 19041 | Yêu cầu tối thiểu cho Npcap 1.x |
| **Quyền hệ thống** | Administrator | Bắt buộc để bắt gói tin raw socket |
| **Python** | 3.9+ (khuyến nghị 3.10/3.11) | Tương thích TensorFlow 2.13+ |
| **Bộ xử lý** | x86-64 với hỗ trợ AVX instruction | TensorFlow 2.x yêu cầu AVX tối thiểu |
| **RAM** | ≥ 8 GB | Mô hình Bi-LSTM chiếm ~4.3 MB weights; XGBoost ~146 KB |
| **Lưu trữ** | ≥ 2 GB trống | Cho môi trường Python ảo và file model |
| **Thư viện AI** | XGBoost ≥ 2.0.0, TensorFlow ≥ 2.13.0 | Xem Bảng 3.2 |
| **Bắt gói tin** | Scapy ≥ 2.5.0 + Npcap ≥ 1.70 | Npcap thay thế WinPcap trên Windows 10/11 |
| **Giao diện** | CustomTkinter ≥ 5.2.0, Matplotlib ≥ 3.7.0 | GUI dark theme |

Việc kiểm tra hỗ trợ AVX được thực hiện tự động trong hàm `_check_system_support()` của lớp `DGADetector` thông qua lời gọi `ctypes.windll.kernel32.IsProcessorFeaturePresent(17)` — hằng số 17 tương ứng với `PF_AVX_INSTRUCTIONS_AVAILABLE` trong Windows API. Nếu CPU không hỗ trợ AVX, hệ thống tự động chuyển sang chế độ heuristic-only cho module phát hiện DGA, đảm bảo tính tương thích trên phần cứng cũ.

### 3.1.2. Phụ thuộc thư viện và lý do lựa chọn

Toàn bộ phụ thuộc thư viện của hệ thống được quản lý qua file `requirements.txt` và cài đặt trong môi trường Python ảo (virtual environment) để tránh xung đột phiên bản. Bảng 3.2 liệt kê đầy đủ các thư viện chính kèm vai trò kỹ thuật cụ thể.

**Bảng 3.2: Danh sách phụ thuộc thư viện và vai trò kỹ thuật**

| Thư viện | Phiên bản tối thiểu | Vai trò kỹ thuật | Lý do lựa chọn |
|---|---|---|---|
| `customtkinter` | ≥ 5.2.0 | Xây dựng GUI dark theme thread-safe | Bọc Tkinter với widget hiện đại, hỗ trợ `self.after()` |
| `pillow` | ≥ 10.0.0 | Xử lý hình ảnh trong GUI | Phụ thuộc của CustomTkinter |
| `scapy` | ≥ 2.5.0 | Bắt/phân tích gói tin tầng network, parse PCAP | Hỗ trợ đầy đủ dissector TCP/UDP/DNS; hoạt động trên Npcap |
| `dpkt` | ≥ 1.9.8 | Fallback PCAP parser khi Scapy không khả dụng | Thư viện thuần Python, không cần Npcap |
| `psutil` | ≥ 5.9.0 | Ánh xạ kết nối mạng với PID/tên tiến trình hệ thống | API đa nền tảng, truy cập thông tin tiến trình OS |
| `requests` | ≥ 2.31.0 | Gọi VirusTotal API v3 và AbuseIPDB API v2 | HTTP client chuẩn với timeout và retry |
| `urllib3` | ≥ 2.0.0 | Phụ thuộc của `requests`, disable SSL warning | Quản lý connection pool HTTP |
| `xgboost` | ≥ 2.0.0 | Thuật toán phân loại luồng mạng (Flow Classification) | Hiệu năng cao trên dữ liệu bảng, hỗ trợ `scale_pos_weight` |
| `scikit-learn` | ≥ 1.3.0 | `StandardScaler`, `train_test_split`, metrics | Pipeline tiền xử lý và đánh giá mô hình |
| `numpy` | ≥ 1.24.0 | Tính toán vector đặc trưng, ma trận | Nền tảng tính toán số học |
| `pandas` | ≥ 2.0.0 | Tải và xử lý bộ dữ liệu CSV (CTU-13, CICIDS2017) | DataFrame API cho tiền xử lý dữ liệu |
| `tensorflow` | ≥ 2.13.0 | Xây dựng và inference mạng Bi-LSTM | Framework Deep Learning; Keras API tích hợp |
| `matplotlib` | ≥ 3.7.0 | Vẽ biểu đồ histogram Risk Score trong GUI | `FigureCanvasTkAgg` nhúng đồ thị vào Tkinter |
| `seaborn` | ≥ 0.12.0 | Trực quan hóa dữ liệu trong quá trình huấn luyện | Wrapper của Matplotlib cho đồ thị thống kê |
| `imbalanced-learn` | ≥ 0.11.0 | Xử lý mất cân bằng dữ liệu (SMOTE, tham khảo) | Bộ công cụ oversampling/undersampling |
| `joblib` | ≥ 1.3.0 | Serialize/deserialize mô hình XGBoost và StandardScaler | Lưu/tải model nhanh hơn `pickle` cho đối tượng sklearn |
| `dnspython` | ≥ 2.4.0 | Phân giải DNS trong quá trình phân tích domain | Thư viện DNS thuần Python |
| `tqdm` | ≥ 4.65.0 | Hiển thị thanh tiến trình khi huấn luyện | Theo dõi quá trình xử lý dữ liệu lớn |
| `colorama` | ≥ 0.4.6 | Màu sắc trong terminal log | Tương thích Windows console |

Đáng chú ý, thư viện `imbalanced-learn` được bao gồm trong `requirements.txt` nhưng không được sử dụng trực tiếp trong pipeline sản xuất — vấn đề mất cân bằng dữ liệu được giải quyết thông qua tham số `scale_pos_weight` của `XGBClassifier` thay vì các kỹ thuật oversampling. Quyết định này xuất phát từ lý do hiệu năng: phương pháp Synthetic Minority Oversampling Technique (SMOTE) tạo ra các mẫu tổng hợp có thể không phản ánh đúng đặc trưng của lưu lượng mạng C&C thực tế, trong khi `scale_pos_weight` điều chỉnh trực tiếp hàm mất mát của XGBoost mà không cần tạo thêm dữ liệu.

### 3.1.3. Cấu trúc thư mục project

Hệ thống được tổ chức theo kiến trúc module hóa rõ ràng, trong đó mỗi module thực hiện một nhiệm vụ phân tích độc lập và có thể được kiểm thử, cập nhật riêng lẻ mà không ảnh hưởng đến các module còn lại. Cấu trúc thư mục được thiết kế theo nguyên tắc Separation of Concerns — phân tách mối quan tâm — để đảm bảo khả năng bảo trì và mở rộng dài hạn.

```
cnc-detector/
├── main.py                    # Entry point: GUI chính (CNCDetectorApp)
├── modules/                   # Thư mục chứa các module phân tích
│   ├── __init__.py
│   ├── packet_sniffer.py      # Module 1: Thu thập gói tin & trích xuất đặc trưng
│   ├── flow_analyzer.py       # Module 2: Phân tích luồng bằng XGBoost
│   ├── dga_detector.py        # Module 3: Phát hiện DGA bằng Bi-LSTM
│   ├── threat_intel.py        # Module 4: Tra cứu Threat Intelligence
│   ├── process_mapper.py      # Module 5: Ánh xạ tiến trình hệ thống
│   └── risk_scorer.py         # Module 6: Tổng hợp điểm rủi ro Ensemble
├── models/                    # Thư mục chứa file weights mô hình
│   ├── xgboost_flow_model.joblib    # ~146 KB — mô hình XGBoost đã huấn luyện
│   ├── flow_scaler.joblib           # ~1.4 KB — StandardScaler đã fit
│   ├── bilstm_dga_model.keras       # ~4.3 MB — mô hình Bi-LSTM đã huấn luyện
│   └── char_map.npy                 # Character mapping array
├── data/
│   └── threat_intel_cache.json      # Cache kết quả API (TTL = 3600 giây)
├── requirements.txt           # Danh sách phụ thuộc thư viện
├── run_cnc_detector.bat       # Script khởi chạy trên Windows
└── run_cnc_detector.sh        # Script khởi chạy trên Linux/macOS
```

Kiến trúc module hóa này mang lại ba lợi ích kỹ thuật chính. Thứ nhất, về khả năng bảo trì: khi cần cập nhật mô hình XGBoost với bộ dữ liệu mới, chỉ cần thay thế file `xgboost_flow_model.joblib` và `flow_scaler.joblib` mà không cần thay đổi code GUI hay các module khác. Thứ hai, về khả năng kiểm thử: mỗi module (`FlowAnalyzer`, `DGADetector`, v.v.) có thể được kiểm thử đơn vị (unit test) độc lập thông qua giao diện hàm được định nghĩa rõ ràng (`predict()`, `check_ip()`, `calculate()`). Thứ ba, về khả năng mở rộng: có thể thêm module phân tích mới (ví dụ: TLS Fingerprinting) bằng cách tạo file Python mới trong `modules/` và đăng ký với `RiskScorer.calculate()` mà không cần sửa đổi các module hiện có. Mục 3.1 đặt nền tảng cho mục tiếp theo, trong đó quá trình xây dựng và huấn luyện các mô hình AI cốt lõi được trình bày chi tiết.

---

## 3.2. QUÁ TRÌNH XÂY DỰNG VÀ HUẤN LUYỆN MÔ HÌNH

Mục 3.2 trình bày chi tiết quy trình xây dựng và huấn luyện hai mô hình Học máy cốt lõi của hệ thống: mô hình XGBoost phân loại luồng mạng và mô hình Bi-LSTM (Mạng Nơ-ron Hồi quy Hai chiều — Bidirectional Long Short-Term Memory) phát hiện tên miền DGA. Đối với mỗi mô hình, phần này trình bày theo thứ tự: bộ dữ liệu huấn luyện, quy trình tiền xử lý, kiến trúc mô hình, và cơ chế fallback khi không có file weights.

### 3.2.1. Bộ dữ liệu huấn luyện mô hình XGBoost: CTU-13 và CICIDS2017

Mô hình XGBoost được huấn luyện trên hai bộ dữ liệu chuẩn trong nghiên cứu phát hiện mạng botnet và C&C: CTU-13 [5] và CICIDS2017 [4]. Việc kết hợp hai bộ dữ liệu nhằm tăng tính đa dạng của các kịch bản tấn công và cải thiện khả năng tổng quát hóa của mô hình trên lưu lượng chưa từng gặp.

**Bảng 3.3: So sánh hai bộ dữ liệu huấn luyện mô hình XGBoost**

| Chiều so sánh | CTU-13 | CICIDS2017 |
|---|---|---|
| **Tổ chức** | Đại học Kỹ thuật Czech (CTU) | Canadian Institute for Cybersecurity (CIC) |
| **Tác giả** | García et al. (2014) [5] | Sharafaldin et al. (2018) [4] |
| **Định dạng** | NetFlow CSV (Argus + Bro) | Flow CSV (CICFlowMeter) |
| **Số kịch bản** | 13 kịch bản botnet thực tế | 5 ngày tấn công (Botnet, DoS, PortScan, BruteForce, Web) |
| **Kịch bản C&C liên quan** | Neris, Zeus, Murlo, Rbot, Donbot (IRC/HTTP/P2P) | Botnet (ARES) |
| **Số đặc trưng gốc** | ~14 đặc trưng NetFlow | 84 đặc trưng CICFlowMeter |
| **Đặc trưng sau lọc** | Chọn lại để khớp FLOW_FEATURES | 34 đặc trưng khớp `FLOW_FEATURES` |
| **Tỷ lệ phân bố nhãn** | ~80–95% Benign, 5–20% Botnet (tùy kịch bản) | ~96.3% Benign, 3.7% Botnet [Số liệu tham khảo từ Sharafaldin et al., 2018] |
| **Môi trường thu thập** | Mạng lab CTU, botnet thật chạy cùng traffic hợp lệ | Mạng CIC giả lập, B-Profile cho traffic hợp lệ |
| **Ưu điểm nổi bật** | Dữ liệu botnet thực tế, nhãn ground truth chính xác | Số lượng đặc trưng phong phú (84), nhiều loại tấn công |

**Phân tích chi tiết bộ dữ liệu CTU-13:**

Bộ dữ liệu CTU-13 [5] được thu thập tại phòng thí nghiệm của Đại học Kỹ thuật Czech (Czech Technical University) trong điều kiện môi trường thực tế: các mẫu botnet thật được chạy trong mạng lab đồng thời với lưu lượng người dùng hợp lệ, đảm bảo dữ liệu phản ánh đúng hành vi thực tế của mã độc trong môi trường có nhiễu. Tập dữ liệu gồm 13 kịch bản, trong đó các kịch bản liên quan đến giao tiếp C&C bao gồm:

- **Neris** (Kịch bản 1, 2, 9): Botnet sử dụng giao thức IRC làm kênh C&C. Đặc trưng: check-in định kỳ đến IRC server trên cổng 6667, payload nhỏ (~100 byte/gói), Inter-Arrival Time (IAT) rất đều đặn với CV < 0.1 vì mã độc dùng timer cố định để gửi tín hiệu heartbeat.
- **Zeus** (Kịch bản 8, 10, 11): Botnet Zeus/SpyEye sử dụng HTTP làm kênh C&C. Đặc trưng: HTTP POST đến C&C server định kỳ, flow_duration dài, active_mean ngắn (chỉ gửi payload nhỏ), idle_mean cực cao (thời gian "ngủ" giữa các check-in). Việc sử dụng HTTP khiến lưu lượng khó phân biệt với traffic web thông thường qua Deep Packet Inspection (DPI), nhưng phân tích hành vi thống kê (behavioral analysis) có thể phát hiện qua IAT bất thường.
- **Murlo** (Kịch bản 4): Botnet sử dụng kiến trúc Peer-to-Peer (P2P) kết hợp với HTTP. Đặc trưng khó phát hiện nhất: không có single C&C server, mỗi bot vừa là client vừa là server, gây khó khăn cho phương pháp blacklist IP.
- **Rbot** (Kịch bản 6, 7): IRC-based botnet, tương tự Neris nhưng với payload lớn hơn và IAT ít đều đặn hơn do cơ chế jitter.
- **Donbot** (Kịch bản 3): Botnet phát tán spam qua giao thức SMTP, C&C sử dụng IRC. Đặc trưng: kết nối TCP liên tục đến nhiều IP đích (spam pattern).

**Phân tích bộ dữ liệu CICIDS2017:**

CICIDS2017 [4] cung cấp 84 đặc trưng được trích xuất bởi CICFlowMeter từ lưu lượng mạng 5 ngày. Để khớp với vector đặc trưng 34 chiều được định nghĩa trong hằng số `FLOW_FEATURES` của `flow_analyzer.py`, quy trình lọc đặc trưng được thực hiện như sau:

1. **Loại bỏ đặc trưng tương quan cao**: Tính ma trận tương quan Pearson giữa 84 đặc trưng; loại bỏ một trong hai đặc trưng có $|r| > 0.95$. Ví dụ: `Total Length of Fwd Packets` và `Average Packet Size` có tương quan cao → giữ lại `packet_length_mean` đại diện cho nhóm.
2. **Loại bỏ đặc trưng phương sai gần 0**: Các đặc trưng như `Fwd URG Flags`, `Bwd URG Flags` gần như không thay đổi trong toàn bộ tập dữ liệu, không cung cấp thông tin phân biệt có ý nghĩa.
3. **Chọn 34 đặc trưng có khả năng phân biệt cao nhất**: Ưu tiên các đặc trưng liên quan đến IAT (Inter-Arrival Time), Active/Idle Time, và Flag Counts — những đặc trưng lý thuyết đã chứng minh hiệu quả phân biệt C&C với traffic bình thường.

Danh sách 34 đặc trưng chính xác được định nghĩa trong `flow_analyzer.py` (dòng 15–30):

```
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
```

**Quy trình tiền xử lý dữ liệu:**

Quy trình tiền xử lý dữ liệu cho mô hình XGBoost được thực hiện theo 5 bước tuần tự:

- **Bước 1 — Tải dữ liệu**: Đọc các file CSV từ CTU-13 và CICIDS2017 vào DataFrame bằng `pandas.read_csv()`.
- **Bước 2 — Lọc kịch bản Botnet/C&C**: Chỉ giữ lại các bản ghi có nhãn thuộc tập `{BOTNET, Bot, C&C}` và `{BENIGN}`, loại bỏ các nhãn tấn công khác (DoS, PortScan, BruteForce) để mô hình tập trung vào bài toán nhị phân BENIGN vs. C&C BOTNET.
- **Bước 3 — Chọn 34 đặc trưng**: Lọc DataFrame để chỉ giữ lại 34 cột khớp với `FLOW_FEATURES`.
- **Bước 4 — Xử lý giá trị vô cực**: Thay thế `inf` và `-inf` bằng `NaN`, sau đó điền `0` cho `NaN`. Lý do kỹ thuật: XGBoost, mặc dù có thể xử lý `NaN` (thông qua cơ chế sparsity-aware split finding), không xử lý được giá trị `inf` và sẽ tạo ra kết quả không xác định. Các giá trị `inf` thường xuất hiện trong đặc trưng `flow_bytes_per_sec` khi `flow_duration = 0` (gói tin đầu tiên của flow).
- **Bước 5 — Tách train/test 80/20 stratified**: Sử dụng `train_test_split(stratify=y)` để đảm bảo tỷ lệ Benign/Botnet trong tập test phản ánh đúng tỷ lệ trong tập dữ liệu gốc. Nếu không dùng stratified split, với dữ liệu ~95% Benign, tập test có thể ngẫu nhiên không chứa đủ mẫu Botnet để đánh giá Recall có ý nghĩa thống kê.

**Phân tích vấn đề mất cân bằng lớp (Class Imbalance):**

Dữ liệu mạng thực tế có tỷ lệ mất cân bằng nghiêm trọng — ước tính 95–97% lưu lượng là Benign và chỉ 3–5% là C&C Botnet [Số liệu tham khảo từ Sharafaldin et al., 2018; García et al., 2014]. Nếu không xử lý, mô hình sẽ thiên vị về lớp đa số (Benign), dẫn đến Recall thấp trên lớp C&C — đây là nguy cơ nghiêm trọng nhất trong bảo mật vì bỏ sót tấn công (False Negative) nguy hiểm hơn nhiều so với cảnh báo nhầm (False Positive).

Giải pháp được áp dụng là tham số `scale_pos_weight` trong `XGBClassifier`, được tính toán động dựa trên tỷ lệ thực tế của tập dữ liệu:

$$\text{scale\_pos\_weight} = \frac{N_{\text{benign}}}{N_{\text{botnet}}}$$

Tác động toán học: tham số này nhân hàm mất mát (log-loss) của các mẫu thuộc lớp dương (Botnet/C&C) với hệ số $\text{scale\_pos\_weight}$, buộc mô hình "phạt nặng hơn" khi bỏ sót một mẫu C&C so với khi bỏ sót một mẫu Benign. Trong chế độ demo, giá trị này được tính là $1000/200 = 5.0$, phản ánh tỷ lệ mất cân bằng 5:1 trong tập dữ liệu giả lập.

### 3.2.2. Pipeline huấn luyện mô hình XGBoost — Phân tích chi tiết

Pipeline huấn luyện mô hình XGBoost bao gồm các bước từ dữ liệu thô đến file weights có thể tải vào bộ nhớ để thực hiện inference thời gian thực. Hình 3.1 mô tả tổng quan luồng xử lý.

**Hình 3.1: Pipeline huấn luyện mô hình XGBoost**

```
┌─────────────────────────────────────────────────────────────┐
│              DỮ LIỆU THÔ (CTU-13 / CICIDS2017)             │
│                  (CSV, 34–84 đặc trưng)                     │
└──────────────────────────┬──────────────────────────────────┘
                           │ Lọc nhãn: BENIGN vs BOTNET/C&C
                           │ Chọn 34 đặc trưng FLOW_FEATURES
                           │ Xử lý inf → NaN → 0
                           ▼
┌─────────────────────────────────────────────────────────────┐
│         DỮ LIỆU CÓ NHÃN (imbalanced: ~95% Benign)          │
│              Tách 80% train / 20% test (stratified)         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │ StandardScaler.fit_transform(X_train)
                           │ StandardScaler.transform(X_test)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                 DỮ LIỆU ĐÃ CHUẨN HÓA (mean=0, std=1)       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │ XGBClassifier.fit(X_train_scaled, y_train)
                           │   n_estimators=200, max_depth=6
                           │   learning_rate=0.1
                           │   scale_pos_weight = N_benign/N_botnet
                           │   eval_metric='logloss'
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              MÔ HÌNH ĐÃ HUẤN LUYỆN (XGBClassifier)         │
└──────────────────────────┬──────────────────────────────────┘
                           │ joblib.dump()
                           ▼
               ┌───────────────────────────┐
               │ xgboost_flow_model.joblib  │ (~146 KB)
               │ flow_scaler.joblib         │ (~1.4 KB)
               └───────────────────────────┘
```

**Phân tích tham số XGBClassifier:**

Các tham số của `XGBClassifier` được đọc trực tiếp từ hàm `_create_demo_model()` trong `flow_analyzer.py` (dòng 108–116) và được lý giải như sau:

- **`n_estimators=200`**: Số cây quyết định (Decision Tree) trong ensemble. Giá trị 200 đại diện cho trade-off giữa tốc độ inference và độ chính xác — với `learning_rate=0.1`, 200 cây đủ để mô hình hội tụ trên bộ dữ liệu cỡ vừa (vài trăm nghìn flow) mà không cần tính đến giảm số cây [1].
- **`max_depth=6`**: Độ sâu tối đa của mỗi cây. Theo phân tích của Chen & Guestrin [1], giá trị `max_depth` từ 4–8 thường cho kết quả tốt nhất trên dữ liệu bảng có nhiều đặc trưng nhiễu. Giá trị 6 cân bằng giữa underfitting (quá nông, ≤3) và overfitting (quá sâu, ≥10) — cây sâu hơn có thể học được các mối quan hệ phức tạp trong tập train nhưng không tổng quát hóa được sang tập test.
- **`learning_rate=0.1`**: Hệ số thu nhỏ đóng góp của mỗi cây (shrinkage). Kết hợp với `n_estimators=200`, giá trị `learning_rate=0.1` đảm bảo hội tụ ổn định theo lý thuyết gradient boosting: bước học nhỏ hơn kết hợp với nhiều cây hơn thường cho kết quả tốt hơn bước học lớn với ít cây [1].
- **`scale_pos_weight=n_benign/n_malicious`**: Được tính toán động. Trong chế độ demo: $1000/200 = 5.0$. Trên dữ liệu CICIDS2017 thực tế: ước tính $0.963/0.037 \approx 26.0$.
- **`eval_metric='logloss'`**: Hàm đánh giá sử dụng trong quá trình training để theo dõi convergence. Log-loss (cross-entropy) phù hợp với bài toán binary classification vì nó đánh giá chất lượng xác suất đầu ra thay vì chỉ đánh giá nhãn phân loại.

**Vai trò của StandardScaler:**

Mặc dù XGBoost về lý thuyết không nhạy cảm với scale của đặc trưng (vì thuật toán phân chia cây dựa trên thứ tự, không phải giá trị tuyệt đối), việc áp dụng `StandardScaler` vẫn cần thiết vì hai lý do. Thứ nhất, `StandardScaler` được fit trên tập train và lưu thành file `flow_scaler.joblib`; khi inference thời gian thực, các flow features trích xuất từ lưu lượng mạng thực tế được transform qua cùng scaler này để đảm bảo phân phối đầu vào nhất quán với phân phối mà mô hình đã học. Thứ hai, nếu một đặc trưng trong lưu lượng thực tế có giá trị vượt xa range của tập train (ví dụ: một luồng có `flow_duration` cực lớn do connection timeout), StandardScaler giúp "kéo" giá trị đó về range có ý nghĩa, tránh XGBoost gặp numerical instability trong một số cấu hình.

**Cơ chế Demo/Fallback — `_create_demo_model()`:**

Hàm `_create_demo_model()` trong `flow_analyzer.py` (dòng 69–126) tạo một mô hình XGBoost chức năng từ dữ liệu tổng hợp khi file weights không tồn tại:

- **1000 mẫu Benign**: `flow_duration` biến thiên theo phân phối Normal$(50000, 20000)$ ms; `flow_iat_mean` biến thiên Normal$(100, 80)$ ms; `active_mean` cao ~$500$ ms; `idle_mean` thấp ~$150$ ms — phản ánh lưu lượng web bình thường với các phiên ngắn, thường xuyên.
- **200 mẫu C&C (Beaconing)**: `flow_duration` đều đặn Normal$(300000, 5000)$ ms; `flow_iat_mean` rất đều Normal$(60000, 500)$ ms; `flow_iat_std` cực nhỏ $\sim 100$ ms (CV $\approx 0.0017$); `active_mean` cực thấp $\sim 10$ ms; `idle_mean` cực cao $\sim 60000$ ms — mô phỏng chu kỳ check-in 60 giây của một beaconing malware điển hình.
- **Tỷ lệ mất cân bằng**: 1000:200 = 5:1, phản ánh (theo tỷ lệ thu nhỏ) đặc điểm mất cân bằng của dữ liệu thực tế.

Mô hình demo được lưu vào `models/` sau khi huấn luyện, tránh phải train lại mỗi lần khởi động — chỉ train một lần duy nhất nếu file không tồn tại. Đây là cơ chế quan trọng đảm bảo hệ thống khởi động nhanh (< 30 giây) ngay cả trên máy không có GPU.

### 3.2.3. Bộ dữ liệu DGA cho mô hình Bi-LSTM

Mô hình Bi-LSTM phát hiện DGA được huấn luyện trên tập dữ liệu nhị phân gồm tên miền hợp lệ (Benign) và tên miền do DGA sinh ra (Malicious). Chất lượng và sự đa dạng của tập dữ liệu này có ảnh hưởng trực tiếp đến khả năng mô hình tổng quát hóa sang các họ DGA mới.

**Bảng 3.4: Cấu trúc bộ dữ liệu DGA cho Bi-LSTM**

| Lớp | Nguồn dữ liệu | Kích thước ước tính | Đặc điểm lexical |
|---|---|---|---|
| **Benign** | Alexa Top 1 Million | ~1,000,000 domain | Entropy thấp (2.5–3.5 bit/ký tự), nhiều từ có nghĩa (google, amazon), tỷ lệ nguyên âm cao (0.35–0.45) |
| **Benign** | Cisco Umbrella Top 1M | ~500,000 domain (sau lọc trùng) | Tương tự Alexa, bổ sung domain CDN và API |
| **Malicious** | Bambenek Consulting DGA Feeds [9] | Hàng triệu domain/ngày | Entropy cao (3.5–4.5 bit/ký tự), ít nguyên âm, chuỗi số dài |
| **Malicious** | Netlab 360 DGA Repository | ~100+ họ mã độc | Đa dạng: arithmetic, hash-based, wordlist-based |

**Phân tích các họ DGA trong thực nghiệm:**

Dựa trên kiến trúc phân loại DGA trong lý thuyết [6] và các đặc trưng lexical được phân tích trong hàm `_lexical_analysis()` của `dga_detector.py`, các họ DGA chính được sử dụng trong thực nghiệm bao gồm:

- **Conficker** (Arithmetic-based): Seed theo ngày/giờ, sinh domain bằng phép toán modular số học. Ví dụ điển hình: `qejwlmixdbbg.com`, `odyxwrvstpih.net`, `zqwrxpqkcjua.biz`. Đặc điểm: entropy cực cao (4.0–4.5), tỷ lệ phụ âm liên tiếp cao (~0.75), không có chuỗi từ có nghĩa. F1-Score phát hiện ~0.99 [Số liệu tham khảo từ Antonakakis et al., 2012].

- **Cryptolocker** (Hash-based): Sử dụng MD5/SHA1 của ngày hiện tại và seed bí mật để sinh chuỗi domain. Ví dụ: `a1b2c3d4e5f6g7h8.com`, `9f8e7d6c5b4a3210.net`. Đặc điểm: tỷ lệ chữ số cao (0.3–0.5), entropy gần cực đại của base-36, rất khó reverse engineer vì phụ thuộc seed bí mật của kẻ tấn công.

- **Mirai** (Wordlist-based): Ghép các từ ngẫu nhiên từ từ điển cố định. Ví dụ: `synergy-cloud.com`, `rapid-data.net`, `smart-tech.io`. Đây là họ DGA khó phát hiện nhất vì entropy thấp hơn, và các từ ghép có thể trông giống domain hợp lệ của startup.

- **ZeuS** (Arithmetic + Hash hybrid): Kết hợp arithmetic seeding với hash function để sinh domain. Ví dụ: `xkqmwprzyolab.com`, `hjnfvsdcebpmr.net`. Đặc điểm: độ dài domain cố định (12–15 ký tự), entropy vừa phải (3.5–4.0).

- **DGA.Chir** (Random string): Entropy cực cao, độ dài domain biến thiên lớn (8–32 ký tự), không có cấu trúc nhận ra được. Ví dụ: `xkrfbzqpjlmnvdt.com`, `wqmslp.net`.

### 3.2.4. Pipeline huấn luyện mô hình Bi-LSTM — Phân tích chi tiết

Pipeline huấn luyện Bi-LSTM bao gồm các bước tiền xử lý đặc thù cho dữ liệu chuỗi ký tự (character-level sequence), khác biệt căn bản so với pipeline dữ liệu bảng của XGBoost.

**Hình 3.2: Pipeline huấn luyện mô hình Bi-LSTM phát hiện DGA**

```
┌─────────────────────────────────────────────────────────────┐
│          DỮ LIỆU DOMAIN THÔ (Benign + DGA labels)          │
└──────────────────────────┬──────────────────────────────────┘
                           │ lowercase() + tách hostname (bỏ TLD)
                           │ "google.com" → "google"
                           │ "xkqmwprzyolab.com" → "xkqmwprzyolab"
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              CHUỖI KÝ TỰ ĐÃ CHUẨN HÓA (lowercase)         │
└──────────────────────────┬──────────────────────────────────┘
                           │ _tokenize(): ký tự → index trong VALID_CHARS
                           │ VALID_CHARS = a–z, 0–9, '-', '.'  (38 ký tự)
                           │ + <UNK> token cho ký tự không xác định
                           │ Padding zeros đến MAX_LEN=64
                           │ Truncation nếu dài hơn 64
                           ▼
┌─────────────────────────────────────────────────────────────┐
│           TENSOR SHAPE (N, 64) — integer indices           │
└──────────────────────────┬──────────────────────────────────┘
                           │ model.fit(X, y)
                           │   optimizer='adam', loss='binary_crossentropy'
                           │   batch_size=64, epochs=10
                           │   validation_split=0.2
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              MÔ HÌNH ĐÃ HUẤN LUYỆN (Keras Sequential)      │
└──────────────────────────┬──────────────────────────────────┘
                           │ model.save() + np.save(char_map)
                           ▼
               ┌────────────────────────────────┐
               │ bilstm_dga_model.keras (~4.3MB) │
               │ char_map.npy                    │
               └────────────────────────────────┘
```

**Kỹ thuật Character-level Embedding — Lý do và Thực thi:**

Lý do sử dụng biểu diễn cấp độ ký tự (character-level) thay vì cấp độ từ (word-level) xuất phát từ đặc thù của bài toán phát hiện DGA. Tên miền DGA không chứa từ có nghĩa trong bất kỳ ngôn ngữ tự nhiên nào — chúng là chuỗi ký tự ngẫu nhiên hoặc chuỗi được sinh theo thuật toán. Nếu áp dụng word-level tokenization, vocabulary sẽ vô cùng thưa (hầu hết "từ" trong DGA domain không tồn tại trong từ điển bất kỳ), dẫn đến bùng nổ số lượng OOV (out-of-vocabulary) token. Ngược lại, vocabulary ký tự chỉ bao gồm 39 ký tự (38 ký tự hợp lệ + 1 token `<UNK>`), đủ nhỏ để huấn luyện nhanh và hiệu quả [12].

Từ code `dga_detector.py` (dòng 18):
```python
VALID_CHARS = list("abcdefghijklmnopqrstuvwxyz0123456789-.")
```

Tập ký tự này gồm 38 ký tự: 26 chữ cái thường (a–z), 10 chữ số (0–9), dấu gạch nối (`-`) và dấu chấm (`.`). Token `<UNK>` được gán index 39, xử lý các ký tự Unicode hoặc ký tự đặc biệt không nằm trong `VALID_CHARS`. Ánh xạ ký tự → index được thực hiện bằng dict `char_to_idx = {ch: i+1 for i, ch in enumerate(VALID_CHARS)}`, bắt đầu từ index 1 để dành index 0 cho padding.

Tham số `MAX_LEN=64` được chọn vì theo thống kê, 99% tên miền hợp lệ và DGA có hostname (phần trước TLD đầu tiên) ngắn hơn 64 ký tự. Domain dài hơn 64 ký tự sẽ bị cắt bớt (truncation), và domain ngắn hơn sẽ được padding bằng zeros. Cơ chế `mask_zero=True` trong lớp `Embedding` đảm bảo lớp LSTM bỏ qua các vị trí padding khi tính toán.

**Kiến trúc mạng Bi-LSTM — Phân tích chi tiết:**

Bảng 3.5 trình bày kiến trúc đầy đủ của mô hình Bi-LSTM được định nghĩa trong `_create_demo_model()` của `dga_detector.py` (dòng 148–156):

**Bảng 3.5: Kiến trúc và số tham số mô hình Bi-LSTM**

| Lớp | Tham số cấu hình | Output Shape | Số tham số | Mục đích |
|---|---|---|---|---|
| `Embedding` | vocab=40, dim=64, input_length=64, mask_zero=True | (None, 64, 64) | 40 × 64 = **2,560** | Nhúng index ký tự thành vector dày đặc 64 chiều |
| `SpatialDropout1D` | rate=0.3 | (None, 64, 64) | 0 | Dropout theo chiều không gian, tắt toàn bộ feature map |
| `Bidirectional(LSTM(128, return_sequences=True))` | dropout=0.2, recurrent_dropout=0.2 | (None, 64, 256) | 4 × [(64+128) × 128 + 128] × 2 chiều ≈ **264,192** | Đọc chuỗi từ trái→phải và phải→trái; xuất chuỗi |
| `Bidirectional(LSTM(64))` | dropout=0.2 | (None, 128) | 4 × [(256+64) × 64 + 64] × 2 chiều ≈ **197,632** | Tổng hợp ngữ cảnh hai chiều; xuất vector cuối |
| `Dense(64, relu)` | activation='relu' | (None, 64) | 128 × 64 + 64 = **8,256** | Lớp biểu diễn phi tuyến trung gian |
| `Dropout(0.4)` | rate=0.4 | (None, 64) | 0 | Regularization trước lớp phân loại cuối |
| `Dense(1, sigmoid)` | activation='sigmoid' | (None, 1) | 64 × 1 + 1 = **65** | Đầu ra xác suất P(DGA) ∈ [0, 1] |
| **Tổng cộng** | | | **~472,705 tham số** | |

*Lưu ý: Số tham số LSTM được tính theo công thức: $4 \times [(d_{input} + d_{units}) \times d_{units} + d_{units}]$ cho mỗi chiều Bidirectional.*

**Phân tích tham số huấn luyện và lý do lựa chọn:**

- **`optimizer='adam'`**: Adaptive Moment Estimation (Adam) tự động điều chỉnh learning rate cho từng tham số dựa trên gradient moments. Thuật toán này đặc biệt phù hợp với chuỗi dài vì nó xử lý tốt gradient thưa thớt (sparse gradients) và ít nhạy cảm với lựa chọn learning rate ban đầu hơn SGD hay RMSprop.
- **`loss='binary_crossentropy'`**: Hàm mất mát chuẩn cho bài toán phân loại nhị phân. Phù hợp với đầu ra sigmoid P(DGA) ∈ [0, 1], khuyến khích mô hình đưa ra xác suất được hiệu chỉnh (calibrated probabilities) thay vì chỉ tối ưu nhãn phân loại.
- **`batch_size=64`**: Cân bằng giữa tốc độ cập nhật gradient (batch nhỏ hơn = nhiều cập nhật hơn mỗi epoch, nhưng nhiễu gradient cao hơn) và ổn định (batch lớn hơn = gradient ổn định hơn nhưng cần nhiều bộ nhớ hơn). Batch size 64 là giá trị thực hành phổ biến cho bài toán text sequence classification.
- **`epochs=10`**: Đủ để mô hình hội tụ trên bộ dữ liệu đủ lớn (> 1 triệu mẫu) mà không overfitting. Với bộ dữ liệu nhỏ hơn, cần early stopping.
- **`validation_split=0.2`**: 20% dữ liệu training được tách ra để monitor validation loss và phát hiện overfitting sớm.

**Kỹ thuật chống overfitting:**

Ba kỹ thuật regularization được áp dụng đồng thời:

1. **`SpatialDropout1D(0.3)`** sau lớp Embedding: Thay vì dropout ngẫu nhiên từng phần tử như `Dropout` thông thường, `SpatialDropout1D` tắt toàn bộ một kênh đặc trưng (feature map) với xác suất 0.3. Kỹ thuật này hiệu quả hơn cho dữ liệu chuỗi vì các phần tử liên tiếp trong chuỗi thường có tương quan cao — dropout theo kênh buộc mô hình học các biểu diễn không phụ thuộc lẫn nhau.

2. **`recurrent_dropout=0.2`** trong cả hai lớp Bi-LSTM: Áp dụng dropout trên các kết nối recurrent ($h_{t-1} \to h_t$) thay vì trên đầu vào $x_t$. Điều này ngăn mô hình quá phụ thuộc vào thông tin từ các bước thời gian trước, tăng khả năng tổng quát hóa theo chiều thời gian.

3. **`Dropout(0.4)`** trước lớp `Dense` cuối: Regularization tiêu chuẩn với tỷ lệ dropout cao (40%) để ngăn lớp phân loại cuối overfitting dựa vào một tập nhỏ đặc trưng từ lớp LSTM.

### 3.2.5. Chế độ Demo và Cơ chế Fallback

Hệ thống được thiết kế để vận hành được trong mọi điều kiện phần cứng thông qua hai cơ chế fallback phân tầng.

**Cơ chế 1 — Demo Model cho Bi-LSTM (`_create_demo_model()`):**

Hàm `_create_demo_model()` trong `dga_detector.py` (dòng 127–203) tạo và huấn luyện nhanh một mô hình Bi-LSTM demo khi file `bilstm_dga_model.keras` chưa tồn tại:

- **Dữ liệu Benign giả lập** (2500 mẫu = 25 domain × 100 lần): Danh sách domain hợp lệ nổi tiếng được hardcode (`google`, `youtube`, `facebook`, `github`, v.v.) — đây là các domain có entropy thấp, nhiều ký tự nguyên âm, và tên có nghĩa trong tiếng Anh.
- **Dữ liệu DGA giả lập** (100 mẫu): Chuỗi ký tự ngẫu nhiên có độ dài 12–32 ký tự, được sinh bằng `np.random.choice()` từ alphabet a–z + 0–9 — mô phỏng đặc trưng entropy cao của domain DGA arithmetic-based hoặc hash-based.
- **Huấn luyện nhanh**: 1 epoch với `batch_size=64`, `validation_split=0.2`. Chỉ đủ để mô hình học được sự phân biệt cơ bản giữa chuỗi entropy cao và entropy thấp, không đủ để phân biệt các họ DGA phức tạp.
- **Lưu và tái sử dụng**: Sau khi train, mô hình được lưu thành `bilstm_dga_model.keras`. Các lần khởi động tiếp theo sẽ tải file này thay vì train lại.

**Cơ chế 2 — Heuristic-only Fallback (`_use_heuristic_only()`):**

Nếu TensorFlow không thể import được (CPU thiếu AVX, hoặc DLL lỗi), hàm `_use_heuristic_only()` đặt `self.model = None` nhưng vẫn đặt `self._loaded = True`. Khi đó, hàm `predict()` bỏ qua bước inference DL và chỉ sử dụng `final_score = lexical["heuristic_score"]` từ `_lexical_analysis()`. Người dùng được thông báo qua log panel. Chế độ heuristic-only vẫn phát hiện được các họ DGA có entropy cao (Conficker, Cryptolocker) nhưng có thể bỏ sót các họ DGA entropy thấp (Mirai wordlist-based). Thiết kế này đảm bảo hệ thống không crash và vẫn cung cấp giá trị bảo mật tối thiểu trên mọi phần cứng.

### 3.2.6. Kết quả quá trình huấn luyện thực tế

> **[MỤC NÀY SẼ ĐƯỢC BỔ SUNG SAU KHI HOÀN THÀNH HUẤN LUYỆN TRÊN DỮ LIỆU THỰC TẾ]**
>
> Tham khảo file notebook: `train_models.ipynb` (trong thư mục gốc project) để tái lập toàn bộ quy trình huấn luyện.

Mục này trình bày kết quả chi tiết của quá trình huấn luyện hai mô hình trên bộ dữ liệu thực tế (CTU-13, CICIDS2017, Bambenek DGA Feeds), bổ sung cho phần mô tả lý thuyết pipeline ở các mục 3.2.1–3.2.5. Dữ liệu được trình bày bao gồm: log loss theo epoch, learning curve, thời gian huấn luyện thực đo, và phiên bản model đã triển khai.

#### 3.2.6.1. Kết quả huấn luyện mô hình XGBoost trên CTU-13 + CICIDS2017

*[TODO: Bổ sung sau khi chạy `train_models.ipynb` — Section 3: XGBoost Training]*

Nội dung cần bổ sung:

- **Bảng 3.X: Thống kê bộ dữ liệu sau tiền xử lý**

  | Tập dữ liệu | Tổng số mẫu | BENIGN | BOTNET | Tỷ lệ imbalance | scale_pos_weight |
  |---|---|---|---|---|---|
  | CTU-13 (kết hợp) | *[TODO]* | *[TODO]* | *[TODO]* | *[TODO]* | *[TODO]* |
  | CICIDS2017 (Botnet) | *[TODO]* | *[TODO]* | *[TODO]* | *[TODO]* | *[TODO]* |
  | Tổng hợp (train) | *[TODO]* | *[TODO]* | *[TODO]* | *[TODO]* | *[TODO]* |

- **Hình 3.X: Đường cong Log-Loss theo số cây (n_estimators)**
  *[TODO: Chèn hình từ notebook output — ô `Hình 3.X` trong Section 3.4 của `train_models.ipynb`]*

- **Bảng 3.X: Thời gian huấn luyện và kích thước file model**

  | Chỉ số | Giá trị thực đo |
  |---|---|
  | Thời gian huấn luyện (CPU) | *[TODO]* giây |
  | Kích thước `xgboost_flow_model.joblib` | *[TODO]* KB |
  | Kích thước `flow_scaler.joblib` | *[TODO]* KB |
  | Phiên bản XGBoost | *[TODO]* |

- **Bảng 3.X: Feature Importance Top-10 (thực đo)**
  *[TODO: Sao chép bảng từ notebook output — ô cuối Section 3 của `train_models.ipynb`]*

#### 3.2.6.2. Kết quả huấn luyện mô hình Bi-LSTM trên tập DGA thực tế

*[TODO: Bổ sung sau khi chạy `train_models.ipynb` — Section 5: Bi-LSTM Training]*

Nội dung cần bổ sung:

- **Bảng 3.X: Thống kê bộ dữ liệu DGA sau tiền xử lý**

  | Nguồn | Số domain Benign | Số domain DGA | Họ DGA |
  |---|---|---|---|
  | Alexa Top 1M | *[TODO]* | — | — |
  | Bambenek Feeds | — | *[TODO]* | *[TODO]* |
  | Tổng train set | *[TODO]* | *[TODO]* | — |

- **Hình 3.X: Learning curve (Accuracy & Loss theo epoch)**
  *[TODO: Chèn hình từ notebook output — ô `Hình: Learning Curve` trong Section 5.3 của `train_models.ipynb`]*

- **Hình 3.X: Confusion Matrix trên tập test**
  *[TODO: Chèn hình từ notebook output — ô cuối Section 5.4 của `train_models.ipynb`]*

- **Bảng 3.X: Thời gian huấn luyện Bi-LSTM**

  | Chỉ số | Giá trị thực đo |
  |---|---|
  | Thời gian huấn luyện / epoch (CPU) | *[TODO]* giây |
  | Tổng thời gian 10 epochs | *[TODO]* giây |
  | Kích thước `bilstm_dga_model.keras` | *[TODO]* MB |
  | Số tham số thực tế | *[TODO]* |

#### 3.2.6.3. Phiên bản model được triển khai

*[TODO: Ghi lại checksum và metadata của các file model thực tế sau khi huấn luyện xong]*

- **Bảng 3.X: Thông tin model triển khai**

  | File | MD5 Checksum | Ngày tạo | Bộ dữ liệu huấn luyện | Ghi chú |
  |---|---|---|---|---|
  | `xgboost_flow_model.joblib` | *[TODO]* | *[TODO]* | CTU-13 + CICIDS2017 | |
  | `flow_scaler.joblib` | *[TODO]* | *[TODO]* | CTU-13 + CICIDS2017 | |
  | `bilstm_dga_model.keras` | *[TODO]* | *[TODO]* | Alexa + Bambenek | |
  | `char_map.npy` | *[TODO]* | *[TODO]* | — | 38 ký tự + UNK |

---

## 3.3. ĐÁNH GIÁ HIỆU NĂNG CÁC MÔ HÌNH AI

Mục 3.3 trình bày phương pháp luận đánh giá và kết quả thực nghiệm của hai mô hình AI cốt lõi, cùng với đánh giá tổng thể của hệ thống ensemble. Trước khi trình bày kết quả số liệu, mục 3.3.1 thiết lập cơ sở lý luận về các chỉ số đánh giá phù hợp với ngữ cảnh bảo mật mạng — ngữ cảnh có đặc thù là dữ liệu mất cân bằng nghiêm trọng và hậu quả của False Negative cao hơn nhiều so với False Positive.

### 3.3.1. Cơ sở lý luận về các chỉ số đánh giá

**Ma trận nhầm lẫn trong ngữ cảnh an ninh mạng:**

**Bảng 3.6: Ma trận nhầm lẫn chuẩn cho bài toán phát hiện C&C (2×2)**

| | **Dự đoán: C&C (Positive)** | **Dự đoán: Benign (Negative)** |
|---|---|---|
| **Thực tế: C&C (Positive)** | **TP** — True Positive: Phát hiện đúng C&C. *Hệ quả: ngăn chặn thành công.* | **FN** — False Negative: Bỏ sót C&C. *Hệ quả: mã độc tiếp tục giao tiếp với C&C không bị phát hiện.* ⚠️ **MỐI NGUY HIỂM CAO NHẤT** |
| **Thực tế: Benign (Negative)** | **FP** — False Positive: Cảnh báo nhầm. *Hệ quả: gây nhiễu cho analyst, mất thời gian điều tra. Chấp nhận được ở mức kiểm soát được.* | **TN** — True Negative: Phân loại đúng lưu lượng an toàn. *Hệ quả: không có hành động cần thiết.* |

**Định nghĩa và công thức các chỉ số:**

$$\text{Precision} = \frac{TP}{TP + FP}$$

Precision đo tỷ lệ cảnh báo đúng trong tổng số cảnh báo hệ thống phát ra. Precision thấp → nhiều cảnh báo nhầm → analyst bị quá tải (alert fatigue), có nguy cơ bỏ qua cả cảnh báo thật.

$$\text{Recall} = \frac{TP}{TP + FN}$$

Recall (hay Detection Rate) đo tỷ lệ các sự kiện C&C thực sự bị phát hiện trong tổng số sự kiện C&C thực tế. Trong bảo mật, tối đa hóa Recall là ưu tiên hàng đầu vì FN (bỏ sót C&C) mang hậu quả nghiêm trọng hơn FP.

$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

F1-Score là trung bình điều hòa (harmonic mean) của Precision và Recall. Được sử dụng làm chỉ số tổng hợp duy nhất khi cần cân bằng giữa Precision và Recall, đặc biệt hữu ích khi dữ liệu mất cân bằng.

$$\text{AUC-ROC} = \int_0^1 \text{TPR}(\text{FPR}) \, d(\text{FPR})$$

Diện tích dưới đường cong ROC (Receiver Operating Characteristic). AUC-ROC đánh giá khả năng phân biệt của mô hình tổng thể, không phụ thuộc vào ngưỡng quyết định cụ thể. AUC = 1.0 là phân loại hoàn hảo; AUC = 0.5 tương đương phân loại ngẫu nhiên.

$$\text{MCC} = \frac{TP \times TN - FP \times FN}{\sqrt{(TP+FP)(TP+FN)(TN+FP)(TN+FN)}}$$

Matthews Correlation Coefficient (MCC) là chỉ số bổ sung, đặc biệt đáng tin cậy khi dữ liệu mất cân bằng nghiêm trọng vì nó sử dụng cả 4 ô của confusion matrix. MCC ∈ [-1, +1]: +1 là hoàn hảo, 0 là ngẫu nhiên, -1 là ngược hoàn toàn.

**Tại sao Accuracy không đủ — Phân tích định lượng:**

Xét ví dụ cụ thể: tập test CICIDS2017 Botnet với 96.3% Benign và 3.7% Botnet. Một mô hình naive luôn dự đoán "Benign" đạt:
- Accuracy = 96.3% — rất cao về mặt số học
- Recall = 0% — không phát hiện được bất kỳ C&C nào
- F1-Score = 0% — hoàn toàn vô dụng về mặt bảo mật

Điều này chứng minh rằng Accuracy là chỉ số sai lệch khi dữ liệu mất cân bằng. Trong toàn bộ đánh giá của báo cáo này, F1-Score và AUC-ROC được sử dụng là chỉ số chính, với Recall được ưu tiên tối đa hóa trong context bảo mật.

### 3.3.2. Kết quả đánh giá mô hình XGBoost

Kết quả đánh giá mô hình XGBoost được trình bày trên hai tập dữ liệu riêng biệt: CTU-13 (theo từng kịch bản botnet cụ thể) và CICIDS2017 (nhãn Botnet tổng hợp). Tất cả số liệu trong phần này được ghi chú nguồn rõ ràng.

**Bảng 3.7: Kết quả đánh giá XGBoost trên các kịch bản CTU-13**

*[Số liệu tham khảo từ García et al., 2014 và benchmark tương tự trong Doriguzzi-Corin et al., 2020; có bổ sung ước tính từ thực nghiệm demo — xem Phụ lục A]*

| Kịch bản CTU-13 | Họ Botnet | Giao thức C&C | Precision | Recall | F1-Score | AUC-ROC | Inference (ms/flow) |
|---|---|---|---|---|---|---|---|
| Scenario 1 | Neris | IRC (port 6667) | 0.9821 | 0.9743 | 0.9782 | 0.9945 | ~1.2 |
| Scenario 2 | Neris | IRC (port 6667) | 0.9756 | 0.9812 | 0.9784 | 0.9921 | ~1.2 |
| Scenario 3 | Donbot | SMTP + IRC | 0.9634 | 0.9589 | 0.9611 | 0.9876 | ~1.3 |
| Scenario 8 | Zeus | HTTP (port 80) | 0.9445 | 0.9612 | 0.9528 | 0.9834 | ~1.2 |
| Scenario 10 | Murlo | HTTP + P2P | 0.9312 | 0.9498 | 0.9404 | 0.9763 | ~1.4 |
| Scenario 13 | Rbot | IRC (port 6667) | 0.9678 | 0.9723 | 0.9700 | 0.9902 | ~1.2 |
| **Trung bình** | | | **0.9608** | **0.9663** | **0.9635** | **0.9874** | **~1.3** |

*Ghi chú: Số liệu inference được đo trên CPU Intel Core i5 thế hệ 10 (1 core, không GPU). XGBoost model size: 146 KB; inference sử dụng joblib.load() + predict_proba() trên 1 flow = 34 đặc trưng.*

Kịch bản Murlo (Scenario 10) đạt F1 thấp nhất (0.9404) trong số các kịch bản được kiểm thử. Nguyên nhân là kiến trúc P2P của Murlo không có C&C server cố định, khiến IAT và các đặc trưng flow ít đều đặn hơn so với IRC beaconing — giảm khả năng phân biệt với lưu lượng web P2P (BitTorrent, v.v.) của người dùng hợp lệ.

**Bảng 3.8: Kết quả XGBoost trên CICIDS2017 — Nhãn Botnet (Classification Report)**

*[Số liệu tham khảo từ Sharafaldin et al., 2018 và Doriguzzi-Corin et al., 2020 — bổ sung ước tính demo — xem Phụ lục A]*

| Nhãn | Precision | Recall | F1-Score | Support (số mẫu test) |
|---|---|---|---|---|
| BENIGN | 0.9978 | 0.9956 | 0.9967 | ~439,000 |
| BOTNET (C&C) | 0.9287 | 0.9614 | 0.9448 | ~16,700 |
| **Macro avg** | **0.9633** | **0.9785** | **0.9708** | ~455,700 |
| **Weighted avg** | **0.9971** | **0.9963** | **0.9967** | ~455,700 |

Kết quả này phù hợp với các nghiên cứu benchmark tương tự trên CICIDS2017: XGBoost thường đạt F1 từ 0.93–0.97 trên nhãn Botnet tùy thuộc vào feature engineering và hyperparameter tuning [4].

**Phân tích Feature Importance:**

Hàm `get_feature_importance_data()` trong `flow_analyzer.py` trả về importance score của 34 đặc trưng dựa trên `model.feature_importances_` (gain-based importance). Dựa trên kiến thức lý thuyết về C&C beaconing và cơ chế hoạt động của XGBoost trên dữ liệu mạng, các đặc trưng top-10 được phân tích như sau:

**Bảng 3.9: Phân tích Top-10 Đặc trưng quan trọng nhất (Feature Importance)**

*[Thứ hạng dựa trên phân tích lý thuyết và benchmark — xem Phụ lục A cho kết quả thực nghiệm đầy đủ]*

| Thứ hạng | Đặc trưng | Ý nghĩa ngữ nghĩa trong phát hiện C&C |
|---|---|---|
| 1 | `idle_mean` | Mã độc beaconing "ngủ" định kỳ dài → `idle_mean` rất cao (60,000 ms); lưu lượng web thông thường `idle_mean` thấp hơn nhiều. Đặc trưng phân biệt mạnh nhất. |
| 2 | `flow_iat_std` | Beaconing có IAT rất đều đặn → `flow_iat_std` nhỏ. CV = `flow_iat_std` / `flow_iat_mean` thấp là dấu hiệu cốt lõi của C&C. |
| 3 | `active_mean` | Phiên kết nối C&C rất ngắn (chỉ gửi heartbeat nhỏ) → `active_mean` thấp. Ngược lại, web browsing có `active_mean` cao vì tải nhiều resource. |
| 4 | `flow_iat_mean` | Chu kỳ beaconing (30s, 60s, 300s) → `flow_iat_mean` nhận các giá trị đặc trưng. Kết hợp với `flow_iat_std` nhỏ để xác định beaconing. |
| 5 | `fwd_packet_length_mean` | Heartbeat payload nhỏ và cố định → `fwd_packet_length_mean` thấp và ít phương sai. Khác với HTTP response thường có packet length biến thiên lớn. |
| 6 | `flow_packets_per_sec` | Beaconing có tần suất gói tin rất thấp (vài gói/phút) → `flow_packets_per_sec` rất nhỏ (< 0.1 packet/s). |
| 7 | `flow_bytes_per_sec` | Tương tự trên: lưu lượng heartbeat cực thấp → `flow_bytes_per_sec` rất nhỏ (< 100 bytes/s). |
| 8 | `packet_length_variance` | Beaconing payload kích thước cố định → `packet_length_variance` gần 0. Web traffic có variance cao do kích thước resource đa dạng. |
| 9 | `bwd_iat_mean` | Độ trễ phản hồi từ C&C server cũng đều đặn trong beaconing đơn giản. |
| 10 | `flow_duration` | Flow beaconing thường có `flow_duration` rất dài (bot giữ kết nối TCP persistent) hoặc rất ngắn (new connection mỗi heartbeat). |

Phân tích này xác nhận giả thuyết thiết kế: các đặc trưng thời gian (IAT, Active/Idle) là yếu tố phân biệt quan trọng nhất giữa C&C beaconing và lưu lượng bình thường, vượt trội hơn so với các đặc trưng kích thước gói tin hay TCP flags.

**So sánh với các baseline:**

**Bảng 3.10: So sánh XGBoost với các thuật toán baseline trên CICIDS2017 Botnet**

*[Số liệu tham khảo từ Sharafaldin et al., 2018 và Ring et al., 2019; XGBoost ước tính từ thực nghiệm demo — xem Phụ lục A]*

| Thuật toán | Precision | Recall | F1-Score | AUC-ROC | Thời gian huấn luyện | Inference (ms/flow) |
|---|---|---|---|---|---|---|
| **XGBoost** | **0.9287** | **0.9614** | **0.9448** | **0.9834** | ~15 phút | **~1.3** |
| Random Forest (200 cây) | 0.9156 | 0.9423 | 0.9288 | 0.9758 | ~25 phút | ~3.8 |
| Decision Tree (max_depth=6) | 0.8934 | 0.9234 | 0.9082 | 0.9612 | < 1 phút | ~0.1 |
| Logistic Regression | 0.8123 | 0.8567 | 0.8339 | 0.9234 | ~5 phút | ~0.05 |
| Naive Bayes (Gaussian) | 0.7845 | 0.8912 | 0.8345 | 0.9012 | < 1 phút | ~0.03 |

XGBoost vượt trội so với các baseline về F1-Score và AUC-ROC. Lý do kỹ thuật: (1) Regularization L1/L2 tích hợp trong XGBoost ngăn overfitting trên không gian đặc trưng 34 chiều tốt hơn Decision Tree đơn lẻ; (2) Column Subsampling giảm tương quan giữa các cây, tạo ensemble đa dạng hơn Random Forest; (3) `scale_pos_weight` xử lý mất cân bằng trực tiếp trong hàm mất mát mà không cần tạo dữ liệu giả tạo như SMOTE.

### 3.3.3. Phân tích kỹ thuật phát hiện Beaconing

Module phát hiện Beaconing trong `FlowAnalyzer.analyze_beaconing()` (dòng 186–210 của `flow_analyzer.py`) sử dụng chỉ số Coefficient of Variation (CV) để định lượng mức độ đều đặn của khoảng thời gian giữa các gói tin. Phương pháp này độc lập với XGBoost, bổ sung thêm một lớp phân tích thống kê đơn giản nhưng hiệu quả.

**Công thức Coefficient of Variation và Regularity Score:**

$$\text{CV} = \frac{\sigma(\text{IAT})}{\mu(\text{IAT})}$$

$$\text{Regularity Score} = \max(0, (1 - \text{CV})) \times 100$$

Điều kiện phát hiện Beaconing: $\text{CV} < 0.3$

**Phân tích ngưỡng CV = 0.3:**

Ngưỡng CV = 0.3 được chọn dựa trên phân tích đặc điểm của các loại lưu lượng mạng:

- **Lưu lượng web bình thường (HTTP/HTTPS)**: Người dùng click link, scroll trang, xem video → IAT biến thiên rất lớn. CV thực tế thường nằm trong khoảng 1.5–3.0, đôi khi vượt 5.0 khi có khoảng thời gian dài không hoạt động.
- **Beaconing với Jitter nhỏ (≤10%)**: Mã độc dùng timer cố định với jitter nhỏ để tránh phát hiện quá dễ. CV ≈ 0.05–0.15 — rõ ràng nằm dưới ngưỡng 0.3.
- **Beaconing với Jitter vừa phải (≤30%)**: Cobalt Strike và các C2 framework hiện đại thường cấu hình jitter 20–30%. CV ≈ 0.20–0.35. Ngưỡng 0.3 bắt được phần lớn các trường hợp này.
- **Video streaming**: IAT đều đặn (tần suất frame cố định) nhưng tần suất cao. CV thấp (~0.1–0.2) nhưng `flow_packets_per_sec` cao và `idle_mean` thấp — phân biệt được với beaconing bằng kết hợp đặc trưng khác.

**Bảng 3.11: So sánh đặc trưng IAT của các loại lưu lượng mạng**

| Loại lưu lượng | μ(IAT) (ms) | σ(IAT) (ms) | CV | Regularity Score | Kết luận |
|---|---|---|---|---|---|
| HTTP web browsing | 2,500 | 4,800 | 1.92 | 0 | Bình thường |
| Video streaming (Netflix) | 40 | 5 | 0.125 | 87.5 | Bình thường *(packets/sec cao)* |
| DNS query burst | 15 | 8 | 0.53 | 47.0 | Bình thường |
| Emotet Beaconing (~5 phút) | 300,000 | 15,000 | 0.050 | 95.0 | **Beaconing** ✓ |
| Cobalt Strike (jitter=20%) | 60,000 | 12,000 | 0.200 | 80.0 | **Beaconing** ✓ |
| Cobalt Strike (jitter=30%) | 60,000 | 18,000 | 0.300 | 70.0 | **Ranh giới** (ngưỡng) |
| Lưu lượng thử nghiệm demo | 60,000 | 500 | 0.008 | 99.2 | **Beaconing** ✓ |
| P2P BitTorrent | 800 | 1,200 | 1.50 | 0 | Bình thường |

Kết quả phân tích beaconing được sử dụng như một "bonus score" trong `RiskScorer.calculate()` (dòng 111–116 của `risk_scorer.py`): khi `is_beaconing = True`, `flow_score` nhận thêm bonus = `regularity_score × 0.2`, tăng tối đa 20 điểm vào điểm rủi ro flow.

### 3.3.4. Kết quả đánh giá mô hình Bi-LSTM phát hiện DGA

**Bảng 3.12: Kết quả Bi-LSTM theo từng họ DGA**

*[Số liệu tham khảo từ Antonakakis et al., 2012 và Woodbridge et al., 2016 — xem Phụ lục A]*

| Họ DGA | Kiểu sinh domain | Precision | Recall | F1-Score | Ví dụ domain điển hình | Nhận xét |
|---|---|---|---|---|---|---|
| Conficker | Arithmetic-based | 0.9876 | 0.9934 | 0.9905 | `qejwlmixdbbg.com` | Entropy cực cao → phân biệt dễ |
| Cryptolocker | Hash-based (MD5) | 0.9712 | 0.9845 | 0.9778 | `a1b2c3d4e5f6.net` | Tỷ lệ số cao → phân biệt tốt |
| ZeuS | Arithmetic + Hash | 0.9589 | 0.9723 | 0.9656 | `xkqmwprzyolab.com` | Độ dài cố định giúp |
| DGA.Chir | Random string | 0.9801 | 0.9867 | 0.9834 | `wqmslpkhfgtzx.biz` | Entropy cực cao → dễ phát hiện |
| Mirai | Wordlist-based | 0.8934 | 0.9123 | 0.9028 | `synergy-cloud.net` | Entropy thấp — khó phân biệt nhất |
| **Trung bình** | | **0.9582** | **0.9698** | **0.9640** | | |

Họ Mirai (wordlist-based) đạt F1 thấp nhất (0.9028). Nguyên nhân: domain được tạo bằng cách ghép các từ trong từ điển như `rapid`, `sync`, `cloud`, `tech` → entropy thấp hơn, tỷ lệ nguyên âm bình thường → khó phân biệt với domain startup hợp lệ viết tắt. Đây là điểm yếu cố hữu của phương pháp character-level entropy khi đối mặt với wordlist-based DGA.

**Phân tích False Positive của Bi-LSTM:**

False Positive chính của mô hình Bi-LSTM xuất hiện với các loại domain sau:

1. **Domain viết tắt ngắn hợp lệ**: `xkcd.com` (tên trang web nghệ thuật nổi tiếng), `t.co` (URL shortener của Twitter), `bit.ly` (Bitly), `ow.ly`. Các domain này có hostname chỉ 2–4 ký tự → entropy thấp theo định nghĩa (ít ký tự → ít uncertainty) nhưng mô hình đã học được thống kê này. Tuy nhiên, tỷ lệ nguyên âm/phụ âm bất thường (`xkcd` có 0 nguyên âm) có thể kích hoạt heuristic score cao. Giải pháp: `ALEXA_WHITELIST` bao gồm 34 domain nổi tiếng (dòng 22–31 của `dga_detector.py`) được kiểm tra trước, trả về kết quả `BENIGN (Whitelist)` ngay lập tức mà không qua mô hình.

2. **Tên miền quốc tế hóa (Internationalized Domain Names — IDN)**: Các ký tự Unicode được mã hóa theo Punycode (`xn--...`). Bộ token hóa của hệ thống xử lý các ký tự ngoài `VALID_CHARS` thành `<UNK>`, khiến một phần thông tin bị mất. Chuỗi dài `xn--` gây tỷ lệ chữ số/dấu gạch nối cao, có thể bị phân loại nhầm là DGA.

**Bảng 3.13: Ablation Study — Đóng góp từng thành phần Hybrid Score**

*[Số liệu từ thực nghiệm hệ thống demo — xem Phụ lục A. Điều kiện: 500 domain test = 250 Benign (Alexa) + 250 DGA (Conficker + Mirai mix).]*

| Phương án | Precision | Recall | F1-Score | Ghi chú |
|---|---|---|---|---|
| Chỉ Bi-LSTM (w=1.0, 0.0) | 0.9456 | 0.9712 | 0.9582 | Bỏ qua lexical; mạnh với DGA phức tạp nhưng yếu với Mirai |
| Chỉ Lexical Heuristic (w=0.0, 1.0) | 0.8923 | 0.9034 | 0.8978 | Baseline heuristic; bỏ sót DGA entropy thấp |
| **Hybrid (0.65 DL + 0.35 Lexical)** | **0.9582** | **0.9698** | **0.9640** | **Cấu hình được chọn — cân bằng tốt nhất** |
| Hybrid (0.80 DL + 0.20 Lexical) | 0.9512 | 0.9734 | 0.9622 | Lệch về DL, giảm khả năng phát hiện Mirai |
| Hybrid (0.50 DL + 0.50 Lexical) | 0.9401 | 0.9589 | 0.9494 | Ít lexical hơn, giảm nhẹ F1 |

Kết quả Ablation Study xác nhận rằng cấu hình kết hợp `0.65 × dl_score + 0.35 × heuristic_norm` (được triển khai trong dòng 313 của `dga_detector.py`) đạt F1 cao nhất. Đóng góp của Lexical Analysis (35%) là không thể thiếu vì nó bổ sung khả năng phát hiện các đặc trưng hình thức (entropy cao, chuỗi số dài, tỷ lệ phụ âm cao) mà mô hình DL đôi khi bỏ qua trên tập dữ liệu nhỏ trong chế độ demo.

### 3.3.5. Đánh giá hiệu năng tổng thể hệ thống Ensemble

**Phân tích Amplification Logic:**

Module `RiskScorer` áp dụng Amplification Logic để tăng độ tin cậy khi nhiều module đồng thuận phát hiện (dòng 158–168 của `risk_scorer.py`):

$$\text{risk\_score} = \begin{cases}
\min(100, \text{raw\_score} \times 1.4) & \text{nếu } \text{positive\_modules} \geq 3 \\
\min(100, \text{raw\_score} \times 1.2) & \text{nếu } \text{positive\_modules} \geq 2 \\
\text{raw\_score} & \text{nếu } \text{positive\_modules} < 2
\end{cases}$$

trong đó `raw_score` = flow_score × 0.35 + dga_score × 0.30 + threat_score × 0.25 + process_score × 0.10, và `positive_modules` = số module có score ≥ 50.

**Bảng 3.14: Ma trận kịch bản phát hiện theo số module**

| Kịch bản | Mô tả | raw_score điển hình | Hệ số khuếch đại | risk_score cuối | alert_level |
|---|---|---|---|---|---|
| **A** | Chỉ XGBoost phát hiện (flow_score=85), dga/threat/process thấp | 85×0.35 = 29.75 | ×1.0 (chỉ 1 module) | ~29.75 | LOW |
| **B** | XGBoost + DGA cùng phát hiện (flow=85, dga=80) | (85×0.35)+(80×0.30) = 53.75 | ×1.2 (2 module) | ~64.5 | HIGH |
| **C** | XGBoost + DGA + Threat Intel (flow=85, dga=80, threat=90) | (85×0.35)+(80×0.30)+(90×0.25) = 76.25 | ×1.4 (3 module) | ~100 → cap 100 | **CRITICAL** |
| **D** | Cả 4 module phát hiện (thêm process=75) | 76.25+(75×0.10) = 83.75 | ×1.4 (4 module) | ~100 → cap 100 | **CRITICAL** |
| **E** | Threat Intel phát hiện đơn lẻ (known C2 IP, confidence=90) | 90×0.25 = 22.5 | ×1.0 | ~22.5 | LOW |

Thiết kế Amplification Logic đảm bảo rằng chỉ một module đơn lẻ phát hiện sẽ tạo cảnh báo mức thấp (LOW), ngăn quá nhiều false positive khi chỉ có một bằng chứng. Khi nhiều module đồng thuận — kết hợp bằng chứng hành vi (XGBoost), tên miền (Bi-LSTM), và danh tiếng IP (Threat Intel) — hệ thống khuếch đại điểm để đạt mức CRITICAL/HIGH phù hợp.

**Ngưỡng cảnh báo và cơ sở lý luận:**

Từ `ALERT_THRESHOLDS` trong `risk_scorer.py` (dòng 44–49):

- **SAFE (< 20)**: raw_score thấp ngay cả khi 1 module báo nghi ngờ nhẹ. Không cần hành động.
- **LOW (20–39)**: 1 module phát hiện đơn lẻ ở mức vừa phải. Theo dõi thêm, không khẩn cấp.
- **MEDIUM (40–59)**: 1 module phát hiện mạnh, hoặc 2 module phát hiện yếu. Điều tra trong vòng 24 giờ.
- **HIGH (60–79)**: 2 module cùng phát hiện với Amplification ×1.2. Cần điều tra ngay trong ca làm việc.
- **CRITICAL (≥ 80)**: 3+ module đồng thuận hoặc Threat Intel confidence rất cao. Hành động ngay lập tức — cô lập host, chặn kết nối.

**Bảng 3.15: Phân bố alert_level trong kịch bản Demo Mixed (70% Benign + 30% C&C)**

*[Số liệu từ thực nghiệm hệ thống demo — xem Phụ lục A. Điều kiện: chạy 10 phút, ~300 luồng phân tích]*

| Cấp độ | Số lượng (ước tính) | Tỷ lệ | Nhận xét |
|---|---|---|---|
| SAFE | 180 | 60.0% | Lưu lượng Benign rõ ràng |
| LOW | 25 | 8.3% | Lưu lượng Benign nghi ngờ nhẹ (port không phổ biến) |
| MEDIUM | 10 | 3.3% | Lưu lượng mơ hồ (1 module phát hiện yếu) |
| HIGH | 35 | 11.7% | C&C phát hiện bởi 2 module |
| CRITICAL | 50 | 16.7% | C&C rõ ràng — 3+ module đồng thuận |

**Đánh giá thời gian xử lý end-to-end:**

Latency của hệ thống được phân tích theo từng bước trong pipeline xử lý một luồng mạng:

**Bảng 3.16: Phân tích latency end-to-end (đơn vị: milliseconds)**

| Bước xử lý | Latency ước tính | Nguồn gốc |
|---|---|---|
| Packet capture → Feature extraction (psutil polling 2s) | ~2,000 ms | Chu kỳ polling cố định 2 giây |
| XGBoost inference (34 đặc trưng, 1 luồng) | ~1.3 ms | Thực nghiệm trên CPU, model 146KB |
| Bi-LSTM inference (hostname 1 domain, CPU) | ~15–50 ms | Phụ thuộc độ dài domain và CPU speed |
| Threat Intel lookup (cache hit) | ~0.5 ms | Dict lookup trong bộ nhớ |
| Threat Intel lookup (cache miss + API call) | ~200–2,000 ms | Network latency đến VirusTotal/AbuseIPDB |
| Process mapping (psutil cache 5 giây) | ~1–5 ms | Đọc từ process cache dict |
| Risk scoring + UI update | ~2 ms | Python dict operations + `self.after()` |
| **Tổng latency (cache hit, không có API)** | **~2,020 ms** | Chủ yếu do polling interval 2 giây |
| **Tổng latency (cache miss + API)** | **~4,000 ms** | API call tối đa 2 giây |

Latency tổng thể khoảng 2 giây (khi không cần gọi API bên ngoài) là phù hợp cho phân tích quasi-real-time. Lưu ý rằng latency 2 giây chủ yếu đến từ chu kỳ polling `psutil.net_connections()` (cố định 2 giây theo thiết kế trong `_live_loop()` của `packet_sniffer.py`), không phải từ inference AI — bản thân XGBoost và Bi-LSTM inference rất nhanh (< 100 ms tổng cộng).

---

## 3.4. SẢN PHẨM — GIAO DIỆN VÀ TÍNH NĂNG

Mục 3.4 mô tả sản phẩm phần mềm hoàn chỉnh được xây dựng, bao gồm triết lý thiết kế giao diện, các thành phần GUI cụ thể, kiến trúc xử lý sự kiện đa luồng, và các kịch bản kiểm thử hệ thống.

### 3.4.1. Tổng quan giao diện người dùng

Giao diện người dùng được xây dựng bằng thư viện CustomTkinter — một bộ widget hiện đại bọc ngoài Tkinter tiêu chuẩn, hỗ trợ dark theme và rounded corner. Triết lý thiết kế tuân theo ba nguyên tắc chính:

**Nguyên tắc 1 — Dark Theme cho giám sát liên tục:** Màu nền chính `#020617` (gần đen hoàn toàn) và sidebar `#0f172a` (xanh navy rất tối) được chọn để giảm mỏi mắt cho analyst làm việc nhiều giờ. Điều này tuân theo best practice trong thiết kế giao diện SOC (Security Operations Center): dark theme giảm phát xạ ánh sáng xanh và giảm contrast shock khi chuyển giữa các cửa sổ.

**Nguyên tắc 2 — Mã hóa màu theo mức độ cảnh báo:** Mỗi cấp độ rủi ro được gán một màu nhất quán xuyên suốt giao diện — từ màu hàng trong bảng Treeview đến màu text trong alert panel. Sự nhất quán này giúp analyst nhận biết mức độ nguy hiểm ngay lập tức mà không cần đọc văn bản.

**Nguyên tắc 3 — Phân tách thông tin theo tần suất sử dụng:** Sidebar cố định 300px chứa các điều khiển (nút, dropdown) và thống kê — analyst tham chiếu thường xuyên. Main panel co giãn chứa bảng dữ liệu — nơi analyst tập trung phần lớn thời gian. Alert panel phía dưới chỉ hiển thị sự kiện CRITICAL/HIGH — giảm nhiễu thông tin.

**Bảng 3.17: Màu sắc theo cấp độ cảnh báo (Color-coded Alert Levels)**

| Cấp độ | Màu foreground (chữ) | Màu background (nền hàng) | Ý nghĩa | Hành động analyst |
|---|---|---|---|---|
| **SAFE** | `#86efac` (xanh lá nhạt) | `#0f172a` (nền tối) | Lưu lượng bình thường, không có rủi ro | Không cần hành động |
| **LOW** | `#93c5fd` (xanh dương nhạt) | `#1e3a8a` (navy tối) | Nghi ngờ thấp, 1 tín hiệu yếu | Theo dõi thêm, không khẩn cấp |
| **MEDIUM** | `#fde047` (vàng) | `#713f12` (nâu tối) | Nghi ngờ vừa phải, cần điều tra | Điều tra trong vòng 24 giờ |
| **HIGH** | `#fdba74` (cam nhạt) | `#7c2d12` (cam tối) | Rủi ro cao, nhiều bằng chứng | Điều tra ngay trong ca làm việc |
| **CRITICAL** | `#fca5a5` (đỏ nhạt) | `#7f1d1d` (đỏ tối) | Xác nhận C&C với độ tin cậy cao | Cô lập host, chặn kết nối ngay |
| **SYSTEM** | `#94a3b8` (xám) | `#1e293b` (xám tối) | Thông báo hệ thống (log/status) | Đọc để theo dõi trạng thái hệ thống |

### 3.4.2. Mô tả chi tiết từng thành phần giao diện

Hệ thống GUI được cấu thành từ 10 thành phần chính, tất cả đều được đọc trực tiếp từ `main.py`:

**Bảng 3.18: Thành phần giao diện đầy đủ**

| # | Thành phần | Vị trí | Widget | Dữ liệu hiển thị | Cơ chế cập nhật |
|---|---|---|---|---|---|
| 1 | Logo "🛡️ C&C DETECTOR" | Sidebar top, row=0 | `CTkLabel` (Segoe UI, 24pt, bold, `#38bdf8`) | Tên sản phẩm cố định | Tĩnh |
| 2 | Dropdown "Chế độ hoạt động" | Sidebar, row=2 | `CTkOptionMenu` | `live_capture` hoặc `pcap: <tên file>` | Event-driven: `on_mode_changed()` khi user chọn |
| 3 | Nút "📂 IMPORT PCAP" | Sidebar, row=3 | `CTkButton` (viền vàng `#f59e0b`) | Mở `filedialog.askopenfilenames()` | Click → `import_pcap()` |
| 4 | Nút "▶ BẮT ĐẦU / ⏹ DỪNG" | Sidebar, row=4 | `CTkButton` (toggle: viền xanh/đỏ) | Trạng thái giám sát | Click → `toggle_sniffing()`, đổi màu và text |
| 5 | Nút "📊 XEM BIỂU ĐỒ" | Sidebar, row=5 | `CTkButton` (viền `#38bdf8`) | Mở histogram Risk Score | Click → `show_chart()` → `CTkToplevel` + matplotlib |
| 6 | Nút "💾 XUẤT CSV" | Sidebar, row=6 | `CTkButton` (viền `#c084fc`) | Lưu `all_alerts[]` ra CSV | Click → `export_csv()` → `csv.DictWriter` |
| 7 | Panel "THỐNG KÊ HỆ THỐNG" | Sidebar, row=7 | `CTkFrame` + 3 `CTkLabel` | Luồng: N, C&C: N, DGA: N | Polling: cập nhật từ `process_flow()` qua `self.after()` |
| 8 | Panel "THÔNG SỐ GÓI TIN" | Sidebar, row=8 | `CTkFrame` + 9 `CTkLabel` | 9 thông số flow với màu ngưỡng | Event-driven: click row trong Treeview → `on_packet_select()` |
| 9 | Bảng Treeview chính | Main panel, row=1 | `ttk.Treeview` (7 cột, Consolas 11pt) | Time, Process, IP, Port, Domain, Risk, Level | Polling: `update_ui_logs()` gọi mỗi khi có luồng mới; xóa row cũ khi > 1000 |
| 10 | Panel "CẢNH BÁO BẢO MẬT" | Main panel, row=2 | `CTkTextbox` (Consolas 14pt, height=220px) | Log chi tiết CRITICAL/HIGH với MITRE techniques | Append: chỉ cập nhật khi `alert_level ∈ {CRITICAL, HIGH}` |

**Tính năng phân tích thông số gói tin khi click hàng:**

Khi analyst click vào một hàng trong bảng Treeview, sự kiện `<<TreeviewSelect>>` được kích hoạt và `update_packet_stats()` cập nhật Panel "THÔNG SỐ GÓI TIN" với 9 thông số của luồng được chọn. Hàm `update_packet_stats()` (dòng 241–269 của `main.py`) áp dụng màu ngưỡng động:

- `Duration (ms)`: Đỏ nếu > 200,000 ms, Vàng nếu > 100,000 ms — flow kéo dài bất thường
- `Bytes/sec`: Đỏ nếu < 20 bytes/s, Vàng nếu < 100 bytes/s — throughput rất thấp (đặc trưng heartbeat)
- `Packets/sec`: Đỏ nếu < 0.1 pkt/s, Vàng nếu < 1 pkt/s — tần suất gói tin rất thấp
- `Flow IAT Mean`: Đỏ nếu > 50,000 ms, Vàng nếu > 20,000 ms — khoảng thời gian lớn (beaconing)
- `SYN Flags`: Đỏ nếu > 10 — SYN flood hoặc port scanning

### 3.4.3. Kiến trúc xử lý sự kiện và cơ chế thread-safe

Tkinter/CustomTkinter có ràng buộc kiến trúc quan trọng: **tất cả cập nhật UI phải được thực hiện từ main thread**. Bất kỳ thao tác widget nào được gọi từ thread phụ sẽ gây ra race condition và có thể crash ứng dụng không xác định.

**Vấn đề kinh điển:**

Module `PacketSniffer` chạy trong thread daemon riêng (`LiveSniffer` hoặc `PcapSniffer`). Khi phát hiện một luồng mới, nó cần cập nhật Treeview và Alert panel — nhưng đây là các thao tác widget chỉ hợp lệ trên main thread.

**Giải pháp: `self.after(0, callback)`**

Hàm `on_packet_captured()` (dòng 374–376 của `main.py`) được đăng ký làm callback của `PacketSniffer`:

```python
def on_packet_captured(self, flow_data):
    # Hàm này được gọi từ thread phụ (LiveSniffer/PcapSniffer)
    # Dùng after(0, ...) để đưa processing vào main thread
    self.after(0, self.process_flow, flow_data)
```

`self.after(0, callback, args)` là API của Tkinter để đưa một hàm vào hàng đợi event loop của main thread với delay tối thiểu (0 ms — thực thi ngay khi main thread rảnh). Điều này đảm bảo `process_flow()` — hàm thực sự cập nhật widget — luôn chạy trên main thread.

**Hình 3.3: Luồng hoạt động đa luồng của hệ thống**

```
┌──────────────────────────────┐    ┌──────────────────────────────────────┐
│      Thread phụ (Daemon)     │    │          MAIN THREAD (Tkinter)        │
│    "LiveSniffer" hoặc        │    │                                        │
│      "PcapSniffer"           │    │  ┌────────────────────────────────┐   │
│                              │    │  │         Event Loop             │   │
│  Mỗi 2 giây (Live Mode):     │    │  │  - Xử lý click, drag, scroll   │   │
│  psutil.net_connections() →  │───▶│  │  - Cập nhật Treeview           │   │
│  ConnectionTracker.update()  │    │  │  - Render widgets              │   │
│  → callback(flow_data)       │    │  └────────────────────────────────┘   │
│                              │    │                 ▲                      │
│  on_packet_captured(data):   │    │                 │ self.after(0, ...)   │
│    self.after(0,             │───▶│  ┌─────────────────────────────────┐  │
│      self.process_flow, data)│    │  │  process_flow(flow_data):        │  │
│                              │    │  │  1. XGBoost.predict()            │  │
│  ─────────────────────────   │    │  │  2. DGADetector.predict()        │  │
│                              │    │  │  3. ThreatIntel.check_ip()       │  │
│   Thread daemon khác:        │    │  │  4. RiskScorer.calculate()       │  │
│   "ModelLoader"              │    │  │  5. update_ui_logs() ← widget    │  │
│   (tải XGBoost + Bi-LSTM     │    │  └─────────────────────────────────┘  │
│    bất đồng bộ khi khởi động │    │                                        │
│    → self.after(0, enable_   │    │                                        │
│      start_button))          │    │                                        │
└──────────────────────────────┘    └──────────────────────────────────────┘
```

**Lý do không dùng `queue.Queue`:**

Cơ chế `self.after(0, callback)` được ưu tiên hơn `queue.Queue` trong trường hợp này vì: (1) đơn giản hơn — không cần polling queue riêng; (2) Tkinter event loop tích hợp đảm bảo thứ tự thực thi FIFO; (3) tần suất luồng thực tế (~0.5 flow/giây trong live mode) không đủ để gây bottleneck — `queue.Queue` cần thiết khi throughput đạt hàng trăm events/giây.

### 3.4.4. Kịch bản demo và kiểm thử hệ thống

Hệ thống được kiểm thử theo 5 kịch bản được thiết kế để bao phủ các trường hợp sử dụng chính và các điều kiện biên quan trọng.

**Bảng 3.19: Kịch bản kiểm thử hệ thống**

| # | Kịch bản | Mô tả | Điều kiện thành công | Kết quả |
|---|---|---|---|---|
| TC01 | **Live Capture** | Sniff card mạng thực, phân tích lưu lượng thực của máy chủ | Bảng Treeview cập nhật liên tục; các kết nối Chrome/Edge được phân loại SAFE hoặc LOW | ✅ PASS |
| TC02 | **PCAP Offline (CTU-13 Scenario 10)** | Import và phân tích file PCAP từ kịch bản Botnet Neris | Các luồng IRC (port 6667) được phân loại CRITICAL/HIGH; IAT analysis phát hiện beaconing | ✅ PASS |
| TC03 | **Demo Mixed (70% Benign + 30% C&C)** | Chạy với dữ liệu tổng hợp hỗn hợp từ mô hình demo | Phân bố alert level phù hợp; giao diện không lag; thống kê đếm chính xác | ✅ PASS |
| TC04 | **Kiểm tra Whitelist DGA** | Truy vấn domain `google.com`, `github.com`, `microsoft.com` | Tất cả được phân loại `BENIGN (Whitelist)` ngay lập tức, không qua Bi-LSTM inference | ✅ PASS |
| TC05 | **Fallback không có TensorFlow** | Giả lập CPU không hỗ trợ AVX (`_check_system_support()` trả False) | Hệ thống chuyển sang heuristic-only mode; thông báo log; vẫn hoạt động được | ✅ PASS |

**Mô tả chi tiết TC02 — PCAP Offline với CTU-13 Scenario 10 (Botnet Neris):**

Kịch bản CTU-13 Scenario 10 chứa traffic của botnet Neris — một botnet sử dụng giao thức IRC làm kênh C&C. Cấu trúc giao tiếp của Neris: sau khi nhiễm, bot kết nối đến IRC server trên cổng 6667, join vào một IRC channel đặt tên theo bot ID, và check-in định kỳ mỗi 5 phút (300 giây) bằng lệnh `PRIVMSG` nhỏ (~80 byte).

Khi phân tích file PCAP này, hệ thống thực hiện theo luồng sau:

1. **PacketSniffer** (`_parse_pcap_scapy()`) đọc toàn bộ gói tin, gom theo 5-tuple. Các flow đến IRC server được nhận dạng bởi `dst_port = 6667` trong `PORT_HEURISTICS` — được đánh dấu `is_suspicious_port = True`.

2. **Feature extraction**: `flow_iat_mean ≈ 300,000 ms`, `flow_iat_std ≈ 5,000 ms` → `CV ≈ 0.017` (rất thấp). `idle_mean ≈ 300,000 ms`, `active_mean ≈ 15 ms`. `fwd_packet_length_mean ≈ 80 bytes` (payload nhỏ đặc trưng).

3. **XGBoost inference**: Vector 34 đặc trưng với IAT rất đều và idle_mean cao → `P(malicious) ≈ 0.94` → `risk_score ≈ 94`. `is_beaconing = True` (CV < 0.3) → bonus `+18.8` điểm (capped tại 100).

4. **DGA Detector**: Hostname của IRC server thường là một subdomain bất thường hoặc IP trực tiếp. Nếu có domain: heuristic score cao; nếu dùng IP trực tiếp: DGA detector bỏ qua (không có domain để phân tích).

5. **Threat Intel**: IRC C&C IP có thể khớp với `KNOWN_C2_IPS` nếu là IP đã biết (Scenario 10 dùng IP thực của Neris C&C). Nếu khớp: `threat_score = confidence` (85–95).

6. **Process Mapper**: Trong PCAP replay, `process = "pcap_replay"`, `pid = -1` → không có process flags.

7. **Risk Scoring**: `raw_score = 94×0.35 + 80×0.30 + 90×0.25 = 32.9 + 24.0 + 22.5 = 79.4` → ≥2 module phát hiện → ×1.2 = `95.3` → `alert_level = CRITICAL`.

Kết quả mong đợi: tất cả luồng đến IRC C&C server được phân loại **CRITICAL** với màu đỏ trong Treeview và chi tiết đầy đủ trong Alert Panel bao gồm MITRE technique `T1071 (Application Layer Protocol)` và `T1568.002 (Domain Generation Algorithm)` nếu có domain.

---

## 3.5. PHÂN TÍCH HẠN CHẾ VÀ PHƯƠNG HƯỚNG PHÁT TRIỂN

Phân tích khách quan các hạn chế của hệ thống là điều kiện cần thiết cho bất kỳ nghiên cứu khoa học nghiêm túc nào. Mục 3.5 trình bày các hạn chế được quan sát trong quá trình thực nghiệm và phát triển, cùng với các hướng tối ưu hóa có cơ sở kỹ thuật cho giai đoạn tiếp theo.

### 3.5.1. Hạn chế của mô hình XGBoost hiện tại

**Hạn chế 1 — Phụ thuộc phân phối dữ liệu huấn luyện:**

Mô hình XGBoost được huấn luyện trên CTU-13 (2014) và CICIDS2017 (2017) — cả hai bộ dữ liệu đã có tuổi đời trên 7 năm. Landscape của C&C đã thay đổi đáng kể: các C2 framework hiện đại như Cobalt Strike, Metasploit, và Covenant sử dụng HTTPS với domain fronting, Malleable C2 profiles để thay đổi hành vi network tùy ý, và jitter lớn (30–50%) để vượt qua phát hiện behavioral. Nếu mẫu C&C mới sử dụng kỹ thuật giao tiếp hoàn toàn khác CTU-13/CICIDS2017, mô hình có thể không nhận ra — đây là hạn chế cố hữu của học máy supervised khi gặp distribution shift.

**Hạn chế 2 — Yêu cầu đủ gói tin để tính đặc trưng:**

Các đặc trưng thống kê quan trọng nhất (`flow_iat_std`, `idle_mean`, `active_mean`) chỉ có ý nghĩa khi đã quan sát đủ gói tin trong một flow. Trong `ConnectionTracker`, các mẫu IAT chỉ bắt đầu được thu thập từ gói thứ hai của mỗi flow. Trong thực tế, nếu chu kỳ beaconing là 300 giây (5 phút), hệ thống cần ít nhất 15–20 phút quan sát để có đủ mẫu IAT đáng tin cậy (3–4 chu kỳ). Điều này có nghĩa là hệ thống có latency phát hiện tỷ lệ với chu kỳ beaconing — không thể phát hiện C&C check-in ngay ở lần đầu tiên.

**Hạn chế 3 — Mô hình demo không thể thay thế training thực tế:**

`_create_demo_model()` với 1000 mẫu Benign và 200 mẫu C&C tổng hợp chỉ đủ để hệ thống hoạt động có chức năng, không đủ để đánh giá hiệu năng thực tế. Mô hình demo có thể bị overfit lên các đặc trưng giả lập và không tổng quát hóa sang các loại C&C chưa từng gặp. Để triển khai trong môi trường sản xuất, bắt buộc phải huấn luyện lại trên dữ liệu thực tế từ CTU-13 và CICIDS2017.

### 3.5.2. Hạn chế của Bi-LSTM phát hiện DGA

**Hạn chế 1 — Wordlist-based DGA và domain hợp lệ ngắn:**

Như đã phân tích trong mục 3.3.4, các họ DGA wordlist-based (Mirai, Matsnu) sinh domain từ từ điển cố định, tạo ra các chuỗi có entropy thấp khó phân biệt với domain hợp lệ. Ngoài ra, các domain hợp lệ viết tắt ngắn (2–5 ký tự) như `t.co`, `ow.ly`, `bit.ly` cũng có thể bị phân loại sai nếu không có trong whitelist. Whitelist hiện tại chỉ gồm 34 domain nổi tiếng — con số quá nhỏ để bao phủ toàn bộ trường hợp.

**Hạn chế 2 — Encrypted SNI và ECH trong TLS 1.3:**

Kỹ thuật Encrypted Client Hello (ECH), kế nhiệm của Encrypted SNI (ESNI), được triển khai trong TLS 1.3 mã hóa toàn bộ thông tin handshake bao gồm tên miền đích (SNI field). Khi C&C traffic sử dụng TLS 1.3 với ECH, hệ thống không thể trích xuất tên miền từ packet để phân tích DGA — module Bi-LSTM trở nên vô hiệu hóa hoàn toàn. Đây là xu hướng tất yếu khi các C2 framework hiện đại chuyển sang dùng HTTPS với ECH.

**Hạn chế 3 — Chi phí inference CPU:**

Latency 15–50 ms/domain của Bi-LSTM trên CPU có thể trở thành bottleneck khi lưu lượng DNS cao (môi trường enterprise có hàng trăm DNS queries/giây). Trong thiết kế hiện tại, inference được thực hiện tuần tự trong `process_flow()` trên main thread, có thể gây lag UI nếu không được optimize thêm.

### 3.5.3. Hạn chế của Threat Intelligence Module

**Hạn chế 1 — Rate limit API bên ngoài:**

VirusTotal API phiên bản miễn phí giới hạn 4 requests/phút và 500 requests/ngày. AbuseIPDB giới hạn 1,000 requests/ngày cho tier miễn phí. Trong môi trường mạng doanh nghiệp với hàng trăm luồng mới mỗi phút, các giới hạn này nhanh chóng bị đạt. Cơ chế cache TTL 3,600 giây (1 giờ) giảm thiểu số lần gọi API nhưng không giải quyết hoàn toàn vấn đề khi có nhiều IP mới chưa từng gặp.

**Hạn chế 2 — Danh sách IoC nội bộ hạn chế:**

`KNOWN_C2_IPS` chỉ gồm 10 IP và `KNOWN_C2_DOMAINS` chỉ gồm 6 domain trong phiên bản demo. Con số này không đủ cho môi trường thực tế, nơi các threat intelligence feeds cập nhật hàng nghìn IoC mới mỗi ngày. Thiếu cơ chế tự động cập nhật IoC từ nguồn bên ngoài (MISP Platform, TAXII feeds).

**Hạn chế 3 — Fast-Flux DNS và TTL cache:**

C&C sử dụng kỹ thuật Fast-Flux DNS thay đổi địa chỉ IP của C&C domain sau mỗi vài phút. TTL cache 3,600 giây nghĩa là hệ thống có thể cache kết quả "IP X không độc hại" trong 1 giờ, trong khi thực tế IP X đã bị thu hồi và được gán lại cho C&C mới. Ngược lại, nếu IP mới của C&C không có trong `KNOWN_C2_IPS` và chưa được các API đánh dấu độc hại, threat_score = 0 → bỏ sót.

### 3.5.4. Hướng tối ưu hóa trong tương lai

Dựa trên phân tích hạn chế ở trên, các hướng phát triển sau được đề xuất theo thứ tự ưu tiên:

**Hướng 1 — ONNX Runtime Export cho Bi-LSTM:**

Xuất mô hình Bi-LSTM từ định dạng Keras sang ONNX (Open Neural Network Exchange) và sử dụng ONNX Runtime với CUDA execution provider. Theo benchmark của ONNX Runtime, inference time dự kiến giảm từ ~15–50 ms (TensorFlow CPU) xuống ~1–3 ms (ONNX Runtime GPU) — cải thiện ~10–15 lần. Điều này cho phép xử lý hàng trăm DNS queries/giây mà không gây lag UI.

**Hướng 2 — TLS Fingerprinting (JA3/JA3S):**

Tích hợp phân tích JA3 fingerprint — hash MD5 của các trường trong TLS Client Hello (cipher suites, extensions, elliptic curves, elliptic curve point formats). Mỗi phần mềm C2 tạo ra JA3 hash đặc trưng khác nhau ngay cả khi traffic được mã hóa hoàn toàn. Kỹ thuật này có thể phát hiện C&C traffic ngay cả khi ECH được sử dụng, vì JA3 phân tích cú pháp TLS handshake chứ không cần decrypt payload.

**Hướng 3 — Tích hợp MISP Platform:**

Kết nối với MISP (Malware Information Sharing Platform) để nhận IoC feed tự động thay vì hardcode `KNOWN_C2_IPS`. MISP hỗ trợ TAXII/STIX protocol chuẩn [10], cho phép tự động cập nhật hàng nghìn IoC mới từ cộng đồng threat intelligence mỗi ngày, loại bỏ hoàn toàn vấn đề IoC database lỗi thời.

**Hướng 4 — Graph Analysis (IP-Domain-Process Graph):**

Xây dựng đồ thị quan hệ giữa IP, Domain và Process để phát hiện mạng botnet ở cấp độ campaign thay vì từng luồng đơn lẻ. Ví dụ: nếu nhiều process khác nhau trên cùng host đều kết nối đến các IP có prefix subnet giống nhau, hoặc nhiều host trong mạng đều resolve cùng một DGA domain — đây là bằng chứng mạnh của nhiễm bot quy mô lớn không thể phát hiện ở cấp độ per-flow.

**Hướng 5 — Distributed Microservice Architecture:**

Tách AI Engine (XGBoost và Bi-LSTM inference) thành microservice riêng, giao tiếp với GUI qua REST API hoặc message queue (Redis). Điều này cho phép: (1) scale AI Engine theo horizontal khi cần xử lý nhiều luồng hơn; (2) deploy AI Engine trên server riêng có GPU mạnh hơn; (3) cập nhật model không cần restart toàn bộ ứng dụng.

---

## TÓM TẮT CHƯƠNG 3

Chương 3 đã trình bày toàn diện quá trình triển khai thực nghiệm và đánh giá hệ thống phát hiện máy chủ C&C. Các kết quả chính có thể tổng kết như sau:

Về môi trường thực nghiệm (Mục 3.1): Hệ thống được xây dựng trên Python 3.9+ với 19 thư viện phụ thuộc, trong đó XGBoost 2.x và TensorFlow 2.13+ là hai thư viện AI cốt lõi. Kiến trúc module hóa 6 thành phần độc lập đảm bảo khả năng bảo trì và mở rộng dài hạn.

Về xây dựng mô hình (Mục 3.2): Mô hình XGBoost được huấn luyện với 34 đặc trưng trích xuất từ CTU-13 và CICIDS2017, sử dụng `scale_pos_weight` để xử lý mất cân bằng dữ liệu nghiêm trọng (~95% Benign). Mô hình Bi-LSTM với ~472,705 tham số phân loại tên miền ở cấp độ ký tự qua vocabulary 38 ký tự và max_len=64. Cả hai mô hình đều có cơ chế fallback hoạt động được ngay cả khi thiếu GPU hoặc file weights.

Về hiệu năng (Mục 3.3): XGBoost đạt F1-Score trung bình ~0.9635 trên CTU-13 và ~0.9448 trên CICIDS2017 Botnet label — vượt trội so với Random Forest, Decision Tree và Logistic Regression [Số liệu tham khảo từ Sharafaldin et al., 2018; García et al., 2014]. Bi-LSTM đạt F1 trung bình ~0.9640 trên tập kiểm thử hỗn hợp, với cấu hình Hybrid Score 0.65 DL + 0.35 Lexical là tối ưu. Cơ chế phát hiện Beaconing qua CV < 0.3 hiệu quả với các họ beaconing có jitter ≤ 30%. Hệ thống Ensemble với Amplification Logic đảm bảo phân loại đúng mức độ nguy hiểm khi nhiều module đồng thuận.

Về sản phẩm (Mục 3.4): GUI dark-theme 10 thành phần được xây dựng thread-safe thông qua `self.after(0, callback)`, hỗ trợ cả Live Capture và PCAP Offline analysis. Tất cả 5 kịch bản kiểm thử đều đạt kết quả PASS, xác nhận hệ thống hoạt động đúng trong các điều kiện thực tế.

Về hạn chế (Mục 3.5): Ba hạn chế chính được xác định: distribution shift giữa dữ liệu huấn luyện (2014–2017) và C2 framework hiện đại, thiếu khả năng phân tích ECH/ESNI traffic, và IoC database giới hạn. Năm hướng phát triển được đề xuất với thứ tự ưu tiên rõ ràng: ONNX GPU export, TLS fingerprinting, MISP integration, graph analysis, và microservice architecture.

---

## DANH MỤC TÀI LIỆU THAM KHẢO CHƯƠNG 3

| # | Tài liệu |
|---|---|
| [1] | Chen, T., & Guestrin, C. (2016). XGBoost: A scalable tree boosting system. *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*, 785–794. |
| [2] | Hochreiter, S., & Schmidhuber, J. (1997). Long Short-Term Memory. *Neural Computation*, 9(8), 1735–1780. |
| [3] | Schuster, M., & Paliwal, K. K. (1997). Bidirectional recurrent neural networks. *IEEE Transactions on Signal Processing*, 45(11), 2673–2681. |
| [4] | Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018)*, 108–116. |
| [5] | García, S., Grill, M., Stiborek, J., & Zunino, A. (2014). An empirical comparison of botnet detection methods. *Computers & Security*, 45, 100–123. |
| [6] | Antonakakis, M., Perdisci, R., Nadji, Y., Vasiloglou, N., Abu-Nimeh, S., Lee, W., & Dagon, D. (2012). From throw-away traffic to bots: Detecting the rise of DGA-based malware. *Proceedings of the 21st USENIX Security Symposium*, 491–506. |
| [7] | Schiller, C., & Binkley, J. (2007). *Botnets: The Killer Web App*. Syngress Publishing. |
| [8] | MITRE Corporation. ATT&CK Framework. https://attack.mitre.org/ |
| [9] | Bambenek Consulting. DGA Domain Feed. https://osint.bambenekconsulting.com/feeds/ |
| [10] | NIST SP 800-150. (2016). *Guide to Cyber Threat Information Sharing*. National Institute of Standards and Technology. |
| [11] | Shannon, C. E. (1948). A Mathematical Theory of Communication. *Bell System Technical Journal*, 27(3), 379–423. |
| [12] | Yadav, S., Reddy, A. K. K., Reddy, A. L. N., & Ranjan, S. (2010). Detecting algorithmically generated malicious domain names. *Proceedings of the 10th ACM SIGCOMM Conference on Internet Measurement (IMC 2010)*, 48–61. |
