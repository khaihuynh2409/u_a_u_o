# MỤC LỤC CHI TIẾT — BÁO CÁO KẾT QUẢ SẢN PHẨM
### Hệ thống Phát hiện Máy chủ C&C sử dụng Phân tích Đa lớp và Trí tuệ Nhân tạo
*(Ước tính ~100 trang)*

---

## PHẦN MỞ ĐẦU *(~5 trang)*

- Tính cấp thiết của đề tài: Sự gia tăng của mã độc sử dụng kỹ thuật ẩn mình (Beaconing, DGA) qua mặt các hệ thống giám sát truyền thống dựa trên chữ ký (Signature-based IDS/IPS).
- Mục tiêu nghiên cứu: Xây dựng hệ thống phát hiện máy chủ C&C dựa trên phân tích đa lớp (Multi-layered Analysis) sử dụng AI, không phụ thuộc vào chữ ký tĩnh.
- Đối tượng và phạm vi nghiên cứu: Luồng dữ liệu mạng (Network Flows — 5-tuple) và tên miền truy vấn (DNS/SNI) trên môi trường thực tế Windows.
- Phương pháp nghiên cứu: Kết hợp lý thuyết an toàn thông tin với thực nghiệm Học máy (XGBoost) và Học sâu (Bi-LSTM).
- Bố cục của báo cáo.

---

## CHƯƠNG 1: TỔNG QUAN VỀ C&C SERVER VÀ CƠ SỞ LÝ THUYẾT AI *(~28 trang)*

### 1.1. Cơ chế hoạt động của máy chủ Command & Control (C&C) *(~10 trang)*
> *Tham khảo: Schiller & Binkley (2007); MITRE ATT&CK Framework; Symantec ISTR.*

**1.1.1. Vòng đời của botnet và vai trò của máy chủ C&C**
- Mô hình Cyber Kill Chain (Lockheed Martin): từ Reconnaissance đến Actions on Objectives.
- Phân loại kiến trúc C&C: Centralized (IRC/HTTP), Peer-to-Peer, Hybrid.

**1.1.2. Kỹ thuật giao tiếp định kỳ (Beaconing) và các phương thức lẩn tránh**
- Định nghĩa Beaconing: tín hiệu "heartbeat" định kỳ (MITRE T1071).
- Kỹ thuật Jitter (thêm nhiễu ngẫu nhiên), Fast-Flux DNS, Domain Fronting.
- Chỉ số nhận biết: Coefficient of Variation (CV) của Inter-Arrival Time (IAT).

**1.1.3. Các giao thức ứng dụng phổ biến trong kênh C&C**
- HTTP/HTTPS Beaconing (T1071.001): ngụy trang trong lưu lượng web hợp lệ.
- DNS Tunneling (T1071.004): mã hóa dữ liệu trong truy vấn DNS.
- IRC và các giao thức tùy biến.

**1.1.4. Thuật toán sinh tên miền tự động (Domain Generation Algorithm — DGA)**
- Nguyên lý: seed theo ngày/giờ → sinh hàng nghìn tên miền mỗi ngày.
- Phân loại: Arithmetic-based (Conficker), Hash-based (Cryptolocker), Wordlist-based.
- Điểm yếu của hệ thống chặn IP/domain tĩnh trước DGA.

### 1.2. Phân tích hành vi luồng mạng (Network Flow Analysis) *(~8 trang)*
> *Tham khảo: Sharafaldin et al., ICISSP 2018 (CICIDS2017); RFC 3954 (NetFlow); RFC 7011 (IPFIX).*

**1.2.1. Khái niệm luồng dữ liệu 5-tuple**
- Định nghĩa đúng: (Source IP, Destination IP, Source Port, Destination Port, Protocol).
- Chuẩn NetFlow (RFC 3954) và IPFIX (RFC 7011).
- Ưu điểm của Flow-based Analysis khi lưu lượng bị mã hóa (TLS/HTTPS) so với DPI.

**1.2.2. Các đặc trưng thời gian thực quan trọng**
- **Inter-Arrival Time (IAT)**: mean, std, max, min — dấu hiệu cốt lõi của Beaconing.
- **Active/Idle Time**: chu kỳ "hoạt động ngắn — ngủ dài" của mã độc.
- **Packet Length Distribution**: mean, variance — đặc trưng heartbeat payload nhỏ.
- **TCP Flag Counts**: SYN, ACK, FIN, RST — phát hiện scanning và kết nối bất thường.
- Bảng đối chiếu 34 đặc trưng từ CIC-IDS2017 sử dụng trong hệ thống.

### 1.3. Cơ sở lý thuyết về các thuật toán Học máy áp dụng *(~7 trang)*
> *Tham khảo: Chen & Guestrin, KDD 2016 (XGBoost); Hochreiter & Schmidhuber, 1997 (LSTM); Schuster & Paliwal, IEEE TSP 1997 (Bi-LSTM).*

**1.3.1. Thuật toán XGBoost trong phân tích dữ liệu bảng (Tabular Data)**
- Gradient Boosting cơ bản: từ AdaBoost đến GBDT.
- Đóng góp của XGBoost: Regularization (L1/L2), Column Subsampling, Weighted Quantile Sketch.
- Xử lý mất cân bằng dữ liệu: tham số `scale_pos_weight`.
- Tại sao XGBoost phù hợp với dữ liệu mạng dạng bảng thống kê.

**1.3.2. Mạng nơ-ron hồi quy Bi-LSTM trong xử lý chuỗi ký tự tên miền**
- LSTM: cơ chế cổng (Forget Gate, Input Gate, Output Gate) giải quyết Vanishing Gradient.
- Bidirectional LSTM: đọc chuỗi từ hai chiều để nắm ngữ cảnh đầy đủ.
- Character-level Embedding: lý do dùng ký tự thay vì từ cho bài toán DGA.

### 1.4. Tình báo mối đe dọa (Threat Intelligence) và Chỉ số xâm phạm (IoC) *(~3 trang)*
> *Tham khảo: NIST SP 800-150; MISP Threat Sharing Platform.*

- Định nghĩa IoC: IP độc hại, hash file, domain.
- Các nguồn Threat Intelligence mở (OSINT): AbuseIPDB, VirusTotal API v3, Feodo Tracker.
- Cơ chế caching IoC để tránh gọi API liên tục trong hệ thống thời gian thực.

---

## CHƯƠNG 2: PHÂN TÍCH THIẾT KẾ VÀ KIẾN TRÚC HỆ THỐNG *(~37 trang)*

### 2.1. Phân tích yêu cầu và Sơ đồ Use Case *(~10 trang)*

**2.1.1. Xác định tác nhân (Actor) của hệ thống**

| Actor | Mô tả |
|---|---|
| **Người phân tích bảo mật** (Security Analyst) | Người dùng chính: giám sát, điều tra cảnh báo, xuất báo cáo |
| **Hệ thống mạng** (Network) | Nguồn sinh luồng dữ liệu và gói tin thô |
| **Mô hình AI** (AI Engine) | XGBoost + Bi-LSTM — tác nhân phân tích nội bộ |
| **Nguồn Threat Intel** (TI Feed) | VirusTotal API, AbuseIPDB API, Local IOC DB |
| **Hệ điều hành** (OS) | Cung cấp thông tin tiến trình qua `psutil` |

**2.1.2. Sơ đồ Use Case tổng thể (System Use Case Diagram)**

*Mô tả sơ đồ gồm các Use Case chính (UML):*

```
Actor: Security Analyst
  ├── UC01: Khởi động/Dừng giám sát mạng
  ├── UC02: Import file PCAP để phân tích ngoại tuyến
  ├── UC03: Xem danh sách luồng mạng theo thời gian thực
  ├── UC04: Xem chi tiết cảnh báo CRITICAL/HIGH
  ├── UC05: Xem biểu đồ phân bố điểm rủi ro
  └── UC06: Xuất báo cáo CSV

Actor: Network (tự động)
  └── UC07: Bắt gói tin và trích xuất đặc trưng Flow

Actor: AI Engine (tự động, được kích hoạt bởi UC07)
  ├── UC08: Phân loại luồng mạng bằng XGBoost
  ├── UC09: Phát hiện tên miền DGA bằng Bi-LSTM
  └── UC10: Tính điểm rủi ro tổng hợp (Weighted Ensemble)

Actor: TI Feed (tự động, được kích hoạt bởi UC07)
  └── UC11: Tra cứu IP/Domain với cơ sở dữ liệu IoC

Actor: OS (tự động, được kích hoạt bởi UC07)
  └── UC12: Ánh xạ kết nối với tiến trình hệ thống
```

**2.1.3. Bảng đặc tả Use Case chi tiết**

---
**UC01 — Khởi động/Dừng giám sát mạng**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Khởi động / Dừng giám sát mạng |
| **Actor chính** | Security Analyst |
| **Mô tả** | Người dùng nhấn nút "BẮT ĐẦU GIÁM SÁT" để bắt đầu luồng phân tích, nhấn "DỪNG" để kết thúc |
| **Điều kiện tiên quyết** | Mô hình AI (XGBoost, Bi-LSTM) đã được tải thành công vào bộ nhớ |
| **Luồng chính** | 1. Người dùng chọn chế độ (Live Capture hoặc PCAP file) → 2. Nhấn "▶ BẮT ĐẦU" → 3. Hệ thống khởi động thread `PacketSniffer` → 4. Callback `on_packet_captured` được đăng ký → 5. Giao diện bắt đầu cập nhật thời gian thực |
| **Luồng thay thế** | Nếu file PCAP không tồn tại → hiển thị cảnh báo và hủy khởi động |
| **Hậu điều kiện** | Thread sniffer đang chạy, bảng dữ liệu được cập nhật liên tục |
| **Ngoại lệ** | Quyền Administrator không đủ → Npcap từ chối bắt gói tin |

---
**UC02 — Import file PCAP để phân tích ngoại tuyến**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Import file PCAP |
| **Actor chính** | Security Analyst |
| **Mô tả** | Người dùng nhập một hoặc nhiều file `.pcap`/`.pcapng` vào hệ thống để phân tích ngoại tuyến |
| **Điều kiện tiên quyết** | File PCAP hợp lệ tồn tại trên hệ thống |
| **Luồng chính** | 1. Nhấn "📂 IMPORT PCAP" → 2. Hộp thoại `filedialog.askopenfilenames()` mở → 3. Chọn một hoặc nhiều file → 4. Tên file được thêm vào dropdown "Chế độ hoạt động" → 5. Tự động chuyển chế độ sang file vừa thêm |
| **Hậu điều kiện** | File PCAP xuất hiện trong danh sách dropdown, sẵn sàng phân tích |
| **Ngoại lệ** | File trùng lặp → bỏ qua và hiển thị thông báo |

---
**UC03 — Xem danh sách luồng mạng theo thời gian thực**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Giám sát luồng mạng thời gian thực |
| **Actor chính** | Security Analyst, Network |
| **Mô tả** | Bảng Treeview hiển thị mỗi luồng mạng kèm: thời gian, tiến trình, IP đích, cổng, domain, điểm rủi ro, cấp độ cảnh báo |
| **Điều kiện tiên quyết** | Hệ thống đang ở trạng thái giám sát (UC01 đã kích hoạt) |
| **Luồng chính** | 1. Gói tin được bắt → 2. `process_flow()` xử lý → 3. `update_ui_logs()` gọi `self.after()` → 4. Treeview chèn hàng mới với màu theo cấp độ (CRITICAL=đỏ/HIGH=cam/MEDIUM=vàng/LOW=xanh/SAFE=xanh lá) → 5. Bảng tự cuộn xuống cuối |
| **Luồng thay thế** | Nếu bảng vượt 1000 dòng → tự động xóa dòng cũ nhất |
| **Hậu điều kiện** | Người dùng thấy dữ liệu mới nhất luôn hiển thị |

---
**UC04 — Xem chi tiết cảnh báo CRITICAL/HIGH**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Xem chi tiết cảnh báo bảo mật |
| **Actor chính** | Security Analyst |
| **Mô tả** | Panel cảnh báo phía dưới hiển thị chi tiết các sự kiện mức CRITICAL và HIGH, bao gồm IP, domain, tiến trình, họ mã độc, kỹ thuật MITRE |
| **Điều kiện tiên quyết** | Có ít nhất một cảnh báo mức HIGH hoặc CRITICAL |
| **Luồng chính** | 1. Risk Scorer trả về `alert_level ∈ {CRITICAL, HIGH}` → 2. `alert_msg` được tạo với đầy đủ `details[]` và `mitre_techniques[]` → 3. Chèn vào `CTkTextbox` (alert panel) → 4. Tự cuộn xuống dòng mới nhất |
| **Ngoại lệ** | Không có cảnh báo → panel trống |

---
**UC05 — Xem biểu đồ phân bố điểm rủi ro**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Xem biểu đồ Risk Score |
| **Actor chính** | Security Analyst |
| **Mô tả** | Mở cửa sổ popup với biểu đồ histogram phân bố điểm rủi ro (0–100) của tất cả luồng đã phân tích |
| **Điều kiện tiên quyết** | Đã có ít nhất một luồng được phân tích (`all_alerts` không rỗng) |
| **Luồng chính** | 1. Nhấn "📊 XEM BIỂU ĐỒ" → 2. `show_chart()` mở `CTkToplevel` → 3. `matplotlib` vẽ histogram 20 bins từ `all_alerts["Risk"]` → 4. Nhúng vào cửa sổ qua `FigureCanvasTkAgg` |
| **Luồng thay thế** | Chưa có dữ liệu → hiển thị thông báo trong log |

---
**UC06 — Xuất báo cáo CSV**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Xuất báo cáo CSV |
| **Actor chính** | Security Analyst |
| **Mô tả** | Xuất toàn bộ danh sách cảnh báo ra file CSV với đầy đủ các trường: Time, Process, IP, Port, Domain, Risk, Level |
| **Điều kiện tiên quyết** | Đã có ít nhất một luồng được phân tích |
| **Luồng chính** | 1. Nhấn "💾 XUẤT CSV" → 2. `filedialog.asksaveasfilename()` mở → 3. Người dùng chọn đường dẫn → 4. `csv.DictWriter` ghi toàn bộ `all_alerts[]` → 5. Hiển thị thông báo thành công |
| **Ngoại lệ** | Lỗi ghi file (quyền truy cập) → hiển thị lỗi trong log |

---
**UC07 — Bắt gói tin và trích xuất đặc trưng Flow**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Packet Sniffing & Feature Extraction |
| **Actor chính** | Network (tự động) |
| **Mô tả** | Module `PacketSniffer` (Scapy) bắt gói tin từ card mạng hoặc PCAP, gộp theo khóa 5-tuple, tính 34 đặc trưng thống kê |
| **Điều kiện tiên quyết** | Npcap/WinPcap đã cài, quyền Administrator |
| **Luồng chính** | 1. Scapy lắng nghe card mạng → 2. Nhận gói tin → 3. Xác định 5-tuple (src_ip, dst_ip, src_port, dst_port, proto) → 4. Cập nhật Flow dictionary → 5. Tính IAT, Active/Idle, Flag Counts → 6. Gọi callback `on_packet_captured(flow_data)` |

---
**UC08 — Phân loại luồng mạng bằng XGBoost**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | XGBoost Flow Classification |
| **Actor chính** | AI Engine (tự động) |
| **Mô tả** | `FlowAnalyzer.predict()` nhận 34 đặc trưng, chuẩn hóa qua StandardScaler, dự đoán xác suất [P(benign), P(malicious)], trả về risk_score 0–100 |
| **Điều kiện tiên quyết** | Mô hình XGBoost và StandardScaler đã được tải (`_loaded = True`) |
| **Luồng chính** | 1. Nhận dict `flow_features` → 2. Tạo vector 34 chiều → 3. `scaler.transform()` → 4. `model.predict_proba()` → 5. risk_score = P(malicious) × 100 → 6. Trả về top-5 Feature Importance |

---
**UC09 — Phát hiện tên miền DGA bằng Bi-LSTM**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Bi-LSTM DGA Detection |
| **Actor chính** | AI Engine (tự động) |
| **Mô tả** | `DGADetector.predict()` kiểm tra whitelist, phân tích lexical và deep learning, trả về final_score tổng hợp |
| **Điều kiện tiên quyết** | Tên miền khác với IP (có domain thực sự cần kiểm tra) |
| **Luồng chính** | 1. Kiểm tra `ALEXA_WHITELIST` → nếu có: trả về an toàn ngay → 2. `_lexical_analysis()`: tính Entropy, digit_ratio, consonant_ratio, length → 3. `_tokenize()`: chuyển chuỗi ký tự → vector số, padding tới MAX_LEN=64 → 4. Bi-LSTM `model.predict()` → dl_score → 5. final_score = dl_score × 0.65 + heuristic × 0.35 |
| **Luồng thay thế** | TensorFlow không hỗ trợ CPU (thiếu AVX) → fallback dùng heuristic-only |

---
**UC10 — Tính điểm rủi ro tổng hợp (Weighted Ensemble)**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Ensemble Risk Scoring |
| **Actor chính** | AI Engine (tự động) |
| **Mô tả** | `RiskScorer.calculate()` kết hợp 4 nguồn điểm theo trọng số, áp dụng Amplification Logic, tạo `AlertRecord` |
| **Điều kiện tiên quyết** | Đã có kết quả từ ít nhất UC08 |
| **Luồng chính** | 1. Lấy flow_score (XGBoost) × 0.35 → 2. dga_score (Bi-LSTM) × 0.30 → 3. threat_score (TI) × 0.25 → 4. process_score × 0.10 → 5. raw_score = tổng có trọng số → 6. Nếu ≥3 module cùng phát hiện: raw_score × 1.4 → 7. Xác định alert_level theo ngưỡng → 8. Gắn MITRE techniques |
| **Hậu điều kiện** | `AlertRecord` được tạo với đầy đủ thông tin phục vụ UC03, UC04 |

---
**UC11 — Tra cứu IP/Domain với cơ sở dữ liệu IoC**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Threat Intelligence Lookup |
| **Actor chính** | TI Feed (tự động) |
| **Mô tả** | `ThreatIntelligence.check_ip()` tra cứu IP trong `KNOWN_C2_IPS`, gọi VirusTotal API v3 và AbuseIPDB API nếu có key |
| **Điều kiện tiên quyết** | IP đích không rỗng |
| **Luồng chính** | 1. Kiểm tra cache (TTL=1 giờ) → nếu có: trả về ngay → 2. Tra cứu `KNOWN_C2_IPS` local → 3. Gọi VirusTotal `/api/v3/ip_addresses/{ip}` nếu có API key → 4. Gọi AbuseIPDB `/api/v2/check` nếu có key → 5. Tổng hợp confidence score, malware_family, MITRE techniques → 6. Lưu cache |
| **Ngoại lệ** | API timeout hoặc không có key → chỉ dùng local IOC DB |

---
**UC12 — Ánh xạ kết nối với tiến trình hệ thống**

| Trường | Nội dung |
|---|---|
| **Tên Use Case** | Process Mapping & Masquerading Detection |
| **Actor chính** | OS (tự động) |
| **Mô tả** | `ProcessMapper` dùng `psutil.net_connections()` tương quan kết nối mạng với PID/tên tiến trình, phát hiện Masquerading |
| **Điều kiện tiên quyết** | Quyền đọc thông tin tiến trình OS |
| **Luồng chính** | 1. `psutil.net_connections(kind='inet')` lấy tất cả kết nối → 2. Với mỗi kết nối: `_get_process_info(pid)` → 3. `_analyze_process_suspicion()` kiểm tra: tên trong `SUSPICIOUS_PROCESS_NAMES`, đường dẫn không thuộc `LEGITIMATE_PATHS`, cổng không phổ biến, tiến trình hệ thống quan trọng có outbound → 4. Trả về danh sách `suspicious_flags[]` |

---

### 2.2. Kiến trúc tổng thể hệ thống *(~5 trang)*

**2.2.1. Sơ đồ kiến trúc module và luồng dữ liệu**
- 5 bước xử lý: Sniffing → Feature Extraction → Process Mapping → AI Analysis → Risk Scoring.
- Sơ đồ thành phần: `packet_sniffer` → `flow_analyzer` + `dga_detector` + `threat_intel` + `process_mapper` → `risk_scorer` → `GUI`.

**2.2.2. Cơ chế xử lý bất đồng bộ (Multi-threading)**
- Thread riêng cho packet capture, thread riêng cho model loading, GUI trên main thread.
- Cơ chế `self.after(0, callback)` của Tkinter để update UI an toàn từ thread phụ.
- Hàng đợi dữ liệu ngăn blocking giao diện khi tải AI models.

### 2.3. Thiết kế Module phân tích hành vi luồng (Flow Analyzer — XGBoost) *(~5 trang)*

**2.3.1. Thiết kế lớp `FlowAnalyzer` và giao diện hàm**
- Sơ đồ lớp (Class Diagram): thuộc tính `model`, `scaler`, `_loaded`; phương thức `load()`, `predict()`, `analyze_beaconing()`, `get_feature_importance_data()`.
- Pipeline dữ liệu: dict 34 đặc trưng → vector numpy → StandardScaler → XGBClassifier.

**2.3.2. Thiết kế hàm phát hiện Beaconing (`analyze_beaconing`)**
- Input: danh sách khoảng thời gian giữa các gói tin (intervals).
- Công thức: CV = σ / μ; Regularity Score = (1 − CV) × 100.
- Ngưỡng: CV < 0.3 → kết luận là Beaconing.

### 2.4. Thiết kế Module phát hiện DGA (DGA Detector — Bi-LSTM) *(~6 trang)*

**2.4.1. Sơ đồ lớp `DGADetector` và luồng xử lý tên miền**
- Thuộc tính: `model`, `char_to_idx`, `_loaded`.
- Phương thức: `load()`, `predict()`, `_tokenize()`, `_lexical_analysis()`, `_calculate_entropy()`, `analyze_dns_stream()`.

**2.4.2. Kiến trúc mạng Bi-LSTM (từ mã nguồn `dga_detector.py`)**

| Lớp | Tham số | Mục đích |
|---|---|---|
| Embedding | vocab=39, dim=64, max_len=64, mask_zero=True | Nhúng ký tự thành vector dày đặc |
| SpatialDropout1D | rate=0.3 | Chống overfitting theo chiều không gian |
| Bidirectional LSTM | units=128, return_sequences=True, dropout=0.2 | Đọc chuỗi hai chiều, lớp 1 |
| Bidirectional LSTM | units=64, dropout=0.2 | Đọc chuỗi hai chiều, lớp 2 |
| Dense | units=64, activation='relu' | Lớp biểu diễn trung gian |
| Dropout | rate=0.4 | Chống overfitting |
| Dense | units=1, activation='sigmoid' | Đầu ra xác suất DGA |

**2.4.3. Thiết kế Hybrid Scoring: Bi-LSTM + Lexical Analysis**
- Các đặc trưng Lexical: Shannon Entropy, digit_ratio, consonant_ratio, length, char_diversity.
- Công thức kết hợp: `final_score = (dl_score × 0.65 + heuristic_norm × 0.35) × 100`.
- Cơ chế fallback: nếu TensorFlow không hỗ trợ CPU → heuristic_only mode.

### 2.5. Thiết kế Module Threat Intelligence *(~3 trang)*

**2.5.1. Sơ đồ lớp `ThreatIntelligence` và chiến lược caching**
- Cache file JSON với TTL = 3600 giây, lưu tại `data/threat_intel_cache.json`.
- Ba nguồn theo thứ tự ưu tiên: Local IOC DB → VirusTotal API v3 → AbuseIPDB API.

**2.5.2. Cấu trúc cơ sở dữ liệu IoC nội bộ**
- `KNOWN_C2_IPS`: 10 IP C&C đã biết (Emotet, Cobalt Strike, TrickBot, LockBit...) với confidence score và nguồn.
- `KNOWN_C2_DOMAINS`: 6 domain C&C mẫu.
- `MITRE_ATTACK_MAP`: ánh xạ họ mã độc → danh sách kỹ thuật MITRE.

### 2.6. Thiết kế Module Ánh xạ Tiến trình (Process Mapper) *(~3 trang)*

**2.6.1. Danh sách đặc trưng phát hiện Masquerading (từ `process_mapper.py`)**

| Dấu hiệu | Mô tả | MITRE |
|---|---|---|
| Tên trong `SUSPICIOUS_PROCESS_NAMES` | svchost32.exe, mimikatz.exe, powershell.exe... | T1055 |
| Tên hợp lệ nhưng đường dẫn sai | svchost.exe chạy từ %TEMP% | T1036 (Masquerading) |
| Tiến trình hệ thống quan trọng có outbound | lsass.exe, winlogon.exe kết nối ra ngoài | T1003 |
| Script shell có kết nối mạng | powershell.exe, cmd.exe, wscript.exe | T1059 |
| Cổng không phổ biến (>1024, không phải 80/443) | Kết nối ra cổng bất thường | T1571 |

### 2.7. Thiết kế Module Tính điểm Rủi ro (Ensemble Risk Scorer) *(~5 trang)*

**2.7.1. Sơ đồ lớp `RiskScorer` và cấu trúc `AlertRecord`**

| Trường AlertRecord | Kiểu | Nguồn |
|---|---|---|
| timestamp | str | datetime.now() |
| remote_ip / remote_port | str / int | PacketSniffer |
| domain | str | DNS/SNI |
| process_name / process_pid | str / int | ProcessMapper |
| risk_score | float (0–100) | Weighted Ensemble |
| alert_level | str (SAFE/LOW/MEDIUM/HIGH/CRITICAL) | Threshold map |
| flow_score / dga_score / threat_intel_score / process_score | float | 4 modules |
| malware_family | str | ThreatIntelligence |
| details | list[str] | Tổng hợp lý do cảnh báo |
| mitre_techniques | list[str] | T1071, T1568.002, T1055... |

**2.7.2. Thuật toán Weighted Ensemble với Amplification Logic**
- Bảng trọng số: Flow Behavior 35%, DGA Detection 30%, Threat Intel 25%, Process Anomaly 10%.
- Amplification Logic: ≥3 module phát hiện → raw_score × 1.4; ≥2 module → × 1.2.
- Ngưỡng cảnh báo: SAFE (<20) | LOW (20–39) | MEDIUM (40–59) | HIGH (60–79) | CRITICAL (≥80).

---

## CHƯƠNG 3: TRIỂN KHAI THỰC NGHIỆM VÀ ĐÁNH GIÁ *(~30 trang)*

### 3.1. Môi trường thực nghiệm *(~4 trang)*

**3.1.1. Cấu hình phần cứng và phần mềm**

| Thành phần | Yêu cầu |
|---|---|
| Hệ điều hành | Windows 10/11 (64-bit) |
| Quyền hệ thống | Administrator (yêu cầu Npcap) |
| Python | 3.9+ |
| Thư viện AI | XGBoost 2.x, TensorFlow/Keras 2.x |
| Bắt gói tin | Scapy + Npcap (Windows) |
| Giao diện | CustomTkinter 5.x, Matplotlib 3.x |

**3.1.2. Phụ thuộc thư viện (từ `requirements.txt`)**
- Danh sách đầy đủ: scapy, xgboost, tensorflow, customtkinter, psutil, requests, joblib, pandas, numpy, matplotlib, Pillow.

### 3.2. Quá trình xây dựng và huấn luyện mô hình *(~12 trang)*

**3.2.1. Bộ dữ liệu: CTU-13 và CICIDS2017 (cho XGBoost)**

| Bộ dữ liệu | Nguồn | Kịch bản liên quan | Định dạng |
|---|---|---|---|
| CTU-13 | Đại học Kỹ thuật Czech (García et al., 2014) | 13 kịch bản botnet thực tế: Zeus, Murlo, Rbot, Neris | NetFlow (CSV) |
| CICIDS2017 | Canadian Institute for Cybersecurity (Sharafaldin et al., 2018) | Botnet, DoS, PortScan, BruteForce | Flow CSV với 84 đặc trưng |
| CSE-CIC-IDS2018 | Canadian Institute for Cybersecurity | Botnet, Infiltration | Flow CSV |

- Quy trình chuẩn bị dữ liệu: tải từ nguồn gốc → lọc kịch bản Botnet/C&C → chọn 34 đặc trưng khớp `FLOW_FEATURES` → xử lý giá trị vô cực (inf → NaN → 0) → tách train/test 80/20 stratified.

**3.2.2. Pipeline huấn luyện mô hình XGBoost**

```
Dữ liệu thô (CTU-13 / CICIDS2017)
       ↓  Lọc nhãn: BENIGN vs BOTNET/C&C
Dữ liệu có nhãn (imbalanced: ~95% Benign, ~5% Botnet)
       ↓  StandardScaler.fit_transform()
Dữ liệu đã chuẩn hóa
       ↓  XGBClassifier.fit()
           - n_estimators=200, max_depth=6
           - learning_rate=0.1
           - scale_pos_weight = N_benign / N_botnet
           - eval_metric='logloss'
Mô hình đã huấn luyện
       ↓  joblib.dump()
xgboost_flow_model.joblib + flow_scaler.joblib
```

- Lý do chọn tham số: max_depth=6 cân bằng độ phức tạp/overfitting; `scale_pos_weight` xử lý mất cân bằng dữ liệu nghiêm trọng.

**3.2.3. Bộ dữ liệu DGA: Bambenek Feeds, Alexa/Cisco Top 1M (cho Bi-LSTM)**

| Lớp | Nguồn | Kích thước ước tính | Đặc điểm |
|---|---|---|---|
| Benign | Alexa Top 1 Million / Cisco Umbrella Top 1M | ~1,000,000 domain | Tên miền con người đặt, entropy thấp |
| Malicious (DGA) | Bambenek Consulting DGA Feeds | Hàng triệu domain/ngày | Ngẫu nhiên cao, entropy cao |
| Malicious (DGA) | Netlab 360 DGA repository | ~100+ họ mã độc | Conficker, Cryptolocker, Mirai, DGA.Chir, ZeuS |

**3.2.4. Pipeline huấn luyện mô hình Bi-LSTM**

```
Dữ liệu domain thô (Benign + DGA)
       ↓  Tiền xử lý: lowercase, tách hostname (bỏ TLD)
       ↓  _tokenize(): chuyển ký tự → index trong VALID_CHARS
       ↓  Padding / Truncation tới MAX_LEN=64
Tensor shape (N, 64)
       ↓  model.fit()
           - optimizer='adam'
           - loss='binary_crossentropy'
           - batch_size=64, epochs=10
           - validation_split=0.2
Mô hình đã huấn luyện
       ↓  model.save()
bilstm_dga_model.keras + char_map.npy
```

- Kỹ thuật chống overfitting: SpatialDropout1D(0.3) sau Embedding, Dropout(0.4) trước lớp Dense cuối, Recurrent Dropout(0.2) trong LSTM.

**3.2.5. Chế độ Demo (Synthetic Data) khi không có file weights**
- `FlowAnalyzer._create_demo_model()`: tạo 1000 mẫu Benign + 200 mẫu C&C giả lập với đặc trưng Beaconing (IAT mean=60000ms đều đặn, idle_mean cao, active_mean thấp).
- `DGADetector._create_demo_model()`: tạo danh sách domain sạch (Google, YouTube...) và domain DGA ngẫu nhiên, train nhanh 1 epoch.
- Cả hai mô hình demo được lưu vào thư mục `models/` để tái sử dụng.

### 3.3. Đánh giá hiệu năng các mô hình AI *(~8 trang)*

**3.3.1. Các chỉ số đánh giá cho bài toán mất cân bằng dữ liệu**
- Phân tích Ma trận nhầm lẫn (Confusion Matrix): TP, FP, TN, FN — ý nghĩa trong ngữ cảnh bảo mật.
- Precision (Độ chính xác), Recall (Detection Rate), F1-Score, ROC-AUC.
- Tại sao Accuracy một mình không đủ: 95% traffic Benign → mô hình dự đoán tất cả Benign vẫn đạt 95% Accuracy.
- Ý nghĩa thực tế: False Negative (bỏ sót C&C) nguy hiểm hơn False Positive.

**3.3.2. Kết quả đánh giá mô hình XGBoost**
- Bảng kết quả trên CTU-13 (per-scenario) và CICIDS2017 (Botnet label).
- Phân tích Feature Importance top-10: `idle_mean`, `flow_iat_std`, `active_mean` dẫn đầu.
- So sánh với baseline: Random Forest, Decision Tree, Logistic Regression.

**3.3.3. Kết quả đánh giá mô hình Bi-LSTM**
- Bảng kết quả theo họ DGA: Conficker, Cryptolocker, Mirai, ZeuS.
- Phân tích false positive: domain viết tắt ngắn (`xkcd.com`, `t.co`) → xử lý bằng Whitelist.
- Đóng góp của Hybrid Score trong cải thiện F1-Score.

### 3.4. Sản phẩm — Giao diện và Tính năng *(~6 trang)*

**3.4.1. Tổng quan giao diện người dùng (CustomTkinter)**
- Theme Dark (`#020617` nền), sidebar `#0f172a`, bảng chính `#0f172a`.
- Font: Segoe UI (tiêu đề), Consolas (dữ liệu số/kỹ thuật).
- Bố cục 2 cột: Sidebar điều khiển (300px) + Main Panel (co giãn).

**3.4.2. Mô tả chi tiết các thành phần giao diện**

| Thành phần | Vị trí | Chức năng |
|---|---|---|
| Logo "🛡️ C&C DETECTOR" | Sidebar top | Nhận diện sản phẩm |
| Dropdown "Chế độ hoạt động" | Sidebar | Chọn Live Capture hoặc file PCAP |
| Nút "📂 IMPORT PCAP" | Sidebar | Thêm file PCAP vào danh sách phân tích |
| Nút "▶ BẮT ĐẦU / ⏹ DỪNG" | Sidebar | Toggle giám sát; đổi màu theo trạng thái |
| Nút "📊 XEM BIỂU ĐỒ" | Sidebar | Mở histogram Risk Score (matplotlib popup) |
| Nút "💾 XUẤT CSV" | Sidebar | Xuất toàn bộ log ra file CSV |
| Panel "THỐNG KÊ HỆ THỐNG" | Sidebar | Đếm luồng, C&C nghi ngờ, DGA phát hiện |
| Panel "THÔNG SỐ GÓI TIN" | Sidebar | Hiển thị 9 thông số flow khi click dòng |
| Bảng Treeview chính | Main Panel | 1000 dòng max, màu theo alert_level |
| Panel "CẢNH BÁO BẢO MẬT" | Main Panel bottom | Log chi tiết CRITICAL/HIGH với MITRE |

**3.4.3. Quy trình xử lý sự kiện khi click vào bảng dữ liệu**
- Sự kiện `<<TreeviewSelect>>` → `on_packet_select()` → `update_packet_stats()` → cập nhật 9 thông số với màu ngưỡng (trắng/vàng/đỏ) trong sidebar.

**3.4.4. Kịch bản demo và kiểm thử hệ thống**

| Kịch bản | Mô tả | Mục đích |
|---|---|---|
| Live Capture | Sniff card mạng thực, phân tích lưu lượng thực | Kiểm tra hoạt động end-to-end |
| PCAP Offline | Import file PCAP từ CTU-13 Scenario 10 (Botnet Neris) | Kiểm chứng phát hiện C&C trên dữ liệu chuẩn |
| Demo Mixed | 70% lưu lượng Benign + 30% C&C mô phỏng | Kiểm tra giao diện cập nhật real-time |
| Demo Malicious | 100% lưu lượng C&C mô phỏng | Kiểm tra cảnh báo CRITICAL liên tục |
| Demo Clean | 100% lưu lượng Benign | Xác nhận không có false positive |

---

## KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN *(~5 trang)*

**Tổng kết các đóng góp kỹ thuật của đề tài:**
- Hệ thống phân tích đa lớp (4 module) tích hợp XGBoost + Bi-LSTM + Threat Intel + Process Mapping.
- Thuật toán Weighted Ensemble với Amplification Logic cho độ chính xác tổng hợp cao hơn mô hình đơn lẻ.
- Phát hiện Beaconing qua chỉ số Coefficient of Variation (CV) của Inter-Arrival Time.
- Hybrid DGA Scoring kết hợp Deep Learning (65%) và Lexical Analysis (35%).
- Ánh xạ cảnh báo theo khung MITRE ATT&CK (T1071, T1568.002, T1055, T1036, T1059).
- Giao diện giám sát thời gian thực với multi-threading và cơ chế fallback heuristic khi thiếu GPU.

**Hạn chế và hướng tối ưu hóa trong tương lai:**
- Mô hình hiện dùng synthetic data cho demo; cần full-scale training trên CTU-13 và Bambenek thật.
- Hướng tối ưu: ONNX Runtime GPU export cho inference nhanh hơn trên thiết bị biên (Edge).
- Tích hợp MISP Platform để tự động cập nhật IoC feed từ cộng đồng.
- Mở rộng phát hiện: TLS fingerprinting (JA3/JA3S) cho Encrypted Traffic Analysis (ETA).
- Cải tiến UI: thêm timeline view, graph visualization quan hệ IP-Domain-Process.

---

## DANH MỤC TÀI LIỆU THAM KHẢO

| # | Tài liệu | Ứng dụng trong báo cáo |
|---|---|---|
| [1] | Chen, T., & Guestrin, C. (2016). **XGBoost: A scalable tree boosting system**. *KDD 2016*, 785–794. | Lý thuyết XGBoost (Mục 1.3.1) |
| [2] | Hochreiter, S., & Schmidhuber, J. (1997). **Long Short-Term Memory**. *Neural Computation*, 9(8), 1735–1780. | Lý thuyết LSTM (Mục 1.3.2) |
| [3] | Schuster, M., & Paliwal, K. K. (1997). **Bidirectional recurrent neural networks**. *IEEE TSP*, 45(11), 2673–2681. | Lý thuyết Bi-LSTM (Mục 1.3.2) |
| [4] | Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). **Toward generating a new intrusion detection dataset and intrusion traffic characterization**. *ICISSP 2018*, 108–116. | Bộ dữ liệu CICIDS2017 (Mục 3.2.1) |
| [5] | García, S., Grill, M., Stiborek, J., & Zunino, A. (2014). **An empirical comparison of botnet detection methods**. *Computers & Security*, 45, 100–123. | Bộ dữ liệu CTU-13 (Mục 3.2.1) |
| [6] | Antonakakis, M., et al. (2012). **From Throw-Away Traffic to Bots: Detecting the Rise of DGA-Based Malware**. *USENIX Security 2012*. | Lý thuyết DGA (Mục 1.1.4) |
| [7] | Schiller, C., & Binkley, J. (2007). **Botnets: The Killer Web App**. *Syngress Publishing*. | Tổng quan C&C (Mục 1.1) |
| [8] | MITRE Corporation. **ATT&CK Framework**. https://attack.mitre.org/ | MITRE mapping (Mục 2.7.2, Kết luận) |
| [9] | Bambenek Consulting. **DGA Domain Feed**. https://osint.bambenekconsulting.com/feeds/ | Dataset DGA (Mục 3.2.3) |
| [10] | NIST SP 800-150. (2016). **Guide to Cyber Threat Information Sharing**. | Lý thuyết Threat Intel (Mục 1.4) |
| [11] | Shannon, C. E. (1948). **A Mathematical Theory of Communication**. *Bell System Technical Journal*, 27(3), 379–423. | Shannon Entropy trong DGA detection (Mục 2.4.3) |
| [12] | Yadav, S., et al. (2010). **Detecting algorithmically generated malicious domain names**. *IMC 2010*, 48–61. | Phân tích lexical tên miền DGA (Mục 2.4.3) |
