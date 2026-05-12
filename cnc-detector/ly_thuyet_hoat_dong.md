# Lý thuyết và Nguyên lý Hoạt động của C&C Server Detection System

Tài liệu này giải thích chi tiết về cơ chế hoạt động, các thuật toán trí tuệ nhân tạo (AI) và các bộ dữ liệu được áp dụng để xây dựng công cụ phát hiện máy chủ Command & Control (C&C).

---

## 1. Nguyên lý hoạt động tổng thể
Hệ thống phát hiện C&C này hoạt động theo nguyên lý **Phân tích Đa lớp (Multi-layered Analysis)**. Thay vì dựa vào chữ ký tĩnh (signature-based) như các phần mềm diệt virus truyền thống (rất dễ bị qua mặt khi mã độc thay đổi mã băm), hệ thống tập trung phân tích hành vi mạng. 

Quá trình diễn ra theo thời gian thực gồm 5 bước:

*   **Bước 1 - Bắt gói tin (Sniffing):** Giám sát card mạng để bắt các gói tin và gộp chúng thành các luồng dữ liệu (Flows) dựa trên 5-tuple (IP Nguồn, Cổng Nguồn, IP Đích, Cổng Đích, Giao thức).
*   **Bước 2 - Trích xuất đặc trưng:** Hệ thống không đọc nội dung payload (vì thường bị mã hóa), mà tính toán các "đặc trưng hành vi" như: Khoảng thời gian giữa các gói tin (IAT), tỷ lệ byte gửi/nhận, thời gian kết nối "ngủ" (Idle time) và "hoạt động" (Active time).
*   **Bước 3 - Tham chiếu Tiến trình (Process Mapping):** Đối chiếu xem luồng mạng đó do ứng dụng nào trên máy tính tạo ra. Ví dụ: trình duyệt web kết nối ra ngoài là bình thường, nhưng nếu một tệp tin hệ thống như `svchost.exe` kết nối đến một IP lạ ở cổng bất thường, đó là dấu hiệu của kỹ thuật "Masquerading" (Giả mạo tiến trình).
*   **Bước 4 - Phân tích qua AI & Threat Intel:** Các đặc trưng trích xuất được đẩy vào 2 mô hình Học máy (XGBoost & Bi-LSTM) và bộ lọc đối chiếu với cơ sở dữ liệu IP đen (Threat Intelligence).
*   **Bước 5 - Chấm điểm Rủi ro (Risk Scoring):** Hệ thống tổng hợp kết quả (Ensemble) từ tất cả các module để tính ra điểm số rủi ro từ 0 - 100. Cảnh báo đỏ (CRITICAL/HIGH) sẽ được phát ra nếu điểm số > 75.

---

## 2. Các thuật toán Học Máy (Machine Learning) được sử dụng

Công cụ chia bài toán phát hiện thành 2 hướng và sử dụng 2 thuật toán chuyên biệt:

### A. Phân tích hành vi luồng mạng bằng XGBoost (Extreme Gradient Boosting)
*   **Chức năng:** Nhận diện hành vi **Beaconing** (kỹ thuật mã độc dùng để gửi tín hiệu "nhịp tim" định kỳ về máy chủ chủ quản C&C nhằm báo cáo trạng thái đang hoạt động).
*   **Tại sao dùng XGBoost?** Dữ liệu mạng bao gồm các cột số liệu thống kê (Packet Length, Packets/sec, Flag counts) là dạng dữ liệu bảng (Tabular Data). XGBoost là một tập hợp các cây quyết định (Tree-based ensemble) cực kỳ mạnh mẽ đối với dạng dữ liệu này. Thuật toán có tốc độ suy luận rất nhanh và ít bị ảnh hưởng bởi dữ liệu nhiễu.
*   **Cách nó nhận diện:** XGBoost học được quy luật rằng: Nếu một kết nối mạng có thời gian `Idle` (ngủ dài), nhưng `Active` (hoạt động) rất ngắn và chu kỳ này lặp lại liên tục, đồng thời khối lượng byte truyền tải rất nhỏ (chỉ vài byte để ping), thì nó có xác suất rất cao là một kết nối C&C Beaconing, chứ không phải do con người lướt web.

### B. Phát hiện tên miền sinh tự động bằng Bi-LSTM (Bidirectional Long Short-Term Memory)
*   **Chức năng:** Phát hiện kỹ thuật DGA (Domain Generation Algorithm) - thuật toán tạo ra hàng nghìn tên miền ngẫu nhiên mỗi ngày để qua mặt hệ thống chặn IP/Domain tĩnh.
*   **Tại sao dùng Bi-LSTM?** Tên miền bản chất là một chuỗi ký tự. Bi-LSTM là một mạng nơ-ron hồi quy học sâu (Deep RNN) có khả năng ghi nhớ đặc điểm ngữ cảnh của ký tự từ cả 2 chiều (từ trái sang phải và ngược lại).
*   **Cách nó nhận diện:** Mô hình nhúng (Embed) các ký tự thành vector và phân tích ngữ nghĩa. Nó sẽ học được quy luật tự nhiên của tên miền con người đặt (ví dụ `google.com`, có tỷ lệ nguyên âm/phụ âm hợp lý) so sánh với độ hỗn loạn (Entropy) cao của tên miền do máy sinh ra (ví dụ: `xkqzvy123.com`), từ đó phân loại tên miền là DGA hay Bình thường.

---

## 3. Các bộ dữ liệu (Datasets) tiêu chuẩn

Mặc dù phần mềm Demo có khả năng tự động tạo dữ liệu giả lập (simulated data) để hệ thống chạy độc lập không cần file weights khổng lồ, nhưng để có mô hình AI đủ sức mạnh thực tế, các kiến trúc này thường được huấn luyện trên các bộ dữ liệu bảo mật chuẩn quốc tế sau:

### Dữ liệu cho Mô hình XGBoost (Flow Behavior)
1.  **CTU-13 Dataset:** Bộ dữ liệu nổi tiếng của Đại học Kỹ thuật Séc, chứa lượng lớn NetFlows thực tế của các loại Botnet khác nhau (Zeus, Murlo, Rbot). Nó có sẵn nhãn phân biệt lưu lượng mã độc và lưu lượng nền bình thường.
2.  **CICIDS2017 / CSE-CIC-IDS2018:** Của Viện An ninh mạng Canada, chứa các đặc trưng mạng chi tiết có sẵn theo các kịch bản tấn công hiện đại, hữu ích để trích xuất các thông số IAT (Inter-Arrival Time).

### Dữ liệu cho Mô hình Bi-LSTM (DGA Detection)
1.  **Dữ liệu sạch (Benign Domains):** Lấy từ danh sách Alexa Top 1 Million hoặc Cisco Umbrella Top 1M để mô hình học cách con người đặt tên miền.
2.  **Dữ liệu độc hại (Malicious DGA Domains):** Được tổng hợp từ các nguồn tình báo đe dọa mở (OSINT) như Bambenek Consulting DGA Feeds, hoặc dataset từ Netlab 360 (bao gồm hàng triệu tên miền sinh ra bởi các dòng mã độc như Cryptolocker, Conficker, Mirai).
