## HƯỚNG DẪN SỬ DỤNG VÀ NGUYÊN LÝ HOẠT ĐỘNG
### CÔNG CỤ PHÁT HIỆN MÁY CHỦ C&C TRÊN MẠNG INTERNET

---

**Nhóm thực hiện:** Huỳnh Quốc Khải - B5D13, Nguyễn Hữu Hoàng - B5D13, Vũ Thị Thu Trang - B6D13
**Giảng viên hướng dẫn:** Đại úy TS. Tống Anh Tuấn

---

### PHẦN 1: HƯỚNG DẪN SỬ DỤNG CHI TIẾT

**1. Khởi động phần mềm**
- Mở thư mục gốc của dự án.
- Nhấn đúp chuột vào file **`Khoi_dong_CNC_Detector.bat`**. File này sẽ mở giao diện dòng lệnh, tự động cài đặt tất cả các thư viện cần thiết (nếu chưa có) và tự động mở Giao diện hệ thống chính.
- Bạn cần chờ vài giây để hệ thống tự động tải 2 mô hình học máy (XGBoost và Bi-LSTM) vào bộ nhớ. Khi tải xong, phần mềm sẽ thông báo sẵn sàng hoạt động ở bảng log và nút bấm "BẮT ĐẦU GIÁM SÁT" sẽ sáng lên.

**2. Các chế độ hoạt động (Mode Selection)**
Ở thanh điều khiển bên trái, bạn có thể lựa chọn 1 trong 4 chế độ:
- **`live_capture`**: Bắt gói tin trực tiếp từ card mạng thật của máy tính theo thời gian thực. (*Lưu ý: Để chạy chế độ này tốt nhất cần khởi chạy mã nguồn dưới quyền Administrator hoặc cài đặt thêm Npcap/WinPcap*).
- **`demo_mixed`**: Chế độ phát lại mô phỏng lưu lượng mạng hỗn hợp (gồm cả gói tin sạch của người dùng và gói tin độc hại C&C đan xen) để kiểm thử độ nhạy của phần mềm.
- **`demo_clean`**: Mô phỏng phát lại luồng dữ liệu mạng hoàn toàn bình thường (không có mã độc).
- **`demo_malicious`**: Mô phỏng phát lại chuyên biệt các luồng mạng do mã độc hoặc Botnet phát sinh (giúp thử nghiệm báo động đỏ).

**3. Bảng điều khiển công cụ (Controls)**
- **▶ BẮT ĐẦU GIÁM SÁT**: Khởi động module bắt gói tin và bắt đầu đưa dữ liệu qua mô hình AI xử lý ngay lập tức.
- **📊 XEM BIỂU ĐỒ**: Hiện cửa sổ đồ thị (Histogram phân bố) tổng hợp trực quan điểm rủi ro (Risk Score) của tất cả các kết nối mạng được ghi nhận.
- **💾 XUẤT CSV**: Lưu toàn bộ lịch sử phân tích và cảnh báo ra tệp tin định dạng `.csv`, phục vụ cho mục đích lập báo cáo điều tra sự cố.

**4. Giao diện Giám sát chính**
- **Bảng theo dõi luồng mạng (Packet Table)**: Hiển thị danh sách các kết nối hiện hành gồm các cột: Thời gian, Tiến trình (Process) phát sinh kết nối, IP Đích, Tên miền (Domain), Điểm Rủi ro và Cấp độ Báo động.
  - *Mẹo:* Bạn có thể **click chuột** vào từng dòng cụ thể trong bảng này. Khi click, bảng "THÔNG SỐ GÓI TIN" ở góc dưới bên trái màn hình sẽ phân tích sâu các đặc trưng kỹ thuật của chính kết nối đó (Duration, Flow IAT Mean, Pkts/sec...). Thông số nào vi phạm ngưỡng bất thường sẽ tự bôi đỏ/vàng.
- **Khu vực Cảnh báo (Alerts Panel)**: Bất kỳ khi nào phát hiện kết nối đạt điểm rủi ro CAO (HIGH) hoặc ĐẶC BIỆT NGUY HIỂM (CRITICAL), hệ thống sẽ đẩy log cảnh báo chi tiết nhất (bao gồm loại mã độc tình nghi, dấu hiệu vi phạm) vào khu vực Text Box nền xám/đỏ ở dưới cùng màn hình để quản trị viên phản ứng.

---

### PHẦN 2: NGUYÊN LÝ HOẠT ĐỘNG (HỆ THỐNG & AI)

Hệ thống hoạt động theo nguyên tắc **Phân tích hành vi mạng (Behavioral Analysis)** thay vì quét chữ ký tĩnh truyền thống. Luồng xử lý dữ liệu được thiết kế gồm 5 tầng chính như sau:

**Tầng 1: Lắng nghe và trích xuất Luồng mạng (Packet Sniffer & Flow Analyzer)**
- Sử dụng công nghệ trích xuất gói tin thời gian thực. Tuy nhiên, thay vì xử lý từng packet riêng lẻ, module này gom cụm chúng thành các **Luồng mạng (Flows)** dựa trên quy tắc 5 tuple (IP Nguồn, IP Đích, Cổng Nguồn, Cổng Đích, Protocol).
- Quá trình gom cụm giúp tính toán các đặc trưng thống kê vô cùng quan trọng như: Tốc độ truyền tải Byte/giây, số lượng cờ SYN/ACK, và độ trễ ngẫu nhiên giữa các gói tin (Inter-Arrival Time).

**Tầng 2: Ánh xạ tiến trình hệ điều hành (Process Mapper)**
- Nhằm chống lại kỹ thuật "Masquerading" của mã độc (hiện tượng ẩn nấp, tiêm mã vào tiến trình hợp pháp như `svchost.exe`, `explorer.exe`), hệ thống liên tục tra cứu Socket hệ thống để ghép cặp luồng mạng với PID/tên phần mềm đang thực thi. Bất kỳ kết nối mờ ám nào từ một tiến trình cốt lõi của Windows sẽ lập tức kích hoạt cờ bất thường.

**Tầng 3: Nhận diện Hành vi bằng XGBoost (Behavioral Engine)**
- Áp dụng kỹ thuật Máy học (Machine Learning) **XGBoost** trên nhóm dữ liệu đặc trưng dạng bảng đã được trích xuất từ Tầng 1. 
- XGBoost đặc biệt nhạy bén trong việc phát hiện hành vi **Beaconing** của Botnet: Tức là hành vi gửi tín hiệu "nhịp tim" định kỳ với máy chủ C&C (Lưu lượng cực nhỏ, chu kì nhàn rỗi (idle) rất cao xen lẫn các chớp sáng kết nối ngắn). Dữ liệu này khác hoàn toàn với cách người dùng bình thường duyệt web.

**Tầng 4: Giải thuật Học sâu Bi-LSTM xử lý Tên miền sinh tự động (Lexical Engine)**
- Botnet hiện đại thường lẩn tránh phòng thủ IP bằng cách dùng thuật toán DGA (Domain Generation Algorithm) sinh ra hàng nghìn tên miền rác mỗi ngày.
- Ở tầng này, mạng thần kinh **Bi-LSTM (Bidirectional Long Short-Term Memory)** phân tích độc lập chuỗi ký tự tên miền có trong gói tin. Nhờ cơ chế đọc 2 chiều, mô hình học được trật tự ngôn ngữ tự nhiên, từ đó tách biệt chính xác một tên miền hợp lệ (như `google.com`) khỏi một tên miền dị hình do máy sinh ra (ví dụ: `asdxzcqwe.net` với tỉ lệ nguyên âm/phụ âm hỗn loạn và entropy cao).

**Tầng 5: Chấm điểm rủi ro tổng hợp (Ensemble Risk Scorer)**
- Các mô hình không hoạt động rời rạc. Risk Scorer thu thập toàn bộ "xác suất tình nghi" từ XGBoost, Bi-LSTM, kết quả tra cứu tình báo mối đe dọa (Threat Intelligence), và đánh giá Tiến trình.
- Thuật toán Ensemble sau đó sẽ hòa trộn các thông số này để cấp ra một thang điểm chung cuộc **Final Risk Score (0-100)**:
  - Từ 0 đến 40: SAFE (Bình thường)
  - Từ 40 đến 60: LOW (Rủi ro thấp)
  - Từ 60 đến 80: MEDIUM (Đáng nghi vấn)
  - Từ 80 đến 90: HIGH (Có dấu hiệu liên lạc C&C rõ rệt)
  - Trên 90: CRITICAL (Đã xác nhận nhiễm mã độc/C&C Botnet)

> **Tóm lại:** Việc bám sát mô hình lai XGBoost (phát hiện bằng hành vi mạng) và Bi-LSTM (phát hiện bằng chữ viết tên miền) giúp công cụ phòng thủ triệt để trước mọi sự thay đổi và lẩn tránh của các máy chủ C&C thế hệ mới trên Internet.
