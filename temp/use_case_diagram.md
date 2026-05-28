# Sơ đồ Use Case - Hệ thống phát hiện C&C

Dưới đây là sơ đồ Use Case đã được cập nhật, tập trung hoàn toàn vào 2 tác nhân là **Người dùng** và **Hệ thống** theo yêu cầu của bạn.

## Sơ đồ Mermaid

```mermaid
flowchart LR
    %% Định nghĩa các Actor
    User(("🧑‍💻 Người dùng"))
    Sys(("🤖 Hệ thống"))

    %% Các Use Case
    subgraph SystemBoundary ["Chức năng phần mềm"]
        direction TB
        
        %% Nhóm Use Case tương tác giao diện
        UC1(["▶️ Giám sát thời gian thực"])
        UC2(["📁 Phân tích tệp PCAP"])
        UC3(["📊 Xem danh sách kết nối"])
        UC4(["🔍 Xem chi tiết cảnh báo"])
        UC5(["📈 Xem biểu đồ thống kê"])
        UC6(["💾 Xuất báo cáo CSV"])

        %% Nhóm Use Case xử lý ngầm
        UC7(["⚙️ Tiền xử lý & Trích xuất"])
        UC8(["🤖 Phân loại XGBoost"])
        UC9(["🤖 Phát hiện Bi-LSTM"])
        UC10(["🔎 Tra cứu Threat Intel"])
        UC11(["⚖️ Tính điểm rủi ro tổng hợp"])
    end

    %% Tương tác của Người dùng (Bên trái)
    User --> UC1
    User --> UC2
    User --> UC3
    User --> UC4
    User --> UC5
    User --> UC6

    %% Tương tác của Hệ thống (Bên phải)
    Sys --> UC7
    Sys --> UC8
    Sys --> UC9
    Sys --> UC10
    Sys --> UC11

    %% Luồng liên kết logic giữa các Use Case (tuỳ chọn để thể hiện luồng chạy)
    UC1 -. "<<include>>" .-> UC7
    UC2 -. "<<include>>" .-> UC7
    
    UC7 -. "<<include>>" .-> UC8
    UC7 -. "<<include>>" .-> UC9
    
    UC8 -. "<<include>>" .-> UC11
    UC9 -. "<<include>>" .-> UC11
    UC11 -. "<<include>>" .-> UC10
```

## Giải thích chi tiết

### 1. Tác nhân (Actors)
- **Người dùng:** Chủ thể trực tiếp tương tác với phần mềm thông qua Giao diện đồ họa (GUI). Người dùng ra lệnh thu thập, tải file lên và xem các báo cáo kết quả.
- **Hệ thống:** Tác nhân ngầm đóng vai trò tự động hóa. Hệ thống chịu trách nhiệm chạy nền các quy trình phức tạp (tính toán, học máy, kết nối mạng) để phục vụ cho Người dùng mà không cần con người can thiệp thủ công.

### 2. Phân chia Use Case
**Nhóm do Người dùng chủ động tương tác:**
- **Giám sát thời gian thực:** Ra lệnh bắt gói tin từ card mạng nội bộ.
- **Phân tích tệp PCAP:** Tải lên file lưu lượng ngoại tuyến.
- **Xem danh sách / chi tiết / biểu đồ:** Khai thác dữ liệu hiển thị trên các bảng điều khiển.
- **Xuất báo cáo:** Kết xuất dữ liệu luồng ra tệp CSV để lưu trữ.

**Nhóm do Hệ thống tự động thực thi:**
- **Tiền xử lý & Trích xuất:** Tự động gom luồng và tạo véc-tơ đặc trưng (bảng hoặc chuỗi) ngay khi có dữ liệu.
- **Phân loại bằng XGBoost & Bi-LSTM:** Tự động đẩy véc-tơ vào các mô hình trí tuệ nhân tạo để lấy xác suất độ độc hại.
- **Tra cứu tình báo & Tính điểm rủi ro:** Tự động tổng hợp xác suất học máy và đối chiếu chéo (Threat Intel) để trả về kết quả hiển thị cho người dùng.
