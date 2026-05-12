# Sử dụng Ubuntu làm base image
FROM ubuntu:22.04

# Tránh các câu hỏi tương tác khi cài đặt
ENV DEBIAN_FRONTEND=noninteractive

# Cài đặt các thư viện hệ thống và dependencies cho Zeek
NCKHRUN apt-get update && apt-get install -y \
    curl \
    gnupg2 \
    ca-certificates \
    python3 \
    python3-pip \
    wget \
    bzip2 \
    && rm -rf /var/lib/apt/lists/*

# Cài đặt Zeek từ repository chính thức
RUN echo 'deb http://download.opensuse.org/repositories/network:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/network:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/network:/zeek/xUbuntu_22.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/network_zeek.gpg > /dev/null && \
    apt-get update && \
    apt-get install -y zeek-6.0

# Thiết lập biến môi trường cho Zeek
ENV PATH="/opt/zeek/bin:${PATH}"

# Thiết lập thư mục làm việc
WORKDIR /app

# Cài đặt thư viện Python cần thiết cho Data Science
RUN pip3 install pandas numpy requests tqdm sympy

# Copy file xử lý chính vào container
COPY main_process.py .

# Tạo thư mục chứa dữ liệu tạm và output
RUN mkdir -p /app/output /app/pcaps

# Mặc định chạy script chính khi container khởi động
CMD ["python3", "main_process.py"]
