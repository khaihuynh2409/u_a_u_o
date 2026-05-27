#!/bin/bash

# Đặt tiêu đề cho cửa sổ Terminal
echo -ne "\033]0;Khoi dong C and C Detector - De tai nghien cuu khoa hoc\007"

# Khai báo mã màu (0A = Xanh lục nhạt, 0C = Đỏ)
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m' # Reset màu

echo -e "${GREEN}=======================================================${NC}"
echo ""
echo -e "${GREEN}    HE THONG PHAT HIEN MAY CHU C&C (C&C DETECTOR)${NC}"
echo -e "${GREEN}    Nghien cuu dua tren AI va Hanh vi mang (Behavioral)${NC}"
echo ""
echo -e "${GREEN}=======================================================${NC}"
echo ""

# Di chuyển vào thư mục chứa file script hiện tại
cd "$(dirname "$0")" || exit

# ============================================================
# BUOC 1: Tim Python
# ============================================================
PYTHON_CMD=""

# Ưu tiên tìm python3 trước, sau đó mới tìm python
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
fi

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}[!] Loi: Khong tim thay Python tren may tinh nay.${NC}"
    echo "    Vui long cai dat Python bang lenh Terminal (VD: sudo apt install python3)"
    echo ""
    read -p "Nhan Enter de thoat..."
    exit 1
fi

echo "[*] Tim thay Python: $($PYTHON_CMD --version) tai $(which $PYTHON_CMD)"
echo ""

# ============================================================
# BUOC 2: Kiem tra pip
# ============================================================
if ! $PYTHON_CMD -m pip --version &> /dev/null; then
    echo "[*] Pip chua co. Dang thu cai bang ensurepip..."
    $PYTHON_CMD -m ensurepip --upgrade &> /dev/null
    
    if ! $PYTHON_CMD -m pip --version &> /dev/null; then
        echo "[*] ensurepip that bai. Dang tai get-pip.py tu internet..."
        $PYTHON_CMD -c "import urllib.request; urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', 'get-pip.py')"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Loi: Khong the tai get-pip.py. Kiem tra lai ket noi mang.${NC}"
            echo ""
            read -p "Nhan Enter de thoat..."
            exit 1
        fi
        
        echo "[*] Dang chay get-pip.py..."
        $PYTHON_CMD get-pip.py --quiet
        rm -f get-pip.py
        
        if ! $PYTHON_CMD -m pip --version &> /dev/null; then
            echo -e "${RED}[!] Loi: Khong the cai pip. Vui long thu cai dat thu cong (VD: sudo apt install python3-pip)${NC}"
            echo ""
            read -p "Nhan Enter de thoat..."
            exit 1
        fi
    fi
fi

echo "[*] Pip san sang."
echo ""

# ============================================================
# BUOC 3: Cai dat cac thu vien can thiet
# ============================================================
echo "[*] Dang kiem tra va cai dat cac thu vien Python can thiet..."
echo ""
$PYTHON_CMD -m pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo ""
    echo -e "${RED}[!] Loi: Khong the cai dat thu vien.${NC}"
    echo "    - Kiem tra lai ket noi mang."
    echo "    - Tren mot so ban Linux moi, ban co the can them '--break-system-packages' vao file script hoac dung moi truong ao (venv)."
    echo ""
    read -p "Nhan Enter de thoat..."
    exit 1
fi

# ============================================================
# BUOC 4: Chay chuong trinh chinh
# ============================================================
echo ""
echo "[*] Cai dat thanh cong. Dang khoi dong Giao dien chinh..."
echo "[*] Luu y: Che do Live Capture tren Linux thuong yeu cau quyen root (sudo)."
echo ""

$PYTHON_CMD main.py

if [ $? -ne 0 ]; then
    echo ""
    echo -e "${RED}[!] Chuong trinh dong voi ma loi, xin hay kiem tra lai.${NC}"
fi

echo ""
read -p "Nhan Enter de thoat..."
