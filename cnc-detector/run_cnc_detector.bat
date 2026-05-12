@echo off
chcp 65001 >nul
title Khởi động C^&C Detector - Đề tài nghiên cứu khoa học
color 0A

echo =======================================================
echo.
echo    HỆ THỐNG PHÁT HIỆN MÁY CHỦ C^&C (C^&C DETECTOR)
echo    Nghiên cứu dựa trên AI và Hành vi mạng (Behavioral)
echo.
echo =======================================================
echo.

cd /d "%~dp0"

echo [*] Dang kiem tra va cai dat cac thu vien Python can thiet...
echo.
pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo.
    color 0C
    echo [!] Loi: Khong the cai dat thu vien. Vui long kiem tra lai Python/pip.
    pause
    exit /b
)

echo.
echo [*] Cai dat thanh cong. Dang khoi dong Giao dien chinh...
echo.

python main.py

if %errorlevel% neq 0 (
    echo.
    color 0C
    echo [!] Chuong trinh dong voi ma loi, xin hay kiem tra lai.
)

echo.
pause
