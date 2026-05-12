@echo off
title CNC Detection System Pipeline
echo ======================================================
echo   HE THONG PHAT HIEN MAY CHU C&C (RESEARCH PROJECT)
echo ======================================================
echo.

echo [*] Buoc 1: Cai dat moi truong Python...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [!] Loi khi cai dat thu vien.
    pause
    exit /b
)

echo.
echo [*] Buoc 2: Tien xu ly va Trich xuat dac trung (Feature Engineering)...
python feature_engineering.py
if %errorlevel% neq 0 (
    echo [!] Loi tai giai doan Feature Engineering.
    pause
    exit /b
)

echo.
echo [*] Buoc 3: Huan luyen mang No-ron LSTM...
python model_engine.py
if %errorlevel% neq 0 (
    echo [!] Loi tai giai doan Training.
    pause
    exit /b
)

echo.
echo [*] Buoc 4: Khoi chay Giao dien Giam sat (Dashboard)...
streamlit run dashboard_app.py

pause
