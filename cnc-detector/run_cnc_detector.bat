@echo off
chcp 65001 >nul
title Khoi dong CnC Detector - De tai nghien cuu khoa hoc
color 0A

echo =======================================================
echo.
echo    HE THONG PHAT HIEN MAY CHU C^&C (C^&C DETECTOR)
echo    Nghien cuu dua tren AI va Hanh vi mang (Behavioral)
echo.
echo =======================================================
echo.

cd /d "%~dp0"

:: ============================================================
:: BUOC 1: Tim Python
:: ============================================================
set PYTHON_CMD=

where py >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=py
    goto python_found
)

where python >nul 2>&1
if %errorlevel% equ 0 (
    python --version >nul 2>&1
    if %errorlevel% equ 0 (
        set PYTHON_CMD=python
        goto python_found
    )
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python3
    goto python_found
)

color 0C
echo.
echo [!] Loi: Khong tim thay Python tren may tinh nay.
echo     Vui long cai dat Python tu https://www.python.org/downloads/
echo     va dam bao chon "Add Python to PATH" khi cai dat.
echo.
pause
exit /b 1

:python_found
for /f "tokens=*" %%v in (
'
%PYTHON_CMD% --version 2^>^&1
'
) do set PYTHON_VER=%%v
echo [*] Tim thay Python: %PYTHON_VER%
echo.

:: ============================================================
:: BUOC 2: Kiem tra pip
:: ============================================================
%PYTHON_CMD% -m pip --version >nul 2>&1
if %errorlevel% equ 0 goto pip_ready

echo [*] Pip chua co. Dang thu cai bang ensurepip...
%PYTHON_CMD% -m ensurepip --upgrade >nul 2>&1

%PYTHON_CMD% -m pip --version >nul 2>&1
if %errorlevel% equ 0 goto pip_ready

echo [*] ensurepip that bai. Dang tai get-pip.py tu internet...
%PYTHON_CMD% -c "import urllib.request; urllib.request.urlretrieve(
'
https://bootstrap.pypa.io/get-pip.py
'
, 
'
get-pip.py
'
)"
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [!] Loi: Khong the tai get-pip.py. Kiem tra lai ket noi mang.
    echo.
    pause
    exit /b 1
)

echo [*] Dang chay get-pip.py...
%PYTHON_CMD% get-pip.py --quiet
del /f /q get-pip.py >nul 2>&1

%PYTHON_CMD% -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [!] Loi: Khong the cai pip. Vui long thu cai dat thu cong.
    echo     Tham khao: https://pip.pypa.io/en/stable/installation/
    echo.
    pause
    exit /b 1
)

:pip_ready
echo [*] Pip san sang.
echo.

:: ============================================================
:: BUOC 3: Cai dat cac thu vien can thiet
:: ============================================================
echo [*] Dang kiem tra va cai dat cac thu vien Python can thiet...
echo.
%PYTHON_CMD% -m pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    color 0C
    echo [!] Loi: Khong the cai dat thu vien.
    echo     - Kiem tra lai ket noi mang.
    echo     - Thu chay lai script voi quyen Administrator neu can.
    echo.
    pause
    exit /b 1
)

:: ============================================================
:: BUOC 4: Chay chuong trinh chinh
:: ============================================================
echo.
echo [*] Cai dat thanh cong. Dang khoi dong Giao dien chinh...
echo [*] Luu y: Che do Live Capture tren Windows yeu cau Npcap duoc cai dat.
echo     Tai tai: https://npcap.com/#download
echo.

%PYTHON_CMD% main.py

if %errorlevel% neq 0 (
    echo.
    color 0C
    echo [!] Chuong trinh dong voi ma loi, xin hay kiem tra lai.
)

echo.
pause
