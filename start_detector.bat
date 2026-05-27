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

:: Luu thu muc goc chua script nay
set ROOT_DIR=%~dp0
cd /d "%ROOT_DIR%"

:: ============================================================
:: BUOC 1: Tim Python he thong
:: ============================================================
set PYTHON_CMD=

where py >nul 2>&1
if %errorlevel% equ 0 ( set PYTHON_CMD=py & goto python_found )

where python >nul 2>&1
if %errorlevel% equ 0 ( set PYTHON_CMD=python & goto python_found )

where python3 >nul 2>&1
if %errorlevel% equ 0 ( set PYTHON_CMD=python3 & goto python_found )

color 0C
echo.
echo [!] Loi: Khong tim thay Python. Cai dat tai https://www.python.org/downloads/
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
:: BUOC 2: Tao/kiem tra Virtual Environment
:: ============================================================
echo [*] Dang thiet lap moi truong ao (Virtual Environment)...
echo.

:: Neu venv hop le thi bo qua buoc tao
if exist "%ROOT_DIR%venv\Scripts\python.exe" goto venv_ok

:: Neu venv ton tai nhung bi hong (Linux venv) -> xoa bang PowerShell
if exist "%ROOT_DIR%venv" (
    echo [*] Phat hien venv cu bi hong. Dang xoa bang PowerShell...
    powershell -Command "Remove-Item -Path '%ROOT_DIR%venv' -Recurse -Force -ErrorAction SilentlyContinue"
    echo [*] Da xoa xong.
    echo.
)

:: Tao venv moi
echo [*] Dang tao moi truong ao moi...
%PYTHON_CMD% -m venv "%ROOT_DIR%venv"
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [!] Loi: Khong the tao moi truong ao.
    echo     Thu chay lai voi quyen Administrator.
    echo.
    pause
    exit /b 1
)
echo [*] Tao venv thanh cong.
echo.

:: Kiem tra lai sau khi tao
if not exist "%ROOT_DIR%venv\Scripts\python.exe" (
    color 0C
    echo.
    echo [!] Loi: venv\Scripts\python.exe khong ton tai. Xoa thu muc venv va chay lai.
    echo.
    pause
    exit /b 1
)

:venv_ok
:: Dung duong dan tuyet doi de tranh loi relative path
set VENV_PYTHON=%ROOT_DIR%venv\Scripts\python.exe
set VENV_PIP=%ROOT_DIR%venv\Scripts\pip.exe
echo [*] venv san sang.
echo.

:: ============================================================
:: BUOC 3: Cai dat cac thu vien can thiet
:: (Dung requirements.txt cua cnc-detector)
:: ============================================================
echo [*] Dang cai dat cac thu vien vao venv...
"%VENV_PIP%" install -r "%ROOT_DIR%cnc-detector\requirements.txt"

if %errorlevel% neq 0 (
    echo.
    color 0C
    echo [!] Loi: Khong the cai dat thu vien.
    echo     Kiem tra mang hoac file requirements.txt.
    echo.
    pause
    exit /b 1
)

:: ============================================================
:: BUOC 4: Chay chuong trinh chinh trong thu muc cnc-detector
:: ============================================================
echo.
echo [*] Cai dat thanh cong. Dang khoi dong Giao dien chinh...
echo [*] Luu y: Che do Live Capture tren Windows yeu cau Npcap.
echo     Tai tai: https://npcap.com/#download
echo.

:: cd vao cnc-detector truoc khi chay main.py
cd /d "%ROOT_DIR%cnc-detector"
"%VENV_PYTHON%" main.py

if %errorlevel% neq 0 (
    echo.
    color 0C
    echo [!] Chuong trinh dong voi ma loi, xin hay kiem tra lai.
)

echo.
pause
