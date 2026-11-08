@echo off
title Enclave - EXE Derleyici
setlocal

cd /d "%~dp0"
echo ===================================================
echo   Enclave - dist/ klasorune EXE derleniyor...
echo ===================================================

where python >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [HATA] Python bulunamadi! Lutfen Python'in yuklu ve PATH'e ekli oldugundan emin olun.
    pause
    exit /b 1
)

python build_exe.py
if %errorLevel% EQU 0 (
    echo.
    echo ===================================================
    echo [BASARILI] dist\Enclave.exe guncellendi!
    echo ===================================================
) else (
    echo.
    echo [HATA] Derleme sirasinda bir hata olustu.
)

pause
