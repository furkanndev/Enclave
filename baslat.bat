@echo off
title Enclave Baslatici
setlocal

cd /d "%~dp0"

where pythonw >nul 2>&1
if %errorLevel% EQU 0 (
    start "" pythonw main.py %*
    exit /b
)

where python >nul 2>&1
if %errorLevel% EQU 0 (
    start "" python main.py %*
    exit /b
)

if exist "dist\Enclave.exe" (
    start "" "dist\Enclave.exe" %*
    exit /b
)

echo Hata: Sistemde Python veya Enclave.exe bulunamadi!
pause
exit /b
