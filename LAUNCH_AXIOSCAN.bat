@echo off
title AXIOSCAN v1.0 — Axios Supply Chain Attack Detector
color 0C

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║  AXIOSCAN v1.0  —  NEATLABS™ / Security 360, LLC   ║
echo  ║  Axios Supply Chain Attack Detector ^& Remediator     ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)

:: Install dependency if missing
echo  Checking dependencies...
python -c "import customtkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo  Installing customtkinter...
    pip install customtkinter --quiet
)

echo  Launching AXIOSCAN...
echo.
python AXIOSCAN.py

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] AXIOSCAN exited with an error.
    pause
)
