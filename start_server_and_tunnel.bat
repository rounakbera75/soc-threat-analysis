@echo off
title SentinelX SOC Platform Launcher
echo ===================================================
echo       STARTING SENTINELX AI THREAT SIEM PLATFORM
echo ===================================================
echo.

cd /d "%~dp0"

echo [1/2] Launching Flask Backend on http://127.0.0.1:5000 ...
start "SentinelX Flask Server" /min cmd /c ".\.venv\Scripts\python.exe app.py"

timeout /t 3 /nobreak >nul

echo [2/2] Launching Cloudflare Live Public Tunnel ...
echo.
echo ===================================================
echo Watch the terminal below for your live public URL:
echo ===================================================
echo.
.\cloudflared.exe tunnel --url http://127.0.0.1:5000
pause
