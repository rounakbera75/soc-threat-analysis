@echo off
title SentinelX - GitHub Uploader
color 0b
echo ========================================================
echo        SentinelX - Automated GitHub Project Uploader
echo ========================================================
echo.

set /p GITHUB_USER=Enter your GitHub Username (default is rounakbera75): 
if "%GITHUB_USER%"=="" set GITHUB_USER=rounakbera75

echo.
echo [*] Step 1: Initializing Git repository...
git init
git branch -M main

echo [*] Step 2: Staging all SentinelX files...
git add .

echo [*] Step 3: Creating commit...
git commit -m "feat: SentinelX Autonomous AI Threat Intelligence & Next-Gen SIEM Platform"

echo [*] Step 4: Connecting to https://github.com/%GITHUB_USER%/SentinelX.git ...
git remote remove origin >nul 2>&1
git remote add origin https://github.com/%GITHUB_USER%/SentinelX.git

echo.
echo ========================================================
echo [*] Step 5: Pushing code to GitHub...
echo (If a browser window opens, click Authorize/Sign In)
echo ========================================================
echo.

git push -u origin main

echo.
echo ========================================================
echo [*] Done! Your public GitHub link is:
echo     https://github.com/%GITHUB_USER%/SentinelX
echo ========================================================
echo.
pause
