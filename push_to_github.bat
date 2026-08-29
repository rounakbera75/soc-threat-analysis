@echo off
title SOC Threat Analysis - GitHub Uploader
color 0b
echo ========================================================
echo        SOC Threat Analysis - GitHub Project Uploader
echo ========================================================
echo.

set GITHUB_USER=rounakbera75
set REPO_NAME=soc-threat-analysis

echo [*] Target Repository: https://github.com/%GITHUB_USER%/%REPO_NAME%.git
echo.

echo [*] Staging all files...
git add .

echo [*] Committing changes...
git commit -m "feat: SOC Threat Intelligence & AI Security Operations Center SIEM" >nul 2>&1

echo [*] Setting remote origin...
git remote remove origin >nul 2>&1
git remote add origin https://github.com/%GITHUB_USER%/%REPO_NAME%.git

echo.
echo ========================================================
echo [*] Pushing code to GitHub...
echo (If a browser login window opens, click Authorize/Sign in)
echo ========================================================
echo.

git push -u origin main

echo.
echo ========================================================
echo [*] Process finished! Check your repo at:
echo     https://github.com/%GITHUB_USER%/%REPO_NAME%
echo ========================================================
echo.
pause
