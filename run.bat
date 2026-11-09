@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 cf_ip_finder.py
) else (
  python cf_ip_finder.py
)
if errorlevel 1 pause
