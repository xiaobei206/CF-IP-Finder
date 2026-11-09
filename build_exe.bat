@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
if not exist VERSION (
  echo VERSION file is missing.
  exit /b 1
)
set /p APP_VERSION=<VERSION
echo Building CF IP Finder %APP_VERSION%...
py -3 -m pip install --upgrade pyinstaller
if errorlevel 1 goto failed
py -3 -m PyInstaller --noconfirm --clean --windowed --onefile --name CF-IP-Finder-%APP_VERSION% --hidden-import cf_ip_tester_legacy cf_ip_finder.py
if errorlevel 1 goto failed
echo.
echo EXE output: dist\CF-IP-Finder-%APP_VERSION%.exe
exit /b 0
:failed
echo Build failed.
exit /b 1
