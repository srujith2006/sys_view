@echo off
title QE-NIDS Low-Power Background Monitor
echo ======================================================================
echo   QE-NIDS LOW-POWER BACKGROUND NETWORK THREAT MONITOR
echo ======================================================================
echo.
echo [1/2] Verifying dependencies...
python -m pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies. Ensure Python 3.10+ is installed.
    pause
    exit /b %errorlevel%
)

echo.
echo [2/2] Starting Low-Power Endpoint Monitor...
echo - Idle CPU: ~0.1%% (Tier-1 fast filter)
echo - Windows 10/11 Desktop Toast Notifications enabled.
echo - Inspects network flows with explicit user consent.
echo.
echo (Press Ctrl+C anytime to stop monitoring)
echo.
python agent/low_power_monitor.py
pause
