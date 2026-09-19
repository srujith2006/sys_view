@echo off
title QE-NIDS Endpoint Threat Detection System
echo ======================================================================
echo   QUANTUM-ENHANCED NETWORK INTRUSION & ANOMALY DETECTION SYSTEM (QE-NIDS)
echo ======================================================================
echo.
echo [1/2] Verifying Python and installing dependencies...
python -m pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies. Ensure Python 3.10+ is installed and on PATH.
    pause
    exit /b %errorlevel%
)

echo.
echo [2/2] Launching SOC Endpoint Dashboard & Monitoring Console...
echo Opening in your default browser at http://localhost:8501
echo.
python -m streamlit run dashboard/app.py
pause
