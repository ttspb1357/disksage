@echo off
setlocal
title DiskSage
cd /d "%~dp0"

rem Find Python 3.10 or newer: "python" on PATH first, then the py launcher.
set "PY="
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1 && set "PY=python"
if not defined PY py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1 && set "PY=py -3"
if not defined PY (
  echo DiskSage needs Python 3.10 or newer.
  echo Download it from https://www.python.org/downloads/
  echo While installing, tick "Add python.exe to PATH", then double-click DiskSage.bat again.
  echo.
  pause
  exit /b 1
)

where ollama >nul 2>&1
if errorlevel 1 (
  echo Note: Ollama isn't installed, so there won't be AI explanations.
  echo Scanning and cleaning still work. For the AI, install Ollama from https://ollama.com
  echo and then run:  ollama pull deepseek-r1:8b
  echo.
)

%PY% -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
  echo Couldn't install DiskSage's Python packages. Check your internet connection and try again.
  pause
  exit /b 1
)

%PY% app.py
pause
