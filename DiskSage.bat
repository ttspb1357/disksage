@echo off
rem Double-click to start DiskSage. Needs Python 3.12+ and Ollama.
cd /d "%~dp0"
python -m pip install --quiet --disable-pip-version-check -r requirements.txt
python app.py
pause
