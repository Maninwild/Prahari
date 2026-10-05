@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  py -3.12 -m venv .venv
  if errorlevel 1 goto fail
)
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto fail
echo Open http://127.0.0.1:8000/ to try Prahari.
.venv\Scripts\python.exe -m uvicorn prahari.api:app --host 127.0.0.1 --port 8000 --no-access-log
goto end
:fail
echo Setup failed. Install Python 3.12 and review the error above.
:end
pause
