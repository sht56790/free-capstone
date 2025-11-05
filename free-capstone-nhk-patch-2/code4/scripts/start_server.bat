@echo off
setlocal EnableExtensions
cd /d %~dp0

REM Optional: set PORT (default 8081)
if "%PORT%"=="" set PORT=8081
echo Starting server on port %PORT% ...

REM Activate local venv if exists (optional)
if exist "%~dp0venv\Scripts\activate.bat" (
  call "%~dp0venv\Scripts\activate.bat"
)

REM Check python availability
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] 'python' not found. Please install Python or add to PATH.
  goto :end
)

REM Ensure dependencies are installed
where pip >nul 2>nul
if not errorlevel 1 (
  echo Installing/validating dependencies from requirements.txt ...
  pip install -q -r requirements.txt
)

REM If you have a Google API key, set it before running (optional)
REM set GOOGLE_API_KEY=YOUR_KEY

python app.py
if errorlevel 1 (
  echo [ERROR] Server terminated with errors. See messages above.
)

:end
pause

