@echo off
setlocal
cd /d %~dp0

echo Initializing database...
flask --app app.py init-db
if errorlevel 1 (
  echo [ERROR] Failed to initialize database.
  exit /b 1
)
echo Done.


