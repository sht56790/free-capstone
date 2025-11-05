@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d %~dp0

REM Usage: run_benchmark_ollama.bat "텍스트" model1 model2 model3
set TEXT=%~1
if "%TEXT%"=="" set TEXT=홍길동 고객의 계좌 123-456-789012를 확인해주세요

shift
if "%1"=="" (
  set MODELS=qwen3:8b
) else (
  set MODELS=
  :collect
  if "%1"=="" goto collected
    if defined MODELS (
      set MODELS=!MODELS!,"%~1"
    ) else (
      set MODELS="%~1"
    )
    shift
    goto collect
  :collected
)

set JSON_MODELS=[!MODELS!]

set BASE=http://localhost:8081

REM Check server health
for /f "usebackq tokens=*" %%i in (`curl -s -o NUL -w "%%{http_code}" %BASE%/health`) do set HC=%%i
if not "%HC%"=="200" (
  echo [ERROR] Server not responding on %BASE% (health=%HC%). Start the server first.
  goto :end
)

REM Check jq availability (optional)
where jq >nul 2>nul
if errorlevel 1 (
  set PRINT_SUMMARY=powershell -NoProfile -Command "(Invoke-WebRequest -UseBasicParsing -Method Post -ContentType 'application/json' -Body $args[0] '%BASE%/api/admin/ollama-benchmark').Content | ConvertFrom-Json | Select-Object -ExpandProperty summary | ConvertTo-Json -Depth 5"
  set PRINT_RESULTS=powershell -NoProfile -Command "(Invoke-WebRequest -UseBasicParsing -Method Post -ContentType 'application/json' -Body $args[0] '%BASE%/api/admin/ollama-benchmark').Content | ConvertFrom-Json | Select-Object -ExpandProperty results | ConvertTo-Json -Depth 5"
) else (
  set PRINT_SUMMARY=curl -s -X POST %BASE%/api/admin/ollama-benchmark -H "Content-Type: application/json" -d %%PAY%% ^| jq .summary
  set PRINT_RESULTS=curl -s -X POST %BASE%/api/admin/ollama-benchmark -H "Content-Type: application/json" -d %%PAY%% ^| jq .results
)

echo Benchmark judge across models: !JSON_MODELS!
set PAY={"text":"!TEXT!","models":!JSON_MODELS!,"task":"judge"}
call %PRINT_SUMMARY% "!PAY!"

echo.
echo Benchmark regex pattern generation across models: !JSON_MODELS!
set PAY={"text":"계좌번호 열두자리 숫자","models":!JSON_MODELS!,"task":"regex"}
call %PRINT_RESULTS% "!PAY!"

echo.
echo Done.
:end
pause


