@echo off
setlocal
echo ============================================
echo Ollama 모델 다운로드 스크립트
echo ============================================

where ollama >nul 2>nul
if errorlevel 1 (
  echo [ERROR] 'ollama' 명령어를 찾을 수 없습니다.
  echo.
  echo Ollama를 먼저 설치해주세요:
  echo 1. https://ollama.com/download 에서 Ollama 다운로드
  echo 2. 설치 후 터미널을 다시 열어주세요
  echo 3. Ollama 서비스가 자동으로 시작됩니다 (백그라운드)
  echo.
  pause
  exit /b 1
)

echo [확인] Ollama가 설치되어 있습니다.
echo.
echo 필요한 모델을 다운로드합니다...
echo.

set MODELS=qwen3:8b llama3.1:8b mistral:7b
for %%m in (%MODELS%) do (
  echo [다운로드 중] %%m...
  ollama pull %%m
  if errorlevel 1 (
    echo [경고] 모델 %%m 다운로드 실패
  ) else (
    echo [완료] %%m 다운로드 완료
  )
  echo.
)

echo ============================================
echo 다운로드 완료!
echo ============================================
echo.
echo 참고:
echo - Ollama 서비스는 기본적으로 백그라운드에서 실행됩니다
echo - 서비스가 실행 중인지 확인: ollama list
echo - 서비스 수동 시작: ollama serve
echo.
pause

