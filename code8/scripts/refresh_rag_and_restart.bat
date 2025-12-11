@echo off
setlocal EnableExtensions

REM 현재 스크립트 위치로 이동
cd /d %~dp0
REM 프로젝트 루트로 이동 (scripts 상위)
cd /d %~dp0\..

chcp 65001 >nul
echo [1/3] 가상환경 확인 중...
if exist ".venv\Scripts\activate.bat" (
  call ".venv\Scripts\activate.bat"
) else (
  echo     * 로컬 가상환경(.venv^)이 없으면 무시하고 계속 진행합니다.
)

echo [2/3] RAG 문서 임베딩 갱신...
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] python 명령을 찾을 수 없습니다. PATH를 확인하세요.
  goto :end
)
python scripts\embed_documents.py
if errorlevel 1 (
  echo [ERROR] 임베딩 생성 중 오류가 발생했습니다.
  goto :end
)

echo [3/3] 서버 재시작...
call scripts\start_server.bat

:end
endlocal

