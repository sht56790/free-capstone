# 금융 AI 챗봇 (Gemini + Ollama)

## 📋 필수 사전 준비

### 1. Google Gemini API 키 발급
1. [Google AI Studio](https://makersuite.google.com/app/apikey)에 접속
2. **Create API Key** 버튼 클릭
3. API 키 복사

### 2. 환경 변수 설정
프로젝트 루트 디렉토리에 `.env` 파일 생성:

```bash
# .env.example을 복사하여 .env 파일 생성
copy .env.example .env
```

`.env` 파일에 API 키 입력:
```env
GOOGLE_API_KEY=여기에_발급받은_API_키_입력
HOST=0.0.0.0
PORT=8081
DATABASE_URL=sqlite:///instance/database.db
```

### 3. 의존성 설치
```bash
pip install -r requirements.txt
```

### 4. 데이터베이스 초기화
```bash
python -c "from app import create_app; app=create_app(); app.app_context().push(); from database import db; db.create_all()"
```

## 🚀 서버 실행

### 방법 1: Python 직접 실행
```bash
python app.py
```

### 방법 2: 배치 스크립트 실행 (권장)
```bash
scripts\start_server.bat
```

## 🌐 접속 주소
서버 실행 후 브라우저에서:
- **로그인 페이지**: http://localhost:8081/
- **채팅 페이지**: http://localhost:8081/chat
- **관리자 페이지**: http://localhost:8081/admin

## ✅ Gemini 작동 확인

### 1. 환경 변수 확인
```bash
python -c "import os; print('GOOGLE_API_KEY:', 'SET' if os.getenv('GOOGLE_API_KEY') else 'NOT SET')"
```

### 2. API 연결 테스트
```bash
python -c "import google.generativeai as genai; import os; genai.configure(api_key=os.getenv('GOOGLE_API_KEY')); model=genai.GenerativeModel('gemini-2.0-flash'); print(model.generate_content('안녕하세요').text)"
```

## 🔧 문제 해결

### Gemini 응답이 없는 경우
1. `.env` 파일에 `GOOGLE_API_KEY`가 제대로 설정되어 있는지 확인
2. API 키가 유효한지 확인 (Google AI Studio에서 재발급)
3. 서버 재시작

### 포트 충돌 발생 시
`.env` 파일에서 `PORT` 값 변경:
```env
PORT=8082
```

## 🤖 지원 모델
- **Gemini**: gemini-2.0-flash (기본)
- **Ollama**: qwen3:8b (로컬 실행 시)

