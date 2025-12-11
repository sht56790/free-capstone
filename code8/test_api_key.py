"""Gemini API 키 직접 테스트"""
import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

api_key = os.environ.get("GOOGLE_API_KEY")

if not api_key:
    print("❌ .env 파일에 GOOGLE_API_KEY가 없습니다.")
    exit(1)

print(f"✅ API 키 로드됨: {api_key[:10]}...")

try:
    genai.configure(api_key=api_key)
    print("✅ API 키 설정 완료")
    
    # 간단한 테스트 요청
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content("안녕하세요")
    
    print(f"✅ 테스트 성공!")
    print(f"응답: {response.text[:100]}...")
    
except Exception as e:
    print(f"❌ API 호출 실패: {e}")
    print("\n가능한 원인:")
    print("1. API 키가 유출되어 차단됨")
    print("2. API 키 제한 설정 문제")
    print("3. Google Cloud 프로젝트 제한")
    print("\n해결책: 새 프로젝트를 만들고 새 키를 발급받으세요.")
