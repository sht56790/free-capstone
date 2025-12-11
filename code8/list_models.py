"""사용 가능한 Gemini 모델 목록 확인"""
import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()
api_key = os.environ.get("GOOGLE_API_KEY")

if not api_key:
    print("❌ API 키 없음")
    exit(1)

genai.configure(api_key=api_key)

print("🔍 사용 가능한 모델 목록:\n")

try:
    for model in genai.list_models():
        if 'generateContent' in model.supported_generation_methods:
            print(f"✅ {model.name}")
            print(f"   - 설명: {model.display_name}")
            print(f"   - 지원 메서드: {model.supported_generation_methods}")
            print()
except Exception as e:
    print(f"❌ 오류: {e}")
