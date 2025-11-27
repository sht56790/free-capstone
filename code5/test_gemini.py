import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

print("="*70)
print("🤖 Gemini API 테스트")
print("="*70)
print()

# API 키 확인
api_key = os.environ.get("GOOGLE_API_KEY")
if not api_key:
    print("❌ GOOGLE_API_KEY가 설정되지 않았습니다!")
    exit(1)

print(f"✅ API Key: {api_key[:10]}...{api_key[-4:]}")
print()

try:
    # Gemini 설정
    genai.configure(api_key=api_key)
    
    # 모델 초기화
    model = genai.GenerativeModel("gemini-2.0-flash")
    print("✅ 모델 초기화 완료: gemini-2.0-flash")
    print()
    
    # 테스트 질문
    test_prompts = [
        "안녕하세요! 간단히 인사해주세요.",
        "1+1은 얼마인가요?",
        "금융 상담에서 고객의 개인정보를 보호하는 방법을 한 문장으로 설명해주세요."
    ]
    
    for i, prompt in enumerate(test_prompts, 1):
        print(f"📝 테스트 {i}: {prompt}")
        print("-"*70)
        
        try:
            response = model.generate_content(prompt)
            print(f"✅ 응답:")
            print(response.text)
            print()
        except Exception as e:
            print(f"❌ 오류: {e}")
            print()
    
    print("="*70)
    print("✅ Gemini API 테스트 완료!")
    print("="*70)
    
except Exception as e:
    print(f"❌ Gemini API 오류: {e}")
    import traceback
    traceback.print_exc()
