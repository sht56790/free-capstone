"""Gemini + RAG 통합 테스트 스크립트"""
import os
import sys
from dotenv import load_dotenv
import google.generativeai as genai

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.rag_service import retrieve_context

load_dotenv()

def test_rag_gemini():
    """RAG + Gemini 통합 테스트"""
    
    # 1. API 키 확인
    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        print("❌ GOOGLE_API_KEY가 .env 파일에 설정되지 않았습니다.")
        print("   https://makersuite.google.com/app/apikey 에서 발급받으세요.")
        return
    
    genai.configure(api_key=api_key)
    print("✅ Gemini API 키 설정 완료\n")
    
    # 2. 테스트 질문
    test_questions = [
        "직원 매뉴얼에 대해 알려줘",
        "검사업무 절차는 어떻게 되나요?",
        "고객 응대 시 주의사항이 있나요?",
    ]
    
    for idx, question in enumerate(test_questions, 1):
        print(f"{'='*60}")
        print(f"[테스트 {idx}] 질문: {question}")
        print(f"{'='*60}\n")
        
        # 3. RAG로 관련 문서 검색
        print("🔍 [1단계] 벡터 DB에서 관련 문서 검색 중...")
        context = retrieve_context(question, k=3)
        print(f"검색 결과:\n{context[:300]}...\n")
        
        # 4. Gemini에게 질문 (RAG 컨텍스트 포함)
        print("🤖 [2단계] Gemini에게 답변 요청 중...")
        
        system_instruction = (
            "당신은 '금융회사 직원 보조용' 상담 에이전트입니다. "
            "아래 [검색된 참고 자료]를 바탕으로 답변하세요.\n\n"
            f"--- [검색된 참고 자료] ---\n{context}\n"
            "------------------------\n\n"
            "답변 형식:\n"
            "## 답변\n"
            "- 입력 요약: (질문 요약)\n"
            "- 고객 응대 멘트: (직원이 읽어줄 1~3문장)\n\n"
            "## 근거 출처\n"
            "- [문서명] 섹션\n"
        )
        
        model = genai.GenerativeModel(
            "gemini-2.0-flash-exp",  # 또는 gemini-1.5-pro
            system_instruction=system_instruction
        )
        
        try:
            response = model.generate_content(question)
            print(f"✅ Gemini 응답:\n{response.text}\n")
        except Exception as e:
            print(f"❌ Gemini 호출 오류: {e}\n")
        
        print(f"{'='*60}\n\n")


if __name__ == "__main__":
    print("🚀 Gemini + RAG 통합 테스트 시작\n")
    test_rag_gemini()
    print("✅ 테스트 완료!")
