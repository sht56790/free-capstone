"""
웹 검색 서비스 - Gemini에게 실시간 정보 제공
Google Custom Search API 사용
"""
import requests
import os
from typing import List, Dict, Optional, Any
from dotenv import load_dotenv

load_dotenv()

# Google Custom Search API 설정
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID")  # Custom Search Engine ID

def google_search(query: str, num_results: int = 3) -> Dict[str, Any]:
    """Google Custom Search API로 웹 검색
    
    무료 할당량: 하루 100회
    설정 방법:
    1. https://console.cloud.google.com/apis/library/customsearch.googleapis.com 에서 API 활성화
    2. https://programmablesearchengine.google.com/controlpanel/create 에서 검색 엔진 생성
    3. .env에 GOOGLE_CSE_ID 추가
    
    Args:
        query: 검색 쿼리
        num_results: 반환할 결과 수 (최대 10)
        
    Returns:
        검색 결과 딕셔너리
    """
    if not GOOGLE_API_KEY:
        return {
            "success": False,
            "error": "GOOGLE_API_KEY가 설정되지 않았습니다.",
            "results": []
        }
    
    if not GOOGLE_CSE_ID:
        return {
            "success": False,
            "error": "GOOGLE_CSE_ID가 설정되지 않았습니다. Google Custom Search Engine을 생성하세요.",
            "help": "https://programmablesearchengine.google.com/controlpanel/create",
            "results": []
        }
    
    try:
        url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "key": GOOGLE_API_KEY,
            "cx": GOOGLE_CSE_ID,
            "q": query,
            "num": min(num_results, 10),  # 최대 10개
            "lr": "lang_ko",  # 한국어 우선
            "gl": "kr"  # 한국 지역
        }
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if "items" not in data:
            return {
                "success": False,
                "error": "검색 결과가 없습니다.",
                "results": []
            }
        
        # 검색 결과 포맷팅
        results = []
        for item in data["items"][:num_results]:
            results.append({
                "title": item.get("title", ""),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "displayLink": item.get("displayLink", "")
            })
        
        # Gemini가 읽기 쉬운 형태로 변환
        formatted_text = f"[웹 검색 결과: '{query}']\n\n"
        for i, result in enumerate(results, 1):
            formatted_text += f"{i}. {result['title']}\n"
            formatted_text += f"   출처: {result['displayLink']}\n"
            formatted_text += f"   내용: {result['snippet']}\n\n"
        
        return {
            "success": True,
            "query": query,
            "results": results,
            "formatted": formatted_text,
            "total_results": len(results)
        }
        
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": f"검색 API 요청 실패: {str(e)}",
            "results": []
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"검색 처리 중 오류: {str(e)}",
            "results": []
        }


def should_search(user_input: str) -> Optional[str]:
    """사용자 입력에서 검색이 필요한지 판단하고 검색 쿼리 생성
    
    Returns:
        검색 쿼리 (검색 불필요시 None)
    """
    user_lower = user_input.lower()
    
    # 검색 키워드 (실시간 정보, 최신 정보 관련)
    search_keywords = [
        # 시간 관련
        "현재", "지금", "오늘", "최근", "최신",
        # 정보 요청
        "뉴스", "소식", "알려줘", "알려주세요", "어떻게 돼", 
        # 실시간 정보
        "날씨", "기온", "온도", "시간", "주가", "환율", "코스피",
        # 일반 검색
        "찾아", "검색", "조회", "확인",
    ]
    
    # 금융 매뉴얼 관련 키워드 (검색 불필요)
    internal_keywords = [
        "대출", "예금", "적금", "펀드", "보험", "카드", 
        "계좌", "이체", "송금", "출금", "입금",
        "가입", "신청", "해지", "연장", "갱신",
        "금리", "수수료", "한도", "만기", "중도",
        "상품", "서비스", "안내", "절차", "방법"
    ]
    
    # 금융 관련 질문이면 검색하지 않음 (내부 RAG 사용)
    if any(keyword in user_lower for keyword in internal_keywords):
        return None
    
    # 검색이 필요한 질문이면 쿼리 반환
    if any(keyword in user_lower for keyword in search_keywords):
        # 사용자 입력을 검색 쿼리로 사용
        return user_input
    
    return None


def search_and_format(user_input: str) -> Optional[str]:
    """사용자 질문 분석 후 필요시 검색하고 포맷팅된 결과 반환
    
    Returns:
        검색 결과 텍스트 (검색 불필요시 None)
    """
    query = should_search(user_input)
    
    if not query:
        return None
    
    print(f"[SEARCH] 검색 실행: '{query}'")
    
    search_result = google_search(query, num_results=3)
    
    if search_result["success"]:
        print(f"[SEARCH] 검색 성공: {search_result['total_results']}개 결과")
        return search_result["formatted"]
    else:
        print(f"[SEARCH] 검색 실패: {search_result.get('error', 'Unknown error')}")
        # 검색 실패 시 None 반환 (Gemini가 자체 지식으로 답변)
        return None

