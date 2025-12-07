"""
웹 스크래핑 서비스 - 다양한 실시간 정보 제공
완전 무료, API 키 불필요
"""
import requests
from bs4 import BeautifulSoup
from typing import Optional, Dict, Any
import re


def scrape_naver_search(query: str, num_results: int = 3) -> Optional[str]:
    """네이버 검색 결과 스크래핑
    
    Args:
        query: 검색어
        num_results: 가져올 결과 수
        
    Returns:
        포맷팅된 검색 결과 텍스트
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        url = f"https://search.naver.com/search.naver?query={query}"
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        results = []
        
        # 1. 지식인 답변 (가장 유용)
        knowledge = soup.select('.answer_text')
        if knowledge:
            for i, item in enumerate(knowledge[:num_results]):
                text = item.get_text(strip=True)
                if len(text) > 50:  # 의미있는 답변만
                    results.append(f"[네이버 지식인] {text[:300]}")
        
        # 2. 뉴스 결과
        news = soup.select('.news_tit')
        if news:
            for i, item in enumerate(news[:num_results]):
                title = item.get_text(strip=True)
                link = item.get('href', '')
                results.append(f"[뉴스] {title}")
        
        # 3. 일반 검색 결과
        if not results:
            general = soup.select('.total_tit')
            for i, item in enumerate(general[:num_results]):
                title = item.get_text(strip=True)
                results.append(f"[검색 결과] {title}")
        
        if results:
            formatted = f"[웹 검색: '{query}']\n\n" + "\n\n".join(results)
            print(f"[WEB SCRAPE] 네이버 검색 성공: {len(results)}개 결과")
            return formatted
        
        return None
        
    except Exception as e:
        print(f"[WEB SCRAPE] 네이버 검색 실패: {str(e)}")
        return None


def scrape_kospi() -> Optional[str]:
    """네이버 금융에서 코스피 지수 스크래핑"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        url = "https://finance.naver.com/sise/"
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 코스피 지수
        kospi_elem = soup.select_one('#KOSPI_now')
        kospi_change_elem = soup.select_one('#KOSPI_change')
        kospi_rate_elem = soup.select_one('#KOSPI_rate')
        
        if kospi_elem:
            kospi = kospi_elem.get_text(strip=True)
            change = kospi_change_elem.get_text(strip=True) if kospi_change_elem else "0"
            rate = kospi_rate_elem.get_text(strip=True) if kospi_rate_elem else "0%"
            
            # 상승/하락 판단
            if '+' in change or '상승' in str(soup):
                direction = "상승"
            elif '-' in change or '하락' in str(soup):
                direction = "하락"
            else:
                direction = "보합"
            
            result = f"[실시간 정보] 코스피 지수: {kospi}포인트 ({change}, {rate}) - {direction}"
            print(f"[WEB SCRAPE] 코스피 조회 성공: {kospi}")
            return result
        
        return None
        
    except Exception as e:
        print(f"[WEB SCRAPE] 코스피 조회 실패: {str(e)}")
        return None


def scrape_weather(location: str = "서울") -> Optional[str]:
    """네이버 날씨 스크래핑"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        url = f"https://search.naver.com/search.naver?query={location}+날씨"
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 현재 온도
        temp = soup.select_one('.temperature_text strong')
        # 날씨 상태
        weather_status = soup.select_one('.weather.before_slash')
        # 미세먼지
        dust = soup.select_one('.air_good, .air_normal, .air_bad, .air_worst')
        
        if temp:
            temp_text = temp.get_text(strip=True).replace('현재 온도', '').strip()
            status_text = weather_status.get_text(strip=True) if weather_status else "정보 없음"
            dust_text = dust.get_text(strip=True) if dust else "정보 없음"
            
            result = f"[실시간 정보] {location} 날씨: {temp_text}, {status_text}, 미세먼지 {dust_text}"
            print(f"[WEB SCRAPE] 날씨 조회 성공: {location} {temp_text}")
            return result
        
        return None
        
    except Exception as e:
        print(f"[WEB SCRAPE] 날씨 조회 실패: {str(e)}")
        return None


def scrape_exchange_rate(currency: str = "USD") -> Optional[str]:
    """네이버 금융에서 환율 스크래핑"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        currency_map = {
            "달러": "USD", "usd": "USD", "미국": "USD",
            "엔": "JPY", "jpy": "JPY", "일본": "JPY",
            "유로": "EUR", "eur": "EUR",
            "위안": "CNY", "cny": "CNY", "중국": "CNY",
        }
        
        currency_code = currency_map.get(currency.lower(), currency.upper())
        
        url = f"https://finance.naver.com/marketindex/exchangeDetail.naver?marketindexCd=FX_{currency_code}KRW"
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        rate_elem = soup.select_one('.no_today .no_up, .no_today .no_down, .no_today .no_exday')
        change_elem = soup.select_one('.no_today .no_change')
        
        if rate_elem:
            rate = rate_elem.get_text(strip=True)
            change = change_elem.get_text(strip=True) if change_elem else "0"
            
            result = f"[실시간 정보] {currency_code}/KRW 환율: {rate}원 (전일대비 {change})"
            print(f"[WEB SCRAPE] 환율 조회 성공: {currency_code} {rate}")
            return result
        
        return None
        
    except Exception as e:
        print(f"[WEB SCRAPE] 환율 조회 실패: {str(e)}")
        return None


def smart_scrape(query: str) -> Optional[str]:
    """질문 내용에 따라 적절한 스크래핑 함수 선택
    
    Args:
        query: 사용자 질문
        
    Returns:
        스크래핑 결과 (없으면 None)
    """
    query_lower = query.lower()
    
    # 1. 주가/증시 관련
    if any(keyword in query_lower for keyword in ["코스피", "kospi", "증시", "주가지수"]):
        result = scrape_kospi()
        if result:
            return result
    
    # 2. 환율 관련
    if any(keyword in query_lower for keyword in ["환율", "달러", "엔화", "유로", "위안"]):
        # 통화 추출
        currency = "USD"
        if "엔" in query or "일본" in query:
            currency = "JPY"
        elif "유로" in query:
            currency = "EUR"
        elif "위안" in query or "중국" in query:
            currency = "CNY"
        
        result = scrape_exchange_rate(currency)
        if result:
            return result
    
    # 3. 날씨 관련
    if any(keyword in query_lower for keyword in ["날씨", "기온", "온도", "덥", "춥", "비", "눈"]):
        # 지역 추출
        location = "서울"
        cities = ["서울", "부산", "인천", "대구", "대전", "광주", "울산", "수원", 
                  "한성대", "성북", "강남", "홍대", "신촌"]
        for city in cities:
            if city in query:
                location = city
                break
        
        result = scrape_weather(location)
        if result:
            return result
    
    # 4. 일반 검색 (최후 수단)
    # 금융 내부 질문이 아닌 경우에만
    internal_keywords = ["대출", "예금", "적금", "펀드", "보험", "카드", "계좌", "이체"]
    if not any(keyword in query_lower for keyword in internal_keywords):
        result = scrape_naver_search(query, num_results=3)
        if result:
            return result
    
    return None

