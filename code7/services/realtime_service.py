"""
실시간 정보 제공 서비스
- 날씨: OpenWeatherMap API
- 시간: 서버 시간
- 주가: Yahoo Finance (yfinance)
"""
import requests
from datetime import datetime
from typing import Dict, Optional, Any


def get_current_time() -> Dict[str, Any]:
    """현재 서버 시간 반환"""
    now = datetime.now()
    return {
        "success": True,
        "time": now.strftime("%H:%M:%S"),
        "date": now.strftime("%Y년 %m월 %d일"),
        "weekday": ["월", "화", "수", "목", "금", "토", "일"][now.weekday()],
        "formatted": f"{now.strftime('%Y년 %m월 %d일')} ({['월', '화', '수', '목', '금', '토', '일'][now.weekday()]}) {now.strftime('%H:%M:%S')}"
    }


def get_weather(location: str = "서울") -> Dict[str, Any]:
    """OpenWeatherMap API로 날씨 정보 조회
    
    무료 API 키 필요: https://openweathermap.org/api
    .env에 OPENWEATHER_API_KEY 추가
    """
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    api_key = os.getenv("OPENWEATHER_API_KEY")
    
    if not api_key:
        return {
            "success": False,
            "error": "API 키가 설정되지 않았습니다. OpenWeatherMap API 키를 .env에 추가하세요.",
            "fallback": f"{location} 날씨는 기상청(weather.go.kr)에서 확인하실 수 있습니다."
        }
    
    # 한국 주요 도시 좌표 매핑
    city_coords = {
        "서울": {"lat": 37.5665, "lon": 126.9780},
        "부산": {"lat": 35.1796, "lon": 129.0756},
        "인천": {"lat": 37.4563, "lon": 126.7052},
        "대구": {"lat": 35.8714, "lon": 128.6014},
        "대전": {"lat": 36.3504, "lon": 127.3845},
        "광주": {"lat": 35.1595, "lon": 126.8526},
        "울산": {"lat": 35.5384, "lon": 129.3114},
        "수원": {"lat": 37.2636, "lon": 127.0286},
        "성북": {"lat": 37.5894, "lon": 127.0167},  # 한성대 근처
        "성북구": {"lat": 37.5894, "lon": 127.0167},
        "한성대": {"lat": 37.5828, "lon": 127.0093},
        "한성대학교": {"lat": 37.5828, "lon": 127.0093},
    }
    
    # 위치에서 좌표 찾기
    coords = city_coords.get(location, city_coords["서울"])
    
    try:
        url = "https://api.openweathermap.org/data/2.5/weather"
        params = {
            "lat": coords["lat"],
            "lon": coords["lon"],
            "appid": api_key,
            "units": "metric",  # 섭씨
            "lang": "kr"
        }
        
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        # 날씨 상태 한글 변환
        weather_kr = {
            "Clear": "맑음",
            "Clouds": "흐림",
            "Rain": "비",
            "Drizzle": "이슬비",
            "Thunderstorm": "뇌우",
            "Snow": "눈",
            "Mist": "안개",
            "Fog": "안개",
            "Haze": "연무"
        }
        
        main_weather = data["weather"][0]["main"]
        weather_desc = weather_kr.get(main_weather, data["weather"][0]["description"])
        
        return {
            "success": True,
            "location": location,
            "temperature": round(data["main"]["temp"]),
            "feels_like": round(data["main"]["feels_like"]),
            "humidity": data["main"]["humidity"],
            "weather": weather_desc,
            "description": data["weather"][0]["description"],
            "wind_speed": round(data["wind"]["speed"], 1),
            "formatted": f"{location} 날씨: {weather_desc}, 기온 {round(data['main']['temp'])}°C (체감 {round(data['main']['feels_like'])}°C), 습도 {data['main']['humidity']}%, 풍속 {round(data['wind']['speed'], 1)}m/s"
        }
        
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": f"날씨 정보를 가져올 수 없습니다: {str(e)}",
            "fallback": f"{location} 날씨는 기상청(weather.go.kr)에서 확인하실 수 있습니다."
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"날씨 처리 중 오류: {str(e)}",
            "fallback": f"{location} 날씨는 기상청(weather.go.kr)에서 확인하실 수 있습니다."
        }


def get_stock_price(ticker: str = "^KS11") -> Dict[str, Any]:
    """주가 정보 조회 (yfinance 사용)
    
    Args:
        ticker: 종목 코드
            - "^KS11": 코스피 지수
            - "^KQ11": 코스닥 지수
            - "005930.KS": 삼성전자
    """
    try:
        import yfinance as yf
        
        # 한글 이름 매핑
        ticker_names = {
            "^KS11": "코스피",
            "^KQ11": "코스닥",
            "005930.KS": "삼성전자",
            "000660.KS": "SK하이닉스",
            "035720.KS": "카카오",
            "035420.KS": "NAVER",
        }
        
        # 키워드로 ticker 찾기
        ticker_map = {
            "코스피": "^KS11",
            "kospi": "^KS11",
            "코스닥": "^KQ11",
            "kosdaq": "^KQ11",
            "삼성": "005930.KS",
            "삼성전자": "005930.KS",
            "sk하이닉스": "000660.KS",
            "카카오": "035720.KS",
            "네이버": "035420.KS",
        }
        
        # ticker 변환
        ticker_lower = ticker.lower()
        if ticker_lower in ticker_map:
            ticker = ticker_map[ticker_lower]
        
        stock = yf.Ticker(ticker)
        # 5일치 데이터 가져오기 (주말/휴일 대비)
        info = stock.history(period="5d")
        
        if info.empty:
            return {
                "success": False,
                "error": "주가 정보를 가져올 수 없습니다.",
                "fallback": "실시간 주가는 증권사 MTS 앱이나 포털 금융 섹션에서 확인하실 수 있습니다."
            }
        
        # 가장 최근 데이터 사용
        current_price = info['Close'].iloc[-1]
        last_date = info.index[-1].strftime("%Y-%m-%d %H:%M")
        
        # 이전 종가 계산 (2일 이상 데이터가 있으면)
        if len(info) >= 2:
            prev_close = info['Close'].iloc[-2]
        else:
            prev_close = current_price
            
        change = current_price - prev_close
        change_percent = (change / prev_close) * 100 if prev_close != 0 else 0
        
        name = ticker_names.get(ticker, ticker)
        
        print(f"[STOCK] {name} 조회 성공: {current_price:,.2f} (기준: {last_date})")
        
        return {
            "success": True,
            "ticker": ticker,
            "name": name,
            "price": round(current_price, 2),
            "change": round(change, 2),
            "change_percent": round(change_percent, 2),
            "last_update": last_date,
            "formatted": f"{name}: {round(current_price, 2):,}{'포인트' if ticker.startswith('^') else '원'} ({'+' if change >= 0 else ''}{round(change, 2):,}, {'+' if change >= 0 else ''}{round(change_percent, 2)}%) [기준: {last_date}]"
        }
        
    except ImportError:
        return {
            "success": False,
            "error": "yfinance 모듈이 설치되지 않았습니다. 'pip install yfinance' 실행 필요",
            "fallback": "실시간 주가는 증권사 MTS 앱이나 포털 금융 섹션에서 확인하실 수 있습니다."
        }
    except Exception as e:
        print(f"[STOCK] 조회 실패: {str(e)}")
        return {
            "success": False,
            "error": f"주가 조회 중 오류: {str(e)}",
            "fallback": "실시간 주가는 증권사 MTS 앱이나 포털 금융 섹션에서 확인하실 수 있습니다."
        }


def detect_and_fetch_realtime_info(user_input: str) -> Optional[str]:
    """사용자 질문에서 실시간 정보 요청을 감지하고 데이터를 가져옵니다.
    
    Returns:
        실시간 정보 텍스트 (Gemini 컨텍스트에 추가할 내용)
    """
    user_input_lower = user_input.lower()
    realtime_context = []
    
    # 시간 요청 감지
    if any(keyword in user_input_lower for keyword in ["시간", "몇 시", "지금 몇시"]):
        time_info = get_current_time()
        if time_info["success"]:
            realtime_context.append(f"[실시간 정보] 현재 시간: {time_info['formatted']}")
    
    # 날씨 요청 감지
    if any(keyword in user_input_lower for keyword in ["날씨", "기온", "온도", "덥", "춥", "비", "눈"]):
        # 위치 추출 시도
        location = "서울"
        for city in ["한성대", "한성대학교", "성북", "성북구", "서울", "부산", "인천", "대구", "대전", "광주", "울산", "수원"]:
            if city in user_input:
                location = city
                break
        
        weather_info = get_weather(location)
        if weather_info["success"]:
            realtime_context.append(f"[실시간 정보] {weather_info['formatted']}")
        else:
            realtime_context.append(f"[정보] 날씨 API 오류. {weather_info['fallback']}")
    
    # 주가 요청 감지
    if any(keyword in user_input_lower for keyword in ["주가", "코스피", "코스닥", "삼성", "주식", "증시"]):
        # 종목 추출 시도
        ticker = "^KS11"  # 기본값: 코스피
        if "코스닥" in user_input_lower or "kosdaq" in user_input_lower:
            ticker = "^KQ11"
        elif "삼성" in user_input:
            ticker = "005930.KS"
        
        stock_info = get_stock_price(ticker)
        if stock_info["success"]:
            realtime_context.append(f"[실시간 정보] {stock_info['formatted']}")
        else:
            realtime_context.append(f"[정보] 주가 API 오류. {stock_info['fallback']}")
    
    return "\n".join(realtime_context) if realtime_context else None

