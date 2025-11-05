"""
Ollama 서비스 모듈
- 민감정보 판정 (judge_sensitive_with_ollama)
- 정규식 생성 (generate_regex_from_ollama)
"""
import re
import json
import traceback
from typing import List, Dict, Any
import requests

# Ollama 설정
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL_FOR_JUDGE = "qwen3:8b"
OLLAMA_MODEL_FOR_REGEX = "qwen3:8b"


def _post_ollama_generate(model: str, prompt: str, *, as_json: bool, timeout: int = 30) -> Dict[str, Any]:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    if as_json:
        payload["format"] = "json"
    resp = requests.post(OLLAMA_API_URL, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def judge_sensitive_with_ollama(text: str, model: str | None = None) -> List[Dict[str, Any]]:
    """Ollama를 사용하여 텍스트에서 민감 정보 구간을 찾습니다."""

    # Ollama 모델에 맞는 프롬프트 (튜닝 필요!)
    # format: "json" 옵션을 사용하므로, JSON 형식만 출력하도록 명확히 지시
    prompt = f"""다음 텍스트에서 실제 개인정보나 민감한 정보만 찾아주세요.

**중요: 질문이나 일반적인 문의는 민감정보가 아닙니다!**

**허용되는 것 (민감정보가 아님):**
- "수수료는 어떻게 결정되나요?" → 질문, 민감정보 아님
- "금리는 어떻게 되나요?" → 질문, 민감정보 아님  
- "수수료 결정 방식" → 일반 문의, 민감정보 아님
- "금리 정보" → 일반 문의, 민감정보 아님
- 금융 용어 자체 (수수료, 금리, 이자율 등) → 민감정보 아님

**차단해야 할 것 (실제 개인정보):**
- 이름: "홍길동", "김철수"
- 전화번호: "010-1234-5678"
- 계좌번호: "123-456-789012"
- 주소: "서울시 강남구..."
- 이메일: "user@example.com"
- 고객번호: "123456"

**차단해야 할 것 (확정 표현):**
- "수수료는 5,000원입니다" (확정 금액)
- "금리는 3.5%입니다" (확정 수치)

찾은 내용을 담은 유효한 JSON 배열만 반환해야 합니다. 각 결과는 반드시 "span"(시작 및 끝 문자 인덱스 목록, 예: [10, 22]), "label"(예: NAME, ADDRESS, EMAIL, PHONE, ACCOUNT, CUSTOMER_ID), "action"("mask" 또는 매우 민감하면 "block") 키를 가진 객체여야 합니다.
아무것도 찾지 못하면 빈 JSON 배열 []을 반환하세요. JSON 외의 설명이나 다른 텍스트는 절대 포함하지 마세요.

Text:
{text}

JSON Array:"""

    try:
        response_data = _post_ollama_generate(model or OLLAMA_MODEL_FOR_JUDGE, prompt, as_json=True, timeout=30)
        json_str = response_data.get("response", "[]")

        # 만약을 대비한 정리 (Ollama가 완벽하지 않을 수 있음)
        json_str = json_str.strip()
        if not (json_str.startswith('[') and json_str.endswith(']')):
            # JSON 배열 패턴을 다시 찾아봄
            match = re.search(r"\[.*\]", json_str, re.DOTALL)
            json_str = match.group(0) if match else '[]'

        try:
            arr = json.loads(json_str)
        except json.JSONDecodeError as json_err:
            print(f"[judge_sensitive_with_ollama] JSON 파싱 오류: {json_err} - 응답: {json_str[:200]}...")
            arr = []  # 파싱 실패 시 빈 배열 반환

        out = []
        if isinstance(arr, list):  # 최종 결과가 리스트인지 확인
            for j in arr:
                # 각 항목이 딕셔너리인지, 필요한 키가 있는지, 타입이 맞는지 검증
                if (isinstance(j, dict) and
                        "span" in j and isinstance(j["span"], list) and len(j["span"]) == 2 and
                        all(isinstance(x, int) for x in j["span"]) and
                        0 <= j["span"][0] < j["span"][1] <= len(text) and  # span 범위 검증
                        "label" in j and isinstance(j["label"], str)):

                    out.append({
                        "span": j["span"],
                        "label": j["label"].upper(),  # 라벨 대문자 통일
                        "action": "block" if j.get("action") == "block" else "mask"  # action 기본값 'mask'
                    })
                else:
                    print(f"[judge_sensitive_with_ollama] 잘못된 형식의 결과 항목 건너뜀: {j}")

        return out

    # requests 오류 (연결 실패, 타임아웃 등) 또는 HTTP 오류 처리
    except requests.exceptions.RequestException as req_err:
        print(f"[judge_sensitive_with_ollama] Ollama API 요청 오류: {req_err}")
        traceback.print_exc()  # 상세 오류 로깅
        return []  # 오류 시 빈 배열 반환
    # 그 외 예외 처리
    except Exception as e:
        print(f"[judge_sensitive_with_ollama] 예상치 못한 오류: {e}")
        traceback.print_exc()
        return []

def generate_regex_from_ollama(description: str, model: str | None = None) -> str:
    """Ollama를 사용하여 자연어 설명으로부터 정규식을 생성합니다."""
    from flask import current_app  # 함수 내에서 current_app 임포트

    # Ollama 모델에 맞는 프롬프트 (튜닝 필요!)
    prompt = f"""당신은 Python 호환 정규식 작성 전문가입니다. 사용자의 설명을 유효한 단일 정규식 패턴으로 변환하는 것이 유일한 임무입니다.
오직 정규식 패턴만 출력하고 다른 설명, 백틱(`), 마크다운 또는 기타 텍스트는 절대 포함하지 마세요.

Description: '{description}'

Regex Pattern:"""

    try:
        response_data = _post_ollama_generate(model or OLLAMA_MODEL_FOR_REGEX, prompt, as_json=False, timeout=20)
        regex_pattern = response_data.get("response", "").strip()

        # 응답에서 불필요한 부분 제거 (예: 설명, 백틱 등)
        # 가장 흔한 패턴 위주로 제거
        if regex_pattern.startswith('`') and regex_pattern.endswith('`'):
            regex_pattern = regex_pattern[1:-1]
        # 추가적인 정리 로직 필요시 여기에 구현

        # 생성된 정규식이 유효한지 컴파일 시도
        try:
            re.compile(regex_pattern)
            print(f"[generate_regex_from_ollama] 생성된 정규식: {regex_pattern}")
            return regex_pattern
        except re.error as re_err:
            print(f"[generate_regex_from_ollama] AI가 잘못된 정규식 생성: {regex_pattern} - 오류: {re_err}")
            raise ValueError(f"AI가 잘못된 정규식을 생성했습니다.")

    except requests.exceptions.RequestException as req_err:
        print(f"[generate_regex_from_ollama] Ollama API 요청 오류: {req_err}")
        traceback.print_exc()
        raise RuntimeError(f"Ollama API 호출 실패: {req_err}")
    except Exception as e:
        print(f"[generate_regex_from_ollama] 예상치 못한 오류: {e}")
        traceback.print_exc()
        raise RuntimeError(f"AI 정규식 생성 중 오류 발생: {e}")


def benchmark_ollama(text: str, models: list[str], task: str = "judge") -> list[Dict[str, Any]]:
    """여러 Ollama 모델에 대해 동일 입력을 실행하여 시간/결과를 비교합니다.

    task: "judge"(민감정보 판정) | "regex"(정규식 생성)
    """
    import time

    results: list[Dict[str, Any]] = []
    for m in models:
        start = time.perf_counter()
        try:
            if task == "regex":
                out = generate_regex_from_ollama(text, model=m)
            else:
                out = judge_sensitive_with_ollama(text, model=m)
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            results.append({
                "model": m,
                "task": task,
                "duration_ms": elapsed_ms,
                "result": out if task == "judge" else {"pattern": out},
                "error": None,
            })
        except Exception as e:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            results.append({
                "model": m,
                "task": task,
                "duration_ms": elapsed_ms,
                "result": None,
                "error": str(e),
            })
    return results

