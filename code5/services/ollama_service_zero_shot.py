"""
Zero-Shot 능력 강화 버전 - 새로운 개념도 탐지 가능
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.ollama_service import _post_ollama_generate, get_cache, OLLAMA_MODEL_FOR_JUDGE
from typing import List, Dict, Any
import re
import json

def judge_sensitive_zero_shot(text: str, model: str | None = None, use_cache: bool = True) -> List[Dict[str, Any]]:
    """Zero-Shot 능력 강화: 사전 정의되지 않은 민감정보도 탐지"""
    
    cache = get_cache()
    model_name = model or OLLAMA_MODEL_FOR_JUDGE
    cache_key = f"zero_shot_{text}"
    
    if use_cache:
        cached_result = cache.get(cache_key, model_name)
        if cached_result is not None:
            return cached_result
    
    # Zero-Shot 프롬프트: 카테고리 대신 "특성" 정의
    prompt = f"""You are a universal sensitive information detector for Korean financial services.

WHAT IS SENSITIVE INFORMATION? (General Definition)
Information that:
1. Can IDENTIFY a specific person (name, ID, number)
2. Can ACCESS financial accounts (account, card, password, PIN, code)
3. Reveals PRIVATE financial details (balance, salary, debt, rate)
4. Commands FINANCIAL TRANSACTIONS (send money, transfer, withdraw)
5. Contains CONFIDENTIAL data (SSN, passport, license, secret code)

PRIORITY LEVELS:
[P10-BLOCK] Direct identifiers: 주민번호, 계좌번호, 카드번호, 비밀번호, PIN, 시크릿코드
[P9-BLOCK] Financial commitments: 확정금리, 거래실행, 송금/이체/출금 명령
[P8-MASK] Contact & financial amounts: 전화번호, 이메일, 금액, 잔액, 연봉
[P7-MASK] Personal identifiers: 이름, 주소, 생년월일, 직장

REASONING STEPS:
1. IDENTIFY: What information is present?
2. CATEGORIZE: Which sensitivity type does it match?
3. ASSESS RISK: How harmful if leaked? (P10=critical, P7=moderate)
4. CONTEXTUALIZE: Is this actual data or just general discussion?
5. DECIDE: block/mask/ignore

EXAMPLES (including unknown types):

Example 1 - Known type:
Input: "홍길동 010-1234-5678"
Step 1: Name + phone number
Step 2: Personal identifier (name) + contact (phone)
Step 3: P7 (name) + P8 (phone)
Step 4: Actual personal data
Step 5: Mask both
Output: [{{"span":[0,3],"label":"NAME","action":"mask","priority":7}},{{"span":[4,17],"label":"PHONE","action":"mask","priority":8}}]

Example 2 - Unknown type (new concept):
Input: "시크릿코드: ABC123XYZ"
Step 1: "시크릿코드" = secret code (unknown category)
Step 2: Access credential type (like password)
Step 3: P10 (can access system/account)
Step 4: Actual code value
Step 5: Block
Output: [{{"span":[0,19],"label":"SECRET_CODE","action":"block","priority":10}}]

Example 3 - Unknown type (new concept):
Input: "인증번호 654321 입력하세요"
Step 1: "인증번호" = authentication number
Step 2: Temporary access code
Step 3: P10 (can access/verify identity)
Step 4: Actual auth code
Step 5: Block
Output: [{{"span":[5,11],"label":"AUTH_CODE","action":"block","priority":10}}]

Example 4 - Unknown type (new concept):
Input: "여권번호 M12345678"
Step 1: "여권번호" = passport number
Step 2: Government ID (like SSN)
Step 3: P10 (strong identifier)
Step 4: Actual passport number
Step 5: Block
Output: [{{"span":[5,14],"label":"PASSPORT","action":"block","priority":10}}]

Example 5 - General question (NOT sensitive):
Input: "대출 한도는 어떻게 되나요"
Step 1: Question about loan limit
Step 2: General inquiry, no specific data
Step 3: P0 (not sensitive)
Step 4: Just asking, no actual data
Step 5: Ignore
Output: []

CRITICAL RULES:
- If it can IDENTIFY a person → P7-P10
- If it can ACCESS an account → P10
- If it reveals PRIVATE numbers → P8-P10
- If it commands ACTION → P9-P10
- If it's JUST A QUESTION → ignore
- When unsure, CREATE a new label that describes it (e.g., "SECRET_CODE", "AUTH_CODE", "PASSPORT")

NOW ANALYZE (think step-by-step, create new labels if needed):
Text: "{text}"
JSON:"""

    try:
        response_data = _post_ollama_generate(
            model_name,
            prompt=prompt,
            as_json=False,
            timeout=35,
        )
        raw_response = response_data.get("response", "[]")
        
        # JSON 추출
        json_str = raw_response.strip()
        match = re.search(r"\[.*\]", json_str, re.DOTALL)
        json_str = match.group(0) if match else '[]'
        
        arr = json.loads(json_str)
        out = []
        
        for j in arr:
            if not isinstance(j, dict) or "span" not in j:
                continue
            
            start, end = j["span"]
            if not (0 <= start < end <= len(text)):
                continue
            
            label = j.get("label", "UNKNOWN").upper()
            priority = j.get("priority", 5)
            
            # 가중치 기반 액션
            if priority >= 9:
                action = "block"
            elif priority >= 7:
                action = "mask"
            else:
                continue
            
            out.append({
                "span": [start, end],
                "label": label,
                "action": action,
                "priority": priority,
                "confidence": j.get("confidence", 0.7)
            })
        
        if use_cache:
            cache.set(cache_key, model_name, out)
        
        return out
        
    except Exception as e:
        print(f"[judge_sensitive_zero_shot] 오류: {e}")
        return []


def judge_sensitive_hybrid_with_zero_shot(text: str, model: str | None = None) -> List[Dict[str, Any]]:
    """하이브리드: CoT(알려진 카테고리) + Zero-Shot(새로운 카테고리)"""
    
    # 1단계: CoT로 알려진 카테고리 탐지
    from services.ollama_service import judge_sensitive_with_ollama
    known_detections = judge_sensitive_with_ollama(text, model, use_cache=False)
    
    # 2단계: Zero-Shot으로 새로운 카테고리 탐지
    all_detections = judge_sensitive_zero_shot(text, model, use_cache=False)
    
    # 중복 제거 (같은 span은 우선순위 높은 것만)
    merged = {}
    for d in known_detections + all_detections:
        span_key = tuple(d["span"])
        if span_key not in merged or d["priority"] > merged[span_key]["priority"]:
            merged[span_key] = d
    
    return list(merged.values())
