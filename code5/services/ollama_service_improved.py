"""
개선된 Ollama 서비스 모듈
- 프롬프트 엔지니어링 강화
- 가중치 기반 중요도 조정
- Chain-of-Thought (CoT) 적용
- 자기 검증(Self-Verification) 추가
"""
import re
import json
import traceback
from typing import List, Dict, Any, Optional
import requests
from .ollama_cache import get_cache

OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL_FOR_JUDGE = "qwen3:8b"

# 민감정보 가중치 설정 (높을수록 중요)
SENSITIVITY_WEIGHTS = {
    "주민번호": 10,
    "계좌번호": 10,
    "카드번호": 10,
    "전화번호": 8,
    "이름": 7,
    "주소": 7,
    "금리확정": 9,
    "거래요청": 9,
    "일반질문": 1
}

def _post_ollama_generate(
    model: str,
    *,
    prompt: Optional[str] = None,
    messages: Optional[List[Dict[str, str]]] = None,
    as_json: bool,
    timeout: int = 30,
) -> Dict[str, Any]:
    """Ollama API 호출"""
    if prompt is None and messages is None:
        raise ValueError("prompt 또는 messages 중 하나는 제공되어야 합니다.")

    payload: Dict[str, Any] = {
        "model": model,
        "stream": False,
    }
    if messages is not None:
        payload["messages"] = messages
    else:
        payload["prompt"] = prompt

    if as_json:
        payload["format"] = "json"
    resp = requests.post(OLLAMA_API_URL, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def judge_sensitive_improved_v1(text: str, model: str | None = None, use_cache: bool = True) -> List[Dict[str, Any]]:
    """개선안 1: Chain-of-Thought (CoT) + 가중치 명시"""
    
    cache = get_cache()
    model_name = model or OLLAMA_MODEL_FOR_JUDGE
    cache_key = f"v1_{text}"
    
    if use_cache:
        cached_result = cache.get(cache_key, model_name)
        if cached_result is not None:
            return cached_result
    
    # CoT 프롬프트: 단계별 추론 유도
    prompt = f"""You are a sensitive information detector for Korean financial services.

PRIORITY LEVELS (10=highest):
- 주민번호(SSN): 10 → ALWAYS block
- 계좌번호(Account): 10 → ALWAYS block
- 카드번호(Card): 10 → ALWAYS block
- 금리확정(Fixed Rate): 9 → block
- 거래요청(Transaction): 9 → block
- 전화번호(Phone): 8 → mask
- 이름(Name): 7 → mask
- 주소(Address): 7 → mask

STEP-BY-STEP ANALYSIS:
1. Read the text carefully
2. Identify patterns matching above categories
3. Determine exact character positions (span)
4. Assign action (block for 9-10, mask for 7-8)
5. Return JSON array ONLY

EXAMPLES:
Input: "홍길동 010-1234-5678"
Step 1: Found name "홍길동" (position 0-3)
Step 2: Found phone "010-1234-5678" (position 4-17)
Output: [{{"span":[0,3],"label":"NAME","action":"mask","priority":7}},{{"span":[4,17],"label":"PHONE","action":"mask","priority":8}}]

Input: "계좌 123-456-789"
Step 1: Found account number (position 3-14)
Output: [{{"span":[3,14],"label":"ACCOUNT","action":"block","priority":10}}]

Input: "금리는 3.5%입니다"
Step 1: Found fixed rate statement (position 0-11)
Output: [{{"span":[0,11],"label":"FIXED_RATE","action":"block","priority":9}}]

NOW ANALYZE:
Input: {text}
Output JSON:"""

    try:
        response_data = _post_ollama_generate(
            model_name,
            prompt=prompt,
            as_json=False,
            timeout=40,  # CoT는 시간 더 필요
        )
        raw_response = response_data.get("response", "[]")
        
        # JSON 추출
        json_str = raw_response.strip()
        match = re.search(r"\[.*\]", json_str, re.DOTALL)
        json_str = match.group(0) if match else '[]'
        
        arr = json.loads(json_str)
        out = []
        
        for j in arr:
            if not isinstance(j, dict):
                continue
            
            # 기본 검증
            if "span" not in j or len(j["span"]) != 2:
                continue
            
            start, end = j["span"]
            if not (0 <= start < end <= len(text)):
                continue
            
            # priority 기반 action 재조정
            priority = j.get("priority", 5)
            if priority >= 9:
                action = "block"
            elif priority >= 7:
                action = "mask"
            else:
                continue  # 낮은 우선순위는 무시
            
            out.append({
                "span": [start, end],
                "label": j.get("label", "SENSITIVE").upper(),
                "action": action,
                "priority": priority,
                "confidence": j.get("confidence", 0.8)
            })
        
        if use_cache:
            cache.set(cache_key, model_name, out)
        
        return out
        
    except Exception as e:
        print(f"[judge_sensitive_improved_v1] 오류: {e}")
        traceback.print_exc()
        return []


def judge_sensitive_improved_v2(text: str, model: str | None = None, use_cache: bool = True) -> List[Dict[str, Any]]:
    """개선안 2: 자기 검증(Self-Verification) 2단계"""
    
    cache = get_cache()
    model_name = model or OLLAMA_MODEL_FOR_JUDGE
    cache_key = f"v2_{text}"
    
    if use_cache:
        cached_result = cache.get(cache_key, model_name)
        if cached_result is not None:
            return cached_result
    
    # 1단계: 초기 탐지
    prompt_detect = f"""Find ALL sensitive information in Korean text. Return JSON array.

Categories (Priority):
[P10-BLOCK] 주민번호, 계좌번호, 카드번호
[P9-BLOCK] 금리확정, 거래요청
[P8-MASK] 전화번호
[P7-MASK] 이름, 주소

Text: {text}
JSON:"""

    try:
        # 1단계: 탐지
        response1 = _post_ollama_generate(
            model_name,
            prompt=prompt_detect,
            as_json=False,
            timeout=30,
        )
        raw1 = response1.get("response", "[]")
        match = re.search(r"\[.*\]", raw1, re.DOTALL)
        json_str = match.group(0) if match else '[]'
        candidates = json.loads(json_str)
        
        if not candidates:
            return []
        
        # 2단계: 검증
        prompt_verify = f"""VERIFY these detections. Remove false positives.

Original Text: {text}
Detected Items: {json.dumps(candidates)}

Check each item:
1. Is the span position correct?
2. Is the label appropriate?
3. Is it really sensitive information?

Return ONLY valid items as JSON array:"""
        
        response2 = _post_ollama_generate(
            model_name,
            prompt=prompt_verify,
            as_json=False,
            timeout=30,
        )
        raw2 = response2.get("response", "[]")
        match2 = re.search(r"\[.*\]", raw2, re.DOTALL)
        json_str2 = match2.group(0) if match2 else '[]'
        verified = json.loads(json_str2)
        
        out = []
        for j in verified:
            if not isinstance(j, dict) or "span" not in j:
                continue
            
            start, end = j["span"]
            if not (0 <= start < end <= len(text)):
                continue
            
            out.append({
                "span": [start, end],
                "label": j.get("label", "SENSITIVE").upper(),
                "action": j.get("action", "mask"),
                "verified": True
            })
        
        if use_cache:
            cache.set(cache_key, model_name, out)
        
        return out
        
    except Exception as e:
        print(f"[judge_sensitive_improved_v2] 오류: {e}")
        traceback.print_exc()
        return []


def judge_sensitive_improved_v3(text: str, model: str | None = None, use_cache: bool = True) -> List[Dict[str, Any]]:
    """개선안 3: 강력한 Few-Shot + 부정 예제 추가"""
    
    cache = get_cache()
    model_name = model or OLLAMA_MODEL_FOR_JUDGE
    cache_key = f"v3_{text}"
    
    if use_cache:
        cached_result = cache.get(cache_key, model_name)
        if cached_result is not None:
            return cached_result
    
    prompt = f"""Detect sensitive info in Korean financial text. Return JSON array ONLY.

POSITIVE EXAMPLES (MUST DETECT):
Text: "홍길동 010-1234-5678"
→ [{{"span":[0,3],"label":"NAME","action":"mask"}},{{"span":[4,17],"label":"PHONE","action":"mask"}}]

Text: "계좌 110-123-456789"
→ [{{"span":[3,17],"label":"ACCOUNT","action":"block"}}]

Text: "금리는 3.5%입니다"
→ [{{"span":[0,11],"label":"FIXED_RATE","action":"block"}}]

Text: "송금해주세요"
→ [{{"span":[0,6],"label":"TRANSACTION","action":"block"}}]

Text: "주민번호 801225-1234567"
→ [{{"span":[5,20],"label":"SSN","action":"block"}}]

NEGATIVE EXAMPLES (DO NOT DETECT):
Text: "대출 상담 받고 싶습니다"
→ []

Text: "금리 조건이 궁금합니다"
→ []

Text: "영업시간이 어떻게 되나요"
→ []

CRITICAL RULES:
1. 주민번호(SSN): XXXXXX-XXXXXXX format → block
2. 계좌번호(ACCOUNT): XXX-XXX-XXXXXX format → block
3. 금리 + 숫자 + %: "금리는 X%" → block
4. "송금", "이체", "출금" + "해주세요" → block
5. 전화번호: 010-XXXX-XXXX → mask
6. 한글 이름: 2-4자 한글 + 사람 관련 문맥 → mask

NOW DETECT:
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
            
            label = j.get("label", "SENSITIVE").upper()
            action = j.get("action", "mask")
            
            # 라벨별 가중치 적용
            weight = SENSITIVITY_WEIGHTS.get(label, 5)
            if weight >= 9:
                action = "block"
            
            out.append({
                "span": [start, end],
                "label": label,
                "action": action,
                "weight": weight
            })
        
        if use_cache:
            cache.set(cache_key, model_name, out)
        
        return out
        
    except Exception as e:
        print(f"[judge_sensitive_improved_v3] 오류: {e}")
        traceback.print_exc()
        return []


def judge_sensitive_hybrid(text: str, model: str | None = None, use_cache: bool = True) -> List[Dict[str, Any]]:
    """하이브리드: 3가지 방법 모두 실행 후 투표(Voting)"""
    
    results = []
    
    # 3가지 방법 실행
    r1 = judge_sensitive_improved_v1(text, model, use_cache)
    r2 = judge_sensitive_improved_v2(text, model, use_cache)
    r3 = judge_sensitive_improved_v3(text, model, use_cache)
    
    # 모든 결과 병합
    all_detections = {}
    
    for detection in r1 + r2 + r3:
        span_key = tuple(detection["span"])
        if span_key not in all_detections:
            all_detections[span_key] = {
                "span": detection["span"],
                "labels": [],
                "actions": [],
                "votes": 0
            }
        all_detections[span_key]["labels"].append(detection["label"])
        all_detections[span_key]["actions"].append(detection["action"])
        all_detections[span_key]["votes"] += 1
    
    # 2표 이상 받은 것만 채택
    for span_key, data in all_detections.items():
        if data["votes"] >= 2:  # 3개 중 2개 이상 동의
            # 가장 많이 나온 라벨과 액션
            most_common_label = max(set(data["labels"]), key=data["labels"].count)
            most_common_action = max(set(data["actions"]), key=data["actions"].count)
            
            results.append({
                "span": data["span"],
                "label": most_common_label,
                "action": most_common_action,
                "confidence": data["votes"] / 3.0
            })
    
    return results
