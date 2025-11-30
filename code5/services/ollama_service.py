"""
Ollama 서비스 모듈
- 민감정보 판정 (judge_sensitive_with_ollama)
- 정규식 생성 (generate_regex_from_ollama)
- 캐싱 시스템 통합
"""
import re
import json
import traceback
from typing import List, Dict, Any, Optional
import requests
from .ollama_cache import get_cache

# Ollama 설정
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL_FOR_JUDGE = "qwen3:8b"
OLLAMA_MODEL_FOR_REGEX = "qwen3:8b"


def _post_ollama_generate(
    model: str,
    *,
    prompt: Optional[str] = None,
    messages: Optional[List[Dict[str, str]]] = None,
    as_json: bool,
    timeout: int = 30,
) -> Dict[str, Any]:
    """Ollama API 호출을 공통 처리한다."""
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


def judge_sensitive_with_ollama(text: str, model: str | None = None, use_cache: bool = True) -> List[Dict[str, Any]]:
    """Ollama를 사용하여 텍스트에서 민감 정보 구간을 찾습니다. (CoT + 가중치 시스템 적용)"""

    # 캐시 확인
    cache = get_cache()
    model_name = model or OLLAMA_MODEL_FOR_JUDGE
    
    if use_cache:
        cached_result = cache.get(text, model_name)
        if cached_result is not None:
            return cached_result
    
    # CoT + 가중치 + Zero-Shot 프롬프트 (완전 개선 버전)
    prompt = f"""=== ROLE ===
You are an expert Korean financial sensitive information detector.
Your mission: Find ANY information that could harm users if leaked, including types you've never seen before.

=== SENSITIVE INFORMATION DEFINITION ===
Information is SENSITIVE if it has ONE OR MORE of these characteristics:

1️⃣ IDENTIFIER (식별자)
   - Can uniquely identify a specific person
   - Examples: 주민번호, 여권번호, 면허번호, 사원번호
   - New types: ANY unique ID (VIP코드, 회원번호, 환자번호, etc.)

2️⃣ ACCESS CREDENTIAL (접근 자격증명)
   - Grants access to accounts/systems
   - Examples: 비밀번호, PIN, OTP, 인증번호
   - New types: ANY access code (시크릿코드, 보안토큰, 액세스키, etc.)

3️⃣ FINANCIAL INFORMATION (금융 정보)
   - Related to money or financial status
   - Examples: 계좌번호, 카드번호, 잔액, 연봉, 대출액
   - New types: ANY money-related number (투자금액, 보험금, 세금, etc.)

4️⃣ CONTACT/LOCATION (연락/위치)
   - Enables direct contact or reveals location
   - Examples: 전화번호, 이메일, 주소
   - New types: ANY contact method (팩스, SNS계정, GPS좌표, etc.)

5️⃣ ACTION COMMAND (행동 지시)
   - Instructs to execute financial transactions
   - Examples: "송금해주세요", "이체 실행", "출금 부탁"
   - New types: ANY transaction command

=== PRIORITY LEVELS ===
[P10-BLOCK] CRITICAL - Must block immediately:
• Strong IDENTIFIERS: 주민번호, 여권번호, 면허번호, 외국인등록번호
• ACCESS CREDENTIALS: 비밀번호, PIN, OTP, 인증번호, 시크릿코드, 보안토큰
• Financial ACCOUNTS: 계좌번호, 카드번호
• Reason: Can directly access accounts or uniquely identify person

[P9-BLOCK] HIGH - Must block:
• CONFIRMED RATES: "금리는 3.5%입니다" (creates legal commitment)
• TRANSACTION REQUESTS: "100만원 송금해주세요" (executes money transfer)
• Reason: Creates financial obligations or executes transactions

[P8-MASK] MEDIUM - Must mask:
• CONTACT INFO: 전화번호, 이메일, 팩스
• FINANCIAL AMOUNTS: 잔액, 연봉, 대출액, 급여
• Reason: Reveals wealth/debt or enables direct contact

[P7-MASK] LOW - Must mask:
• PERSONAL INFO: 이름, 주소, 직장명
• Reason: Identifies person but less critical than P10

[P0-IGNORE] Not sensitive:
• GENERAL QUESTIONS: "금리가 어떻게 되나요?" (just asking)
• PUBLIC INFO: "영업시간", "지점 위치"
• Reason: No harm if known

=== 5-STEP REASONING PROCESS ===
For EVERY piece of text, think step-by-step:

Step 1: IDENTIFY - What type of information is this?
Step 2: CATEGORIZE - Which of 5 characteristics (IDENTIFIER/CREDENTIAL/FINANCIAL/CONTACT/COMMAND)?
Step 3: CONTEXTUALIZE - Is this actual data or just general discussion?
Step 4: ASSESS RISK - What harm if leaked? Assign priority (P10/P9/P8/P7/P0)
Step 5: DECIDE - block/mask/ignore + create appropriate label

=== EXAMPLES (Known + Unknown types) ===

Example 1 - Known type:
Input: "홍길동 010-1234-5678"
Step 1: Name + phone number
Step 2: IDENTIFIER (name) + CONTACT (phone)
Step 3: Actual personal data present
Step 4: P7 (name) + P8 (phone) - moderate risk
Step 5: Mask both
Output: [{{"span":[0,3],"label":"NAME","action":"mask","priority":7}},{{"span":[4,17],"label":"PHONE","action":"mask","priority":8}}]

Example 2 - Known financial:
Input: "계좌번호 110-123-456789"
Step 1: Account number detected
Step 2: FINANCIAL + IDENTIFIER (bank account)
Step 3: Actual account number, not example
Step 4: P10 - can access money directly
Step 5: Block
Output: [{{"span":[5,20],"label":"ACCOUNT","action":"block","priority":10}}]

Example 3 - NEW type (never seen before):
Input: "VIP고객코드 GOLD-12345"
Step 1: "VIP고객코드" = VIP customer code (unknown type!)
Step 2: ACCESS CREDENTIAL (grants special access)
Step 3: Actual code value present
Step 4: P10 - can access VIP accounts
Step 5: Block + CREATE new label "VIP_CODE"
Output: [{{"span":[7,17],"label":"VIP_CODE","action":"block","priority":10}}]

Example 4 - NEW type:
Input: "시크릿코드 ABC123XYZ"
Step 1: "시크릿코드" = secret code
Step 2: ACCESS CREDENTIAL (like password)
Step 3: Actual secret value
Step 4: P10 - grants system access
Step 5: Block + CREATE "SECRET_CODE"
Output: [{{"span":[6,15],"label":"SECRET_CODE","action":"block","priority":10}}]

Example 5 - Context matters:
Input: "금리 조건이 궁금합니다"
Step 1: Question about interest rate
Step 2: No specific commitment
Step 3: General inquiry, not confirmed rate
Step 4: P0 - not sensitive (just asking)
Step 5: Ignore
Output: []

Example 6 - Confirmed vs inquiry:
Input: "이 상품의 금리는 3.5%로 확정됩니다"
Step 1: Confirmed interest rate
Step 2: FINANCIAL commitment
Step 3: Specific rate stated (not inquiry)
Step 4: P9 - creates legal obligation
Step 5: Block
Output: [{{"span":[8,22],"label":"FIXED_RATE","action":"block","priority":9}}]

=== CRITICAL RULES ===
1. IGNORE Placeholders and Templates:
   ✗ DO NOT flag placeholders: [ADDRESS], [ACCOUNT], [NAME], [PHONE], [REDACTED], etc.
   ✗ DO NOT flag template variables: angle brackets, curly braces, square brackets with UPPERCASE
   ✗ DO NOT flag documentation examples in brackets/braces
   ✓ ONLY flag actual sensitive data values
   
   Examples:
   • "[ADDRESS]하세요" → IGNORE (placeholder, not real address)
   • "[ACCOUNT] 확인 필요" → IGNORE (template marker)
   • "서울시 강남구 테헤란로 123" → FLAG (real address)
   • "계좌번호 110-123-456" → FLAG (real account number)

2. For UNKNOWN types:
   ✓ Analyze characteristics (IDENTIFIER? CREDENTIAL? FINANCIAL? CONTACT? COMMAND?)
   ✓ Assess risk: Could it harm users if leaked?
   ✓ CREATE descriptive English label (e.g., "VIP_CODE", "SECRET_CODE", "AUTH_TOKEN")
   ✓ Use conservative approach: When unsure, assume sensitive

3. Context is CRITICAL:
   ✓ "금리는 3.5%" = BLOCK (confirmed)
   ✓ "금리가 궁금해요" = IGNORE (inquiry)

4. Priority determines action:
   ✓ P10, P9 → block (critical/high)
   ✓ P8, P7 → mask (medium/low)
   ✓ P0-P6 → ignore

5. Be COMPREHENSIVE:
   ✓ Check ALL 5 characteristics for each text
   ✓ One text can match multiple characteristics
   ✓ Use highest priority if multiple match

=== YOUR TASK ===
Analyze this Korean financial text step-by-step:
Text: "{text}"

Think through all 5 steps carefully, then return ONLY the JSON array:
JSON:"""

    try:
        # prompt 방식 사용 (messages 대신)
        response_data = _post_ollama_generate(
            model_name,
            prompt=prompt,
            as_json=False,  # JSON 강제 비활성화
            timeout=30,
        )
        raw_response = response_data.get("response", "[]")
        json_str = raw_response.strip()

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
                # 스키마 검증: span, label, action 필수
                if not isinstance(j, dict):
                    print(f"[judge_sensitive_with_ollama] 객체가 아닌 항목 건너뜀: {j}")
                    continue
                
                # span 검증
                if "span" not in j or not isinstance(j["span"], list) or len(j["span"]) != 2:
                    print(f"[judge_sensitive_with_ollama] span 누락/잘못된 형식: {j}")
                    continue
                
                start, end = j["span"]
                if not (isinstance(start, int) and isinstance(end, int)):
                    print(f"[judge_sensitive_with_ollama] span이 정수가 아님: {j}")
                    continue
                
                if not (0 <= start < end <= len(text)):
                    print(f"[judge_sensitive_with_ollama] span 범위 오류 (start={start}, end={end}, text_len={len(text)}): {j}")
                    continue
                
                # label 검증
                if "label" not in j or not isinstance(j["label"], str):
                    print(f"[judge_sensitive_with_ollama] label 누락/잘못된 타입: {j}")
                    continue
                
                label = j["label"].upper()
                
                # priority 기반 action 재조정 (AI가 잘못 판단한 경우 보정)
                priority = j.get("priority", get_sensitivity_score(label))
                
                # 가중치 기반 자동 액션 결정
                if priority >= 9:
                    action = "block"  # 고위험: 차단
                elif priority >= 7:
                    action = "mask"   # 중위험: 마스킹
                else:
                    # 낮은 우선순위는 무시 (일반 질문 등)
                    print(f"[judge_sensitive_with_ollama] 낮은 우선순위({priority}) 무시: {j}")
                    continue
                
                # AI가 명시한 action이 있으면 우선 사용 (단, 검증 필요)
                ai_action = j.get("action", "")
                if ai_action in ["mask", "block"]:
                    # AI action이 priority와 맞는지 검증
                    if priority >= 9 and ai_action != "block":
                        print(f"[judge_sensitive_with_ollama] priority {priority}인데 action이 {ai_action} → block으로 보정")
                        action = "block"
                    elif priority < 9 and ai_action == "block":
                        print(f"[judge_sensitive_with_ollama] priority {priority}인데 action이 block → mask로 보정")
                        action = "mask"
                    else:
                        action = ai_action
                
                out.append({
                    "span": [start, end],
                    "label": label,
                    "action": action,
                    "priority": priority,
                    "confidence": j.get("confidence", 0.8)  # AI 신뢰도 (옵션)
                })
        else:
            print(f"[judge_sensitive_with_ollama] 응답이 배열이 아님: {type(arr)}")

        # 캐시에 저장
        if use_cache:
            cache.set(text, model_name, out)
        
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
        response_data = _post_ollama_generate(
            model or OLLAMA_MODEL_FOR_REGEX,
            prompt=prompt,
            as_json=False,
            timeout=20,
        )
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


def get_sensitivity_score(label: str) -> int:
    """라벨에 따른 민감도 점수 반환 (10=최고 위험)"""
    scores = {
        "SSN": 10,
        "주민번호": 10,
        "ACCOUNT": 10,
        "계좌번호": 10,
        "CARD": 10,
        "카드번호": 10,
        "FIXED_RATE": 9,
        "금리확정": 9,
        "TRANSACTION": 9,
        "거래요청": 9,
        "PHONE": 8,
        "전화번호": 8,
        "AMOUNT": 8,
        "금액": 8,
        "NAME": 7,
        "이름": 7,
        "ADDRESS": 7,
        "주소": 7,
    }
    return scores.get(label.upper(), 5)  # 기본값 5점


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

