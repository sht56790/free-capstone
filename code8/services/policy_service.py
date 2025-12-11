import re
from typing import List, Dict, Any, Tuple

from services.ner_service import run_ner

# Rule 타입 힌트를 위해 models.Rule 임포트 (순환 임포트 회피용 런타임 사용 최소화)
try:
    from models import Rule
except Exception:  # 타입 힌트 용도로만 사용
    class Rule:  # type: ignore
        regex: str
        name: str
        action: str


def luhn_ok(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def apply_patterns(text: str, rules: List[Rule]) -> Tuple[str, List[Dict[str, Any]]]:
    """사용자 입력 필터링용: block 액션은 ValueError 발생 (텍스트에서 가장 먼저 나타나는 첫 번째 차단 항목만 차단 사유로 사용)"""
    masked = text
    findings: List[Dict[str, Any]] = []
    priority = {"block": 0, "mask": 1, "generalize": 2}
    guard = re.compile(
        r"\[(PHONE|CARD|EMAIL|IP|JWT|UUID|MAC|ADDRESS|ACCOUNT|TOKEN|PASSPORT|DRIVER_LICENSE|CREDENTIAL|CUSTOMER_ID|NAME|DOB|REDACTED)\]"
    )
    
    # 패턴 이름을 라벨로 매핑하는 딕셔너리 (apply_patterns_for_output과 동일하게)
    name_to_label = {
        "계좌번호": "ACCOUNT",
        "고객번호": "CUSTOMER_ID",
        "전화번호": "PHONE",
        "고객명": "NAME",
        "주소": "ADDRESS",
        "생년월일": "DOB",
    }
    
    # 패턴 우선순위: 계좌번호, 고객번호 등이 생년월일보다 먼저 매칭되도록
    pattern_priority = {
        "계좌번호": 0,
        "고객번호": 1,
        "전화번호": 2,
        "생년월일": 10,  # 계좌번호보다 나중에 매칭
        "주소": 11,
    }
    
    def rule_sort_key(rule):
        # action 우선순위 (block > mask > generalize)
        action_priority = priority.get(getattr(rule, "action", ""), 3)
        # 패턴 이름별 우선순위
        name_priority = pattern_priority.get(getattr(rule, "name", ""), 100)
        return (action_priority, name_priority)

    # 계좌번호 패턴 (생년월일 오판정 방지용)
    account_patterns = [
        re.compile(r"\d{3}[-\s]?\d{3}[-\s]?\d{6}"),  # 3-3-6 형식
        re.compile(r"\d{4}[-\s]?\d{4}[-\s]?\d{4,6}"),  # 4-4-4/6 형식
        re.compile(r"\d{10,14}"),  # 연속 10~14자리
    ]
    
    # 텍스트에서 가장 먼저 나타나는 차단 항목 찾기
    first_block_match = None  # (position, pattern_name)
    
    for p in sorted(rules, key=rule_sort_key):
        if p.action != "block":
            continue  # block 액션만 확인
        
        # 생년월일은 차단 사유에서 완전히 제외 (마스킹만 적용)
        if p.name == "생년월일":
            continue  # 생년월일은 차단 목록에서 완전히 건너뛰기
        
        rx = re.compile(p.regex)
        matches = list(rx.finditer(masked))
        
        for m in matches:
            val = m.group(0)
            if guard.search(val):
                continue  # 이미 마스킹된 부분은 건너뛰기
            
            # 가장 먼저 나타나는 차단 항목 기록
            if first_block_match is None or m.start() < first_block_match[0]:
                first_block_match = (m.start(), p.name)
    
    # 가장 먼저 나타나는 차단 항목이 있으면 즉시 예외 발생
    if first_block_match:
        first_block_name = first_block_match[1]
        raise ValueError(first_block_name)
    
    # 차단 항목이 없으면 정상적으로 마스킹 진행
    for p in sorted(rules, key=rule_sort_key):
        rx = re.compile(p.regex)

        def _repl(m, pattern_name=p.name):
            val = m.group(0)
            if guard.search(val):
                return val

            # 생년월일 패턴인 경우 계좌번호 패턴과 겹치는지 확인
            should_skip_birthdate = False
            if pattern_name == "생년월일":
                wider_context = masked[max(0, m.start()-30):min(len(masked), m.end()+30)]
                
                if "계좌" in wider_context:
                    should_skip_birthdate = True
                else:
                    for acc_pattern in account_patterns:
                        if acc_pattern.search(wider_context):
                            if "생년월일" not in wider_context and "생년" not in wider_context:
                                should_skip_birthdate = True
                                break
                
                if should_skip_birthdate:
                    return val

            # 패턴 이름을 라벨로 변환 (일관성 유지)
            label = name_to_label.get(pattern_name, pattern_name.upper())
            findings.append({"name": label, "value": val, "action": p.action})

            rep = "[REDACTED]"
            return rep

        masked = rx.sub(_repl, masked)
    
    return masked, findings


def apply_patterns_for_output(text: str, rules: List[Rule]) -> Tuple[str, List[Dict[str, Any]]]:
    """어시스턴트 응답 마스킹용: block 액션도 마스킹 처리 (차단하지 않음)"""
    masked = text
    findings: List[Dict[str, Any]] = []
    priority = {"block": 0, "mask": 1, "generalize": 2}
    # 이미 마스킹된 부분을 감지하는 guard 패턴 (라벨 형식 및 REDACTED 포함)
    guard = re.compile(
        r"\[(PHONE|CARD|EMAIL|IP|JWT|UUID|MAC|ADDRESS|ACCOUNT|TOKEN|PASSPORT|DRIVER_LICENSE|CREDENTIAL|CUSTOMER_ID|NAME|DOB|REDACTED)\]"
    )
    
    # 패턴 이름을 라벨로 매핑하는 딕셔너리
    name_to_label = {
        "계좌번호": "ACCOUNT",
        "고객번호": "CUSTOMER_ID",
        "전화번호": "PHONE",
        "고객명": "NAME",
        "주소": "ADDRESS",
        "생년월일": "DOB",
    }

    for p in sorted(rules, key=lambda x: priority.get(x.action, 3)):
        rx = re.compile(p.regex)

        def _repl(m):
            val = m.group(0)
            if guard.search(val):
                return val

            # 패턴 이름을 라벨로 변환 (없으면 그대로 사용)
            label = name_to_label.get(p.name, p.name.upper())
            
            findings.append({"name": label, "value": val, "action": p.action})
            
            # block 액션이어도 마스킹 처리 (차단하지 않음)
            rep = f"[{label}]"
            return rep

        masked = rx.sub(_repl, masked)
    return masked, findings


def apply_patterns_for_output_excluding_summary(text: str, rules: List[Rule]) -> Tuple[str, List[Dict[str, Any]]]:
    """어시스턴트 응답 마스킹용: '입력 요약:' 섹션은 제외하고 마스킹"""
    # "입력 요약:" 섹션을 임시로 보호
    import re
    summary_pattern = re.compile(r"(입력 요약[:\s]+)(.*?)(?=\n|$)", re.MULTILINE)
    protected_parts = []
    protected_text = text
    summary_marker = "___INPUT_SUMMARY_PROTECTED_{}___"
    
    # "입력 요약:" 섹션을 임시 마커로 교체
    idx = 0
    for match in summary_pattern.finditer(text):
        protected_parts.append((idx, match.group(0)))
        protected_text = protected_text.replace(match.group(0), summary_marker.format(idx), 1)
        idx += 1
    
    # 나머지 부분에 대해 마스킹 적용
    masked, findings = apply_patterns_for_output(protected_text, rules)
    
    # 보호된 섹션을 원래대로 복원
    for idx, original in protected_parts:
        masked = masked.replace(summary_marker.format(idx), original)
    
    return masked, findings


def apply_ai_judgement(text: str, judgements: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
    if not judgements:
        return text, []
    out = []
    # block으로 차단하지 않을 레이블 목록 (일반적인 질문/내용은 차단하지 않음)
    non_blockable_labels = {"ETC", "ORG", "GENERAL", "QUESTION", "DOB"}  # DOB(생년월일)는 차단하지 않고 마스킹만
    
    for j in sorted(judgements, key=lambda x: x["span"][0], reverse=True):
        s, e = j["span"]
        val = text[s:e]
        act = j.get("action", "mask")
        label = (j.get("label", "SENSITIVE") or "").upper()
        
        # ETC, ORG, DOB 같은 레이블은 block으로 차단하지 않고 mask로 처리
        if act == "block" and label in non_blockable_labels:
            act = "mask"
            j["action"] = "mask"
        
        if act == "block":
            raise ValueError(f"모델 판정 차단: {label}")
        rep = j.get("replacement", f"[{label}]")
        text = text[:s] + rep + text[e:]
        out.append({"name": label, "value": val, "action": act})
    return text, list(reversed(out))


def detect_sensitive_with_ner(text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    NER 결과를 민감정보 후보 형태로 변환한다.
    - 현재는 PERSON/ORG 위주로 NAME/ORG로 매핑
    - 나중에 도메인 특화 레이블(예: COMPANY_SECRET 등) 추가 가능

    필터링 규칙:
    - PERSON: 한글 이름 패턴만 허용 (2~5자, 한글만)
    - ORG: 기관명 키워드 포함 또는 적절한 길이

    반환:
    - (필터링된 결과, 원본 NER 결과) 튜플
    - 원본 결과는 로그 분석/튜닝용으로 사용 가능
    """
    import re

    ents = run_ner(text)
    raw_ner_results = ents.copy() if ents else []  # 원본 보관
    
    if not ents:
        return [], raw_ner_results

    ner_label_to_sensitive = {
        "PERSON": "NAME",
        "ORG": "ORG",
    }

    # 한글 이름 패턴: 2~5자, 한글만 (성씨 체크는 별도)
    korean_name_pattern = re.compile(r"^[가-힣]{2,5}$")
    # 한국 성씨 목록 (주요 성씨만)
    korean_surnames = {
        "김",
        "이",
        "박",
        "최",
        "정",
        "강",
        "조",
        "윤",
        "장",
        "임",
        "한",
        "오",
        "서",
        "신",
        "권",
        "황",
        "안",
        "송",
        "류",
        "전",
        "홍",
        "고",
        "문",
        "양",
        "손",
        "배",
        "조",
        "백",
        "허",
        "유",
        "남",
        "심",
        "노",
        "정",
        "하",
        "곽",
        "성",
        "길",
        "주",
        "우",
        "진",
        "민",
        "지",
    }

    # 기관명 키워드
    org_keywords = {"은행", "회사", "기업", "그룹", "전자", "텔레콤", "증권", "보험", "금융", "증권"}

    out: List[Dict[str, Any]] = []
    for e in ents:
        raw_label = (e.get("label") or "").upper()
        mapped = ner_label_to_sensitive.get(raw_label)
        if not mapped:
            continue

        word = e.get("word", "").strip()

        # 토큰화로 인한 ## 제거
        word = word.replace("##", "")

        # PERSON 필터링: 한글 이름 패턴 위주로 허용 (조금 느슨하게)
        if mapped == "NAME":
            # 너무 짧으면 제외 (1글자는 거의 이름이 아님)
            if len(word) < 2:
                continue
            # 한글만 허용
            if not korean_name_pattern.match(word):
                continue
            # 첫 글자가 성씨이면 가산점, 아니면 일단은 허용 (나중에 더 조이기)
            # if word[0] not in korean_surnames:
            #     continue

        # ORG 필터링: 기관명 키워드 포함 또는 적절한 길이
        elif mapped == "ORG":
            # 너무 짧으면 제외
            if len(word) < 2:
                continue
            # 기관명 키워드가 없고 너무 길면 제외 (문장 조각일 가능성)
            if not any(kw in word for kw in org_keywords) and len(word) > 10:
                continue

        out.append(
            {
                "name": mapped,
                "value": word,
                "span": [int(e.get("start", 0)), int(e.get("end", 0))],
                "source": "ner",
                "confidence": float(e.get("score", 0.0)),
                "action": "mask",
            }
        )
    return out, raw_ner_results
