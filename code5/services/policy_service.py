import re
from typing import List, Dict, Any, Tuple

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
    """사용자 입력 필터링용: block 액션은 ValueError 발생"""
    masked = text
    findings: List[Dict[str, Any]] = []
    priority = {"block": 0, "mask": 1, "generalize": 2}
    guard = re.compile(r"\[(PHONE|CARD|EMAIL|IP|JWT|UUID|MAC|ADDRESS|ACCOUNT|TOKEN|PASSPORT|DRIVER_LICENSE|CREDENTIAL|CUSTOMER_ID|NAME|REDACTED)\]")
    
    # 패턴 이름을 라벨로 매핑하는 딕셔너리 (apply_patterns_for_output과 동일하게)
    name_to_label = {
        "계좌번호": "ACCOUNT",
        "고객번호": "CUSTOMER_ID",
        "전화번호": "PHONE",
        "고객명": "NAME",
        "주소": "ADDRESS",
    }

    for p in sorted(rules, key=lambda x: priority.get(x.action, 3)):
        rx = re.compile(p.regex)

        def _repl(m):
            val = m.group(0)
            if guard.search(val):
                return val

            # 패턴 이름을 라벨로 변환 (일관성 유지)
            label = name_to_label.get(p.name, p.name.upper())
            findings.append({"name": label, "value": val, "action": p.action})
            if p.action == "block":
                raise ValueError(p.name)

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
    guard = re.compile(r"\[(PHONE|CARD|EMAIL|IP|JWT|UUID|MAC|ADDRESS|ACCOUNT|TOKEN|PASSPORT|DRIVER_LICENSE|CREDENTIAL|CUSTOMER_ID|NAME|REDACTED)\]")
    
    # 패턴 이름을 라벨로 매핑하는 딕셔너리
    name_to_label = {
        "계좌번호": "ACCOUNT",
        "고객번호": "CUSTOMER_ID",
        "전화번호": "PHONE",
        "고객명": "NAME",
        "주소": "ADDRESS",
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
    non_blockable_labels = {"ETC", "ORG", "GENERAL", "QUESTION"}
    
    for j in sorted(judgements, key=lambda x: x["span"][0], reverse=True):
        s, e = j["span"]
        val = text[s:e]
        act = j.get("action", "mask")
        label = (j.get("label", "SENSITIVE") or "").upper()
        
        # ETC, ORG 같은 일반 레이블은 block으로 차단하지 않고 mask로 처리
        if act == "block" and label in non_blockable_labels:
            act = "mask"
            j["action"] = "mask"
        
        if act == "block":
            raise ValueError(f"모델 판정 차단: {label}")
        rep = j.get("replacement", f"[{label}]")
        text = text[:s] + rep + text[e:]
        out.append({"name": label, "value": val, "action": act})
    return text, list(reversed(out))


