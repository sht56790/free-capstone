# app.py
import os, re, json
import google.generativeai as genai
import time
from typing import List, Dict, Any, Tuple
from flask import Flask, request, jsonify, render_template
from routes.admin import admin_bp
from flask_cors import CORS
from dotenv import load_dotenv
from flask import Flask
from flask_socketio import SocketIO

load_dotenv()
genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))

GMODEL = genai.GenerativeModel(
    "gemini-2.5-pro",
    system_instruction=(
        "You may receive text where personally identifiable information is replaced with "
        "placeholders like [PHONE], [EMAIL], [CARD], [ADDRESS], [JWT], [UUID], etc. "
        "Do NOT attempt to reconstruct hidden values. Answer using the available context. "
        "If the exact value is required to proceed, say so and explain what non-sensitive info you need instead."
    ),
)

# ── Flask ─────────────────────────────────────────────────────────────
app = Flask(__name__)
socketio = SocketIO(app) # 2. SocketIO 객체 생성
CORS(app, origins=["http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:8081", "http://127.0.0.1:8081", "null"])

app.register_blueprint(admin_bp)

@app.route("/")
def index():
    # templates 폴더 안에 있는 login.html 파일을 화면에 보여줍니다.
    return render_template("login.html")

@app.route("/admin")
def admin_page():
    # TODO: 실제 서비스에서는 세션 등을 확인해서
    # 관리자가 아닐 경우 로그인 페이지로 보내는 로직이 필요합니다.
    return render_template("admin.html")

@app.route("/chat")
def chat_page():
    return render_template("Chat Proxy.html")

# ── 패턴 로드 ─────────────────────────────────────────────────────────
PATTERNS: List[Dict[str, Any]] = json.load(open("patterns.json","r",encoding="utf-8"))["sensitive_patterns"]

def luhn_ok(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D","", s)]
    if not (13 <= len(digits) <= 19): return False
    total = 0; parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9: d -= 9
        total += d
    return total % 10 == 0

def apply_patterns(text: str) -> Tuple[str, List[Dict[str,Any]]]:
    """BLOCK -> MASK -> GENERALIZE 순서로 적용하고, 탐지내역을 반환"""
    masked = text
    findings: List[Dict[str,Any]] = []
    priority = {"block":0, "mask":1, "generalize":2}
    # 이미 마스킹된 토큰 방지용: 치환 토큰 패턴
    guard = re.compile(r"\[(PHONE|CARD|EMAIL|IP|JWT|UUID|MAC|ADDRESS|ACCOUNT|TOKEN|PASSPORT|DRIVER_LICENSE|CREDENTIAL)\]")

    for p in sorted(PATTERNS, key=lambda x: priority.get(x["action"], 3)):
        rx = re.compile(p["regex"])
        def _repl(m):
            val = m.group(0)
            # 재마스킹 방지
            if guard.search(val): return val
            # validator (예: Luhn)
            if p.get("validator") == "LUHN" and not luhn_ok(val):
                return val
            findings.append({"name": p["name"], "value": val, "action": p["action"]})
            if p["action"] == "block":
                # BLOCK은 즉시 예외
                raise ValueError(p.get("message", p["name"]))
            # 치환
            rep = p.get("replacement", "[REDACTED]")
            # 백참조(\1 등) 지원: 부분 문자열에 다시 정규식을 쓰면 느리니 group 치환만 처리
            try:
                # 간단치환: \1 등의 백참조가 없으면 그대로 반환
                if r"\1" not in rep and r"\2" not in rep:
                    return rep
                # 백참조가 있으면 원본 매치에만 적용
                return re.sub(rx, rep, val)
            except re.error:
                return rep
        masked = rx.sub(_repl, masked)
    return masked, findings

# ── 2단계(그레이존) 판정: Gemini에 묻기 ───────────────────────────────
# 실제 구현: Gemini API(서버측) 호출로 교체하세요. 여긴 데모 로직.
def judge_sensitive_with_gemini(text: str) -> List[Dict[str,Any]]:
    """
    Gemini에게 ‘JSON만’ 달라고 하고, 파싱 실패에 대비해 백업 파서도 사용.
    """
    prompt = f"""
다음 문장에 개인정보 위험이 있는 구간을 찾아 JSON 배열만 출력하세요.
형식 예시:
[{{"span":[10,22],"label":"NAME","action":"mask"}}]
라벨은 NAME, ADDRESS, ORG, EMAIL, PHONE, ETC 중 하나.
애매하면 action은 "mask", 확실히 유출 위험이면 "block".
문장:
{text}
JSON 외의 텍스트는 출력하지 마세요.
"""
    try:
        resp = GMODEL.generate_content(prompt)
        raw = (resp.text or "").strip()
        # JSON만 추출(실수로 텍스트가 섞일 경우 대비)
        m = re.search(r"\[\s*\{.*\}\s*\]", raw, re.S)
        arr = json.loads(m.group(0) if m else raw)
        # 형식 정규화
        out = []
        for j in arr:
            if not isinstance(j, dict): continue
            span = j.get("span")
            if not (isinstance(span, list) and len(span)==2 and all(isinstance(x,int) for x in span)):
                continue
            out.append({
                "span": span,
                "label": j.get("label","ETC"),
                "action": "block" if j.get("action")=="block" else "mask"
            })
        return out
    except Exception as e:
        print("[judge_sensitive_with_gemini] error:", e)
        return []

def apply_gemini_judgement(text: str, judgements: List[Dict[str,Any]]) -> Tuple[str, List[Dict[str,Any]]]:
    """Gemini 판정 결과대로 텍스트를 마스킹/차단"""
    if not judgements: return text, []
    out = []
    # span 치환은 뒤에서부터 적용(인덱스 안정)
    for j in sorted(judgements, key=lambda x: x["span"][0], reverse=True):
        s, e = j["span"]
        val = text[s:e]
        act = j.get("action","mask")
        if act == "block":
            raise ValueError(f"모델 판정 차단: {j.get('label','SENSITIVE')}")
        rep = j.get("replacement", f"[{j.get('label','SENSITIVE')}]")
        text = text[:s] + rep + text[e:]
        out.append({"name": j.get("label","SENSITIVE"), "value": val, "action": act})
    return text, list(reversed(out))

# ── Gemini 답변 생성(서버측) ───────────────────────────────────────────
def call_gemini_generate(model_id: str, messages: List[Dict[str, str]]) -> str:
    """
    전처리로 마스킹된 대화 히스토리를 모델에 전달해 실제 답변을 받는다.
    - history: 마지막 유저 발화 직전까지
    - send_message: 마지막 유저 발화(빈 문자열 금지)
    """
    # 1) 모델 객체 선택 (UI에서 받은 model_id가 없거나 기본이면 전역 GMODEL 사용)
    if model_id and model_id != "demo-local" and not model_id.lower().startswith("gpt-"):
        gmodel = genai.GenerativeModel(
            model_id,
            system_instruction=getattr(GMODEL, "_system_instruction", None)
        )
    else:
        # demo-local이나 gpt-*가 들어오면 데모 에코 유지 (원하면 여기서도 Gemini로 라우팅 가능)
        last = next((m for m in reversed(messages) if m["role"]=="user"), {"content":""})
        return f"입력 요약: {last['content'][:120]}"

    # 2) 마지막 유저 발화
    last_user_idx = next((i for i in range(len(messages)-1, -1, -1) if messages[i]["role"] == "user"), None)
    if last_user_idx is None:
        return "(no user message)"
    last_user = (messages[last_user_idx].get("content") or "").strip()
    if not last_user:
        return "(empty user message)"

    # 3) 과거 대화 → history로 (마지막 유저 이전까지만)
    history = []
    for m in messages[:last_user_idx]:
        role = "user" if m["role"] == "user" else "model"
        content = (m.get("content") or "").strip()
        if content:
            history.append({"role": role, "parts": [content]})

    # 4) 채팅 호출
    chat = gmodel.start_chat(history=history)
    resp = chat.send_message(last_user)

    return getattr(resp, "text", "") or "(empty response)"

@app.get("/admin/logs")
def get_logs():
    try:
        with open("logs.json", "r", encoding="utf-8") as f:
            logs = json.load(f)
        return jsonify(logs)
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify([])
        
# ── API ───────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"ok": True}

import time

#로그 저장을 위한 헬퍼 함수
def _save_log_entry(log_entry):
    """로그 항목 하나를 logs.json 파일에 추가합니다."""
    try:
        with open("logs.json", "r", encoding="utf-8") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    logs.append(log_entry)
    with open("logs.json", "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)
    
    # with 블록이 끝난 후, 독립적으로 신호를 보냅니다.
    socketio.emit('stats_updated', {'message': 'New log entry saved'})



        
@app.post("/login")
def login():
    data = request.get_json(force=True)
    user_id = data.get("id")
    password = data.get("password")

    try:
        with open("users.json", "r", encoding="utf-8") as f:
            users_data = json.load(f)
            users = users_data.get("users", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({"error": "사용자 데이터를 찾을 수 없습니다."}), 500

    for user in users:
        if user["id"] == user_id and user["password"] == password:
            return jsonify({"success": True, "role": user["role"]})

    return jsonify({"error": "로그인 정보가 올바르지 않습니다."}), 401

@app.post("/chat")
def chat():
    t0 = time.perf_counter()
    data = request.get_json(force=True)
    model_id = data.get("model", "gemini-2.5-pro")
    messages: List[Dict[str,str]] = data.get("messages", [])

    idx = next((i for i in range(len(messages)-1, -1, -1) if messages[i]["role"]=="user"), None)
    if idx is None: return jsonify({"error": "사용자 메시지가 없습니다."}), 400
    orig = messages[idx]["content"]
    
    # --- 1차 필터링 ---
    try:
        sanitized_1, fin_in = apply_patterns(orig)
    except ValueError as e:
        log_entry = {
            "timestamp": time.time(), "user": "temp_user@company.com", "user_prompt": orig,
            "action": "block", "pii": [str(e)], "processed_prompt_for_llm": "BLOCKED",
            "llm_response": "N/A", "detections_in": [{"name": str(e), "value": "N/A", "action": "block"}],
            "detections_out": []
        }
        _save_log_entry(log_entry)
        return jsonify({"error":"민감정보가 포함되어 전송이 차단되었습니다.","detail":str(e)}), 400
    
    t1 = time.perf_counter()

    # --- 2차(모델 판정) ---
    judgements = judge_sensitive_with_gemini(sanitized_1)
    try:
        sanitized_2, fin_in_model = apply_gemini_judgement(sanitized_1, judgements)
    except ValueError as e:
        # ▼▼▼▼▼ 여기가 핵심 수정 부분 ▼▼▼▼▼
        log_entry = {
            "timestamp": time.time(), "user": "temp_user@company.com", "user_prompt": orig,
            "action": "block", "pii": [str(e)], "processed_prompt_for_llm": "BLOCKED_BY_AI",
            "llm_response": "N/A", "detections_in": fin_in + [{"name": str(e), "value": "N/A", "action": "block"}],
            "detections_out": []
        }
        _save_log_entry(log_entry) # 2단계 차단 로그 저장
        # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
        return jsonify({"error":"민감정보가 포함되어 전송이 차단되었습니다.","detail":str(e)}), 400
    
    t2 = time.perf_counter()

    # --- 모델 호출, 출력 필터 등 ---
    sanitized_messages = messages[:]
    sanitized_messages[idx] = {"role":"user", "content": sanitized_2}
    llm_resp = call_gemini_generate(model_id, sanitized_messages)
    t3 = time.perf_counter()
    sanitized_out, fin_out = apply_patterns(llm_resp)
    t4 = time.perf_counter()

    # --- 성공 시 로그 저장 ---
    log_entry = {
        "timestamp": time.time(), "user": "temp_user@company.com", "user_prompt": orig,
        "action": "mask", "pii": [d['name'] for d in (fin_in + fin_in_model)],
        "processed_prompt_for_llm": sanitized_2, "llm_response": llm_resp,
        "detections_in": fin_in + fin_in_model, "detections_out": fin_out
    }
    _save_log_entry(log_entry)

    # 1. 마스킹된 항목들의 이름만 추출 (예: ['전화번호', '이메일'])
    detected_names = [d['name'] for d in (fin_in + fin_in_model)]

    # 2. 사용자에게 보여줄 안내 메시지 생성
    security_notice = None
    if detected_names:
        # 중복 제거 후 보기 좋게 합침 (예: "전화번호, 이메일")
        unique_names = ", ".join(sorted(list(set(detected_names))))
        security_notice = f"🛡️ 입력하신 내용 중 {unique_names} 항목이 마스킹 처리되었습니다."

    # 3. 최종 응답 데이터 구성 (기존 meta 대신 notice 전달)
    return jsonify({
        "content": sanitized_out,
        "notice": security_notice
    })

if __name__ == "__main__":
    app.run(host=os.getenv("HOST","0.0.0.0"), port=int(os.getenv("PORT","8081")), debug=True)
