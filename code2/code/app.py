import os
import re
import json
import time
from typing import List, Dict, Any, Tuple

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
import google.generativeai as genai

# --- 모듈 임포트 ---
from database import db
from routes.admin import admin_bp
from models import User, Log, Rule

# ==================================================================
# 💎 앱 생성 및 초기화 (Application Factory)
# ==================================================================
def create_app():
    """Flask 앱을 생성하고 모든 설정을 마친 후 반환합니다."""
    
    load_dotenv()
    app = Flask(__name__)
    
    # --- 1. 기본 설정 ---
    app.secret_key = os.urandom(24)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    CORS(app, origins=["http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:8081", "http://127.0.0.1:8081", "null"])

    # --- 2. 확장 프로그램 초기화 ---
    db.init_app(app)

    # --- 3. 블루프린트 등록 ---
    app.register_blueprint(admin_bp)

    # --- 4. 전역 변수 설정 ---
    with app.app_context():
        genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
        app.GMODEL = genai.GenerativeModel(
            "gemini-2.5-pro",
            system_instruction=(
                "You may receive text where personally identifiable information is replaced with "
                "placeholders like [PHONE], [EMAIL], [CARD], [ADDRESS], [JWT], [UUID], etc. "
                "Do NOT attempt to reconstruct hidden values. Answer using the available context. "
                "If the exact value is required to proceed, say so and explain what non-sensitive info you need instead."
            )
        )

    # ==================================================================
    # 💎 라우트 및 핵심 로직 정의
    # ==================================================================
    
    # -- 기본 페이지 라우트 --
    @app.route("/")
    def index():
        return render_template("login.html")

    @app.route("/admin")
    def admin_page():
        return render_template("admin.html")

    @app.route("/chat")
    def chat_page():
            # 세션에 'user_id'가 없으면(로그인하지 않았으면)
            if 'user_id' not in session:
                # 로그인 페이지로 돌려보냅니다.
                return redirect(url_for('index'))
        
            # 로그인한 경우에만 채팅 페이지를 보여줍니다.
            return render_template("Chat Proxy.html")

    # -- 상태 확인 API --
    @app.get("/health")
    def health():
        return {"ok": True}
        
    # -- 로그인 API (데이터베이스 사용) --
    @app.post("/login")
    def login():
        data = request.get_json(force=True)
        user_id = data.get("id")
        password = data.get("password")

        user_in_db = User.query.get(user_id)
        
        if user_in_db and user_in_db.password == password:
            session['user_id'] = user_in_db.id
            session['role'] = user_in_db.role
            return jsonify({"success": True, "role": user_in_db.role})
        
        return jsonify({"error": "로그인 정보가 올바르지 않습니다."}), 401

    @app.post("/chat")
    def chat():
        data = request.get_json(force=True)
        model_id = data.get("model", "gemini-2.5-pro")
        messages: List[Dict[str,str]] = data.get("messages", [])

        idx = next((i for i in range(len(messages)-1, -1, -1) if messages[i]["role"]=="user"), None)
        if idx is None: return jsonify({"error": "사용자 메시지가 없습니다."}), 400
        orig = messages[idx]["content"]
    
        try:
            # 🚀 [변경] DB에서 활성화된 규칙을 모두 가져옵니다.
            active_rules = Rule.query.filter_by(is_active=True).all()
        
            # 1차 필터링 (DB에서 가져온 규칙 사용)
            sanitized_1, fin_in = apply_patterns(orig, active_rules)
        
            # 2차 필터링
            judgements = judge_sensitive_with_gemini(sanitized_1, app.GMODEL)
            sanitized_2, fin_in_model = apply_gemini_judgement(sanitized_1, judgements)

            # 모델 호출
            sanitized_messages = messages[:]
            sanitized_messages[idx] = {"role":"user", "content": sanitized_2}
            llm_resp = call_gemini_generate(model_id, sanitized_messages, app.GMODEL)

            # 출력 필터링 (DB에서 가져온 규칙 사용)
            sanitized_out, fin_out = apply_patterns(llm_resp, active_rules)

            # 로그 저장
            log_data = {
                "user": session.get('user_id'), "user_prompt": orig,
                "action": "mask",
                "processed_prompt_for_llm": sanitized_2, "llm_response": llm_resp,
                "detections_in": fin_in + fin_in_model, "detections_out": fin_out
            }
            save_log_to_db(log_data)

            detected_names = [d['name'] for d in (fin_in + fin_in_model)]
            security_notice = None
            if detected_names:
                unique_names = ", ".join(sorted(list(set(detected_names))))
                security_notice = f"🛡️ 입력하신 내용 중 {unique_names} 항목이 마스킹 처리되었습니다."

            return jsonify({"content": sanitized_out, "notice": security_notice})

        except ValueError as e:
            log_data = {
                "user": session.get('user_id'), "user_prompt": orig,
                "action": "block",
                "processed_prompt_for_llm": "BLOCKED", "llm_response": "N/A",
                "detections_in": [{"name": str(e), "value": "N/A", "action": "block"}],
                "detections_out": []
            }
            save_log_to_db(log_data)
            return jsonify({"error":"민감정보가 포함되어 전송이 차단되었습니다.","detail":str(e)}), 400
    # ==================================================================
    # 💎 DB 생성을 위한 커스텀 명령어 추가
    # ==================================================================
    @app.cli.command("init-db")
    def init_db_command():
        """데이터베이스 테이블을 초기화하고 기본 데이터(사용자, 규칙)를 생성합니다."""
        db.create_all()

        # --- 기본 사용자 생성 ---
        if not User.query.get('admin@company.com'):
            print("Creating default admin account...")
            admin = User(id='admin@company.com', password='admin_password', role='admin')
            db.session.add(admin)
        if not User.query.get('user@company.com'):
            print("Creating default user account...")
            user = User(id='user@company.com', password='user_password', role='user')
            db.session.add(user)
    
        # 기본 규칙 생성 (patterns.json -> DB)
        if Rule.query.first() is None:
            print("Migrating initial rules from patterns.json to database...")
            try:
                with open("patterns.json", "r", encoding="utf-8") as f:
                    patterns_data = json.load(f).get("sensitive_patterns", [])
                    for p in patterns_data:
                        new_rule = Rule(
                            name=p.get("name"),
                            regex=p.get("regex"),
                            action=p.get("action", "mask"),
                            is_active=True 
                        )
                        db.session.add(new_rule)
                print(f"Successfully migrated {len(patterns_data)} rules.")
            except FileNotFoundError:
                print("Warning: patterns.json not found. No initial rules were migrated.")

        db.session.commit()
        print("Database initialized!")

    return app

# ==================================================================
# 💎 헬퍼 함수 (Helper Functions)
# ==================================================================

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

def apply_patterns(text: str, rules: List[Rule]) -> Tuple[str, List[Dict[str,Any]]]:
    masked = text
    findings: List[Dict[str,Any]] = []
    priority = {"block":0, "mask":1, "generalize":2}
    guard = re.compile(r"\[(PHONE|CARD|EMAIL|IP|JWT|UUID|MAC|ADDRESS|ACCOUNT|TOKEN|PASSPORT|DRIVER_LICENSE|CREDENTIAL)\]")

    # 딕셔너리 대신 Rule 객체의 속성(action)을 기준으로 정렬
    for p in sorted(rules, key=lambda x: priority.get(x.action, 3)):
        # 딕셔너리 키 접근(p['...'])을 객체 속성 접근(p....)으로 변경
        rx = re.compile(p.regex)
        def _repl(m):
            val = m.group(0)
            if guard.search(val): return val
            
            # (LUHN 검증 로직은 현재 모델에 없으므로 일단 제거)
            
            findings.append({"name": p.name, "value": val, "action": p.action})
            if p.action == "block":
                raise ValueError(p.name) # 룰 이름으로 에러 메시지
            
            # replacement 로직은 현재 모델에 없으므로 기본값 사용
            rep = "[REDACTED]" 
            
            return rep
        masked = rx.sub(_repl, masked)
    return masked, findings

def judge_sensitive_with_gemini(text: str, gmodel) -> List[Dict[str,Any]]:
    prompt = f"다음 문장에 개인정보 위험이 있는 구간을 찾아 JSON 배열만 출력하세요.\n형식 예시:\n[{{\"span\":[10,22],\"label\":\"NAME\",\"action\":\"mask\"}}]\n라벨은 NAME, ADDRESS, ORG, EMAIL, PHONE, ETC 중 하나.\n애매하면 action은 \"mask\", 확실히 유출 위험이면 \"block\".\n문장:\n{text}\nJSON 외의 텍스트는 출력하지 마세요."
    try:
        resp = gmodel.generate_content(prompt)
        raw = (resp.text or "").strip()
        m = re.search(r"\[\s*\{.*\}\s*\]", raw, re.S)
        arr = json.loads(m.group(0) if m else raw)
        out = []
        for j in arr:
            if not isinstance(j, dict): continue
            span = j.get("span")
            if not (isinstance(span, list) and len(span)==2 and all(isinstance(x,int) for x in span)):
                continue
            out.append({"span": span, "label": j.get("label","ETC"), "action": "block" if j.get("action")=="block" else "mask"})
        return out
    except Exception as e:
        print(f"[judge_sensitive_with_gemini] error: {e}")
        return []

def apply_gemini_judgement(text: str, judgements: List[Dict[str,Any]]) -> Tuple[str, List[Dict[str,Any]]]:
    if not judgements: return text, []
    out = []
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

def call_gemini_generate(model_id: str, messages: List[Dict[str, str]], gmodel) -> str:
    if not (model_id and model_id != "demo-local" and not model_id.lower().startswith("gpt-")):
        last = next((m for m in reversed(messages) if m["role"]=="user"), {"content":""})
        return f"입력 요약: {last['content'][:120]}"

    last_user_idx = next((i for i in range(len(messages)-1, -1, -1) if messages[i]["role"] == "user"), None)
    if last_user_idx is None: return "(no user message)"
    
    last_user = (messages[last_user_idx].get("content") or "").strip()
    if not last_user: return "(empty user message)"

    history = []
    for m in messages[:last_user_idx]:
        role = "user" if m["role"] == "user" else "model"
        content = (m.get("content") or "").strip()
        if content:
            history.append({"role": role, "parts": [content]})

    chat_session = gmodel.start_chat(history=history)
    resp = chat_session.send_message(last_user)
    return getattr(resp, "text", "") or "(empty response)"

def save_log_to_db(log_data: Dict[str, Any]):
    """로그 데이터를 받아 Log 객체를 생성하고 DB에 저장합니다."""
    
    # User 모델과 연결하기 위해 user 객체를 찾습니다.
    # 세션에 user_id가 없으면 user는 None이 됩니다.
    user = User.query.get(log_data.get("user"))

    new_log = Log(
        user=user, # user_id 대신 user 객체 자체를 전달
        user_prompt=log_data.get("user_prompt"),
        processed_prompt=log_data.get("processed_prompt_for_llm"),
        llm_response=log_data.get("llm_response"),
        action=log_data.get("action"),
        detections_in=log_data.get("detections_in"),
        detections_out=log_data.get("detections_out")
    )
    db.session.add(new_log)
    db.session.commit()

# Gemini를 사용해 자연어를 정규식으로 변환하는 함수
def generate_regex_from_description(description: str) -> str:
    """Gemini AI에게 자연어 설명을 보내 정규식 패턴을 생성하도록 요청합니다."""
    
    # app 객체는 create_app() 함수 스코프 안에 있으므로, 현재 요청 컨텍스트에서 가져옵니다.
    from flask import current_app
    
    prompt = (
        "You are a world-class expert in writing Python-compatible regular expressions. "
        "Your sole task is to convert the user's description into a single, valid regex pattern. "
        "Output ONLY the regex pattern and nothing else. Do not add explanations, backticks (`), "
        "or any other surrounding text or markdown formatting.\n\n"
        f"Description: '{description}'"
    )
    
    # current_app을 통해 GMODEL에 접근합니다.
    gmodel = current_app.GMODEL
    response = gmodel.generate_content(prompt)
    
    # AI 응답에서 정규식 패턴만 깔끔하게 추출합니다.
    regex_pattern = response.text.strip()
    
    # 혹시 모를 따옴표나 마크다운(`) 제거
    if regex_pattern.startswith('`') and regex_pattern.endswith('`'):
        regex_pattern = regex_pattern.strip('`')
        
    return regex_pattern

# ==================================================================
# 💎 서버 실행
# ==================================================================
if __name__ == '__main__':
    app = create_app()
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8081")), debug=True)