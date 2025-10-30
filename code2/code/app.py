import os
import re
import json
import time
import traceback
from typing import List, Dict, Any, Tuple
import requests
import re

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
import google.generativeai as genai
from werkzeug.utils import secure_filename
from typing import List, Dict, Any

# --- 모듈 임포트 ---
from database import db
from routes.admin import admin_bp
from models import User, Log, Rule

# Ollama 설정 (파일 상단 또는 설정 파일에서 관리)
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL_FOR_JUDGE = "qwen3:8b" # 사용할 모델 선택 (예: llama3:8b, qwen:14b)
OLLAMA_MODEL_FOR_REGEX = "qwen3:8b"

def judge_sensitive_with_ollama(text: str) -> List[Dict[str, Any]]:
    """Ollama를 사용하여 텍스트에서 민감 정보 구간을 찾습니다."""

    # Ollama 모델에 맞는 프롬프트 (튜닝 필요!)
    # format: "json" 옵션을 사용하므로, JSON 형식만 출력하도록 명확히 지시
    prompt = f"""다음 텍스트에서 이름, 주소, 특정 기관명, 이메일, 전화번호, 자격증명 또는 기타 잠재적으로 민감한 개인 정보 구간을 분석하세요.
찾은 내용을 담은 유효한 JSON 배열만 반환해야 합니다. 각 결과는 반드시 "span"(시작 및 끝 문자 인덱스 목록, 예: [10, 22]), "label"(예: NAME, ADDRESS, ORG, EMAIL, PHONE, ETC), "action"("mask" 또는 매우 민감하면 "block") 키를 가진 객체여야 합니다.
아무것도 찾지 못하면 빈 JSON 배열 []을 반환하세요. JSON 외의 설명이나 다른 텍스트는 절대 포함하지 마세요.

Text:
{text}

JSON Array:"""

    payload = {
        "model": OLLAMA_MODEL_FOR_JUDGE,
        "prompt": prompt,
        "format": "json", # Ollama에게 JSON 형식 출력을 강제!
        "stream": False,
        # "options": { "temperature": 0.3 } # 필요시 옵션 추가
    }

    try:
        # 타임아웃을 늘림 (로컬 모델은 느릴 수 있음)
        resp = requests.post(OLLAMA_API_URL, json=payload, timeout=30)
        resp.raise_for_status() # HTTP 오류 발생 시 예외 발생

        # Ollama가 format: "json" 모드에서 'response' 필드에 JSON 문자열을 반환
        response_data = resp.json()
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
             print(f"[judge_sensitive_with_ollama] JSON 파싱 오류: {json_err} - 응답: {json_str[:200]}...") # 오류 시 응답 일부 로깅
             arr = [] # 파싱 실패 시 빈 배열 반환

        out = []
        if isinstance(arr, list): # 최종 결과가 리스트인지 확인
            for j in arr:
                # 각 항목이 딕셔너리인지, 필요한 키가 있는지, 타입이 맞는지 검증
                if (isinstance(j, dict) and
                        "span" in j and isinstance(j["span"], list) and len(j["span"]) == 2 and
                        all(isinstance(x, int) for x in j["span"]) and
                        0 <= j["span"][0] < j["span"][1] <= len(text) and # span 범위 검증
                        "label" in j and isinstance(j["label"], str)):

                    out.append({
                        "span": j["span"],
                        "label": j["label"].upper(), # 라벨 대문자 통일
                        "action": "block" if j.get("action") == "block" else "mask" # action 기본값 'mask'
                    })
                else:
                     print(f"[judge_sensitive_with_ollama] 잘못된 형식의 결과 항목 건너뜀: {j}")

        return out

    # requests 오류 (연결 실패, 타임아웃 등) 또는 HTTP 오류 처리
    except requests.exceptions.RequestException as req_err:
        print(f"[judge_sensitive_with_ollama] Ollama API 요청 오류: {req_err}")
        traceback.print_exc() # 상세 오류 로깅
        return [] # 오류 시 빈 배열 반환
    # 그 외 예외 처리
    except Exception as e:
        print(f"[judge_sensitive_with_ollama] 예상치 못한 오류: {e}")
        traceback.print_exc()
        return []
    
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
        if 'user_id' not in session:
            return jsonify({"error": "로그인이 필요합니다.", "detail": "세션 만료"}), 401
        if not (hasattr(app, 'GMODEL') and app.GMODEL):
            return jsonify({"error": "AI 모델이 설정되지 않았습니다.", "detail": "서버 설정 오류"}), 503

        log_data = {} # 로그 데이터 초기화
        orig = ""     # 원본 프롬프트 초기화
        is_blocked = False
        block_reason = ""

        try:
            # --- 1 & 2. FormData 읽기 및 파일 처리 ---
            model_id = request.form.get("model", "gemini-1.5-flash")
            messages_json_string = request.form.get("messages", "[]")
            user_prompt_text = request.form.get("user_prompt_text", "").strip()
            uploaded_file = request.files.get('file')
            file_content = ""

            if uploaded_file and uploaded_file.filename:
                filename = secure_filename(uploaded_file.filename)
                print(f"Received file: {filename}")
                if filename.lower().endswith('.txt'):
                    try:
                        file_bytes = uploaded_file.read()
                        file_content = file_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        try: file_content = file_bytes.decode('cp949')
                        except: file_content = "[파일 인코딩 오류]"
                    print(f"Read {len(file_content)} chars from {filename}")
                else:
                    print(f"Skipping non-txt file: {filename}")
                    file_content = f"[{filename} 파일 내용은 처리되지 않음]"

            # --- 3. messages 파싱 및 최종 프롬프트 생성 ---
            messages: List[Dict[str, str]] = json.loads(messages_json_string)
            final_user_content = user_prompt_text
            if file_content:
                final_user_content = f"{user_prompt_text}\n\n--- 첨부 파일 내용 ---\n{file_content}".strip()

            if final_user_content:
                messages.append({"role": "user", "content": final_user_content})
            elif not messages:
                return jsonify({"error": "전송할 메시지가 없습니다."}), 400

            orig = final_user_content if final_user_content else "" # 로그용 원본 저장

            # --- 4. 필터링 및 LLM 호출 로직 (ValueError 처리 분리) ---
            last_user_idx = next((i for i in range(len(messages)-1, -1, -1) if messages[i]["role"]=="user"), None)
            if last_user_idx is None:
                return jsonify({"error": "사용자 메시지를 찾을 수 없음"}), 400
            content_to_filter = messages[last_user_idx].get("content", "")

            try: # <-- ValueError 발생 가능 구간 시작
                active_rules = Rule.query.filter_by(is_active=True).all()
                sanitized_1, fin_in = apply_patterns(content_to_filter, active_rules)
                judgements = judge_sensitive_with_ollama(sanitized_1)
                sanitized_2, fin_in_model = apply_ai_judgement(sanitized_1, judgements)
            except ValueError as e: # <-- 차단 처리
                is_blocked = True
                block_reason = str(e)
                log_data = { # 차단 로그 준비
                    "action": "block", "processed_prompt_for_llm": "BLOCKED", "llm_response": "N/A",
                    "detections_in": [{"name": block_reason, "value": "N/A", "action": "block"}], "detections_out": []
                }
                # 이 외 필드는 finally 블록에서 채움

            # --- 차단되지 않은 경우 LLM 호출 및 로그 준비 ---
            if not is_blocked:
                sanitized_messages = messages[:]
                sanitized_messages[last_user_idx] = {"role": "user", "content": sanitized_2}
                llm_resp = call_gemini_generate(model_id, sanitized_messages, app.GMODEL)
                sanitized_out, fin_out = apply_patterns(llm_resp, active_rules)

                log_data = { # 정상 로그 준비
                    "action": "mask", "processed_prompt_for_llm": sanitized_2, "llm_response": llm_resp,
                    "detections_in": fin_in + fin_in_model, "detections_out": fin_out
                }
                # 이 외 필드는 finally 블록에서 채움

        except json.JSONDecodeError: # messages 파싱 오류
            traceback.print_exc()
            return jsonify({"error": "잘못된 messages 형식"}), 400
        except Exception as e: # 그 외 모든 예외 처리 (파일 처리 오류 등)
            print(f"An error occurred BEFORE filtering/LLM call: {e}")
            traceback.print_exc()
            log_data = { # 오류 로그 준비
                "action": "error", "processed_prompt_for_llm": "ERROR", "llm_response": str(e),
                "detections_in": [], "detections_out": []
            }
            # 이 외 필드는 finally 블록에서 채움
            # 오류 발생 시에도 로그 저장 후 500 에러 반환
            try:
                log_data.update({ # 공통 로그 필드 추가
                    "user": session.get('user_id'), "user_prompt": orig
                })
                save_log_to_db(log_data)
            except Exception as db_e:
                print(f"!!! CRITICAL: Failed to save ERROR log to DB: {db_e}")
                traceback.print_exc()
            return jsonify({"error": "서버 내부 오류 발생", "detail": str(e)}), 500

        finally: # --- 정상, 차단, 오류 모든 경우에 로그 저장 시도 ---
            try:
                # log_data가 비어있지 않은 경우 (오류 없이 try 블록을 통과했거나, except 블록에서 설정됨)
                if log_data:
                    # 공통 로그 필드 (user, user_prompt) 추가
                    log_data.update({
                        "user": session.get('user_id'),
                        "user_prompt": orig # try 블록에서 설정된 orig 사용
                    })
                    save_log_to_db(log_data)
            except Exception as db_e:
                print(f"!!! CRITICAL: Failed to save log to DB in finally block: {db_e}")
                traceback.print_exc()

        # --- 최종 응답 반환 ---
        if is_blocked:
            return jsonify({"error": "민감정보가 포함되어 전송이 차단되었습니다.", "detail": block_reason}), 400
        else:
            # 정상 응답 반환 (log_data는 이미 위에서 설정됨)
            detected_names = [d.get('name', 'Unknown') for d in log_data.get("detections_in", [])]
            security_notice = None
            if detected_names:
                unique_names = ", ".join(sorted(list(set(detected_names))))
                security_notice = f"🛡️ 입력하신 내용 중 {unique_names} 항목이 마스킹 처리되었습니다."
            return jsonify({"content": sanitized_out, "notice": security_notice})
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

def apply_ai_judgement(text: str, judgements: List[Dict[str,Any]]) -> Tuple[str, List[Dict[str,Any]]]:
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

# Ollama를 사용해 자연어를 정규식으로 변환하는 함수
def generate_regex_from_ollama(description: str) -> str:
    """Ollama를 사용하여 자연어 설명으로부터 정규식을 생성합니다."""
    from flask import current_app # 함수 내에서 current_app 임포트

    # 모델이 로드되었는지 확인하는 로직 추가 (선택 사항)
    # if not hasattr(current_app, 'OLLAMA_AVAILABLE') or not current_app.OLLAMA_AVAILABLE:
    #    raise RuntimeError("Ollama 모델을 사용할 수 없습니다.")

    # Ollama 모델에 맞는 프롬프트 (튜닝 필요!)
    prompt = f"""당신은 Python 호환 정규식 작성 전문가입니다. 사용자의 설명을 유효한 단일 정규식 패턴으로 변환하는 것이 유일한 임무입니다.
오직 정규식 패턴만 출력하고 다른 설명, 백틱(`), 마크다운 또는 기타 텍스트는 절대 포함하지 마세요.

Description: '{description}'

Regex Pattern:"""

    payload = {
        "model": OLLAMA_MODEL_FOR_REGEX, # 정규식 생성용 모델
        "prompt": prompt,
        # "format": "json", # 정규식은 단순 텍스트이므로 JSON 포맷 불필요
        "stream": False,
        "options": { "temperature": 0.0 } # 정규식 생성은 창의성보다 정확성이 중요
    }

    try:
        resp = requests.post(OLLAMA_API_URL, json=payload, timeout=20) # 타임아웃 적절히 설정
        resp.raise_for_status()

        response_data = resp.json()
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

# ==================================================================
# 💎 서버 실행
# ==================================================================
if __name__ == '__main__':
    app = create_app()
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8081")), debug=True)