import os
import time
import traceback
import json
import re
from datetime import datetime
from typing import List, Dict, Any
from types import SimpleNamespace

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
import google.generativeai as genai
from werkzeug.utils import secure_filename

# --- 모듈 임포트 ---
from database import db
from routes.admin import admin_bp
from models import User, Log, Rule
from services.ollama_service import judge_sensitive_with_ollama, _post_ollama_generate
from services.policy_service import apply_patterns, apply_patterns_for_output_excluding_summary, apply_ai_judgement
from services.rag_service import retrieve_context
from services.realtime_service import detect_and_fetch_realtime_info
from services.search_service import search_and_format
from services.web_scraping_service import smart_scrape

ORIGINAL_GEMINI_SYSTEM_INSTRUCTION = ""
    
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
        api_key = os.environ.get("GOOGLE_API_KEY")
        global ORIGINAL_GEMINI_SYSTEM_INSTRUCTION
        if api_key:
            genai.configure(api_key=api_key)
            system_instr_str = (
                    "당신은 '금융회사 직원 전용 업무 보조 AI'입니다. 답변 대상은 '직원'이며, 직원이 고객에게 안내할 수 있도록 작성합니다.\n\n"
                    
                    "🔍 **핵심 원칙: 가능한 모든 근거를 활용하되, 없으면 일반 지식으로 보완하세요**\n"
                    "시스템이 [실시간 정보], [웹 검색 결과], [검색된 내부 참고 자료] 등을 제공하면 우선적으로 활용하고, 관련 근거가 전혀 없는 주제라도 일반 지식을 기반으로 최선의 답변을 제시하세요. 단, 일반 지식일 경우 '일반 지식 기반'임을 명시하고 과도한 추측은 피하세요.\n\n"
                    
                    "예시:\n"
                    "  • [실시간 정보] 코스피: 2,500포인트 (+1.2%)\n"
                    "    → 답변: '현재 코스피 지수는 2,500포인트로 전일 대비 1.2% 상승했습니다 (실시간 조회)'\n"
                    "  • 내부 참고 없음, 개발 질문\n"
                    "    → 답변: 'printf문은 C 언어에서 형식화된 출력에 사용하는 함수입니다 (일반 지식 기반)'\n\n"
                    
                    "📋 **답변 형식**\n"
                    "## 답변\n"
                    "- 입력 요약: [사용자 질문 요약]\n"
                    "- 고객 응대 멘트: [핵심 답변 1~3문장 - 제공된 근거 또는 일반 지식 기반]\n"
                    "- 참고 정보: [추가 정보, 출처, 확인 방법]\n"
                    "- 내부 체크리스트: [직원 확인 항목]\n\n"
                    "## 근거 출처\n"
                    "- [문서명/정보 출처 없으면 '일반 지식 기반']\n\n"
                    "## 다음 단계\n"
                    "- [후속 조치]\n\n"
                    
                    "🔒 **보안 원칙**\n"
                    "- 계좌번호, 고객번호, 전화번호 등 민감정보는 마스킹 유지\n"
                    "- 금리/수수료는 확정 금액 대신 범위로 안내 (예: '약 3,000~8,000원')\n"
                    "- 실제 거래 실행 금지, 절차 안내만 제공\n"
                )
            ORIGINAL_GEMINI_SYSTEM_INSTRUCTION = system_instr_str
            app.GMODEL = genai.GenerativeModel(
                "gemini-2.0-flash",
                system_instruction=system_instr_str,
                generation_config={
                    "temperature": 0.3,
                    "top_p": 0.8,
                    "top_k": 40,
                }
            )
        else:
            app.GMODEL = None
            ORIGINAL_GEMINI_SYSTEM_INSTRUCTION = ""

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
            # 마지막 로그인 시간 업데이트
            user_in_db.last_login = datetime.utcnow()
            db.session.commit()
            
            session['user_id'] = user_in_db.id
            session['role'] = user_in_db.role
            return jsonify({"success": True, "role": user_in_db.role})
        
        return jsonify({"error": "로그인 정보가 올바르지 않습니다."}), 401

    @app.post("/chat")
    def chat():
        if 'user_id' not in session:
            return jsonify({"error": "로그인이 필요합니다.", "detail": "세션 만료"}), 401
        model_id = request.form.get("model", "gemini-1.5-flash")
        # Gemini 모델이 필요한 경우에만 GMODEL 확인 (로컬 모드 'demo-local'은 예외)
        # Gemini 필요 조건: Ollama 선택이 아니고 demo가 아닐 때만 GMODEL 확인
        if model_id != "demo-local" and not model_id.startswith("ollama:") and not (hasattr(app, 'GMODEL') and app.GMODEL):
            return jsonify({"error": "AI 모델이 설정되지 않았습니다.", "detail": "서버 설정 오류"}), 503

        log_data = {} # 로그 데이터 초기화
        orig = ""     # 원본 프롬프트 초기화
        is_blocked = False
        block_reason = ""
        context = ""

        try:
            # --- 1 & 2. FormData 읽기 및 파일 처리 ---
            # model_id는 상단에서 이미 읽음
            messages_json_string = request.form.get("messages", "[]")
            user_prompt_text = request.form.get("user_prompt_text", "").strip()
            uploaded_file = request.files.get('file')
            file_content = ""

            if uploaded_file and uploaded_file.filename:
                filename = secure_filename(uploaded_file.filename)
                
                # 확장자 추출 (대소문자 무시, 점이 없으면 빈 문자열)
                if '.' in filename:
                    file_ext = filename.lower().rsplit('.', 1)[-1]
                else:
                    file_ext = ''
                
                # 지원하는 파일 형식 확인
                if file_ext == 'txt':
                    # 텍스트 파일 처리
                    try:
                        file_bytes = uploaded_file.read()
                        file_content = file_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        try: 
                            file_content = file_bytes.decode('cp949')
                        except: 
                            file_content = "[파일 인코딩 오류]"
                
                elif file_ext == 'pdf':
                    # PDF 파일 처리
                    try:
                        from pypdf import PdfReader
                        from io import BytesIO
                        
                        pdf_bytes = uploaded_file.read()
                        pdf_file = BytesIO(pdf_bytes)
                        reader = PdfReader(pdf_file)
                        
                        # 모든 페이지에서 텍스트 추출
                        pdf_text = []
                        for i, page in enumerate(reader.pages):
                            page_text = page.extract_text()
                            if page_text.strip():
                                pdf_text.append(f"--- Page {i+1} ---\n{page_text}")
                        
                        file_content = "\n\n".join(pdf_text) if pdf_text else "[PDF에서 텍스트를 추출할 수 없습니다]"
                    except Exception as e:
                        file_content = f"[PDF 파일 처리 오류: {str(e)}]"
                        
                else:
                    # 지원하지 않는 파일 형식
                    return jsonify({
                        "error": "지원하지 않는 파일 형식입니다.",
                        "detail": f"현재 .txt, .pdf 파일만 지원합니다. (업로드된 파일: {filename})"
                    }), 400

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
                # 직원 보조 모드: 입력 단계에서 계좌/전화번호는 차단 대신 마스킹으로 완화
                staff_mode = True  # 세션/환경에 따라 조정 가능: bool(session.get('user_id'))
                if staff_mode:
                    softened: List[Rule] = []
                    for r in active_rules:
                        if getattr(r, 'name', '') in ("계좌번호", "전화번호", "고객번호") and getattr(r, 'action', '') == 'block':
                            softened.append(SimpleNamespace(name=r.name, regex=r.regex, action='mask', is_active=True))
                        else:
                            softened.append(r)
                    active_rules = softened
                sanitized_1, fin_in = apply_patterns(content_to_filter, active_rules)
                judgements = judge_sensitive_with_ollama(sanitized_1)
                # 라벨 보정: 문맥 기반 재분류 및 패턴 매칭 결과와 비교
                if judgements:
                    ctx = content_to_filter
                    # 정규식 패턴에서 이미 탐지된 라벨 목록 (fin_in)
                    pattern_labels = {f.get("name", "").upper() for f in fin_in}
                    
                    for j in judgements:
                        lbl = (j.get("label") or "").upper()
                        s, e = j.get("span", [0, 0])
                        detected_text = ctx[s:e] if s < e else ""
                        
                        # 1) '고객번호' 키워드가 있으면 고객번호로 재분류
                        if "고객번호" in ctx:
                            j["label"] = "CUSTOMER_ID"
                            continue
                        
                        # 2) 정규식 패턴에서 이미 ACCOUNT로 탐지된 경우, PHONE 오판정 보정
                        if "ACCOUNT" in pattern_labels and lbl == "PHONE":
                            # 계좌번호 형식 체크: 3-3-6, 4-4-4/6, 10~14자리 연속 숫자
                            account_pattern = re.compile(
                                r"\d{3}[-\s]?\d{3}[-\s]?\d{6}"
                                r"|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4,6}"
                                r"|\d{10,14}"
                            )
                            if account_pattern.search(detected_text):
                                j["label"] = "ACCOUNT"
                                continue
                        
                        # 3) '계좌', '이체', '적금', '송금' 문맥에서 PHONE 오판정을 ACCOUNT로 보정
                        if any(keyword in ctx for keyword in ["계좌", "이체", "적금", "송금", "입금", "출금"]):
                            if lbl == "PHONE":
                                # 전화번호 형식이 아닌 경우 (계좌번호 형식일 가능성)
                                # 전화번호는 0으로 시작하고 10~11자리
                                phone_pattern = re.compile(r"0\d{1,2}[-\\s]?\d{3,4}[-\\s]?\d{4}|0\d{9,10}")
                                if not phone_pattern.search(detected_text):
                                    # 계좌번호 형식인지 확인 (3-3-6, 4-4-4/6, 10~14자리)
                                    account_pattern = re.compile(
                                        r"\d{3}[-\s]?\d{3}[-\s]?\d{6}"
                                        r"|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4,6}"
                                        r"|\d{10,14}"
                                    )
                                    if account_pattern.search(detected_text):
                                        j["label"] = "ACCOUNT"
                # 직원 보조 모드: Ollama 판정에서 block → mask로 완화
                if staff_mode:
                    for j in judgements:
                        if j.get("action") == "block":
                            j["action"] = "mask"
                sanitized_2, fin_in_model = apply_ai_judgement(sanitized_1, judgements)
                
                # RAG: 유사 문서 검색 (내부 금융 매뉴얼)
                # 원본 텍스트로 검색 (마스킹된 텍스트는 검색 정확도가 떨어짐)
                context = retrieve_context(orig)
                
                # 1순위: Google Custom Search (API 키 있는 경우)
                search_results = search_and_format(orig)
                if search_results:
                    print(f"[SEARCH] Google 검색 결과 추가")
                    context = f"{search_results}\n\n{context}" if context else search_results
                else:
                    # 2순위: 웹 스크래핑 (완전 무료)
                    scraped_info = smart_scrape(orig)
                    if scraped_info:
                        print(f"[WEB SCRAPE] 스크래핑 정보 추가")
                        context = f"{scraped_info}\n\n{context}" if context else scraped_info
                    else:
                        # 3순위: 특정 API (yfinance, OpenWeather 등)
                        realtime_info = detect_and_fetch_realtime_info(orig)
                        if realtime_info:
                            print(f"[REALTIME API] 실시간 API 정보 추가")
                            context = f"{realtime_info}\n\n{context}" if context else realtime_info
            except ValueError as e: # <-- 차단 처리
                is_blocked = True
                block_reason = str(e)
                log_data = { # 차단 로그 준비
                    "action": "block", "processed_prompt_for_llm": "BLOCKED", "llm_response": "N/A",
                    "detections_in": [{"name": block_reason, "value": "N/A", "action": "block"}], "detections_out": []
                }
                # 이 외 필드는 finally 블록에서 채움

            # --- 차단되지 않은 경우 LLM 호출 및 로그 준비 ---
            model_used = "unknown"  # 실제 사용된 모델 추적
            if not is_blocked:
                sanitized_messages = messages[:]
                sanitized_messages[last_user_idx] = {"role": "user", "content": sanitized_2}
                # 모델 라우팅: ollama:* 은 Ollama로, 그 외는 기존 로직
                if model_id.startswith("ollama:"):
                    model_used = model_id  # Ollama 모델 사용
                    final_system_instruction = (
                        "당신은 '금융회사 직원 보조용' AI 어시스턴트입니다.\n\n"
                        "- 금융 질문: 아래 [검색된 참고 자료]를 우선 참조하여 답변하세요. 자료에 없으면 일반 지식으로 답변 가능합니다.\n"
                        "- 일반 질문(날씨, 시간 등): 간결하게 답변하세요.\n\n"
                        "금융 질문은 템플릿(## 답변, ## 근거 출처, ## 다음 단계)을 사용하되, 일반 질문은 자유 형식으로 답변하세요.\n\n"
                        "--- [검색된 참고 자료] ---\n"
                        f"{context}\n"
                        "--------------------------\n"
                    )
                    llm_resp = call_ollama_generate(
                        model_id,
                        sanitized_messages,
                        system_instruction=final_system_instruction
                    )
                else:
                    if model_id == "demo-local":
                        model_used = "demo-local (fallback)"
                        llm_resp = call_gemini_generate(model_id, sanitized_messages, app.GMODEL, context=context)
                    else:
                        if not ORIGINAL_GEMINI_SYSTEM_INSTRUCTION:
                            return jsonify({"error": "Gemini 모델 지침이 설정되지 않았습니다.", "detail": "서버 설정 오류"}), 503
                        
                        # 지원되는 Gemini 텍스트 모델 목록
                        supported_gemini_models = [
                            "gemini-2.0-flash",
                            "gemini-2.0-flash-lite",
                        ]
                        
                        # 사용자가 선택한 모델이 지원되는지 확인, 아니면 기본값 사용
                        if model_id in supported_gemini_models:
                            gemini_model_name = model_id
                        else:
                            gemini_model_name = "gemini-2.0-flash"  # 기본값
                        
                        model_used = gemini_model_name
                        # 디버깅: 컨텍스트 내용 출력
                        print(f"[CONTEXT] Gemini에게 전달되는 컨텍스트 (처음 500자):\n{context[:500] if context else '(없음)'}")
                        final_system_instruction = (
                            ORIGINAL_GEMINI_SYSTEM_INSTRUCTION
                            + "\n\n[검색된 내부 참고 자료]:\n"
                            + context
                        )
                        gmodel_with_rag = genai.GenerativeModel(
                            gemini_model_name,
                            system_instruction=final_system_instruction,
                            generation_config={
                                "temperature": 0.3,
                                "top_p": 0.8,
                                "top_k": 40,
                            }
                        )
                        llm_resp = call_gemini_generate(model_id, sanitized_messages, gmodel_with_rag, context=context)
                llm_resp = format_counselor_response(llm_resp, orig)
                # 어시스턴트 응답은 block 액션도 마스킹 처리 (차단하지 않음)
                # 단, "입력 요약:" 뒤의 내용은 이미 마스킹되어 있으므로 제외
                sanitized_out, fin_out = apply_patterns_for_output_excluding_summary(llm_resp, active_rules)
                # 주소 보조 마스킹 (룰 누락 대비)
                sanitized_out = _mask_addresses(sanitized_out)
                # LLM이 본문을 반복 출력하는 경우가 있어, 연속 중복 줄 제거
                sanitized_out = _remove_consecutive_duplicate_lines(sanitized_out)
                # 입력 요약 이후에 LLM이 생성한 반복 내용 제거
                sanitized_out = _remove_post_summary_duplicates(sanitized_out)
                # 마스킹 줄과 원문 숫자 줄이 함께 있을 때, 원문 줄 제거
                sanitized_out = _dedupe_masked_vs_raw_lines(sanitized_out)
                # 불필요한 PII 안내성 문장 제거
                sanitized_out = _remove_pii_hint_lines(sanitized_out)
                # 요약 이후 동일/유사 문장 최종 중복 제거
                sanitized_out = _dedupe_after_summary_strict(sanitized_out)
                # 요약 라인이 손실된 경우 복원
                sanitized_out = _ensure_masked_summary(sanitized_out, orig)

                log_data = { # 정상 로그 준비
                    "action": "mask", "processed_prompt_for_llm": sanitized_2, "llm_response": llm_resp,
                    "detections_in": fin_in + fin_in_model, "detections_out": fin_out
                }
                # 이 외 필드는 finally 블록에서 채움

        except json.JSONDecodeError: # messages 파싱 오류
            traceback.print_exc()
            return jsonify({"error": "잘못된 messages 형식"}), 400
        except Exception as e: # 그 외 모든 예외 처리 (파일 처리 오류 등)
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
                traceback.print_exc()

        # --- 최종 응답 반환 ---
        if is_blocked:
            # 차단 사유를 사용자 친화적인 메시지로 변환
            block_reason_kr = {
                "계좌번호": "계좌번호",
                "고객번호": "고객번호",
                "전화번호": "전화번호",
                "주소": "주소",
                "ACCOUNT": "계좌번호",
                "CUSTOMER_ID": "고객번호",
                "PHONE": "전화번호",
                "ADDRESS": "주소",
            }.get(block_reason, block_reason)
            
            # 차단 메시지 구성
            error_message = "요청하신 내용에 민감정보가 포함되어 있어 전송이 차단되었습니다."
            detail_message = f"차단된 항목: {block_reason_kr}\n\n"
            detail_message += "다음과 같은 정보는 보안상의 이유로 전송할 수 없습니다:\n"
            detail_message += "• 계좌번호, 고객번호\n"
            detail_message += "• 전화번호, 주소\n"
            detail_message += "• 개인 식별 정보\n\n"
            detail_message += "상담이 필요하신 경우 영업점을 방문하시거나 상담원 연결을 요청해주세요."
            
            return jsonify({"error": error_message, "detail": detail_message}), 400
        else:
            # 정상 응답 반환 (log_data는 이미 위에서 설정됨)
            # 한국어 표기용 라벨 맵 (영문 라벨 및 패턴 이름 모두 포함)
            _label_name = {
                "ACCOUNT": "계좌번호",
                "CUSTOMER_ID": "고객번호",
                "PHONE": "전화번호",
                "NAME": "고객명",
                "ADDRESS": "주소",
                # 패턴 이름도 매핑 (이미 한글이면 그대로 사용)
                "계좌번호": "계좌번호",
                "고객번호": "고객번호",
                "전화번호": "전화번호",
                "고객명": "고객명",
                "주소": "주소",
            }
            detected_names = []
            # 입력/출력 모두의 탐지 항목을 합쳐서 안내 문구에 사용
            all_detections = (log_data.get("detections_in", []) or []) + (log_data.get("detections_out", []) or [])
            for d in all_detections:
                name = str(d.get('name', 'Unknown'))
                # 대소문자 구분 없이 매핑
                mapped_name = _label_name.get(name.upper()) or _label_name.get(name) or name
                detected_names.append(mapped_name)
            security_notice = None
            if detected_names:
                unique_names = ", ".join(sorted(list(set(detected_names))))
                security_notice = f"🛡️ 입력하신 내용 중 {unique_names} 항목이 마스킹 처리되었습니다."
            
            return jsonify({"content": sanitized_out, "notice": security_notice, "model_used": model_used})
    # ==================================================================
    # 💎 DB 생성을 위한 커스텀 명령어 추가
    # ==================================================================
    @app.cli.command("init-db")
    def init_db_command():
        """데이터베이스 테이블을 초기화하고 기본 데이터(사용자)를 생성합니다."""
        db.create_all()

        # --- 기본 사용자 생성 ---
        if not User.query.get('admin@company.com'):
            admin = User(id='admin@company.com', password='admin_password', role='admin')
            db.session.add(admin)
        if not User.query.get('user@company.com'):
            user = User(id='user@company.com', password='user_password', role='user')
            db.session.add(user)

        db.session.commit()

    return app

# ==================================================================
# 💎 헬퍼 함수 (Helper Functions)
# ==================================================================

def call_gemini_generate(
    model_id: str,
    messages: List[Dict[str, str]],
    gmodel,
    *,
    context: str | None = None
) -> str:
    if not (model_id and model_id != "demo-local" and not model_id.lower().startswith("gpt-")):
        last = next((m for m in reversed(messages) if m["role"]=="user"), {"content":""})
        original_summary_source = (last.get("content") or "")
        masked_summary = create_masked_summary(original_summary_source)
        summary = masked_summary[:120] if masked_summary else ""
        return (
            "## 답변\n"
            f"- 입력 요약: {summary}\n"
            "- 고객 응대 멘트: 안내는 영업점 방문 또는 상담원 연결로 진행됩니다. 필요한 경우 연결을 도와드리겠습니다.\n"
            "- 참고 정보: 관련 일반 정보는 내부 매뉴얼 또는 상담원을 통해 확인 가능합니다.\n"
            "- 내부 체크리스트: 관련 약관/상품 설명서 레퍼런스 확인 → 절차만 안내\n\n"
            "## 근거 출처\n- (출처 기입)\n\n"
            "## 다음 단계\n- (다음 조치 제안)"
        )

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

    print(f"[Gemini API] 호출 시작 - 모델: {gmodel.model_name if hasattr(gmodel, 'model_name') else 'unknown'}")
    chat_session = gmodel.start_chat(history=history)
    resp = chat_session.send_message(
        last_user + "\n\n(위 지침의 고정 템플릿을 반드시 사용하세요)"
    )
    result_text = getattr(resp, "text", "") or ""
    print(f"[Gemini API] 응답 수신 완료 (길이: {len(result_text)} 문자)")
    normalized = result_text.strip()
    if (not normalized) or normalized.lower() in {"(empty response)", "empty response"}:
        masked_last_user = create_masked_summary(last_user)
        fallback_summary_raw = masked_last_user if masked_last_user else last_user
        fallback_summary = (fallback_summary_raw[:120] + ("…" if len(fallback_summary_raw) > 120 else "")).replace("\n", " ")
        context_hint = ""
        if context:
            context_line = " ".join(context.strip().splitlines()[:3])
            if context_line:
                context_hint = f" (참고 자료 요약: {context_line[:120]}{'…' if len(context_line) > 120 else ''})"
        return (
            "## 답변\n"
            f"- 입력 요약: {fallback_summary}\n"
            "- 고객 응대 멘트: 내부 매뉴얼을 근거로 정기예금 해지 절차와 대출 심사 단계, 수수료 범위 안내 멘트를 정리해 고객에게 전달하세요.\n"
            "- 참고 정보: 상세한 내용은 내부 매뉴얼 또는 상담원을 통해 확인해주세요.\n"
            "- 내부 체크리스트: 필요한 서류 확인 → 상담 이력 기록 → 면책 문구 포함 안내\n\n"
            "## 근거 출처\n"
            f"- 자동 응답 보정{context_hint}\n"
            "- Gemini 응답 미수신: API 키 또는 안전성 필터 상태 점검\n\n"
            "## 다음 단계\n"
            "- Gemini 응답이 빈 값일 경우 서버 로그, API 키, 모델 설정을 점검하고 다시 시도하세요."
        )
    return result_text

def call_ollama_generate(
    model_id: str,
    messages: List[Dict[str, str]],
    system_instruction: str | None = None
) -> str:
    """Ollama 텍스트 생성. model_id 형식: 'ollama:<model_name>'"""
    model = model_id.split(":", 1)[1] if ":" in model_id else model_id
    ollama_messages: List[Dict[str, str]] = []

    if system_instruction:
        ollama_messages.append({"role": "system", "content": system_instruction})

    for m in messages:
        role = m.get("role", "")
        if role == "system":
            # 이미 시스템 메시지가 포함되어 있다면 유지
            mapped_role = "system"
        elif role == "assistant":
            mapped_role = "assistant"
        else:
            mapped_role = "user"
        content = (m.get("content") or "").strip()
        if content:
            ollama_messages.append({"role": mapped_role, "content": content})

    if not any(msg.get("role") == "user" for msg in ollama_messages):
        return "(no user message)"

    try:
        data = _post_ollama_generate(
            model=model,
            messages=ollama_messages,
            as_json=False,
            timeout=60
        )
        return data.get("response", "") or "(empty response)"
    except Exception as e:
        return f"(ollama error: {e})"

def save_log_to_db(log_data: Dict[str, Any]):
    user = User.query.get(log_data.get("user"))
    new_log = Log(
        user=user,
        user_prompt=log_data.get("user_prompt"),
        processed_prompt=log_data.get("processed_prompt_for_llm"),
        llm_response=log_data.get("llm_response"),
        action=log_data.get("action"),
        detections_in=log_data.get("detections_in"),
        detections_out=log_data.get("detections_out"),
    )
    db.session.add(new_log)
    db.session.commit()


def _validate_no_hallucination(text: str, user_input: str) -> str:
    """Gemini 응답 검증 (Google Search 사용 시에는 실시간 정보 허용)"""
    # Google Search를 사용하면 실시간 정보가 정확하므로 검증 완화
    # 단, 출처가 명시되지 않은 경우에만 경고
    
    if "(출처:" in text or "Google 검색" in text or "검색 결과" in text:
        # 출처가 명시되어 있으면 검증 통과
        print("✅ [SEARCH GROUNDING] 검색 기반 답변 확인됨")
        return text
    
    # 출처 없이 실시간 정보를 제공하는 경우 경고만 출력 (차단하지 않음)
    realtime_keywords = ["날씨", "기온", "온도", "시간", "몇 시", "주가", "코스피", "환율"]
    is_realtime_question = any(keyword in user_input for keyword in realtime_keywords)
    
    if is_realtime_question:
        print("⚠️ [INFO] 실시간 정보 질문이지만 출처가 명시되지 않음 (Google Search 미사용 가능성)")
    
    return text

def format_counselor_response(text: str, original_input: str = "") -> str:
    """응답을 '직원 보조형' 고정 템플릿으로 정규화하고 입력 요약 부분을 마스킹합니다."""
    # 환각 감지 및 수정
    t = _validate_no_hallucination(text, original_input)
    t = (t or "").strip()
    # 섹션 제목이 없으면 템플릿으로 감싼다
    if "## 답변" not in t:
        t = (
            "## 답변\n" + t + "\n\n" +
            "## 근거 출처\n- (출처 기입)\n\n" +
            "## 다음 단계\n- (다음 조치 제안)"
        )
    
    # 입력 요약 처리
    if original_input:
        masked_summary = create_masked_summary(original_input)
        
        if "입력 요약" in t:
            # LLM이 입력 요약을 생성한 경우: 마스킹된 버전으로 교체
            pattern = r"(입력 요약[:\s]+)(.*?)(?=\n|$)"
            def replacer(match):
                prefix = match.group(1)
                # LLM이 만든 요약 내용을 무시하고, 마스킹된 원본 요약으로 교체
                return prefix + masked_summary
            t = re.sub(pattern, replacer, t, flags=re.MULTILINE)
        else:
            # LLM이 입력 요약을 생성하지 않은 경우: "## 답변" 섹션 시작 부분에 자동 추가
            # "## 답변" 다음 줄에 "입력 요약:" 추가
            t = re.sub(
                r"(##\s*답변\s*\n)",
                r"\1- 입력 요약: " + masked_summary + "\n",
                t,
                flags=re.IGNORECASE
            )
    
        # 입력 요약 뒤에 필수 라인 보강
        if "고객 응대 멘트:" not in t:
            t = re.sub(
                r"(입력 요약[:\s].*?\n)",
                r"\1- 고객 응대 멘트: (직원이 그대로 읽어줄 멘트를 작성하세요)\n",
                t,
                count=1
            )
        if "참고 정보:" not in t:
            t = re.sub(
                r"(고객 응대 멘트[:\s].*?\n)",
                r"\1- 참고 정보: (관련 일반 정보 또는 확인 방법 안내)\n",
                t,
                count=1
            )
        if "내부 체크리스트:" not in t:
            t = re.sub(
                r"(참고 정보[:\s].*?\n)",
                r"\1- 내부 체크리스트: (직원이 확인할 항목 1~3개를 제시하세요)\n",
                t,
                count=1
            )

    return t


def _remove_consecutive_duplicate_lines(text: str) -> str:
    """연속으로 같은 내용이 반복되는 줄을 제거합니다 (LLM 에코 중복 완화)."""
    if not text:
        return text
    lines = text.splitlines()
    out = []
    prev = None
    for line in lines:
        if prev is not None and line.strip() == prev.strip():
            # 같은 줄이 연속으로 나오면 스킵
            continue
        out.append(line)
        prev = line
    return "\n".join(out)


def _dedupe_masked_vs_raw_lines(text: str) -> str:
    """같은 내용이 [ACCOUNT]/[PHONE]/[CUSTOMER_ID]로 마스킹된 줄과 원문 숫자 줄로 중복될 때,
    원문 숫자 줄을 제거합니다."""
    if not text:
        return text
    lines = text.splitlines()
    seen_normalized = set()
    out_lines = []
    # 민감 패턴 (간단 휴리스틱): 계좌형 3-3-6 | 4-4-4/6 | 연속 10~14자리, 전화번호 0으로 시작 10~11자리, 고객번호 6~12자리
    account_rx = re.compile(
        r"\d{3}[-\s]?\d{3}[-\s]?\d{6}"
        r"|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4,6}"
        r"|(?<!0)\d{10,14}"
    )
    phone_rx = re.compile(r"0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{4}|0\d{9,10}")
    customer_rx = re.compile(r"(?:고객번호|고객\s*번호)[:은는\s]*\d{6,12}|\d{6,12}(?=\s*(?:고객|님|분))")

    def normalize(s: str) -> str:
        s2 = account_rx.sub("[ACCOUNT]", s)
        s2 = phone_rx.sub("[PHONE]", s2)
        s2 = customer_rx.sub("[CUSTOMER_ID]", s2)
        # [REDACTED]를 포괄 토큰으로 통일
        s2 = s2.replace("[REDACTED]", "[PII]")
        s2 = s2.replace("[ACCOUNT]", "[PII]").replace("[PHONE]", "[PII]").replace("[CUSTOMER_ID]", "[PII]")
        s2 = re.sub(r"\s+", " ", s2).strip().lower()
        return s2

    for line in lines:
        norm = normalize(line)
        contains_raw = ("[ACCOUNT]" not in line and account_rx.search(line)) or \
                      ("[PHONE]" not in line and phone_rx.search(line)) or \
                      ("[CUSTOMER_ID]" not in line and customer_rx.search(line))
        if norm in seen_normalized and contains_raw:
            # 이미 동일 의미의 마스킹 라인이 존재하고, 현재 줄은 원문 숫자를 포함 → 제거
            continue
        out_lines.append(line)
        seen_normalized.add(norm)
    return "\n".join(out_lines)


def _remove_post_summary_duplicates(text: str) -> str:
    """입력 요약 이후에 LLM이 생성한 반복 내용을 제거합니다."""
    if not text or "입력 요약" not in text:
        return text
    
    lines = text.splitlines()
    summary_end_idx = -1
    # "입력 요약:" 섹션의 끝을 찾기
    for i, line in enumerate(lines):
        if "입력 요약" in line:
            # 입력 요약 줄 다음부터 확인
            summary_end_idx = i + 1
            break
    
    if summary_end_idx < 0:
        return text
    
    # 입력 요약 이후의 내용
    summary_text = " ".join(lines[:summary_end_idx]).lower()
    # 한글, 영문, 숫자 모두 포함
    summary_words = set(re.findall(r'[가-힣a-zA-Z0-9]+', summary_text))
    
    out_lines = []
    for i, line in enumerate(lines):
        if i < summary_end_idx:
            # 입력 요약 이전/요약 자체는 그대로 유지
            out_lines.append(line)
            continue
        
        # 입력 요약 이후 줄: 요약과 너무 유사하면 제거
        line_lower = line.lower()
        line_words = set(re.findall(r'[가-힣a-zA-Z0-9]+', line_lower))
        
        # 요약과 단어 겹침 비율이 높으면 중복으로 간주
        if line_words and summary_words:
            overlap_ratio = len(line_words & summary_words) / len(line_words)
            # 70% 이상 겹치고, 민감정보가 원문으로 노출되면 제거
            if overlap_ratio > 0.7 and any(rx.search(line) for rx in [
                re.compile(
                    r"\d{3}[-\s]?\d{3}[-\s]?\d{6}"
                    r"|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4,6}"
                    r"|(?<!0)\d{10,14}"
                ),
                re.compile(r"0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{4}|0\d{9,10}"),
                re.compile(r"(?:고객번호|고객\s*번호)[:은는\s]*\d{6,12}|\d{6,12}(?=\s*(?:고객|님|분))")
            ]):
                continue
        
        out_lines.append(line)
    
    return "\n".join(out_lines)

def _dedupe_after_summary_strict(text: str) -> str:
    """입력 요약 이후 구간에서 동일/유사 문장을 강제 중복 제거합니다.
    - 소문자 변환, 공백 정규화, 숫자 일반화, 마스킹 토큰 동일 처리
    """
    if not text or "입력 요약" not in text:
        return text
    lines = text.splitlines()
    # 입력 요약 줄 다음부터 적용
    start = 0
    for i, line in enumerate(lines):
        if "입력 요약" in line:
            start = i + 1
            break
    seen: set[str] = set()
    out = []
    def norm(s: str) -> str:
        s = s.lower()
        # 숫자는 모두 0으로 일반화 (동일 문장 숫자만 달라 중복되는 경우 방지)
        s = re.sub(r"\d+", "0", s)
        # 다양한 마스킹 토큰을 하나의 토큰으로 통일
        s = s.replace("[redacted]", "[pii]")
        s = s.replace("[account]", "[pii]").replace("[phone]", "[pii]").replace("[customer_id]", "[pii]")
        # 특수문자 → 공백, 다중 공백 축소
        s = re.sub(r"[^가-힣a-z0-9\[\]]+", " ", s)
        s = re.sub(r"\s+", " ", s).strip()
        return s
    for idx, line in enumerate(lines):
        if idx < start:
            out.append(line)
            continue
        key = norm(line)
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        out.append(line)
    return "\n".join(out)

def _mask_addresses(text: str) -> str:
    """일반적인 한국 주소 표현을 [ADDRESS]로 마스킹 (룰 실패 시 보조용)."""
    if not text:
        return text
    patterns = [
        # 시/구/동 + 로/길 + 번지
        re.compile(r"(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|제주)\s*[가-힣]*\s*(?:시|도|군|구)?\s*[가-힣0-9\- ]*(?:로|길)\s*\d+(?:-\d+)*(?:\s*번지)?", re.IGNORECASE),
        # '시 구 동' 스타일 주소
        re.compile(r"[가-힣]{2,10}시\s*[가-힣]{1,10}구\s*[가-힣0-9\- ]{1,20}\d+(?:-\d+)*", re.IGNORECASE),
    ]
    out = text
    for rx in patterns:
        out = rx.sub("[ADDRESS]", out)
    return out

def _remove_pii_hint_lines(text: str) -> str:
    """PII 토큰과 서비스 제공 동사가 함께 있는 중복/안내성 문장을 제거합니다.
    패턴 기반으로 일반화되어 다양한 프롬프트에 적용 가능합니다."""
    if not text:
        return text
    lines = text.splitlines()
    out = []
    pii_token = re.compile(r"\[(?:ACCOUNT|PHONE|CUSTOMER_ID|ADDRESS|REDACTED)\]")
    # 서비스 제공 동사 패턴 (하드코딩 최소화, 패턴 기반)
    # "~해드리다", "~드릴게요", "확인", "연락", "도와드리다" 등 일반적인 서비스 동사
    service_verb_pattern = re.compile(r"(해\s*드리|드릴\s*게요|확인|연락|도와\s*드리|안내|알려\s*드리|알려\s*줄|조치|처리)\w*")
    # 번호/정보 확인 관련 명사 패턴 (PII 토큰과 함께 나올 때 중복 가능성 높음)
    info_confirm_pattern = re.compile(r"(번호|정보|내용|항목|데이터|자료)\s*(확인|조회|안내|제공|알려)")
    
    for line in lines:
        tokens = pii_token.findall(line)
        token_count = len(tokens)
        if token_count == 0:
            # PII 토큰이 없으면 통과
            out.append(line)
            continue
        
        # 일반 단어 추출 (마스킹 토큰, 서비스 동사 제외)
        words = re.findall(r"[가-힣a-zA-Z0-9]+", line)
        # PII 토큰을 제외한 실제 의미 단어 수
        meaningful_words = [w for w in words if not any(tok.lower() in w.lower() for tok in ["account", "phone", "customer", "address", "redacted"])]
        
        has_service_verb = bool(service_verb_pattern.search(line))
        has_info_confirm = bool(info_confirm_pattern.search(line))
        
        # 규칙 1: PII 토큰 2개 이상 + 서비스 동사 → 제거 (중복 가능성 매우 높음)
        if token_count >= 2 and has_service_verb:
            continue
        
        # 규칙 2: PII 토큰 1개 이상 + 서비스 동사 + 정보 확인 표현 → 제거
        if token_count >= 1 and has_service_verb and has_info_confirm:
            continue
        
        # 규칙 3: PII 토큰 존재 + 서비스 동사 + 의미 단어 수가 매우 적음 (토큰 수 + 3 이하)
        # → 안내성 문장으로 간주하여 제거
        if token_count >= 1 and has_service_verb and len(meaningful_words) <= token_count + 3:
            continue
        
        # 규칙 4: 같은 줄에 같은 종류의 PII 토큰이 2회 이상 반복 (예: [PHONE]... [PHONE])
        # → 중복 문장으로 간주
        if len(set(tokens)) < len(tokens):
            continue
        
        out.append(line)
    
    return "\n".join(out)

def _ensure_masked_summary(text: str, original_input: str) -> str:
    """최종 응답에서 '입력 요약' 라인이 누락되었으면 마스킹된 요약으로 복원합니다."""
    if not original_input or "입력 요약" in text:
        return text
    masked_summary = create_masked_summary(original_input)
    if not masked_summary:
        return text
    return re.sub(
        r"(##\s*답변\s*\n)",
        r"\1- 입력 요약: " + masked_summary + "\n",
        text,
        count=1,
        flags=re.IGNORECASE
    )

def create_masked_summary(text: str) -> str:
    """사용자 입력을 마스킹된 요약 버전으로 변환합니다."""
    masked = text
    
    # 1. 이름 마스킹: "홍길동 고객" → "홍OO 고객"
    name_pattern = re.compile(r"(?<![가-힣])([가-힣])([가-힣]{1,2})(?=\s*(고객|님|분|씨))")
    masked = name_pattern.sub(lambda m: m.group(1) + "OO", masked)
    
    # 2. 전화번호 마스킹 (먼저 처리: 0으로 시작하는 패턴)
    phone_pattern = re.compile(r"0\d{1,2}[-\\s]?\d{3,4}[-\\s]?\d{4}|0\d{9,10}")
    masked = phone_pattern.sub("[PHONE]", masked)
    
    # 3. 계좌번호 마스킹: "123-456-789012" → "[ACCOUNT]"
    # 하이픈 포함 계좌번호 패턴 (전화번호는 이미 마스킹됨)
    account_with_dash = re.compile(
        r"\d{3}[-\s]?\d{3}[-\s]?\d{6}"
        r"|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4,6}"
    )
    masked = account_with_dash.sub("[ACCOUNT]", masked)
    # 연속 숫자 (10자리 이상, 0으로 시작하지 않는 것)
    long_numbers = re.compile(r"(?<!0)\d{10,14}")
    masked = long_numbers.sub("[ACCOUNT]", masked)
    
    # 5. 고객번호 마스킹: "123456789" → "[CUSTOMER_ID]" (6~12자리, 0으로 시작하지 않는 숫자)
    # 고객번호 문맥 패턴 먼저 처리: "고객번호는 123456789" 같은 경우
    customer_with_context = re.compile(r"(?:고객번호|고객\s*번호)[:은는\s]*\d{6,12}")
    masked = customer_with_context.sub("[CUSTOMER_ID]", masked)
    # 일반 6~12자리 숫자 (이미 마스킹되지 않은 것, 계좌번호 패턴과 겹치지 않도록)
    # 계좌번호는 10자리 이상이므로, 6~9자리 숫자는 고객번호로 간주
    # 단, 이미 마스킹된 값([ACCOUNT], [PHONE] 등)은 제외
    customer_pattern = re.compile(r"(?<!\[)(?<!\d)([1-9]\d{5,8})(?!\d)(?![-\s]\d)(?!\])")
    masked = customer_pattern.sub("[CUSTOMER_ID]", masked)
    
    # 6. 주소 보조 마스킹
    masked = _mask_addresses(masked)
    
    return masked

# ==================================================================
# 💎 서버 실행
# ==================================================================
if __name__ == '__main__':
    app = create_app()
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8081")), debug=True)