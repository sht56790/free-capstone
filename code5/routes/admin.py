from flask import Blueprint, jsonify, request
from database import db
from models import User, Log
from models import User, Rule
from datetime import datetime, timedelta
from sqlalchemy import func, case
from collections import Counter
from services.ollama_service import benchmark_ollama

# 'admin_api' 블루프린트 생성
admin_bp = Blueprint('admin_api', __name__, url_prefix='/api/admin')

# --- User Management API (데이터베이스 연동) ---

@admin_bp.get("/users")
def get_users():
    """모든 사용자 목록을 데이터베이스에서 조회하여 반환합니다."""
    users_from_db = User.query.all()
    users_list = [
        {
            "id": user.id, 
            "password": user.password, 
            "role": user.role,
            "last_login": user.last_login.isoformat() + "Z" if user.last_login else None
        }
        for user in users_from_db
    ]
    return jsonify(users_list)

@admin_bp.post("/users")
def add_user():
    """새로운 사용자를 DB에 추가합니다."""
    data = request.get_json()
    if not data or 'id' not in data or 'password' not in data:
        return jsonify({"error": "ID와 비밀번호는 필수입니다."}), 400

    if User.query.get(data['id']):
        return jsonify({"error": "이미 존재하는 사용자 ID입니다."}), 409

    new_user = User(
        id=data['id'],
        password=data['password'],
        role=data.get('role', 'user')
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"id": new_user.id, "role": new_user.role}), 201

@admin_bp.put("/users/<string:user_id>")
def update_user(user_id):
    """특정 사용자의 정보를 DB에서 업데이트합니다."""
    data = request.get_json()
    user_to_update = User.query.get(user_id)

    if not user_to_update:
        return jsonify({"error": "사용자를 찾을 수 없습니다."}), 404
        
    if 'role' in data:
        user_to_update.role = data['role']
    if 'password' in data and data['password']:
        user_to_update.password = data['password']

    db.session.commit()
    return jsonify({"id": user_to_update.id, "role": user_to_update.role})

@admin_bp.delete("/users/<string:user_id>")
def delete_user(user_id):
    """특정 사용자를 DB에서 삭제합니다."""
    user_to_delete = User.query.get(user_id)

    if not user_to_delete:
        return jsonify({"error": "삭제할 사용자를 찾을 수 없습니다."}), 404
        
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({"success": True, "message": f"사용자 '{user_id}'가 삭제되었습니다."})

@admin_bp.get("/rules")
def get_rules():
    """모든 탐지 규칙 목록을 DB에서 조회하여 반환합니다."""
    rules_from_db = Rule.query.order_by(Rule.name).all()
    rules_list = [
        {
            "id": rule.id,
            "name": rule.name,
            "regex": rule.regex,
            "action": rule.action,
            "is_active": rule.is_active,
        }
        for rule in rules_from_db
    ]
    return jsonify(rules_list)

@admin_bp.post("/rules")
def add_rule():
    """새로운 탐지 규칙을 DB에 추가합니다."""
    data = request.get_json()
    if not data or not data.get('name') or not data.get('regex'):
        return jsonify({"error": "규칙 이름과 정규식은 필수입니다."}), 400

    if Rule.query.filter_by(name=data['name']).first():
        return jsonify({"error": "이미 존재하는 규칙 이름입니다."}), 409

    new_rule = Rule(
        name=data['name'],
        regex=data['regex'],
        action=data.get('action', 'mask'),
        is_active=data.get('is_active', True)
    )
    db.session.add(new_rule)
    db.session.commit()
    
    return jsonify({"id": new_rule.id, "name": new_rule.name}), 201

@admin_bp.delete("/rules/<int:rule_id>")
def delete_rule(rule_id):
    """특정 탐지 규칙을 DB에서 삭제합니다."""
    rule_to_delete = Rule.query.get_or_404(rule_id)
    
    db.session.delete(rule_to_delete)
    db.session.commit()
    
    return jsonify({"success": True, "message": f"Rule '{rule_to_delete.name}' deleted."})

@admin_bp.put("/rules/<int:rule_id>")
def update_rule(rule_id):
    """특정 탐지 규칙의 내용을 DB에서 수정합니다."""
    data = request.get_json()
    rule_to_update = Rule.query.get_or_404(rule_id)

    if 'name' in data:
        rule_to_update.name = data['name']
    if 'regex' in data:
        rule_to_update.regex = data['regex']
    if 'action' in data:
        rule_to_update.action = data['action']
    if 'is_active' in data:
        rule_to_update.is_active = data['is_active']

    db.session.commit()
    
    return jsonify({"id": rule_to_update.id, "name": rule_to_update.name})
# --- 대시보드 및 로그 API (데이터베이스 연동) ---

@admin_bp.get("/logs")
def get_logs():
    """모든 로그를 DB에서 조회하여 최신순으로 반환합니다."""
    # DB에서 모든 로그를 시간 역순으로 정렬하여 가져옵니다.
    logs_from_db = Log.query.order_by(Log.timestamp.desc()).all()
    
    # DB 객체 리스트를 JSON 형태로 변환합니다.
    logs_list = []
    for log in logs_from_db:
        logs_list.append({
            "id": log.id,
            # 날짜/시간을 ISO 표준 형식 문자열로 변환 (프론트엔드에서 다루기 쉬움)
            "ts": log.timestamp.isoformat() + "Z", 
            "user": log.user_id,
            "user_prompt": log.user_prompt,
            "action": log.action,
            # JSON 필드는 그대로 전달
            "pii": [d['name'] for d in log.detections_in] if log.detections_in else []
        })
    return jsonify(logs_list)

@admin_bp.get("/dashboard-stats")
def get_dashboard_stats():
    """대시보드 통계를 DB에서 직접 계산하여 반환합니다 (최근 7일 기준)."""
    db.session.expire_all()
    
    # 최근 7일 기준 날짜 계산
    today = datetime.utcnow().date()
    seven_days_ago = today - timedelta(days=6)
    seven_days_ago_datetime = datetime.combine(seven_days_ago, datetime.min.time())
    
    # 최근 7일 로그만 조회
    total_requests = db.session.query(Log).filter(
        Log.timestamp >= seven_days_ago_datetime
    ).count()
    
    # 민감정보 탐지 = detections_in 또는 detections_out에 실제 탐지가 있는 로그만 카운트
    recent_logs = Log.query.filter(Log.timestamp >= seven_days_ago_datetime).all()
    pii_detected = sum(
        1 for log in recent_logs 
        if (isinstance(log.detections_in, list) and len(log.detections_in) > 0) or
           (isinstance(log.detections_out, list) and len(log.detections_out) > 0)
    )
    
    # 차단 건수 (최근 7일)
    blocked = db.session.query(Log).filter(
        Log.timestamp >= seven_days_ago_datetime,
        Log.action == 'block'
    ).count()
    
    # 활성 사용자는 전체 기준
    active_users = db.session.query(User).count()

    stats = {
        "today_requests": total_requests,
        "pii_detected": pii_detected,
        "blocked": blocked,
        "active_users": active_users
    }
    print(f"[STATS] 최근7일 - total={total_requests}, detected={pii_detected}, blocked={blocked}, users={active_users}")
    return jsonify(stats)

# AI를 이용해 정규식을 생성하는 API
@admin_bp.post("/rules/generate-regex")
def generate_regex_with_ai():
    """자연어 설명을 받아 AI를 통해 정규식을 생성하여 반환합니다."""
    data = request.get_json()
    description = data.get("description")

    if not description:
        return jsonify({"error": "정규식에 대한 설명이 필요합니다."}), 400

    # 서비스 모듈의 AI 정규식 생성 함수를 사용합니다.
    from services.ollama_service import generate_regex_from_ollama
    
    try:
        # AI에게 정규식 생성을 요청합니다.
        regex_pattern = generate_regex_from_ollama(description)
        # 생성된 정규식을 프론트엔드로 보냅니다.
        return jsonify({"regex": regex_pattern})
    except Exception as e:
        # 오류 발생 시 에러 메시지를 보냅니다.
        return jsonify({"error": str(e)}), 500


# 🔬 Ollama 모델 벤치마크 API
@admin_bp.post("/ollama-benchmark")
def ollama_benchmark():
    """여러 Ollama 모델로 동일 입력을 실행하여 시간/결과를 비교합니다.

    요청 바디 예시:
    {"text": "홍길동 고객의 계좌 123-456-789012", "models": ["qwen3:8b", "llama3:8b"], "task": "judge"}
    task: judge | regex
    """
    data = request.get_json(force=True) or {}
    text = data.get("text", "")
    models = data.get("models") or ["qwen3:8b"]
    task = data.get("task", "judge")
    if not text:
        return jsonify({"error": "text is required"}), 400
    try:
        results = benchmark_ollama(text, models, task=task)
        # 간단 요약: judge일 경우 탐지 수/차단 여부 요약
        summary = None
        if task == "judge":
            summary = [
                {
                    "model": r["model"],
                    "duration_ms": r["duration_ms"],
                    "detections": len(r["result"]) if r["result"] else 0,
                    "blocked": any(d.get("action") == "block" for d in (r["result"] or [])),
                    "error": r["error"],
                }
                for r in results
            ]
        return jsonify({"task": task, "results": results, "summary": summary})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 📈 최근 7일 요청/탐지 추이 데이터 API
@admin_bp.get("/trends")
def get_trends():
    """최근 7일간의 총 요청 수와 탐지/차단 수를 계산하여 반환합니다."""
    db.session.expire_all()
    # 1. 날짜 데이터 준비 (오늘 포함 최근 7일)
    today = datetime.utcnow().date()
    seven_days_ago = today - timedelta(days=6)
    date_labels = [(seven_days_ago + timedelta(days=i)).strftime("%m-%d") for i in range(7)]
    
    # 2. DB에서 최근 7일간의 로그를 가져옴 (datetime 비교 수정)
    seven_days_ago_datetime = datetime.combine(seven_days_ago, datetime.min.time())
    logs = Log.query.filter(Log.timestamp >= seven_days_ago_datetime).all()
    print(f"[TRENDS] Found {len(logs)} logs from {seven_days_ago_datetime}")
    
    # 3. 파이썬으로 날짜별 데이터 집계
    data_map = {label: {'total': 0, 'detected': 0} for label in date_labels}
    
    for log in logs:
        log_date_str = log.timestamp.strftime("%m-%d")
        if log_date_str in data_map:
            data_map[log_date_str]['total'] += 1
            if log.action in ['mask', 'block']:
                data_map[log_date_str]['detected'] += 1
    
    print(f"[TRENDS] Data map: {data_map}")

    # 4. Chart.js 형식으로 변환
    total_requests_data = [data_map[label]['total'] for label in date_labels]
    detected_data = [data_map[label]['detected'] for label in date_labels]

    chart_data = {
        "labels": date_labels,
        "datasets": [
            {
                "label": "총 요청",
                "data": total_requests_data,
                "borderColor": "#60a5fa",
                "backgroundColor": "rgba(96, 165, 250, 0.1)",
                "fill": True,
                "tension": 0.3,
            },
            {
                "label": "탐지/차단",
                "data": detected_data,
                "borderColor": "#f87171",
                "backgroundColor": "rgba(248, 113, 113, 0.1)",
                "fill": True,
                "tension": 0.3,
            },
        ],
    }
    return jsonify(chart_data)

# 🎨 탐지 유형 분포 데이터 API
@admin_bp.get("/distribution")
def get_distribution():
    """모든 로그의 탐지 유형(PII) 분포를 계산하여 반환합니다."""
    db.session.expire_all()
    
    # 최근 7일 로그만 조회 (상단 통계와 일치)
    today = datetime.utcnow().date()
    seven_days_ago = today - timedelta(days=6)
    seven_days_ago_datetime = datetime.combine(seven_days_ago, datetime.min.time())
    logs = Log.query.filter(Log.timestamp >= seven_days_ago_datetime).all()
    
    print(f"[DISTRIBUTION] Total logs (last 7 days): {len(logs)}")
    
    # 라벨 통합 매핑 (다양한 표현을 하나로 통합)
    label_mapping = {
        # 계좌번호 관련
        "ACCOUNT": "계좌번호",
        "계좌번호": "계좌번호",
        "모델 판정 차단: ACCOUNT": "계좌번호",
        
        # 전화번호 관련
        "PHONE": "전화번호",
        "전화번호": "전화번호",
        "모델 판정 차단: PHONE": "전화번호",
        
        # 주소 관련
        "ADDRESS": "주소",
        "주소": "주소",
        "모델 판정 차단: ADDRESS": "주소",
        
        # 고객번호 관련
        "CUSTOMER_ID": "고객번호",
        "고객번호": "고객번호",
        "모델 판정 차단: CUSTOMER_ID": "고객번호",
        
        # 이메일 관련
        "EMAIL": "이메일",
        "이메일": "이메일",
        
        # 이름 관련
        "NAME": "고객명",
        "고객명": "고객명",
        
        # 생년월일 관련
        "DOB": "생년월일",
        "생년월일": "생년월일",
        
        # 기타
        "ETC": "기타",
        "ORG": "조직명",
        "모델 판정 차단: ETC": "기타",
    }
    
    # 2. 파이썬으로 탐지 유형('name')별로 카운트 (라벨 통합)
    pii_counts = Counter()
    for log in logs:
        # 입력 탐지 (detections_in)
        if isinstance(log.detections_in, list) and len(log.detections_in) > 0:
            for detection in log.detections_in:
                if isinstance(detection, dict) and 'name' in detection:
                    raw_label = detection['name']
                    # 라벨 통합 (매핑에 없으면 원본 사용)
                    unified_label = label_mapping.get(raw_label, raw_label)
                    pii_counts[unified_label] += 1
        
        # 출력 탐지 (detections_out)
        if isinstance(log.detections_out, list) and len(log.detections_out) > 0:
            for detection in log.detections_out:
                if isinstance(detection, dict) and 'name' in detection:
                    raw_label = detection['name']
                    unified_label = label_mapping.get(raw_label, raw_label)
                    pii_counts[unified_label] += 1
    
    print(f"[DISTRIBUTION] Unified PII counts: {dict(pii_counts)}")
    
    # 3. Chart.js 형식으로 변환
    labels = list(pii_counts.keys()) if pii_counts else ["데이터 없음"]
    data = list(pii_counts.values()) if pii_counts else [0]
    
    # 배경색 생성 (항목 수만큼)
    colors = ['#60a5fa', '#34d399', '#f87171', '#facc15', '#a78bfa', '#e879f9', '#fb923c', '#a3e635']
    background_colors = [colors[i % len(colors)] for i in range(len(labels))]

    chart_data = {
        "labels": labels,
        "datasets": [
            {
                "label": "탐지 건수",
                "data": data,
                "backgroundColor": background_colors,
            }
        ],
    }
    print(f"[DISTRIBUTION] Returning chart data with {len(labels)} labels")
    return jsonify(chart_data)

# 🖥️ 시스템 상태 API
@admin_bp.get("/system-status")
def get_system_status():
    """시스템 상태 정보를 반환합니다."""
    try:
        import psutil
        import platform
        import sys
        import os
    except ImportError as e:
        return jsonify({"error": f"필요한 모듈을 불러올 수 없습니다: {e}"}), 500
    
    try:
        # 1. 서버 정보
        server_info = {
            "python_version": f"{sys.version.split()[0]}",
            "os": f"{os.name.upper()}",
            "platform": f"{platform.system()} {platform.release()}",
        }
        
        # 2. CPU 및 메모리 사용률
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        resources = {
            "cpu_percent": round(cpu_percent, 1),
            "memory_percent": round(memory.percent, 1),
            "memory_used_gb": round(memory.used / (1024**3), 2),
            "memory_total_gb": round(memory.total / (1024**3), 2),
            "disk_percent": round(disk.percent, 1),
            "disk_used_gb": round(disk.used / (1024**3), 2),
            "disk_total_gb": round(disk.total / (1024**3), 2),
        }
        
        # 3. 데이터베이스 통계
        total_users = User.query.count()
        total_rules = Rule.query.count()
        total_logs = Log.query.count()
        
        # 최근 24시간 로그
        yesterday = datetime.utcnow() - timedelta(hours=24)
        logs_24h = Log.query.filter(Log.timestamp >= yesterday).count()
        
        db_stats = {
            "total_users": total_users,
            "total_rules": total_rules,
            "total_logs": total_logs,
            "logs_24h": logs_24h,
        }
        
        # 4. Ollama 서비스 상태 체크
        ollama_status = "offline"
        ollama_model = "N/A"
        try:
            import requests
            response = requests.get("http://localhost:11434/api/tags", timeout=2)
            if response.status_code == 200:
                ollama_status = "online"
                models = response.json().get('models', [])
                if models:
                    ollama_model = ", ".join([m.get('name', 'unknown') for m in models[:3]])
        except:
            pass
        
        # 5. Gemini API 상태 체크
        gemini_status = "offline"
        gemini_model = "N/A"
        try:
            import google.generativeai as genai
            api_key = os.getenv('GOOGLE_API_KEY')
            if api_key:
                gemini_status = "configured"
                gemini_model = "gemini-2.0-flash"
        except:
            pass
        
        services = {
            "ollama": {
                "status": ollama_status,
                "model": ollama_model
            },
            "gemini": {
                "status": gemini_status,
                "model": gemini_model
            },
            "database": {
                "status": "online",
                "type": "SQLite"
            }
        }
        
        return jsonify({
            "server": server_info,
            "resources": resources,
            "database": db_stats,
            "services": services
        })
        
    except Exception as e:
        print(f"[SYSTEM-STATUS] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# 📄 문서 관리 (RAG) API

@admin_bp.get("/documents")
def get_documents():
    """업로드된 PDF 문서 목록을 반환합니다."""
    import os
    from pathlib import Path
    
    docs_dir = Path("scripts/rag_docs")
    if not docs_dir.exists():
        return jsonify({"documents": []})
    
    documents = []
    for pdf_file in docs_dir.glob("**/*.pdf"):
        stat = pdf_file.stat()
        size_mb = stat.st_size / (1024 * 1024)
        documents.append({
            "filename": pdf_file.name,
            "size": f"{size_mb:.2f} MB",
            "upload_time": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        })
    
    return jsonify({"documents": documents})

@admin_bp.post("/documents/upload")
def upload_documents():
    """PDF 파일을 업로드합니다."""
    import os
    from pathlib import Path
    from werkzeug.utils import secure_filename
    
    print(f"[UPLOAD] Request files: {request.files}")
    
    if 'files' not in request.files:
        return jsonify({"error": "파일이 없습니다."}), 400
    
    files = request.files.getlist('files')
    print(f"[UPLOAD] Files count: {len(files)}")
    
    if not files or (len(files) == 1 and files[0].filename == ''):
        return jsonify({"error": "파일이 없습니다."}), 400
    
    docs_dir = Path("scripts/rag_docs")
    docs_dir.mkdir(parents=True, exist_ok=True)
    
    uploaded_files = []
    errors = []
    
    for file in files:
        if file and file.filename and file.filename.endswith('.pdf'):
            try:
                filename = secure_filename(file.filename)
                filepath = docs_dir / filename
                file.save(str(filepath))
                uploaded_files.append(filename)
                print(f"[UPLOAD] Saved: {filepath}")
            except Exception as e:
                errors.append(f"{file.filename}: {str(e)}")
                print(f"[UPLOAD] Error saving {file.filename}: {e}")
    
    if not uploaded_files and errors:
        return jsonify({"error": f"업로드 실패: {', '.join(errors)}"}), 500
    
    if not uploaded_files:
        return jsonify({"error": "PDF 파일이 없습니다."}), 400
    
    return jsonify({
        "message": f"{len(uploaded_files)}개 파일이 업로드되었습니다.",
        "files": uploaded_files,
        "errors": errors if errors else None
    })

@admin_bp.delete("/documents/<string:filename>")
def delete_document(filename):
    """특정 PDF 파일을 삭제합니다."""
    import os
    from pathlib import Path
    from werkzeug.utils import secure_filename
    
    safe_filename = secure_filename(filename)
    docs_dir = Path("scripts/rag_docs")
    filepath = docs_dir / safe_filename
    
    if not filepath.exists():
        return jsonify({"error": "파일을 찾을 수 없습니다."}), 404
    
    try:
        filepath.unlink()
        return jsonify({"message": f"{safe_filename} 파일이 삭제되었습니다."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.post("/documents/rebuild-rag")
def rebuild_rag():
    """RAG 시스템을 재구축합니다."""
    import subprocess
    import sys
    from pathlib import Path
    
    try:
        script_path = Path("scripts/embed_documents.py")
        if not script_path.exists():
            return jsonify({"error": "embed_documents.py 파일을 찾을 수 없습니다."}), 404
        
        # 백그라운드로 실행하지 않고 직접 실행 (시간이 걸리므로 타임아웃 주의)
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=300  # 5분 타임아웃
        )
        
        # stdout에 성공 메시지가 있으면 성공으로 처리 (stderr는 경고일 수 있음)
        # returncode가 0이거나 성공 메시지가 있으면 성공
        success_indicators = ["Vector DB 생성 완료", "총 소요 시간"]
        is_success = any(indicator in result.stdout for indicator in success_indicators)
        
        if is_success:
            return jsonify({
                "message": "RAG 재구축이 완료되었습니다.",
                "output": result.stdout,
                "warnings": result.stderr if result.stderr else None
            })
        else:
            return jsonify({
                "error": "RAG 재구축 중 오류가 발생했습니다.",
                "output": result.stderr or result.stdout
            }), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({"error": "RAG 재구축 시간이 초과되었습니다. (5분)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500