from flask import Blueprint, jsonify, request
from database import db
from models import User, Log
from models import User, Rule
from datetime import datetime, timedelta
from sqlalchemy import func, case
from collections import Counter

# 'admin_api' 블루프린트 생성
admin_bp = Blueprint('admin_api', __name__, url_prefix='/api/admin')

# --- User Management API (데이터베이스 연동) ---

@admin_bp.get("/users")
def get_users():
    """모든 사용자 목록을 데이터베이스에서 조회하여 반환합니다."""
    users_from_db = User.query.all()
    users_list = [
        {"id": user.id, "password": user.password, "role": user.role}
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
    """대시보드 통계를 DB에서 직접 계산하여 반환합니다."""
    db.session.expire_all()
    # 모든 통계를 DB에서 직접 쿼리합니다.
    total_requests = db.session.query(Log).count()
    pii_detected = db.session.query(Log).filter(Log.action == 'mask').count()
    blocked = db.session.query(Log).filter(Log.action == 'block').count()
    active_users = db.session.query(User).count()

    stats = {
        "today_requests": total_requests,
        "pii_detected": pii_detected,
        "blocked": blocked,
        "active_users": active_users
    }
    return jsonify(stats)

# AI를 이용해 정규식을 생성하는 API
@admin_bp.post("/rules/generate-regex")
def generate_regex_with_ai():
    """자연어 설명을 받아 AI를 통해 정규식을 생성하여 반환합니다."""
    data = request.get_json()
    description = data.get("description")

    if not description:
        return jsonify({"error": "정규식에 대한 설명이 필요합니다."}), 400

    # app.py에 정의할 AI 호출 함수를 사용합니다.
    # 이 함수는 바로 다음 단계에서 만들겠습니다.
    from app import generate_regex_from_ollama
    
    try:
        # AI에게 정규식 생성을 요청합니다.
        from app import generate_regex_from_ollama
        regex_pattern = generate_regex_from_ollama(description)
        # 생성된 정규식을 프론트엔드로 보냅니다.
        return jsonify({"regex": regex_pattern})
    except Exception as e:
        # 오류 발생 시 에러 메시지를 보냅니다.
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
    
    # 2. DB에서 최근 7일간의 로그를 가져옴
    logs = Log.query.filter(Log.timestamp >= seven_days_ago).all()
    
    # 3. 파이썬으로 날짜별 데이터 집계
    data_map = {label: {'total': 0, 'detected': 0} for label in date_labels}
    
    for log in logs:
        log_date_str = log.timestamp.strftime("%m-%d")
        if log_date_str in data_map:
            data_map[log_date_str]['total'] += 1
            if log.action in ['mask', 'block']:
                data_map[log_date_str]['detected'] += 1

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
    # 1. DB에서 detections_in 필드가 비어있지 않은 모든 로그를 가져옴
    logs = Log.query.filter(Log.detections_in.isnot(None)).all()
    
    # 2. 파이썬으로 탐지 유형('name')별로 카운트
    pii_counts = Counter()
    for log in logs:
        # detections_in 필드는 JSON 형태의 리스트일 수 있음
        if isinstance(log.detections_in, list):
            for detection in log.detections_in:
                if isinstance(detection, dict) and 'name' in detection:
                    pii_counts[detection['name']] += 1
    
    # 3. Chart.js 형식에 맞게 데이터 가공
    labels = list(pii_counts.keys())
    data = list(pii_counts.values())

    chart_data = {
        "labels": labels,
        "datasets": [
            {
                "label": "탐지 건수",
                "data": data,
                "backgroundColor": [
                    '#60a5fa', '#34d399', '#f87171', '#facc15', 
                    '#a78bfa', '#e879f9', '#fb923c', '#a3e635'
                ],
            }
        ],
    }
    return jsonify(chart_data)