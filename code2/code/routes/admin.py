# routes/admin.py
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request
import json

# 'admin_api' 블루프린트 생성, 모든 경로는 '/api/admin'으로 시작
admin_bp = Blueprint('admin_api', __name__, url_prefix='/api/admin')

# --- Helper Functions ---
# users.json 파일을 읽고 쓰는 중복 코드를 줄이기 위한 함수들

def _load_users():
    """users.json 파일을 읽어 사용자 목록을 반환합니다."""
    try:
        with open("users.json", "r", encoding="utf-8") as f:
            return json.load(f).get("users", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def _save_users(users_data):
    """사용자 목록을 users.json 파일에 저장합니다."""
    with open("users.json", "w", encoding="utf-8") as f:
        json.dump({"users": users_data}, f, indent=2, ensure_ascii=False)

# --- User Management API ---

# [조회] 모든 사용자 목록 가져오기
@admin_bp.get("/users")
def get_users():
    """모든 사용자 목록을 반환합니다."""
    users = _load_users()
    return jsonify(users)

# [생성] 새 사용자 추가하기
@admin_bp.post("/users")
def add_user():
    """새로운 사용자를 추가합니다."""
    new_user_data = request.get_json()
    if not new_user_data or 'id' not in new_user_data or 'password' not in new_user_data:
        return jsonify({"error": "ID와 비밀번호는 필수입니다."}), 400

    users = _load_users()
    
    # 이메일(id) 중복 확인
    if any(user['id'] == new_user_data['id'] for user in users):
        return jsonify({"error": "이미 존재하는 사용자 ID입니다."}), 409 # 409: Conflict
    
    # 새 사용자 데이터 구성 (role 기본값 설정)
    new_user = {
        "id": new_user_data['id'],
        "password": new_user_data['password'],
        "role": new_user_data.get('role', 'user') # 역할이 없으면 'user'로 기본 설정
    }

    users.append(new_user)
    _save_users(users)
    
    return jsonify(new_user), 201 # 201: Created

# [수정] 특정 사용자 정보 업데이트하기
@admin_bp.put("/users/<string:user_id>")
def update_user(user_id):
    """특정 사용자의 정보를 업데이트합니다 (주로 역할 변경)."""
    update_data = request.get_json()
    users = _load_users()
    
    user_to_update = None
    for user in users:
        if user['id'] == user_id:
            user_to_update = user
            break
            
    if not user_to_update:
        return jsonify({"error": "사용자를 찾을 수 없습니다."}), 404 # 404: Not Found
        
    # 역할 업데이트
    if 'role' in update_data:
        user_to_update['role'] = update_data['role']
    
    # 비밀번호 업데이트 (선택적)
    if 'password' in update_data and update_data['password']:
        user_to_update['password'] = update_data['password']

    _save_users(users)
    return jsonify(user_to_update)

# [삭제] 특정 사용자 삭제하기
@admin_bp.delete("/users/<string:user_id>")
def delete_user(user_id):
    """특정 사용자를 삭제합니다."""
    users = _load_users()
    original_user_count = len(users)
    
    # 삭제할 사용자를 제외한 새로운 리스트 생성
    users_after_deletion = [user for user in users if user['id'] != user_id]
    
    if len(users_after_deletion) == original_user_count:
        return jsonify({"error": "삭제할 사용자를 찾을 수 없습니다."}), 404
        
    _save_users(users_after_deletion)
    return jsonify({"success": True, "message": f"사용자 '{user_id}'가 삭제되었습니다."})

# 기존 로그 조회 API는 그대로 유지
@admin_bp.get("/logs")
def get_logs():
    try:
        with open("logs.json", "r", encoding="utf-8") as f:
            logs = json.load(f)
        return jsonify(logs)
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify([])
    
def _load_logs():
    """logs.json 파일을 읽어 로그 목록을 반환합니다."""
    try:
        with open("logs.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

@admin_bp.get("/dashboard-stats")
def get_dashboard_stats():
    """대시보드에 필요한 통계 데이터를 계산하여 반환합니다."""
    logs = _load_logs()
    users = _load_users()

    # 여기서 실제 시간에 맞춰 24시간 내 데이터만 필터링하는 로직을 추가할 수 있습니다.
    # 지금은 간단하게 전체 개수만 계산합니다.
    total_requests = len(logs)
    pii_detected = sum(1 for log in logs if log.get("detections_in"))
    blocked = sum(1 for log in logs if any(d.get("action") == "block" for d in log.get("detections_in", [])))
    active_users = len(users)

    stats = {
        "today_requests": total_requests,
        "pii_detected": pii_detected,
        "blocked": blocked,
        "active_users": active_users
    }
    return jsonify(stats)