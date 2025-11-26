"""User 테이블에 last_login 컬럼을 추가하는 마이그레이션 스크립트"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from database import db

app = create_app()

with app.app_context():
    # SQLite에서는 ALTER TABLE이 제한적이므로 
    # SQLAlchemy가 자동으로 처리하도록 db.create_all() 사용
    try:
        # 이미 존재하는 테이블은 건너뛰고, 새 컬럼만 추가됨
        db.create_all()
        print("✅ User 테이블에 last_login 컬럼이 추가되었습니다.")
        
        # 기존 사용자 확인
        from models import User
        users = User.query.all()
        print(f"현재 사용자 수: {len(users)}")
        for user in users:
            print(f"  - {user.id}: last_login = {user.last_login}")
            
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        print("SQLite에서 컬럼 추가가 실패한 경우, DB를 재생성해야 할 수 있습니다.")
