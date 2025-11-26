"""모든 감사 로그를 삭제하는 스크립트"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from database import db
from models import Log

app = create_app()

with app.app_context():
    count = Log.query.count()
    print(f"삭제 전 로그 개수: {count}")
    
    # 모든 로그 삭제
    Log.query.delete()
    db.session.commit()
    
    count_after = Log.query.count()
    print(f"삭제 후 로그 개수: {count_after}")
    print("✅ 모든 감사 로그가 삭제되었습니다.")
