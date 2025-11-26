"""현재 DB의 Rule 테이블 조회"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from database import db
from models import Rule

app = create_app()
with app.app_context():
    rules = Rule.query.all()
    print(f"\n총 {len(rules)}개 규칙\n")
    print(f"{'ID':<4} {'이름':<20} {'액션':<8} {'정규식 (일부)':<50}")
    print("="*90)
    for r in rules:
        regex_preview = r.regex[:50] + "..." if len(r.regex) > 50 else r.regex
        print(f"{r.id:<4} {r.name:<20} {r.action:<8} {regex_preview}")
