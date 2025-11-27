import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from database import db
from models import Rule

# database_init.sql에 있는 누락된 규칙들
MISSING_RULES = [
    {
        "name": "수수료 확정 표현",
        "regex": r"수수료는\s*\d+[,\d]*원입니다|수수료\s*\d+[,\d]*원|보험료는\s*\d+[,\d]*원입니다",
        "action": "block"
    },
    {
        "name": "계좌 이체 요청",
        "regex": r"계좌\s*이체|송금\s*요청|이체\s*가능",
        "action": "block"
    },
    {
        "name": "대출 신청",
        "regex": r"대출\s*신청|대출\s*가입|대출\s*가능",
        "action": "block"
    }
]

def add_missing_rules():
    """database_init.sql에 있는 누락된 규칙 추가"""
    app = create_app()
    
    with app.app_context():
        print("="*70)
        print("📋 database_init.sql 누락 규칙 추가")
        print("="*70)
        print()
        
        existing_names = {rule.name for rule in Rule.query.all()}
        print(f"현재 규칙 수: {len(existing_names)}개\n")
        
        added = 0
        skipped = 0
        
        for new_rule in MISSING_RULES:
            if new_rule["name"] in existing_names:
                print(f"⊘ {new_rule['name']:25s} - 이미 존재 (건너뜀)")
                skipped += 1
                continue
            
            rule = Rule(
                name=new_rule["name"],
                regex=new_rule["regex"],
                action=new_rule["action"],
                is_active=True
            )
            db.session.add(rule)
            print(f"✓ {new_rule['name']:25s} - 추가 완료 ({new_rule['action']})")
            added += 1
        
        if added > 0:
            db.session.commit()
            print()
            print(f"✅ {added}개 규칙이 추가되었습니다.")
        else:
            print()
            print("⚠️ 추가된 규칙이 없습니다.")
        
        if skipped > 0:
            print(f"⊘ {skipped}개 규칙은 이미 존재합니다.")
        
        total = Rule.query.count()
        print()
        print("="*70)
        print(f"📊 현재 총 규칙: {total}개")
        print("="*70)

if __name__ == "__main__":
    try:
        add_missing_rules()
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        import traceback
        traceback.print_exc()
