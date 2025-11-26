"""
금융 법령 기준 정규식 패턴을 DB Rule 테이블에 추가하는 스크립트

추가 항목 (법령 기준):
1. 외국인등록번호 (개인정보보호법 - 고유식별정보)
2. 금리 확정 표현 (금융소비자보호법 제19조 - 부당권유행위 금지)
3. 수수료 확정 표현 (금융소비자보호법 제19조 - 부당권유행위 금지)
4. 계좌이체 실행 요청 (전자금융거래법 제9조 - 안전성 확보 의무)
5. 대출 신청/승인 표현 (여신전문금융업법 - 직접 처리 금지)
6. 비밀번호/PIN (정보통신망법 제28조 - 개인정보 보호)
7. CVC/CVV (여신전문금융업법 제14조의6 - 신용정보 보호)
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from database import db
from models import Rule

# 추가할 규칙 (금융 법령 기준)
NEW_RULES = [
    {
        "name": "외국인등록번호",
        "regex": r"\b\d{6}[-\s]?[5-8]\d{6}\b",
        "action": "block"
    },
    {
        "name": "금리_확정표현",
        "regex": r"금리는?\s*\d+\.?\d*%\s*(입니다|이에요|예요)|이자율은?\s*\d+\.?\d*%",
        "action": "block"
    },
    {
        "name": "수수료_확정표현",
        "regex": r"수수료는?\s*\d+[,\d]*원\s*(입니다|이에요|예요)|보험료는?\s*\d+[,\d]*원",
        "action": "block"
    },
    {
        "name": "계좌이체_실행요청",
        "regex": r"(계좌\s*이체|송금|입금|출금)\s*(해\s*줘|해줘|해\s*주세요|부탁|요청|실행)",
        "action": "block"
    },
    {
        "name": "대출_신청승인",
        "regex": r"대출\s*(신청|승인|가능|해\s*줘|처리|진행)",
        "action": "block"
    },
    {
        "name": "비밀번호_PIN",
        "regex": r"(?i)(비밀번호|패스워드|password|pin\s*번호)[:\s]*[\w!@#$%^&*]{4,}",
        "action": "block"
    },
    {
        "name": "카드_보안코드",
        "regex": r"(?i)\b(cvc|cvv|card\s*verification)\s*[:\s]*\d{3,4}\b",
        "action": "block"
    },
    {
        "name": "계좌번호_상세패턴",
        "regex": r"(?:계좌번호[:\s]*)?\d{3}[-\s]?\d{3}[-\s]?\d{6,8}",
        "action": "block"
    }
]

def add_financial_rules():
    """금융 법령 기준 규칙을 DB에 추가"""
    app = create_app()
    
    with app.app_context():
        print("="*70)
        print("🏦 금융 법령 기준 정규식 패턴 추가")
        print("="*70)
        print()
        
        # 기존 규칙 이름 확인
        existing_names = {rule.name for rule in Rule.query.all()}
        print(f"기존 규칙: {len(existing_names)}개\n")
        
        added = 0
        skipped = 0
        
        for new_rule in NEW_RULES:
            if new_rule["name"] in existing_names:
                print(f"⊘ {new_rule['name']:25s} - 이미 존재 (건너뜀)")
                skipped += 1
                continue
            
            # 새 규칙 추가
            rule = Rule(
                name=new_rule["name"],
                regex=new_rule["regex"],
                action=new_rule["action"],
                is_active=True
            )
            db.session.add(rule)
            print(f"✓ {new_rule['name']:25s} - 추가 완료 ({new_rule['action']})")
            added += 1
        
        # 커밋
        if added > 0:
            db.session.commit()
            print()
            print(f"✅ {added}개 규칙이 추가되었습니다.")
        else:
            print()
            print("⚠️ 추가된 규칙이 없습니다.")
        
        if skipped > 0:
            print(f"⊘ {skipped}개 규칙은 이미 존재합니다.")
        
        # 최종 상태
        total = Rule.query.count()
        print()
        print("="*70)
        print(f"📊 현재 총 규칙: {total}개")
        print("="*70)

if __name__ == "__main__":
    try:
        add_financial_rules()
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        import traceback
        traceback.print_exc()
