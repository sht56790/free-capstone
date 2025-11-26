"""
Rule 테이블에 추가 정규식 패턴 삽입 (36개 → 50개)
금융권 특화 패턴 14개 추가
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from database import db
from models import Rule

# 추가할 규칙 (14개)
NEW_RULES = [
    {
        "name": "법인등록번호",
        "regex": r"\b\d{6}[-\s]?\d{7}\b",
        "action": "mask"
    },
    {
        "name": "주민번호_상세",
        "regex": r"\b\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-\s]?[1-4]\d{6}\b",
        "action": "block"
    },
    {
        "name": "증권계좌",
        "regex": r"(?:증권|주식)\s*계좌\s*(?:번호[:\s]*)?\d{3,4}[-\s]?\d{4,6}[-\s]?\d{2,4}",
        "action": "block"
    },
    {
        "name": "보험증권번호",
        "regex": r"(?:보험증권|증권번호)[:\s]*[A-Z]{2,4}[-]?\d{8,12}",
        "action": "mask"
    },
    {
        "name": "연금계좌",
        "regex": r"(?:연금)\s*계좌\s*(?:번호[:\s]*)?\d{3,4}[-\s]?\d{4,6}",
        "action": "block"
    },
    {
        "name": "카드유효기간",
        "regex": r"(?:유효기간|만료일)[:\s]*(0[1-9]|1[0-2])/\d{2}",
        "action": "block"
    },
    {
        "name": "급여정보",
        "regex": r"(?:연봉|월급|급여)[:\s]*\d{1,4}[,.\s]?\d{3}[,.\s]?\d{3}\s*원",
        "action": "mask"
    },
    {
        "name": "대출금액",
        "regex": r"(?:대출|융자)\s*(?:금액|액수)[:\s]*\d{1,4}억|\d{1,4}[,.\s]?\d{3}만\s*원",
        "action": "mask"
    },
    {
        "name": "예금잔액",
        "regex": r"(?:잔액|잔고)[:\s]*\d{1,4}억|\d{1,4}[,.\s]?\d{3}만\s*원",
        "action": "mask"
    },
    {
        "name": "소득금액",
        "regex": r"(?:소득|수입)[:\s]*\d{1,4}[,.\s]?\d{3}[,.\s]?\d{3}\s*원",
        "action": "mask"
    },
    {
        "name": "공인인증서",
        "regex": r"(?i)(?:-----BEGIN CERTIFICATE-----|-----BEGIN RSA PRIVATE KEY-----)",
        "action": "block"
    },
    {
        "name": "OTP번호",
        "regex": r"\b\d{6}\b(?=.*(?:otp|인증|일회용))",
        "action": "block"
    },
    {
        "name": "가족관계",
        "regex": r"(?:배우자|자녀|부모|형제|자매).*?(?:성명|이름)[:\s]*[가-힣]{2,4}",
        "action": "mask"
    },
    {
        "name": "직장명",
        "regex": r"(?:직장|회사)(?:명)?[:\s]*[가-힣A-Za-z]{2,20}(?:주식회사|회사|그룹|은행|증권)?",
        "action": "mask"
    }
]

def add_additional_rules():
    """추가 정규식 규칙을 DB에 삽입"""
    app = create_app()
    
    with app.app_context():
        print("="*70)
        print("금융권 정규식 패턴 확장 (36개 → 50개)")
        print("="*70)
        print()
        
        # 현재 규칙 수 확인
        current_count = Rule.query.count()
        print(f"현재 규칙 수: {current_count}개\n")
        
        # 기존 규칙 이름 확인
        existing_names = {rule.name for rule in Rule.query.all()}
        
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
        
        # 액션별 분포
        block_count = Rule.query.filter_by(action="block").count()
        mask_count = Rule.query.filter_by(action="mask").count()
        print(f"\n🚫 block: {block_count}개")
        print(f"🎭 mask: {mask_count}개")

if __name__ == "__main__":
    try:
        add_additional_rules()
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        import traceback
        traceback.print_exc()
