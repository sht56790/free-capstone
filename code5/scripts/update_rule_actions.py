"""
Rule 테이블의 action을 block → mask로 변경하는 스크립트

변경 기준:
- block: 절대 처리해서는 안 되는 요청 (이체 실행, 대출 승인, 확정 정보 제공)
- mask: 민감정보이지만 마스킹 후 답변 가능 (개인식별정보)
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from database import db
from models import Rule

# block → mask로 변경할 규칙들
CHANGE_TO_MASK = [
    "외국인등록번호",       # 개인정보 → 마스킹 후 답변 가능
    "비밀번호_PIN",        # 입력 차단보다는 마스킹 (로그에서 보호)
    "카드_보안코드",        # CVC/CVV도 마스킹으로 처리
    "계좌번호_상세패턴"     # 계좌번호는 마스킹 (기존 규칙과 일관성)
]

# mask → block으로 변경할 규칙들 (필요시)
CHANGE_TO_BLOCK = []

def update_rule_actions():
    """Rule 액션을 적절하게 수정"""
    app = create_app()
    
    with app.app_context():
        print("="*70)
        print("🔄 Rule 액션 변경 (금융 법령 기준 재조정)")
        print("="*70)
        print()
        
        updated = 0
        
        # block → mask
        if CHANGE_TO_MASK:
            print("📝 block → mask 변경:")
            for rule_name in CHANGE_TO_MASK:
                rule = Rule.query.filter_by(name=rule_name).first()
                if rule:
                    old_action = rule.action
                    rule.action = "mask"
                    print(f"  ✓ {rule_name:25s} | {old_action} → mask")
                    updated += 1
                else:
                    print(f"  ⊘ {rule_name:25s} | 규칙을 찾을 수 없음")
            print()
        
        # mask → block
        if CHANGE_TO_BLOCK:
            print("📝 mask → block 변경:")
            for rule_name in CHANGE_TO_BLOCK:
                rule = Rule.query.filter_by(name=rule_name).first()
                if rule:
                    old_action = rule.action
                    rule.action = "block"
                    print(f"  ✓ {rule_name:25s} | {old_action} → block")
                    updated += 1
                else:
                    print(f"  ⊘ {rule_name:25s} | 규칙을 찾을 수 없음")
            print()
        
        if updated > 0:
            db.session.commit()
            print(f"✅ {updated}개 규칙의 액션이 변경되었습니다.")
        else:
            print("⚠️ 변경된 규칙이 없습니다.")
        
        # 최종 상태 확인
        print()
        print("="*70)
        print("📊 액션별 규칙 분포:")
        print("="*70)
        
        block_rules = Rule.query.filter_by(action="block").all()
        mask_rules = Rule.query.filter_by(action="mask").all()
        
        print(f"\n🚫 block ({len(block_rules)}개):")
        for r in block_rules:
            if r.id >= 29:  # 새로 추가된 규칙만
                print(f"  - {r.name}")
        
        print(f"\n🎭 mask ({len(mask_rules)}개):")
        for r in mask_rules:
            if r.id >= 29:  # 새로 추가된 규칙만
                print(f"  - {r.name}")

if __name__ == "__main__":
    try:
        update_rule_actions()
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        import traceback
        traceback.print_exc()
