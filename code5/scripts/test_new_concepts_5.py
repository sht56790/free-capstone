"""
개선된 프롬프트 테스트 - 새로운 개념 5개
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
import time
from services.ollama_service import judge_sensitive_with_ollama

# 새로운 개념 5개 테스트
NEW_CONCEPT_TESTS = [
    {
        "text": "VIP고객코드 GOLD-12345",
        "expected_category": "ACCESS_CREDENTIAL",
        "description": "새개념1: VIP고객코드"
    },
    {
        "text": "시크릿코드 ABC123XYZ",
        "expected_category": "ACCESS_CREDENTIAL",
        "description": "새개념2: 시크릿코드"
    },
    {
        "text": "보안토큰 TK-9876-ABCD",
        "expected_category": "ACCESS_CREDENTIAL",
        "description": "새개념3: 보안토큰"
    },
    {
        "text": "인증번호 654321",
        "expected_category": "ACCESS_CREDENTIAL",
        "description": "새개념4: 인증번호"
    },
    {
        "text": "여권번호 M12345678",
        "expected_category": "IDENTIFIER",
        "description": "새개념5: 여권번호"
    },
]

def main():
    app = create_app()
    
    with app.app_context():
        print("="*70)
        print("🚀 개선된 프롬프트 테스트 - 새로운 개념 5개")
        print("="*70)
        print()
        
        results = []
        total_time = 0
        
        for i, case in enumerate(NEW_CONCEPT_TESTS, 1):
            print(f"\n{'='*70}")
            print(f"테스트 {i}/5: {case['description']}")
            print('='*70)
            print(f"입력: {case['text']}")
            print(f"기대 특성: {case['expected_category']}")
            
            start = time.perf_counter()
            
            try:
                detections = judge_sensitive_with_ollama(case['text'], use_cache=False)
                elapsed_ms = (time.perf_counter() - start) * 1000
                total_time += elapsed_ms
                
                if detections:
                    status = "✅ 탐지 성공"
                    detected_labels = [d['label'] for d in detections]
                else:
                    status = "❌ 탐지 실패"
                    detected_labels = []
                
                print(f"\n결과: {status}")
                print(f"⏱️  처리 시간: {elapsed_ms:.1f}ms")
                
                if detections:
                    for d in detections:
                        span_text = case['text'][d['span'][0]:d['span'][1]]
                        priority = d.get('priority', '?')
                        confidence = d.get('confidence', '?')
                        print(f"   🔍 탐지 내용:")
                        print(f"      - 라벨: {d['label']}")
                        print(f"      - 텍스트: '{span_text}'")
                        print(f"      - 액션: {d['action']}")
                        print(f"      - 우선순위: P{priority}")
                        print(f"      - 신뢰도: {confidence}")
                else:
                    print(f"   ⚠️  탐지된 항목 없음")
                
                results.append({
                    "description": case['description'],
                    "status": "성공" if detections else "실패",
                    "detected": detected_labels,
                    "time_ms": elapsed_ms
                })
                
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start) * 1000
                total_time += elapsed_ms
                print(f"\n결과: ❌ 오류 발생")
                print(f"⏱️  처리 시간: {elapsed_ms:.1f}ms")
                print(f"⚠️  오류 내용: {e}")
                
                results.append({
                    "description": case['description'],
                    "status": "오류",
                    "detected": [],
                    "time_ms": elapsed_ms
                })
        
        # 최종 통계
        print("\n\n" + "="*70)
        print("📊 최종 결과")
        print("="*70)
        
        success_count = sum(1 for r in results if r['status'] == "성공")
        fail_count = sum(1 for r in results if r['status'] == "실패")
        error_count = sum(1 for r in results if r['status'] == "오류")
        
        print(f"\n✅ 탐지 성공: {success_count}/5")
        print(f"❌ 탐지 실패: {fail_count}/5")
        print(f"⚠️  오류 발생: {error_count}/5")
        print(f"📈 성공률: {(success_count/5)*100:.1f}%")
        print(f"⏱️  평균 처리 시간: {total_time/5:.1f}ms")
        print(f"⏱️  총 처리 시간: {total_time:.1f}ms")
        
        # 상세 결과
        print(f"\n📋 상세 결과:")
        for r in results:
            status_icon = "✅" if r['status'] == "성공" else "❌" if r['status'] == "실패" else "⚠️"
            labels = ", ".join(r['detected']) if r['detected'] else "없음"
            print(f"{status_icon} {r['description']:25s} | 탐지: {labels}")
        
        # 결론
        print(f"\n{'='*70}")
        print("🎯 결론")
        print("="*70)
        if success_count == 5:
            print("✅ 완벽! 모든 새로운 개념을 탐지했습니다!")
            print("   → Zero-Shot 능력이 정상 작동합니다.")
        elif success_count >= 3:
            print(f"⚠️ 부분 성공 ({success_count}/5)")
            print("   → 일부 개념은 탐지하지만 개선이 필요합니다.")
        else:
            print(f"❌ 실패 ({success_count}/5)")
            print("   → 프롬프트 재조정이 필요합니다.")

if __name__ == "__main__":
    main()
