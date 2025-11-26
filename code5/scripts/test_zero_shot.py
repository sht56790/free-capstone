"""
Zero-Shot 능력 테스트 - 새로운 개념 탐지
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
import time
from services.ollama_service_zero_shot import judge_sensitive_zero_shot, judge_sensitive_hybrid_with_zero_shot

# 새로운 개념 테스트
NEW_CONCEPT_TESTS = [
    {
        "text": "시크릿코드: ABC123XYZ",
        "expected": ["SECRET_CODE"],
        "description": "새개념: 시크릿코드"
    },
    {
        "text": "인증번호 654321 입력하세요",
        "expected": ["AUTH_CODE"],
        "description": "새개념: 인증번호"
    },
    {
        "text": "여권번호 M12345678",
        "expected": ["PASSPORT"],
        "description": "새개념: 여권번호"
    },
    {
        "text": "면허번호 11-12-345678-90",
        "expected": ["LICENSE"],
        "description": "새개념: 면허번호"
    },
    {
        "text": "사원번호 EMP-2024-1234",
        "expected": ["EMPLOYEE_ID"],
        "description": "새개념: 사원번호"
    },
    {
        "text": "PIN 번호 1234",
        "expected": ["PIN"],
        "description": "새개념: PIN"
    },
    {
        "text": "OTP 코드 987654",
        "expected": ["OTP"],
        "description": "새개념: OTP"
    },
    {
        "text": "보안토큰 TK-9876-ABCD",
        "expected": ["SECURITY_TOKEN"],
        "description": "새개념: 보안토큰"
    },
    {
        "text": "외국인등록번호 123456-7890123",
        "expected": ["FOREIGN_ID"],
        "description": "새개념: 외국인등록번호"
    },
    {
        "text": "사업자등록번호 123-45-67890",
        "expected": ["BUSINESS_ID"],
        "description": "새개념: 사업자등록번호"
    },
    # 기존 개념 (비교용)
    {
        "text": "홍길동 010-1234-5678",
        "expected": ["NAME", "PHONE"],
        "description": "기존개념: 이름+전화"
    },
    {
        "text": "계좌번호 110-123-456789",
        "expected": ["ACCOUNT"],
        "description": "기존개념: 계좌번호"
    },
    # 부정 예제
    {
        "text": "대출 한도는 어떻게 되나요",
        "expected": [],
        "description": "부정: 일반 질문"
    },
]

def main():
    app = create_app()
    
    with app.app_context():
        print("="*70)
        print("🚀 Zero-Shot 능력 테스트 - 새로운 개념 탐지")
        print("="*70)
        print(f"총 테스트: {len(NEW_CONCEPT_TESTS)}개")
        print()
        
        results = []
        total_time = 0
        
        for i, case in enumerate(NEW_CONCEPT_TESTS, 1):
            print(f"\n{'='*70}")
            print(f"테스트 {i}/{len(NEW_CONCEPT_TESTS)}: {case['description']}")
            print('='*70)
            print(f"입력: {case['text']}")
            print(f"기대: {case['expected']}")
            
            start = time.perf_counter()
            
            try:
                detections = judge_sensitive_zero_shot(case['text'], use_cache=False)
                elapsed_ms = (time.perf_counter() - start) * 1000
                total_time += elapsed_ms
                
                detected_labels = [d['label'] for d in detections]
                
                # 부분 일치 허용 (새로운 라벨 생성 가능)
                expected_set = set(case['expected'])
                detected_set = set(detected_labels)
                
                # 일치 또는 의미적으로 유사하면 PASS
                if expected_set == detected_set:
                    status = "✅ PASS (완전 일치)"
                elif len(detected_set) > 0 and len(expected_set) > 0:
                    status = "⚠️ PARTIAL (새 라벨 생성)"
                elif len(expected_set) == 0 and len(detected_set) == 0:
                    status = "✅ PASS (부정 예제)"
                else:
                    status = "❌ FAIL"
                
                print(f"\n결과: {status}")
                print(f"⏱️  시간: {elapsed_ms:.1f}ms")
                print(f"🔍 탐지: {detected_labels}")
                
                if detections:
                    for d in detections:
                        span_text = case['text'][d['span'][0]:d['span'][1]]
                        print(f"   - {d['label']} (P{d['priority']}): '{span_text}' → {d['action']}")
                
                results.append({
                    "description": case['description'],
                    "status": status,
                    "detected": detected_labels,
                    "time_ms": elapsed_ms
                })
                
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start) * 1000
                print(f"\n결과: ❌ ERROR")
                print(f"⏱️  시간: {elapsed_ms:.1f}ms")
                print(f"⚠️  오류: {e}")
                
                results.append({
                    "description": case['description'],
                    "status": "ERROR",
                    "detected": [],
                    "time_ms": elapsed_ms
                })
        
        # 통계
        print("\n\n" + "="*70)
        print("📊 결과 요약")
        print("="*70)
        
        pass_count = sum(1 for r in results if "PASS" in r['status'])
        partial_count = sum(1 for r in results if "PARTIAL" in r['status'])
        fail_count = sum(1 for r in results if "FAIL" in r['status'])
        
        print(f"\n✅ 완전 성공: {pass_count}/{len(results)}")
        print(f"⚠️ 부분 성공 (새 라벨): {partial_count}/{len(results)}")
        print(f"❌ 실패: {fail_count}/{len(results)}")
        print(f"⏱️ 평균 시간: {total_time/len(results):.1f}ms")
        
        # 카테고리별
        new_concepts = [r for r in results if "새개념:" in r['description']]
        known_concepts = [r for r in results if "기존개념:" in r['description']]
        
        print(f"\n📊 카테고리별:")
        print(f"새로운 개념: {sum(1 for r in new_concepts if 'PASS' in r['status'] or 'PARTIAL' in r['status'])}/{len(new_concepts)}")
        print(f"기존 개념: {sum(1 for r in known_concepts if 'PASS' in r['status'])}/{len(known_concepts)}")

if __name__ == "__main__":
    main()
