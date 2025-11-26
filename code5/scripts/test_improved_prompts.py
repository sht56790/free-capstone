"""
개선된 프롬프트 성능 테스트
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
import time
from services.ollama_service_improved import (
    judge_sensitive_improved_v1,
    judge_sensitive_improved_v2,
    judge_sensitive_improved_v3,
    judge_sensitive_hybrid
)
from services.ollama_service import judge_sensitive_with_ollama

# 테스트 케이스
TEST_CASES = [
    {
        "text": "홍길동 010-1234-5678",
        "expected": ["NAME", "PHONE"],
        "description": "이름 + 전화번호"
    },
    {
        "text": "계좌번호 110-123-456789",
        "expected": ["ACCOUNT"],
        "description": "계좌번호"
    },
    {
        "text": "금리는 3.5%입니다",
        "expected": ["FIXED_RATE"],
        "description": "금리 확정 표현"
    },
    {
        "text": "송금해주세요",
        "expected": ["TRANSACTION"],
        "description": "거래 요청"
    },
    {
        "text": "주민번호 801225-1234567",
        "expected": ["SSN"],
        "description": "주민번호"
    },
    {
        "text": "대출 상담 받고 싶습니다",
        "expected": [],
        "description": "일반 질문 (탐지 안해야 함)"
    },
    {
        "text": "김철수 주소 서울시 강남구 테헤란로 123",
        "expected": ["NAME", "ADDRESS"],
        "description": "이름 + 주소"
    },
    {
        "text": "카드번호 1234-5678-9012-3456",
        "expected": ["CARD"],
        "description": "카드번호"
    }
]

def evaluate_method(method_name, method_func):
    """특정 방법 평가"""
    print(f"\n{'='*70}")
    print(f"🔍 {method_name} 테스트")
    print('='*70)
    
    total_time = 0
    correct = 0
    total = len(TEST_CASES)
    
    for i, case in enumerate(TEST_CASES, 1):
        start = time.perf_counter()
        
        try:
            result = method_func(case["text"], use_cache=False)
            elapsed_ms = (time.perf_counter() - start) * 1000
            total_time += elapsed_ms
            
            detected_labels = [r["label"] for r in result]
            
            # 정확도 판정
            expected_set = set(case["expected"])
            detected_set = set(detected_labels)
            
            if expected_set == detected_set:
                status = "✅ PASS"
                correct += 1
            else:
                status = "❌ FAIL"
            
            print(f"\n테스트 {i}: {case['description']}")
            print(f"  {status}")
            print(f"  ⏱️  시간: {elapsed_ms:.1f}ms")
            print(f"  📝 입력: {case['text']}")
            print(f"  🎯 기대: {case['expected']}")
            print(f"  🔍 탐지: {detected_labels}")
            
            if result:
                for r in result:
                    span_text = case["text"][r["span"][0]:r["span"][1]]
                    print(f"     - {r['label']}: '{span_text}' → {r['action']}")
        
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            total_time += elapsed_ms
            print(f"\n테스트 {i}: {case['description']}")
            print(f"  ❌ ERROR")
            print(f"  ⏱️  시간: {elapsed_ms:.1f}ms")
            print(f"  ⚠️  오류: {e}")
    
    # 통계
    accuracy = (correct / total) * 100
    avg_time = total_time / total
    
    print(f"\n{'='*70}")
    print(f"📊 {method_name} 결과")
    print('='*70)
    print(f"정확도: {correct}/{total} ({accuracy:.1f}%)")
    print(f"평균 시간: {avg_time:.1f}ms")
    print(f"총 시간: {total_time:.1f}ms")
    
    return {
        "method": method_name,
        "accuracy": accuracy,
        "avg_time_ms": avg_time,
        "correct": correct,
        "total": total
    }

def main():
    app = create_app()
    
    with app.app_context():
        print("="*70)
        print("🚀 프롬프트 개선 성능 비교 테스트")
        print("="*70)
        print(f"총 테스트 케이스: {len(TEST_CASES)}개")
        print()
        
        results = []
        
        # 1. 기존 방법
        print("\n\n🔷 기존 방법 (Few-Shot Basic)")
        r1 = evaluate_method("기존 방법", judge_sensitive_with_ollama)
        results.append(r1)
        
        # 2. 개선안 1: CoT + 가중치
        print("\n\n🔷 개선안 1 (Chain-of-Thought + Priority)")
        r2 = evaluate_method("CoT + 가중치", judge_sensitive_improved_v1)
        results.append(r2)
        
        # 3. 개선안 2: 자기 검증
        print("\n\n🔷 개선안 2 (Self-Verification 2단계)")
        r3 = evaluate_method("자기 검증", judge_sensitive_improved_v2)
        results.append(r3)
        
        # 4. 개선안 3: 강화된 Few-Shot
        print("\n\n🔷 개선안 3 (강화 Few-Shot + 부정 예제)")
        r4 = evaluate_method("강화 Few-Shot", judge_sensitive_improved_v3)
        results.append(r4)
        
        # 5. 하이브리드
        print("\n\n🔷 하이브리드 (투표 방식)")
        r5 = evaluate_method("하이브리드", judge_sensitive_hybrid)
        results.append(r5)
        
        # 최종 비교
        print("\n\n" + "="*70)
        print("📊 최종 비교 결과")
        print("="*70)
        print(f"{'방법':<25} {'정확도':<15} {'평균 시간':<15}")
        print("-"*70)
        
        for r in results:
            print(f"{r['method']:<25} {r['accuracy']:>6.1f}%      {r['avg_time_ms']:>8.1f}ms")
        
        # 최고 성능 찾기
        best_accuracy = max(results, key=lambda x: x['accuracy'])
        best_speed = min(results, key=lambda x: x['avg_time_ms'])
        
        print()
        print(f"🏆 최고 정확도: {best_accuracy['method']} ({best_accuracy['accuracy']:.1f}%)")
        print(f"⚡ 최고 속도: {best_speed['method']} ({best_speed['avg_time_ms']:.1f}ms)")

if __name__ == "__main__":
    main()
