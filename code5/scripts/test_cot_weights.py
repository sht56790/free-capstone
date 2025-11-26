"""
CoT + 가중치 개선 효과 테스트
- 다양한 형식의 민감정보 탐지
- 새로운 패턴 대응력 확인
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
import time
from services.ollama_service import judge_sensitive_with_ollama

# 확장된 테스트 케이스 (50개 - 다양한 형식과 패턴)
TEST_CASES = [
    # === 기본 패턴 (10개) ===
    {
        "text": "홍길동 010-1234-5678",
        "expected": ["NAME", "PHONE"],
        "description": "기본: 이름 + 전화번호"
    },
    {
        "text": "계좌번호 110-123-456789",
        "expected": ["ACCOUNT"],
        "description": "기본: 계좌번호"
    },
    {
        "text": "김영수 고객님",
        "expected": ["NAME"],
        "description": "기본: 이름 + 존칭"
    },
    {
        "text": "주민번호 901225-1234567",
        "expected": ["SSN"],
        "description": "기본: 주민번호"
    },
    {
        "text": "카드번호 1234-5678-9012-3456",
        "expected": ["CARD"],
        "description": "기본: 카드번호"
    },
    {
        "text": "금리는 3.5%입니다",
        "expected": ["FIXED_RATE"],
        "description": "기본: 금리 확정"
    },
    {
        "text": "100만원 송금해주세요",
        "expected": ["TRANSACTION"],
        "description": "기본: 거래 요청"
    },
    {
        "text": "서울시 강남구 테헤란로 123",
        "expected": ["ADDRESS"],
        "description": "기본: 주소"
    },
    {
        "text": "연락처 02-3456-7890",
        "expected": ["PHONE"],
        "description": "기본: 유선전화"
    },
    {
        "text": "이메일 hong@example.com",
        "expected": [],
        "description": "기본: 이메일 (탐지안함)"
    },
    
    # === 새로운 형식 (15개) ===
    {
        "text": "고객명: 이영희님",
        "expected": ["NAME"],
        "description": "새형식: 고객명 라벨"
    },
    {
        "text": "성함이 어떻게 되시나요? 박철수입니다",
        "expected": ["NAME"],
        "description": "새형식: 자기소개 이름"
    },
    {
        "text": "잔액이 5천만원 있습니다",
        "expected": ["AMOUNT"],
        "description": "새형식: 잔액 정보"
    },
    {
        "text": "대출금액은 3억원입니다",
        "expected": ["AMOUNT"],
        "description": "새형식: 대출 금액"
    },
    {
        "text": "연봉 8,000만원",
        "expected": ["AMOUNT"],
        "description": "새형식: 연봉"
    },
    {
        "text": "월급여 350만원 수령중",
        "expected": ["AMOUNT"],
        "description": "새형식: 월급"
    },
    {
        "text": "거주지: 경기도 성남시 분당구",
        "expected": ["ADDRESS"],
        "description": "새형식: 거주지 라벨"
    },
    {
        "text": "현주소는 부산광역시 해운대구",
        "expected": ["ADDRESS"],
        "description": "새형식: 현주소"
    },
    {
        "text": "핸드폰 010-9999-8888로 연락주세요",
        "expected": ["PHONE"],
        "description": "새형식: 핸드폰 표현"
    },
    {
        "text": "전화번호는 031-123-4567",
        "expected": ["PHONE"],
        "description": "새형식: 지역번호"
    },
    {
        "text": "예금 계좌 1002-123-456789",
        "expected": ["ACCOUNT"],
        "description": "새형식: 예금계좌"
    },
    {
        "text": "신용카드 4567-8901-2345-6789",
        "expected": ["CARD"],
        "description": "새형식: 신용카드"
    },
    {
        "text": "주민등록번호 851015-2345678",
        "expected": ["SSN"],
        "description": "새형식: 주민등록번호"
    },
    {
        "text": "적용금리는 4.2%로 확정",
        "expected": ["FIXED_RATE"],
        "description": "새형식: 적용금리 확정"
    },
    {
        "text": "이체 실행 부탁드립니다",
        "expected": ["TRANSACTION"],
        "description": "새형식: 이체 실행"
    },
    
    # === 복합 패턴 (10개) ===
    {
        "text": "김철수 고객님 계좌 110-456-789012 잔액 1,500만원",
        "expected": ["NAME", "ACCOUNT", "AMOUNT"],
        "description": "복합: 이름+계좌+금액"
    },
    {
        "text": "박영희(010-1111-2222) 주소 서울시 종로구",
        "expected": ["NAME", "PHONE", "ADDRESS"],
        "description": "복합: 이름+전화+주소"
    },
    {
        "text": "이민준 850505-1234567 계좌 990-888-777777",
        "expected": ["NAME", "SSN", "ACCOUNT"],
        "description": "복합: 이름+주민번호+계좌"
    },
    {
        "text": "카드 1234-5678-9012-3456로 500만원 결제",
        "expected": ["CARD", "AMOUNT"],
        "description": "복합: 카드+금액"
    },
    {
        "text": "최서연 대리 02-456-7890 담당",
        "expected": ["NAME", "PHONE"],
        "description": "복합: 직급+이름+전화"
    },
    {
        "text": "정우진 고객 대출 2억 금리 3.8% 적용",
        "expected": ["NAME", "AMOUNT", "FIXED_RATE"],
        "description": "복합: 이름+대출액+금리"
    },
    {
        "text": "강민지(010-3333-4444) 잔액 7,800만원 확인",
        "expected": ["NAME", "PHONE", "AMOUNT"],
        "description": "복합: 이름+전화+잔액"
    },
    {
        "text": "주민번호 920303-2234567 계좌이체 신청",
        "expected": ["SSN", "TRANSACTION"],
        "description": "복합: 주민번호+거래요청"
    },
    {
        "text": "윤서준 010-7777-8888 서울시 마포구 거주",
        "expected": ["NAME", "PHONE", "ADDRESS"],
        "description": "복합: 이름+전화+거주지"
    },
    {
        "text": "계좌 330-444-555555 금리 2.5% 송금 요청",
        "expected": ["ACCOUNT", "FIXED_RATE", "TRANSACTION"],
        "description": "복합: 계좌+금리+거래"
    },
    
    # === 부정 예제 (10개 - 탐지하면 안됨) ===
    {
        "text": "대출 상담 받고 싶습니다",
        "expected": [],
        "description": "부정: 일반 상담 문의"
    },
    {
        "text": "금리 조건이 궁금합니다",
        "expected": [],
        "description": "부정: 금리 문의"
    },
    {
        "text": "영업시간이 어떻게 되나요",
        "expected": [],
        "description": "부정: 업무시간 문의"
    },
    {
        "text": "예금 상품에 대해 설명해주세요",
        "expected": [],
        "description": "부정: 상품 설명 요청"
    },
    {
        "text": "신용카드 발급 절차가 어떻게 되나요",
        "expected": [],
        "description": "부정: 절차 문의"
    },
    {
        "text": "계좌 개설하려면 무엇이 필요한가요",
        "expected": [],
        "description": "부정: 개설 문의"
    },
    {
        "text": "대출 한도는 어떻게 결정되나요",
        "expected": [],
        "description": "부정: 한도 문의"
    },
    {
        "text": "인터넷뱅킹 이용 방법 알려주세요",
        "expected": [],
        "description": "부정: 이용방법 문의"
    },
    {
        "text": "적금 가입하고 싶어요",
        "expected": [],
        "description": "부정: 가입 희망"
    },
    {
        "text": "지점 위치가 어디인가요",
        "expected": [],
        "description": "부정: 위치 문의"
    },
    
    # === 고급 패턴 (5개 - 문맥 파악 필요) ===
    {
        "text": "박민수 대리님께 전달 부탁드립니다",
        "expected": ["NAME"],
        "description": "고급: 직급 포함 이름"
    },
    {
        "text": "담당자 김영희 과장님",
        "expected": ["NAME"],
        "description": "고급: 직급 포함 담당자"
    },
    {
        "text": "이 상품의 금리가 2.8% 적용됩니다",
        "expected": ["FIXED_RATE"],
        "description": "고급: 금리 확정 (다른 표현)"
    },
    {
        "text": "출금 처리 부탁드립니다",
        "expected": ["TRANSACTION"],
        "description": "고급: 출금 요청"
    },
    {
        "text": "보험금 1,200만원 지급 예정",
        "expected": ["AMOUNT"],
        "description": "고급: 보험금 금액"
    },
]

def calculate_metrics(results):
    """정확도 지표 계산"""
    tp = 0  # True Positive
    fp = 0  # False Positive  
    fn = 0  # False Negative
    
    for r in results:
        expected_set = set(r['expected'])
        detected_set = set(r['detected'])
        
        tp += len(expected_set & detected_set)  # 정확히 맞춘 것
        fp += len(detected_set - expected_set)  # 잘못 탐지
        fn += len(expected_set - detected_set)  # 놓친 것
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "precision": precision * 100,
        "recall": recall * 100,
        "f1": f1 * 100,
        "tp": tp,
        "fp": fp,
        "fn": fn
    }

def main():
    app = create_app()
    
    with app.app_context():
        print("="*70)
        print("🚀 CoT + 가중치 시스템 성능 테스트")
        print("="*70)
        print(f"총 테스트 케이스: {len(TEST_CASES)}개")
        print()
        
        results = []
        total_time = 0
        
        for i, case in enumerate(TEST_CASES, 1):
            print(f"\n{'='*70}")
            print(f"테스트 {i}/{len(TEST_CASES)}: {case['description']}")
            print('='*70)
            print(f"입력: {case['text']}")
            print(f"기대: {case['expected']}")
            
            start = time.perf_counter()
            
            try:
                detections = judge_sensitive_with_ollama(case['text'], use_cache=False)
                elapsed_ms = (time.perf_counter() - start) * 1000
                total_time += elapsed_ms
                
                detected_labels = [d['label'] for d in detections]
                
                # 결과 판정
                expected_set = set(case['expected'])
                detected_set = set(detected_labels)
                
                if expected_set == detected_set:
                    status = "✅ PASS"
                elif len(detected_set) == 0 and len(expected_set) > 0:
                    status = "❌ MISS (놓침)"
                elif len(detected_set) > len(expected_set):
                    status = "⚠️ OVER (과탐지)"
                else:
                    status = "⚠️ PARTIAL (부분)"
                
                print(f"\n결과: {status}")
                print(f"⏱️  시간: {elapsed_ms:.1f}ms")
                print(f"🔍 탐지: {detected_labels}")
                
                if detections:
                    for d in detections:
                        span_text = case['text'][d['span'][0]:d['span'][1]]
                        priority = d.get('priority', '?')
                        confidence = d.get('confidence', '?')
                        print(f"   - {d['label']} (P{priority}): '{span_text}' → {d['action']} (신뢰도: {confidence})")
                
                results.append({
                    "description": case['description'],
                    "expected": case['expected'],
                    "detected": detected_labels,
                    "time_ms": elapsed_ms,
                    "status": status
                })
                
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start) * 1000
                total_time += elapsed_ms
                print(f"\n결과: ❌ ERROR")
                print(f"⏱️  시간: {elapsed_ms:.1f}ms")
                print(f"⚠️  오류: {e}")
                
                results.append({
                    "description": case['description'],
                    "expected": case['expected'],
                    "detected": [],
                    "time_ms": elapsed_ms,
                    "status": "ERROR"
                })
        
        # 최종 통계
        print("\n\n" + "="*70)
        print("📊 최종 결과")
        print("="*70)
        
        pass_count = sum(1 for r in results if r['status'] == "✅ PASS")
        accuracy = (pass_count / len(results)) * 100
        avg_time = total_time / len(results)
        
        print(f"\n정확도 (완전 일치): {pass_count}/{len(results)} ({accuracy:.1f}%)")
        print(f"평균 처리 시간: {avg_time:.1f}ms")
        print(f"총 처리 시간: {total_time:.1f}ms")
        
        # Precision, Recall, F1 계산
        metrics = calculate_metrics(results)
        print(f"\n📈 상세 지표:")
        print(f"Precision (정밀도): {metrics['precision']:.1f}%")
        print(f"Recall (재현율): {metrics['recall']:.1f}%")
        print(f"F1 Score: {metrics['f1']:.1f}%")
        print(f"\nTP (정답): {metrics['tp']}")
        print(f"FP (오탐): {metrics['fp']}")
        print(f"FN (누락): {metrics['fn']}")
        
        # 카테고리별 분석
        print(f"\n📋 카테고리별 성과:")
        basic = [r for r in results if "기본:" in r['description']]
        new_format = [r for r in results if "새 형식:" in r['description']]
        complex_pattern = [r for r in results if "복합:" in r['description'] or "고급:" in r['description']]
        negative = [r for r in results if "부정:" in r['description']]
        
        print(f"기본 패턴: {sum(1 for r in basic if r['status'] == '✅ PASS')}/{len(basic)}")
        print(f"새로운 형식: {sum(1 for r in new_format if r['status'] == '✅ PASS')}/{len(new_format)}")
        print(f"복합/고급: {sum(1 for r in complex_pattern if r['status'] == '✅ PASS')}/{len(complex_pattern)}")
        print(f"부정 예제: {sum(1 for r in negative if r['status'] == '✅ PASS')}/{len(negative)}")

if __name__ == "__main__":
    main()
