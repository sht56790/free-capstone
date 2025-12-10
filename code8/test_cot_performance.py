"""
CoT + 가중치 시스템 성능 평가 스크립트
- 정규식 vs Ollama Basic vs CoT + 가중치 비교
- Precision, Recall, F1 Score 계산
"""
import json
from typing import List, Dict, Tuple
from services.ollama_service import judge_sensitive_with_ollama
from services.policy_service import apply_patterns
from models import Rule
from database import db
from app import create_app

# 테스트 데이터셋 (Ground Truth)
TEST_CASES = [
    # (입력 텍스트, 예상 탐지 항목 리스트, 예상 액션)
    {
        "text": "홍길동 010-1234-5678",
        "expected": [
            {"label": "NAME", "action": "mask"},
            {"label": "PHONE", "action": "mask"}
        ],
        "description": "이름 + 전화번호"
    },
    {
        "text": "계좌번호 110-123-456789로 송금해주세요",
        "expected": [
            {"label": "ACCOUNT", "action": "block"},
            {"label": "TRANSACTION", "action": "block"}
        ],
        "description": "계좌번호 + 거래 요청"
    },
    {
        "text": "금리가 어떻게 되나요?",
        "expected": [],
        "description": "일반 질문 (민감정보 없음)"
    },
    {
        "text": "이 상품의 금리는 3.5%로 확정됩니다",
        "expected": [
            {"label": "FIXED_RATE", "action": "block"}
        ],
        "description": "금리 확정 (법적 책임)"
    },
    {
        "text": "VIP고객코드 GOLD-12345",
        "expected": [
            {"label": "VIP_CODE", "action": "block"}
        ],
        "description": "신규 타입 (VIP 코드)"
    },
    {
        "text": "시크릿코드 ABC123XYZ",
        "expected": [
            {"label": "SECRET_CODE", "action": "block"}
        ],
        "description": "신규 타입 (시크릿 코드)"
    },
    {
        "text": "고객번호 123456789",
        "expected": [
            {"label": "CUSTOMER_ID", "action": "mask"}
        ],
        "description": "고객번호"
    },
    {
        "text": "서울시 강남구 테헤란로 123",
        "expected": [
            {"label": "ADDRESS", "action": "mask"}
        ],
        "description": "주소"
    },
    {
        "text": "잔액이 500만원입니다",
        "expected": [
            {"label": "AMOUNT", "action": "mask"}
        ],
        "description": "금액 정보"
    },
    {
        "text": "영업시간은 9시부터 6시까지입니다",
        "expected": [],
        "description": "공개 정보 (민감정보 없음)"
    }
]


def evaluate_method(method_name: str, detection_func) -> Dict[str, float]:
    """
    특정 탐지 방법의 성능 평가
    
    Returns:
        {
            "accuracy": 정확도,
            "precision": 정밀도,
            "recall": 재현율,
            "f1": F1 Score,
            "true_positive": TP,
            "false_positive": FP,
            "false_negative": FN,
            "true_negative": TN
        }
    """
    tp = 0  # True Positive: 민감정보를 민감정보로 탐지
    fp = 0  # False Positive: 일반 정보를 민감정보로 오탐
    fn = 0  # False Negative: 민감정보를 놓침
    tn = 0  # True Negative: 일반 정보를 일반 정보로 판단
    
    results = []
    
    for case in TEST_CASES:
        text = case["text"]
        expected = case["expected"]
        description = case["description"]
        
        # 탐지 실행
        detected = detection_func(text)
        
        # 라벨 정규화 (대소문자 무시, 유사 라벨 통합)
        def normalize_label(label: str) -> str:
            label_map = {
                "NAME": "NAME",
                "고객명": "NAME",
                "PHONE": "PHONE",
                "전화번호": "PHONE",
                "ACCOUNT": "ACCOUNT",
                "계좌번호": "ACCOUNT",
                "CUSTOMER_ID": "CUSTOMER_ID",
                "고객번호": "CUSTOMER_ID",
                "ADDRESS": "ADDRESS",
                "주소": "ADDRESS",
                "AMOUNT": "AMOUNT",
                "금액": "AMOUNT",
                "FIXED_RATE": "FIXED_RATE",
                "금리확정": "FIXED_RATE",
                "TRANSACTION": "TRANSACTION",
                "거래요청": "TRANSACTION",
                "VIP_CODE": "VIP_CODE",
                "SECRET_CODE": "SECRET_CODE",
            }
            return label_map.get(label.upper(), label.upper())
        
        detected_labels = set(normalize_label(d["label"]) for d in detected)
        expected_labels = set(normalize_label(e["label"]) for e in expected)
        
        # TP, FP, FN 계산
        tp_case = len(detected_labels & expected_labels)
        fp_case = len(detected_labels - expected_labels)
        fn_case = len(expected_labels - detected_labels)
        tn_case = 1 if (not detected_labels and not expected_labels) else 0
        
        tp += tp_case
        fp += fp_case
        fn += fn_case
        tn += tn_case
        
        # 케이스별 결과 저장
        is_correct = (detected_labels == expected_labels)
        results.append({
            "text": text,
            "description": description,
            "expected": list(expected_labels),
            "detected": list(detected_labels),
            "correct": is_correct,
            "tp": tp_case,
            "fp": fp_case,
            "fn": fn_case
        })
    
    # 메트릭 계산
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "method": method_name,
        "accuracy": round(accuracy * 100, 1),
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1 * 100, 1),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "details": results
    }


def regex_only_detection(text: str) -> List[Dict]:
    """정규식만 사용한 탐지 (기존 방식)"""
    app = create_app()
    with app.app_context():
        rules = Rule.query.filter_by(is_active=True).all()
        _, findings = apply_patterns(text, rules)
        return findings


def ollama_cot_detection(text: str) -> List[Dict]:
    """Ollama CoT + 가중치 시스템 (개선 방식)"""
    return judge_sensitive_with_ollama(text, use_cache=False)


def main():
    print("=" * 80)
    print("🧪 민감정보 탐지 시스템 성능 평가")
    print("=" * 80)
    print(f"\n테스트 케이스 수: {len(TEST_CASES)}개\n")
    
    # 1. 정규식만 사용 (기존 방식)
    print("[1/2] 정규식 기반 탐지 평가 중...")
    regex_results = evaluate_method("정규식만 (Regex Only)", regex_only_detection)
    
    # 2. Ollama CoT + 가중치 (개선 방식)
    print("[2/2] CoT + 가중치 시스템 평가 중...")
    cot_results = evaluate_method("CoT + 가중치 (Improved)", ollama_cot_detection)
    
    # 결과 출력
    print("\n" + "=" * 80)
    print("📊 성능 비교 결과")
    print("=" * 80)
    
    methods = [regex_results, cot_results]
    
    print(f"\n{'방법':<25} {'정확도':<10} {'정밀도':<10} {'재현율':<10} {'F1 Score':<10}")
    print("-" * 80)
    for m in methods:
        print(f"{m['method']:<25} {m['accuracy']:>6.1f}%   {m['precision']:>6.1f}%   {m['recall']:>6.1f}%   {m['f1']:>6.1f}%")
    
    # 개선율 계산
    print("\n" + "=" * 80)
    print("📈 개선율")
    print("=" * 80)
    
    baseline = regex_results
    improved = cot_results
    
    acc_improvement = improved['accuracy'] - baseline['accuracy']
    prec_improvement = improved['precision'] - baseline['precision']
    rec_improvement = improved['recall'] - baseline['recall']
    f1_improvement = improved['f1'] - baseline['f1']
    
    print(f"정확도: {baseline['accuracy']:.1f}% → {improved['accuracy']:.1f}% ({acc_improvement:+.1f}%p)")
    print(f"정밀도: {baseline['precision']:.1f}% → {improved['precision']:.1f}% ({prec_improvement:+.1f}%p)")
    print(f"재현율: {baseline['recall']:.1f}% → {improved['recall']:.1f}% ({rec_improvement:+.1f}%p)")
    print(f"F1 Score: {baseline['f1']:.1f}% → {improved['f1']:.1f}% ({f1_improvement:+.1f}%p)")
    
    # 상세 결과 (케이스별)
    print("\n" + "=" * 80)
    print("🔍 케이스별 상세 결과 (CoT + 가중치)")
    print("=" * 80)
    
    for idx, detail in enumerate(cot_results['details'], 1):
        status = "✅" if detail['correct'] else "❌"
        print(f"\n[{idx}] {status} {detail['description']}")
        print(f"    입력: {detail['text']}")
        print(f"    예상: {detail['expected']}")
        print(f"    탐지: {detail['detected']}")
        if not detail['correct']:
            if detail['fp'] > 0:
                print(f"    ⚠️ 오탐 (False Positive): {detail['fp']}개")
            if detail['fn'] > 0:
                print(f"    ⚠️ 미탐 (False Negative): {detail['fn']}개")
    
    # JSON 저장
    output = {
        "test_date": "2025-11-28",
        "test_cases_count": len(TEST_CASES),
        "results": {
            "regex_only": regex_results,
            "cot_weight": cot_results
        },
        "improvements": {
            "accuracy": acc_improvement,
            "precision": prec_improvement,
            "recall": rec_improvement,
            "f1": f1_improvement
        }
    }
    
    with open("performance_results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    
    print("\n" + "=" * 80)
    print("✅ 결과가 'performance_results.json'에 저장되었습니다.")
    print("=" * 80)


if __name__ == "__main__":
    main()

