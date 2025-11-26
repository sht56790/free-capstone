"""
Ollama 모델 성능 벤치마크 스크립트
qwen3:8b, llama3.1:8b, mistral:7b 비교
- 정확도 (민감정보 탐지율)
- 속도 (응답 시간)
- 안정성 (JSON 파싱 성공률)
"""
import sys
import os
import time
import json
from typing import List, Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.ollama_service import judge_sensitive_with_ollama

# 테스트 케이스
TEST_CASES = [
    {
        "id": 1,
        "input": "홍길동 고객님 계좌번호 123-456-789012로 10만원 이체 부탁드립니다.",
        "expected_labels": ["NAME", "ACCOUNT", "TRANSACTION_REQUEST"],
        "category": "개인정보+거래요청"
    },
    {
        "id": 2,
        "input": "금리는 어떻게 결정되나요?",
        "expected_labels": [],
        "category": "일반문의"
    },
    {
        "id": 3,
        "input": "저축 상품 금리는 연 3.5%입니다.",
        "expected_labels": ["FIXED_RATE"],
        "category": "확정표현"
    },
    {
        "id": 4,
        "input": "010-1234-5678로 연락 부탁드립니다.",
        "expected_labels": ["PHONE"],
        "category": "전화번호"
    },
    {
        "id": 5,
        "input": "수수료는 5,000원입니다.",
        "expected_labels": ["FIXED_FEE"],
        "category": "확정표현"
    },
    {
        "id": 6,
        "input": "대출 금리 정보 알려주세요.",
        "expected_labels": [],
        "category": "일반문의"
    },
    {
        "id": 7,
        "input": "고객번호 123456입니다. user@example.com으로 메일 보내주세요.",
        "expected_labels": ["CUSTOMER_ID", "EMAIL"],
        "category": "복합개인정보"
    },
    {
        "id": 8,
        "input": "서울시 강남구 테헤란로 123에 살고 있습니다.",
        "expected_labels": ["ADDRESS"],
        "category": "주소"
    },
    {
        "id": 9,
        "input": "대출 신청해주세요.",
        "expected_labels": ["TRANSACTION_REQUEST"],
        "category": "거래요청"
    },
    {
        "id": 10,
        "input": "계좌 이체 방법이 궁금합니다.",
        "expected_labels": [],
        "category": "일반문의"
    }
]

# 테스트할 모델 목록
MODELS = [
    "qwen3:8b",
    "llama3.1:8b",
    "mistral:7b"
]

def calculate_accuracy(detected: List[str], expected: List[str]) -> Dict[str, float]:
    """정확도 계산: Precision, Recall, F1"""
    detected_set = set(detected)
    expected_set = set(expected)
    
    if not expected_set and not detected_set:
        # True Negative: 민감정보 없고, 탐지도 안함
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "match": "TN"}
    
    if not expected_set:
        # False Positive: 민감정보 없는데 탐지함
        return {"precision": 0.0, "recall": 1.0, "f1": 0.0, "match": "FP"}
    
    if not detected_set:
        # False Negative: 민감정보 있는데 탐지 못함
        return {"precision": 1.0, "recall": 0.0, "f1": 0.0, "match": "FN"}
    
    # True Positive 계산
    tp = len(detected_set & expected_set)
    fp = len(detected_set - expected_set)
    fn = len(expected_set - detected_set)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "match": "TP" if tp > 0 else "MISS"
    }

def run_benchmark():
    """벤치마크 실행"""
    print("="*80)
    print("[Ollama Model Benchmark]")
    print("="*80)
    print()
    
    results = {}
    
    for model in MODELS:
        print(f"\n{'='*80}")
        print(f"[Model: {model}]")
        print(f"{'='*80}\n")
        
        model_results = {
            "total_time_ms": 0,
            "success_count": 0,
            "error_count": 0,
            "json_parse_errors": 0,
            "cases": [],
            "metrics": {"precision": [], "recall": [], "f1": []}
        }
        
        for case in TEST_CASES:
            print(f"[케이스 #{case['id']}] {case['category']}")
            print(f"  입력: {case['input'][:50]}{'...' if len(case['input']) > 50 else ''}")
            
            start_time = time.perf_counter()
            try:
                detections = judge_sensitive_with_ollama(case['input'], model=model)
                elapsed_ms = int((time.perf_counter() - start_time) * 1000)
                
                detected_labels = [d['label'] for d in detections]
                metrics = calculate_accuracy(detected_labels, case['expected_labels'])
                
                model_results["total_time_ms"] += elapsed_ms
                model_results["success_count"] += 1
                model_results["metrics"]["precision"].append(metrics["precision"])
                model_results["metrics"]["recall"].append(metrics["recall"])
                model_results["metrics"]["f1"].append(metrics["f1"])
                
                status = "✓" if metrics["f1"] >= 0.8 else "⚠" if metrics["f1"] >= 0.5 else "✗"
                print(f"  {status} 탐지: {detected_labels} | 예상: {case['expected_labels']}")
                print(f"  ⏱️  {elapsed_ms}ms | F1: {metrics['f1']:.2f} | {metrics['match']}")
                
                model_results["cases"].append({
                    "case_id": case['id'],
                    "detected": detected_labels,
                    "expected": case['expected_labels'],
                    "metrics": metrics,
                    "time_ms": elapsed_ms,
                    "success": True
                })
                
            except Exception as e:
                elapsed_ms = int((time.perf_counter() - start_time) * 1000)
                model_results["error_count"] += 1
                print(f"  ✗ 오류: {str(e)[:60]}")
                print(f"  ⏱️  {elapsed_ms}ms")
                
                model_results["cases"].append({
                    "case_id": case['id'],
                    "error": str(e),
                    "time_ms": elapsed_ms,
                    "success": False
                })
            
            print()
        
        # 모델별 최종 통계
        avg_precision = sum(model_results["metrics"]["precision"]) / len(model_results["metrics"]["precision"]) if model_results["metrics"]["precision"] else 0
        avg_recall = sum(model_results["metrics"]["recall"]) / len(model_results["metrics"]["recall"]) if model_results["metrics"]["recall"] else 0
        avg_f1 = sum(model_results["metrics"]["f1"]) / len(model_results["metrics"]["f1"]) if model_results["metrics"]["f1"] else 0
        avg_time = model_results["total_time_ms"] / len(TEST_CASES)
        
        model_results["summary"] = {
            "avg_precision": avg_precision,
            "avg_recall": avg_recall,
            "avg_f1": avg_f1,
            "avg_time_ms": avg_time,
            "success_rate": model_results["success_count"] / len(TEST_CASES)
        }
        
        print(f"[Results for {model}]")
        print(f"  Avg Precision: {avg_precision:.3f}")
        print(f"  Avg Recall:    {avg_recall:.3f}")
        print(f"  Avg F1 Score:  {avg_f1:.3f}")
        print(f"  Avg Time:      {avg_time:.0f}ms")
        print(f"  Success Rate:  {model_results['summary']['success_rate']*100:.1f}%")
        
        results[model] = model_results
    
    # 모델 비교
    print(f"\n{'='*80}")
    print("[Model Comparison Summary]")
    print(f"{'='*80}\n")
    
    print(f"{'모델':<20} {'F1 Score':<12} {'응답시간':<12} {'성공률':<10}")
    print("-"*80)
    for model, data in results.items():
        summary = data["summary"]
        print(f"{model:<20} {summary['avg_f1']:<12.3f} {summary['avg_time_ms']:<12.0f}ms {summary['success_rate']*100:<10.1f}%")
    
    # 최고 모델 선정
    best_f1_model = max(results.items(), key=lambda x: x[1]["summary"]["avg_f1"])
    best_speed_model = min(results.items(), key=lambda x: x[1]["summary"]["avg_time_ms"])
    
    print()
    print(f"[BEST] Accuracy: {best_f1_model[0]} (F1: {best_f1_model[1]['summary']['avg_f1']:.3f})")
    print(f"[BEST] Speed:    {best_speed_model[0]} ({best_speed_model[1]['summary']['avg_time_ms']:.0f}ms)")
    
    # 결과 저장
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    result_file = f"ollama_benchmark_{timestamp}.json"
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"\n[SAVED] Results saved to: {result_file}")
    print("="*80)

if __name__ == "__main__":
    try:
        run_benchmark()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Test cancelled.")
    except Exception as e:
        print(f"\n\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
