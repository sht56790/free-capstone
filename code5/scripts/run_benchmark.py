"""
벤치마크 30케이스 자동 테스트 스크립트
민감정보 탐지 및 마스킹 성능을 평가합니다.
"""
import json
import requests
import sys
import os
from datetime import datetime
from collections import defaultdict

# 서버 설정
API_URL = "http://localhost:8081/chat"
LOGIN_URL = "http://localhost:8081/login"

# 색상 코드
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def login():
    """로그인하여 세션 쿠키 얻기"""
    session = requests.Session()
    login_data = {
        "id": "user@company.com",
        "password": "user_password"
    }
    response = session.post(LOGIN_URL, json=login_data)
    if response.status_code == 200:
        print(f"{GREEN}✓{RESET} 로그인 성공")
        return session
    else:
        print(f"{RED}✗{RESET} 로그인 실패")
        return None

def test_case(session, case_id, input_text, expected_action):
    """단일 케이스 테스트"""
    form_data = {
        'model': 'ollama:qwen3:8b',
        'messages': '[]',
        'user_prompt_text': input_text
    }
    
    try:
        response = session.post(API_URL, data=form_data, timeout=30)
        
        # 응답 분석
        if response.status_code == 400:
            # 차단된 경우
            actual_action = "block"
            result = response.json()
            detail = result.get('detail', '')
        elif response.status_code == 200:
            # 정상 처리 (mask 또는 allow)
            result = response.json()
            notice = result.get('notice', '')
            if notice and '마스킹' in notice:
                actual_action = "mask"
            else:
                actual_action = "allow"
            detail = notice if notice else "정상 처리"
        else:
            actual_action = "error"
            detail = f"HTTP {response.status_code}"
        
        # 정답 비교
        is_correct = (actual_action == expected_action)
        
        return {
            "case_id": case_id,
            "input": input_text,
            "expected": expected_action,
            "actual": actual_action,
            "correct": is_correct,
            "detail": detail
        }
    
    except requests.exceptions.Timeout:
        return {
            "case_id": case_id,
            "input": input_text,
            "expected": expected_action,
            "actual": "timeout",
            "correct": False,
            "detail": "요청 시간 초과"
        }
    except Exception as e:
        return {
            "case_id": case_id,
            "input": input_text,
            "expected": expected_action,
            "actual": "error",
            "correct": False,
            "detail": str(e)
        }

def run_benchmark():
    """벤치마크 실행"""
    print("="*70)
    print("🧪 민감정보 탐지/마스킹 벤치마크 테스트")
    print("="*70)
    print()
    
    # 벤치마크 데이터 로드
    benchmark_file = "config/benchmark_30_cases.json"
    if not os.path.exists(benchmark_file):
        print(f"{RED}✗{RESET} {benchmark_file} 파일을 찾을 수 없습니다.")
        return
    
    with open(benchmark_file, 'r', encoding='utf-8') as f:
        benchmark_data = json.load(f)
    
    # 로그인
    session = login()
    if not session:
        return
    
    print()
    print(f"📝 총 테스트 케이스: {sum(len(cat['cases']) for cat in benchmark_data['categories'])}개")
    print()
    
    # 결과 저장
    results = []
    category_stats = defaultdict(lambda: {"total": 0, "correct": 0})
    
    # 카테고리별 테스트
    for category in benchmark_data['categories']:
        cat_name = category['category']
        print(f"\n{'='*70}")
        print(f"📂 카테고리: {cat_name}")
        print(f"{'='*70}")
        
        for case in category['cases']:
            case_id = case['id']
            input_text = case['input']
            expected = case['expected_action']
            
            print(f"\n[케이스 #{case_id}]")
            print(f"  입력: {input_text[:60]}{'...' if len(input_text) > 60 else ''}")
            print(f"  예상: {expected.upper()}", end=" ")
            
            # 테스트 실행
            result = test_case(session, case_id, input_text, expected)
            results.append(result)
            
            # 결과 출력
            if result['correct']:
                print(f"→ {GREEN}✓ PASS{RESET} ({result['actual'].upper()})")
                category_stats[cat_name]["correct"] += 1
            else:
                print(f"→ {RED}✗ FAIL{RESET} (실제: {result['actual'].upper()})")
                print(f"     사유: {result['detail'][:80]}")
            
            category_stats[cat_name]["total"] += 1
    
    # 전체 통계
    print(f"\n{'='*70}")
    print("📊 최종 결과")
    print(f"{'='*70}\n")
    
    total_cases = len(results)
    total_correct = sum(1 for r in results if r['correct'])
    accuracy = (total_correct / total_cases * 100) if total_cases > 0 else 0
    
    print(f"전체 정확도: {BLUE}{accuracy:.1f}%{RESET} ({total_correct}/{total_cases})")
    print()
    
    # 카테고리별 통계
    print("카테고리별 정확도:")
    for cat_name, stats in category_stats.items():
        cat_accuracy = (stats['correct'] / stats['total'] * 100) if stats['total'] > 0 else 0
        color = GREEN if cat_accuracy >= 80 else YELLOW if cat_accuracy >= 60 else RED
        print(f"  {cat_name:20s}: {color}{cat_accuracy:5.1f}%{RESET} ({stats['correct']}/{stats['total']})")
    
    # 오답 분석
    wrong_cases = [r for r in results if not r['correct']]
    if wrong_cases:
        print(f"\n{RED}오답 케이스 ({len(wrong_cases)}건):{RESET}")
        print("-"*70)
        for r in wrong_cases:
            print(f"  #{r['case_id']:2d} | 예상: {r['expected']:5s} | 실제: {r['actual']:7s} | {r['input'][:40]}")
    
    # 액션별 통계
    print(f"\n액션별 통계:")
    action_stats = defaultdict(lambda: {"total": 0, "correct": 0})
    for r in results:
        action_stats[r['expected']]["total"] += 1
        if r['correct']:
            action_stats[r['expected']]["correct"] += 1
    
    for action, stats in sorted(action_stats.items()):
        acc = (stats['correct'] / stats['total'] * 100) if stats['total'] > 0 else 0
        print(f"  {action.upper():6s}: {acc:5.1f}% ({stats['correct']}/{stats['total']})")
    
    # 결과 저장
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = f"benchmark_result_{timestamp}.json"
    
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump({
            "timestamp": timestamp,
            "total_cases": total_cases,
            "correct_cases": total_correct,
            "accuracy": accuracy,
            "category_stats": dict(category_stats),
            "action_stats": dict(action_stats),
            "results": results
        }, f, ensure_ascii=False, indent=2)
    
    print(f"\n{GREEN}✓{RESET} 결과가 {result_file}에 저장되었습니다.")
    print("="*70)

if __name__ == "__main__":
    try:
        run_benchmark()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}테스트가 중단되었습니다.{RESET}")
    except Exception as e:
        print(f"\n{RED}오류 발생: {e}{RESET}")
        import traceback
        traceback.print_exc()
