"""
최근 7일 로그의 탐지 내역을 상세 확인
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models import Log
from database import db
from app import create_app
from datetime import datetime, timedelta
from collections import Counter

app = create_app()

with app.app_context():
    print("="*60)
    print("최근 7일 탐지 내역 상세 확인")
    print("="*60)
    
    # 최근 7일 로그
    today = datetime.utcnow().date()
    seven_days_ago = today - timedelta(days=6)
    seven_days_ago_datetime = datetime.combine(seven_days_ago, datetime.min.time())
    logs = Log.query.filter(Log.timestamp >= seven_days_ago_datetime).all()
    
    print(f"\n✅ 최근 7일 로그: {len(logs)}개\n")
    
    # 액션별 통계
    mask_count = sum(1 for log in logs if log.action == 'mask')
    block_count = sum(1 for log in logs if log.action == 'block')
    print(f"📊 액션별 통계:")
    print(f"  Mask:  {mask_count}개")
    print(f"  Block: {block_count}개")
    print(f"  합계:  {mask_count + block_count}개 (탐지된 민감정보)")
    
    # 입력 탐지 분석
    print(f"\n📥 입력(detections_in) 탐지:")
    print("-" * 60)
    in_counts = Counter()
    in_total = 0
    for log in logs:
        if isinstance(log.detections_in, list) and len(log.detections_in) > 0:
            for detection in log.detections_in:
                if isinstance(detection, dict) and 'name' in detection:
                    in_counts[detection['name']] += 1
                    in_total += 1
    
    print(f"  총 {in_total}건 탐지")
    for name, count in in_counts.most_common():
        print(f"    {name}: {count}건")
    
    # 출력 탐지 분석
    print(f"\n📤 출력(detections_out) 탐지:")
    print("-" * 60)
    out_counts = Counter()
    out_total = 0
    for log in logs:
        if isinstance(log.detections_out, list) and len(log.detections_out) > 0:
            for detection in log.detections_out:
                if isinstance(detection, dict) and 'name' in detection:
                    out_counts[detection['name']] += 1
                    out_total += 1
    
    print(f"  총 {out_total}건 탐지")
    for name, count in out_counts.most_common():
        print(f"    {name}: {count}건")
    
    # 통합 카운트
    print(f"\n🔀 통합 탐지 유형 (입력+출력):")
    print("-" * 60)
    all_counts = in_counts + out_counts
    total_detections = sum(all_counts.values())
    print(f"  총 {total_detections}건 탐지")
    for name, count in all_counts.most_common():
        print(f"    {name}: {count}건")
    
    # 샘플 로그 확인 (민감정보 탐지가 있는 것만)
    print(f"\n📋 샘플 로그 (최근 3개):")
    print("-" * 60)
    sample_logs = [log for log in logs if 
                   (isinstance(log.detections_in, list) and len(log.detections_in) > 0) or
                   (isinstance(log.detections_out, list) and len(log.detections_out) > 0)][:3]
    
    for i, log in enumerate(sample_logs, 1):
        print(f"\n{i}. 로그 ID: {log.id} / {log.timestamp}")
        print(f"   액션: {log.action}")
        in_items = len(log.detections_in) if isinstance(log.detections_in, list) else 0
        out_items = len(log.detections_out) if isinstance(log.detections_out, list) else 0
        print(f"   입력 탐지: {in_items}건")
        if in_items > 0:
            for det in log.detections_in:
                print(f"     - {det.get('name', 'Unknown')}")
        print(f"   출력 탐지: {out_items}건")
        if out_items > 0:
            for det in log.detections_out:
                print(f"     - {det.get('name', 'Unknown')}")
    
    print("\n" + "="*60)
