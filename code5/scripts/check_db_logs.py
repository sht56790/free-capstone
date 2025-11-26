"""
DB에 저장된 로그 데이터를 확인하는 스크립트
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models import Log
from database import db
from app import create_app
from datetime import datetime, timedelta

app = create_app()

with app.app_context():
    print("="*60)
    print("DB 로그 데이터 확인")
    print("="*60)
    
    total = Log.query.count()
    print(f"\n✅ 총 로그 개수: {total}개\n")
    
    if total == 0:
        print("❌ DB에 로그가 없습니다. 먼저 챗봇을 사용해서 로그를 생성하세요.")
    else:
        print("📊 최근 3개 로그:")
        print("-" * 60)
        logs = Log.query.order_by(Log.timestamp.desc()).limit(3).all()
        for i, log in enumerate(logs, 1):
            print(f"\n{i}. ID: {log.id}")
            print(f"   시간: {log.timestamp}")
            print(f"   사용자: {log.user_id}")
            print(f"   액션: {log.action}")
            print(f"   입력 탐지: {log.detections_in}")
            print(f"   프롬프트: {log.user_prompt[:50] if log.user_prompt else 'N/A'}...")
        
        print("\n" + "="*60)
        print("📈 액션별 통계:")
        print("-" * 60)
        mask_count = Log.query.filter_by(action='mask').count()
        block_count = Log.query.filter_by(action='block').count()
        allow_count = Log.query.filter_by(action='allow').count()
        print(f"  Mask:  {mask_count}개")
        print(f"  Block: {block_count}개")
        print(f"  Allow: {allow_count}개")
        
        print("\n" + "="*60)
        print("📅 최근 7일간 로그:")
        print("-" * 60)
        seven_days_ago = datetime.utcnow() - timedelta(days=6)
        recent_logs = Log.query.filter(Log.timestamp >= seven_days_ago).all()
        print(f"  최근 7일 로그: {len(recent_logs)}개")
        
        print("\n" + "="*60)
        print("🏷️ 탐지 유형 분포:")
        print("-" * 60)
        from collections import Counter
        pii_counts = Counter()
        for log in Log.query.all():
            if isinstance(log.detections_in, list) and len(log.detections_in) > 0:
                for detection in log.detections_in:
                    if isinstance(detection, dict) and 'name' in detection:
                        pii_counts[detection['name']] += 1
        
        if pii_counts:
            for pii_type, count in pii_counts.most_common():
                print(f"  {pii_type}: {count}건")
        else:
            print("  (탐지된 항목 없음)")
    
    print("\n" + "="*60)
