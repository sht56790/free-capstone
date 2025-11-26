"""
로그의 날짜별 분포를 확인하는 스크립트
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models import Log
from database import db
from app import create_app
from datetime import datetime, timedelta
from collections import defaultdict

app = create_app()

with app.app_context():
    print("="*60)
    print("날짜별 로그 분포 확인")
    print("="*60)
    
    # 모든 로그 가져오기
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    
    if not logs:
        print("\n❌ DB에 로그가 없습니다.")
    else:
        print(f"\n✅ 총 {len(logs)} 개 로그\n")
        
        # 날짜별 집계
        date_counts = defaultdict(lambda: {'total': 0, 'mask': 0, 'block': 0})
        
        for log in logs:
            date_str = log.timestamp.strftime("%Y-%m-%d")
            date_counts[date_str]['total'] += 1
            if log.action == 'mask':
                date_counts[date_str]['mask'] += 1
            elif log.action == 'block':
                date_counts[date_str]['block'] += 1
        
        print("📅 날짜별 통계:")
        print("-" * 60)
        for date_str in sorted(date_counts.keys(), reverse=True):
            counts = date_counts[date_str]
            print(f"{date_str}: 총 {counts['total']:3d}개 (Mask: {counts['mask']:3d}, Block: {counts['block']:3d})")
        
        print("\n" + "="*60)
        print("🕐 시간대 정보:")
        print("-" * 60)
        first_log = logs[-1]
        last_log = logs[0]
        print(f"  가장 오래된 로그: {first_log.timestamp}")
        print(f"  가장 최근 로그:   {last_log.timestamp}")
        print(f"  현재 UTC 시간:    {datetime.utcnow()}")
        print(f"  시간 차이:        {datetime.utcnow() - last_log.timestamp}")
        
        print("\n" + "="*60)
        print("📊 최근 7일 범위 체크:")
        print("-" * 60)
        today = datetime.utcnow().date()
        seven_days_ago = today - timedelta(days=6)
        seven_days_ago_dt = datetime.combine(seven_days_ago, datetime.min.time())
        
        print(f"  오늘 날짜:        {today}")
        print(f"  7일 전 날짜:      {seven_days_ago}")
        print(f"  7일 전 datetime:  {seven_days_ago_dt}")
        
        recent_logs = [log for log in logs if log.timestamp >= seven_days_ago_dt]
        print(f"\n  최근 7일 로그:    {len(recent_logs)}개")
        
        # 최근 7일 날짜별 집계
        print("\n  날짜별 분포:")
        for i in range(7):
            date = seven_days_ago + timedelta(days=i)
            date_str = date.strftime("%Y-%m-%d")
            count = sum(1 for log in recent_logs if log.timestamp.date() == date)
            print(f"    {date_str} ({date.strftime('%m-%d')}): {count}개")
    
    print("\n" + "="*60)
