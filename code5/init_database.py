#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""데이터베이스 초기화 스크립트"""

from app import create_app
from database import db
from models import User, Rule

def init_database():
    app = create_app()
    with app.app_context():
        # 모든 테이블 생성
        db.create_all()
        print("✅ 데이터베이스 테이블 생성 완료")
        
        # 기본 사용자 추가
        admin = User.query.filter_by(id='admin@company.com').first()
        if not admin:
            admin = User(id='admin@company.com', password='admin_password', role='admin')
            db.session.add(admin)
            print("✅ 관리자 계정 생성: admin@company.com")
        
        user = User.query.filter_by(id='user@company.com').first()
        if not user:
            user = User(id='user@company.com', password='user_password', role='user')
            db.session.add(user)
            print("✅ 사용자 계정 생성: user@company.com")
        
        # 기본 규칙 추가
        rules_data = [
            ('계좌번호', r'\d{4}[-\s]?\d{4}[-\s]?\d{4,6}|\d{12,14}', 'block'),
            ('고객번호', r'고객번호[:\s]?\d{6,12}|\d{6,12}(?=\s*고객)', 'block'),
            ('고객명', r'[가-힣]{2,4}(?=\s*(님|고객|분|씨))|[가-힣]{2,4}(?=\s*계좌)|성명[:\s]*[가-힣]{2,4}', 'mask'),
            ('생년월일', r'\d{4}[-.\s]?\d{2}[-.\s]?\d{2}|\d{6}(?=\s*생년)|생년월일[:\s]*\d{4}[-.\s]?\d{2}[-.\s]?\d{2}', 'block'),
            ('전화번호', r'010[-\s]?\d{4}[-\s]?\d{4}|0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{4}', 'block'),
            ('주소', r'([서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|제주]\s*[시도군구]|\d{5}[-\s]?\d{6})', 'block'),
            ('금리 확정 표현', r'금리는\s*\d+[.\d]*%입니다|금리\s*\d+[.\d]*%|이자율\s*\d+[.\d]*%', 'block'),
        ]
        
        for name, regex, action in rules_data:
            rule = Rule.query.filter_by(name=name).first()
            if not rule:
                rule = Rule(name=name, regex=regex, action=action, is_active=True)
                db.session.add(rule)
                print(f"✅ 규칙 추가: {name}")
        
        db.session.commit()
        print("✅ 데이터베이스 초기화 완료!")

if __name__ == '__main__':
    init_database()
