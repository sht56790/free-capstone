from database import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')

    # User와 Log의 관계 설정 (User 한 명이 여러 개의 Log를 가질 수 있음)
    logs = db.relationship('Log', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.id}>'

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.String(100), db.ForeignKey('user.id'), nullable=True)
    user_prompt = db.Column(db.Text, nullable=False)
    processed_prompt = db.Column(db.Text)
    llm_response = db.Column(db.Text)
    action = db.Column(db.String(50), nullable=False)
    detections_in = db.Column(db.JSON)
    detections_out = db.Column(db.JSON)

    def __repr__(self):
        return f'<Log {self.id}>'
    
class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True) # 규칙 이름 (예: 전화번호)
    regex = db.Column(db.String(255), nullable=False) # 탐지에 사용할 정규식
    action = db.Column(db.String(50), nullable=False, default='mask') # 처리 방식 ('mask' 또는 'block')
    is_active = db.Column(db.Boolean, nullable=False, default=True) # 규칙 활성화 여부

    def __repr__(self):
        return f'<Rule {self.name}>'