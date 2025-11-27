import requests
import json

# 테스트할 계정
test_accounts = [
    {"id": "admin@company.com", "password": "admin_password"},
    {"id": "user@company.com", "password": "user_password"}
]

print("="*70)
print("🔐 로그인 테스트")
print("="*70)
print()

for account in test_accounts:
    print(f"테스트 계정: {account['id']}")
    print(f"비밀번호: {account['password']}")
    
    try:
        response = requests.post(
            'http://127.0.0.1:5001/login',
            json=account,
            timeout=5
        )
        
        print(f"상태 코드: {response.status_code}")
        print(f"응답: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ 로그인 성공! 역할: {data.get('role')}")
        else:
            print(f"❌ 로그인 실패!")
            
    except requests.exceptions.ConnectionError:
        print("❌ 서버에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요.")
    except Exception as e:
        print(f"❌ 오류: {e}")
    
    print()
    print("-"*70)
    print()
