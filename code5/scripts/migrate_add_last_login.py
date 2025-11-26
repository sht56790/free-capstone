"""User 테이블에 last_login 컬럼을 직접 추가하는 스크립트"""
import sqlite3
import os

# DB 파일 경로
db_path = os.path.join(os.path.dirname(__file__), '..', 'instance', 'database.db')

if not os.path.exists(db_path):
    print(f"❌ DB 파일을 찾을 수 없습니다: {db_path}")
    exit(1)

print(f"DB 파일: {db_path}")

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 현재 User 테이블 구조 확인
    cursor.execute("PRAGMA table_info(user)")
    columns = cursor.fetchall()
    print("\n현재 User 테이블 컬럼:")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    # last_login 컬럼이 이미 있는지 확인
    column_names = [col[1] for col in columns]
    if 'last_login' in column_names:
        print("\n✅ last_login 컬럼이 이미 존재합니다.")
    else:
        # last_login 컬럼 추가
        cursor.execute("ALTER TABLE user ADD COLUMN last_login DATETIME")
        conn.commit()
        print("\n✅ last_login 컬럼이 추가되었습니다.")
    
    # 사용자 목록 확인
    cursor.execute("SELECT id, role, last_login FROM user")
    users = cursor.fetchall()
    print(f"\n현재 사용자 수: {len(users)}")
    for user in users:
        print(f"  - {user[0]} ({user[1]}): last_login = {user[2] or 'NULL'}")
    
    conn.close()
    print("\n✅ 완료되었습니다.")
    
except Exception as e:
    print(f"❌ 오류 발생: {e}")
    import traceback
    traceback.print_exc()
