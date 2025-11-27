import sqlite3

conn = sqlite3.connect('instance/database.db')
cursor = conn.cursor()

print("✅ 데이터베이스 테이블:")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
for t in tables:
    print(f"  - {t[0]}")

print("\n✅ 사용자 계정:")
cursor.execute("SELECT id, role FROM user")
users = cursor.fetchall()
for u in users:
    print(f"  - {u[0]} ({u[1]})")

print("\n✅ 탐지 규칙:")
cursor.execute("SELECT name, action, is_active FROM rule")
rules = cursor.fetchall()
for r in rules:
    status = "활성" if r[2] else "비활성"
    print(f"  - {r[0]} ({r[1]}) [{status}]")

conn.close()
print("\n✅ 데이터베이스 확인 완료!")
