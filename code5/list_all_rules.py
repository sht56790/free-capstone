import sqlite3

conn = sqlite3.connect('instance/database.db')
cursor = conn.cursor()

print("="*80)
print("📊 데이터베이스 전체 규칙 목록")
print("="*80)
print()

# 총 개수
cursor.execute("SELECT COUNT(*) FROM rule")
total = cursor.fetchone()[0]
print(f"✅ 총 규칙 수: {total}개\n")

# 액션별 개수
cursor.execute("SELECT action, COUNT(*) FROM rule GROUP BY action")
action_counts = cursor.fetchall()
print("📈 액션별 분포:")
for action, count in action_counts:
    print(f"  - {action}: {count}개")
print()

# 전체 규칙 목록
print("="*80)
print("📋 전체 규칙 목록")
print("="*80)
cursor.execute("SELECT id, name, action, is_active FROM rule ORDER BY id")
rules = cursor.fetchall()

block_rules = []
mask_rules = []

for r in rules:
    if r[2] == 'block':
        block_rules.append(r)
    else:
        mask_rules.append(r)

print(f"\n🚫 차단(Block) 규칙 ({len(block_rules)}개):")
for i, r in enumerate(block_rules, 1):
    status = "✓" if r[3] else "✗"
    print(f"  {i:2d}. [{status}] {r[1]}")

print(f"\n🎭 마스킹(Mask) 규칙 ({len(mask_rules)}개):")
for i, r in enumerate(mask_rules, 1):
    status = "✓" if r[3] else "✗"
    print(f"  {i:2d}. [{status}] {r[1]}")

print()
print("="*80)
print("✅ 규칙 확인 완료!")
print("="*80)

conn.close()
