"""Vector DB 완전 재구축 스크립트
이전 파일 잔재를 제거하고 현재 PDF만으로 새로 구축합니다.
"""
import os
import shutil

print("=" * 80)
print("🔧 Vector DB 완전 재구축")
print("=" * 80)

# 1. 기존 Vector DB 삭제
vector_db_path = "vector_db"
if os.path.exists(vector_db_path):
    print(f"\n[1단계] 기존 Vector DB 삭제 중: {vector_db_path}")
    try:
        shutil.rmtree(vector_db_path)
        print("✅ 기존 Vector DB 삭제 완료")
    except Exception as e:
        print(f"❌ 삭제 실패: {e}")
        print("   → 서버를 중지하고 다시 시도하세요")
        exit(1)
else:
    print(f"\n[1단계] 기존 Vector DB 없음 (새로 생성)")

# 2. 현재 PDF 파일 확인
rag_docs_dir = "scripts/rag_docs"
print(f"\n[2단계] 현재 PDF 파일 확인: {rag_docs_dir}")

if not os.path.exists(rag_docs_dir):
    print(f"❌ {rag_docs_dir} 폴더가 없습니다!")
    exit(1)

pdf_files = [f for f in os.listdir(rag_docs_dir) if f.endswith('.pdf')]
if not pdf_files:
    print(f"❌ PDF 파일이 없습니다!")
    print(f"   → {rag_docs_dir}에 PDF 파일을 추가하세요")
    exit(1)

print(f"✅ 발견된 PDF 파일:")
for f in sorted(pdf_files):
    file_path = os.path.join(rag_docs_dir, f)
    size_kb = os.path.getsize(file_path) / 1024
    print(f"   - {f}: {size_kb:.1f} KB")

# 3. 임베딩 실행
print(f"\n[3단계] 문서 임베딩 시작...")
print("=" * 80)

# embed_documents.py 실행
from scripts.embed_documents import build_vector_db

try:
    build_vector_db()
    print("\n" + "=" * 80)
    print("✅ Vector DB 재구축 완료!")
    print("=" * 80)
except Exception as e:
    print(f"\n❌ 임베딩 실패: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# 4. 검증
print("\n[4단계] 재구축 결과 검증...")
from services.rag_service import get_vector_db, retrieve_context

db = get_vector_db()
if not db:
    print("❌ Vector DB 로드 실패")
    exit(1)

collection = db._collection
count = collection.count()
print(f"✅ 총 {count}개 문서 조각 저장됨")

# 출처 확인
all_results = collection.get(include=['metadatas'])
sources = set()
for meta in all_results['metadatas']:
    source = os.path.basename(meta.get('source', '알 수 없음'))
    sources.add(source)

print(f"\n✅ Vector DB에 저장된 파일:")
for source in sorted(sources):
    file_count = sum(1 for m in all_results['metadatas'] 
                    if os.path.basename(m.get('source', '')) == source)
    print(f"   - {source}: {file_count}개 조각")

# 검색 테스트
print("\n[5단계] 검색 테스트...")
test_query = "employee manual"
context = retrieve_context(test_query, k=3)

if "employee_manual.pdf" in context or "employee" in context.lower():
    print(f"✅ '{test_query}' 검색 성공!")
    print(f"   출처에 employee_manual.pdf 포함됨")
else:
    print(f"⚠️ '{test_query}' 검색 결과:")
    print(f"   {context[:200]}...")

print("\n" + "=" * 80)
print("🎉 재구축 완료! 서버를 재시작하세요.")
print("=" * 80)

