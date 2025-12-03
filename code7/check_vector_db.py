"""Vector DB 상태 확인 및 진단 스크립트"""
import os
from services.rag_service import get_vector_db, retrieve_context

print("=" * 80)
print("📊 Vector DB 상태 진단")
print("=" * 80)

# 1. Vector DB 로드
print("\n[1단계] Vector DB 로드 중...")
db = get_vector_db()

if not db:
    print("❌ Vector DB 로드 실패!")
    print("   → 해결: python scripts/embed_documents.py 실행 필요")
    exit(1)

print("✅ Vector DB 로드 성공")

# 2. 저장된 문서 확인
print("\n[2단계] 저장된 문서 조각 확인...")
try:
    collection = db._collection
    count = collection.count()
    print(f"✅ 총 {count}개 문서 조각 저장됨")
    
    if count == 0:
        print("⚠️ 문서 조각이 0개입니다!")
        print("   → 해결: python scripts/embed_documents.py 실행 필요")
        exit(1)
    
    # 샘플 데이터 확인 (처음 3개)
    print("\n[3단계] 샘플 데이터 확인 (처음 3개 조각)...")
    results = collection.get(limit=3, include=['documents', 'metadatas'])
    
    for idx, (doc, meta) in enumerate(zip(results['documents'], results['metadatas']), 1):
        source = os.path.basename(meta.get('source', '알 수 없음'))
        page = meta.get('page', '?')
        print(f"\n--- 조각 {idx} ---")
        print(f"출처: {source} (페이지 {page})")
        print(f"내용 (처음 200자): {doc[:200]}...")
    
    # 모든 출처 파일 목록
    print("\n[4단계] 모든 출처 파일 목록...")
    all_results = collection.get(include=['metadatas'])
    sources = set()
    for meta in all_results['metadatas']:
        source = os.path.basename(meta.get('source', '알 수 없음'))
        sources.add(source)
    
    print(f"✅ Vector DB에 저장된 파일 목록:")
    for source in sorted(sources):
        # 각 파일별 조각 수 계산
        file_count = sum(1 for m in all_results['metadatas'] 
                        if os.path.basename(m.get('source', '')) == source)
        print(f"   - {source}: {file_count}개 조각")
    
    # 현재 rag_docs 폴더의 실제 파일 목록
    print("\n[5단계] 현재 scripts/rag_docs 폴더의 실제 파일...")
    rag_docs_dir = "scripts/rag_docs"
    if os.path.exists(rag_docs_dir):
        actual_files = [f for f in os.listdir(rag_docs_dir) if f.endswith('.pdf')]
        print(f"✅ 실제 PDF 파일 목록:")
        for f in sorted(actual_files):
            file_path = os.path.join(rag_docs_dir, f)
            size_kb = os.path.getsize(file_path) / 1024
            print(f"   - {f}: {size_kb:.1f} KB")
        
        # 불일치 확인
        print("\n[6단계] Vector DB와 실제 파일 비교...")
        db_files = sources
        actual_files_set = set(actual_files)
        
        missing_in_db = actual_files_set - db_files
        extra_in_db = db_files - actual_files_set
        
        if missing_in_db:
            print(f"⚠️ Vector DB에 없는 파일 (재구축 필요):")
            for f in missing_in_db:
                print(f"   - {f}")
        
        if extra_in_db:
            print(f"⚠️ 삭제된 파일이 Vector DB에 남아있음 (재구축 필요):")
            for f in extra_in_db:
                print(f"   - {f}")
        
        if not missing_in_db and not extra_in_db:
            print("✅ Vector DB와 실제 파일이 일치합니다!")
    
    # 검색 테스트
    print("\n[7단계] 검색 기능 테스트...")
    test_queries = [
        "프린터 사용법",
        "고객 응대",
        "금리 확정",
        "employee manual",
    ]
    
    for query in test_queries:
        print(f"\n질문: '{query}'")
        context = retrieve_context(query, k=3)
        
        if "참고: Vector DB가 로드되지 않아" in context:
            print("   ❌ Vector DB 로드 실패")
        elif "참고: 질문과 관련된 내부 문서를 찾지 못했습니다" in context:
            print("   ⚠️ 관련 문서 없음")
        else:
            # 출처 추출
            import re
            found_sources = re.findall(r'출처: ([^)]+)', context)
            if found_sources:
                print(f"   ✅ 검색 성공 - 출처: {', '.join(set(found_sources))}")
            else:
                print(f"   ✅ 검색 성공 (출처 정보 없음)")
    
except Exception as e:
    print(f"❌ 오류 발생: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
print("📋 진단 완료")
print("=" * 80)

# 결론 및 권장사항
print("\n🔧 권장 조치:")
print("1. Vector DB와 실제 파일이 불일치하면:")
print("   → python scripts/embed_documents.py 실행")
print("\n2. 검색 결과가 없으면:")
print("   → PDF 내용이 질문과 무관하거나, PDF가 비어있을 수 있음")
print("   → scripts/rag_docs/employee_manual.pdf 파일 내용 확인")
print("\n3. 모든 테스트 통과 시:")
print("   → 서버 재시작 후 채팅에서 테스트")

