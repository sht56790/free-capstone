"""RAG 기능 디버깅 스크립트"""
from services.rag_service import get_vector_db, retrieve_context

# 1. Vector DB 로드 확인
print("=" * 60)
print("1. Vector DB 로드 테스트")
print("=" * 60)
db = get_vector_db()
if db:
    print("✅ Vector DB 로드 성공")
    # 컬렉션 정보 확인
    try:
        collection = db._collection
        count = collection.count()
        print(f"✅ 저장된 문서 조각 수: {count}개")
    except Exception as e:
        print(f"⚠️ 컬렉션 정보 확인 실패: {e}")
else:
    print("❌ Vector DB 로드 실패 - vector_db 폴더가 없거나 비어있음")
    exit(1)

# 2. 검색 테스트
print("\n" + "=" * 60)
print("2. 문서 검색 테스트")
print("=" * 60)

test_queries = [
    "프린터 사용법",
    "금융 상품",
    "고객 응대",
    "실제 급리는 언제 확정돼",
]

for query in test_queries:
    print(f"\n질문: {query}")
    print("-" * 60)
    context = retrieve_context(query, k=3)
    print(f"검색 결과 길이: {len(context)} 문자")
    
    if "참고: Vector DB가 로드되지 않아" in context:
        print("❌ Vector DB 로드 실패")
    elif "참고: 질문과 관련된 내부 문서를 찾지 못했습니다" in context:
        print("⚠️ 관련 문서 없음 (벡터 DB가 비어있거나 임베딩 안됨)")
    else:
        print("✅ 검색 성공")
        # 출처 파일 추출
        import re
        sources = re.findall(r'출처: ([^)]+)', context)
        if sources:
            print(f"📄 출처: {', '.join(set(sources))}")
        # 샘플 출력
        print(f"샘플 (처음 300자):\n{context[:300]}...")

print("\n" + "=" * 60)
print("3. 진단 완료")
print("=" * 60)

