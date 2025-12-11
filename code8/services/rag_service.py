"""RAG(검색 증강 생성) 서비스 모듈.

문서 임베딩은 `scripts/embed_documents.py`를 통해 미리 수행하고,
여기서는 구축된 Chroma 벡터 DB를 로드하여 질의에 맞는 컨텍스트를 검색한다.
"""
from __future__ import annotations

import os
import time
import traceback
from typing import List, Optional, Tuple

from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document

# Vector DB와 임베딩 모델 설정
DB_DIR = "vector_db"
EMBED_MODEL = "jhgan/ko-sbert-nli"

_embeddings: Optional[HuggingFaceEmbeddings] = None
_db: Optional[Chroma] = None


def _log(msg: str) -> None:
    print(f"[RAG Service] {msg}")


def get_embeddings() -> HuggingFaceEmbeddings:
    """임베딩 모델은 최초 1회만 로드한다."""
    global _embeddings
    if _embeddings is None:
        _log(f"'{EMBED_MODEL}' 임베딩 모델 로드 중...")
        start = time.time()
        model_kwargs = {"device": "cuda" if os.environ.get("CUDA_VISIBLE_DEVICES") else "cpu"}
        encode_kwargs = {"normalize_embeddings": True}
        _embeddings = HuggingFaceEmbeddings(
            model_name=EMBED_MODEL,
            model_kwargs=model_kwargs,
            encode_kwargs=encode_kwargs,
        )
        _log(f"임베딩 모델 로드 완료 (소요 {time.time() - start:.2f}s)")
    return _embeddings


def get_vector_db() -> Optional[Chroma]:
    """Chroma Vector DB를 로드한다. 최초 1회만 생성."""
    global _db
    if _db is None:
        if not os.path.exists(DB_DIR):
            _log(f"[경고] '{DB_DIR}' 폴더가 없습니다. 먼저 문서 임베딩을 생성하세요.")
            return None
        _log(f"'{DB_DIR}' 경로에서 Vector DB 로드 중...")
        start = time.time()
        _db = Chroma(persist_directory=DB_DIR, embedding_function=get_embeddings())
        _log(f"Vector DB 로드 완료 (소요 {time.time() - start:.2f}s)")
    return _db


def reset_vector_db() -> None:
    """Vector DB 캐시를 초기화한다. (문서 삭제/재구축 후 호출)"""
    global _db
    if _db is not None:
        try:
            # ChromaDB 연결 정리 시도
            _db = None
            _log("Vector DB 캐시가 초기화되었습니다.")
            # GC 강제 실행으로 파일 핸들 해제
            import gc
            gc.collect()
            _log("가비지 컬렉션 완료 (파일 핸들 해제)")
        except Exception as e:
            _log(f"Vector DB 정리 중 경고: {e}")
            _db = None
    else:
        _db = None
        _log("Vector DB 캐시가 초기화되었습니다.")


def retrieve_context(question: str, k: int = 3) -> Tuple[str, float, List[dict]]:
    """질의에 맞는 상위 k개 컨텍스트를 검색하여 문자열과 최고 유사도 점수, 문서 정보를 반환한다.
    
    Returns:
        (context_string, max_similarity_score, source_docs) 튜플
        - context_string: 검색된 컨텍스트 문자열
        - max_similarity_score: 최고 유사도 점수 (0.0 ~ 1.0, 높을수록 유사함)
        - source_docs: 참고 문서 정보 리스트 [{"source": "파일명", "similarity": 0.95}, ...]
    """
    try:
        # vector_db 폴더가 없으면 즉시 반환
        if not os.path.exists(DB_DIR):
            _log(f"[경고] Vector DB 폴더가 없습니다: {DB_DIR}")
            return ("참고: 내부 문서가 아직 준비되지 않았습니다. 문서를 업로드하고 RAG를 재구축해주세요.", 0.0, [])
        
        db = get_vector_db()
        if db is None:
            return ("참고: Vector DB가 로드되지 않아 내부 문서를 참조할 수 없습니다.", 0.0, [])

        snippet = (question or "")[:50]
        _log(f"질문 검색: {snippet}...")

        # Chroma는 L2 거리(distance)를 반환 (값이 작을수록 유사)
        # 유사도로 변환: similarity = 1 / (1 + distance)
        # 거리가 0이면 유사도 1.0, 거리가 크면 유사도 0에 가까워짐
        def distance_to_similarity(distance):
            return 1.0 / (1.0 + distance)
        
        # 유사도 점수와 함께 검색 (충분한 개수 가져오기)
        SEARCH_K = 10  # 일단 10개 가져옴
        docs_with_scores = db.similarity_search_with_score(question, k=SEARCH_K)
        if not docs_with_scores:
            _log("관련 문서를 찾지 못했습니다.")
            return ("참고: 질문과 관련된 내부 문서를 찾지 못했습니다.", 0.0, [])
        
        # 동적 필터링: 유사도 0.5 이상만 선택
        CHUNK_SIMILARITY_THRESHOLD = 0.5
        MAX_CHUNKS = 5  # 최대 5개까지만
        
        filtered_docs = [
            (doc, score, distance_to_similarity(score))
            for doc, score in docs_with_scores
            if distance_to_similarity(score) >= CHUNK_SIMILARITY_THRESHOLD
        ]
        
        # 유사도 높은 순으로 정렬하고 최대 개수만큼 선택
        filtered_docs.sort(key=lambda x: x[2], reverse=True)
        filtered_docs = filtered_docs[:MAX_CHUNKS]
        
        if not filtered_docs:
            _log(f"유사도 {CHUNK_SIMILARITY_THRESHOLD} 이상인 문서를 찾지 못했습니다.")
            return ("참고: 질문과 관련된 내부 문서를 찾지 못했습니다.", 0.0, [])
        
        _log(f"필터링 결과: {len(filtered_docs)}개의 관련 chunk 발견 (임계값: {CHUNK_SIMILARITY_THRESHOLD})")
        
        # 최고 유사도 점수 추출
        max_similarity = filtered_docs[0][2]  # 이미 정렬되어 있음
        
        context_lines: List[str] = []
        sources = set()
        source_docs = []  # 문서 정보 리스트
        
        for idx, (doc, score, similarity) in enumerate(filtered_docs, start=1):
            source = os.path.basename(doc.metadata.get("source", "알 수 없음"))
            sources.add(source)
            
            # 문서 정보 추가 (텍스트 내용 포함)
            # 동일 출처에서 여러 조각이 있을 수 있으므로 배열로 관리
            existing_doc = next((d for d in source_docs if d["source"] == source), None)
            if existing_doc:
                # 기존 문서에 새로운 조각 추가
                existing_doc["chunks"].append({
                    "content": doc.page_content[:500],  # 500자로 제한
                    "similarity": round(similarity, 3)
                })
                # 최고 유사도로 업데이트
                if similarity > existing_doc["similarity"]:
                    existing_doc["similarity"] = round(similarity, 3)
            else:
                # 새 문서 추가
                source_docs.append({
                    "source": source,
                    "similarity": round(similarity, 3),
                    "chunks": [{
                        "content": doc.page_content[:500],  # 500자로 제한
                        "similarity": round(similarity, 3)
                    }]
                })
            
            context_lines.append(f"--- 참고자료 {idx} (출처: {source}, 유사도: {similarity:.3f}) ---")
            context_lines.append(doc.page_content)
            context_lines.append("------------------------------------------------")

        _log(f"{len(docs_with_scores)}개 문서 조각 사용 (출처: {sorted(sources)}, 최고 유사도: {max_similarity:.3f})")
        return ("\n".join(context_lines), max_similarity, source_docs)

    except Exception as exc:  # pragma: no cover - 방어적 로깅
        _log(f"[오류] Context 검색 실패: {exc}")
        traceback.print_exc()
        return (f"참고: 내부 문서를 검색하는 중 오류가 발생했습니다. ({exc})", 0.0, [])


if __name__ == "__main__":  # pragma: no cover - 수동 테스트 용도
    _log("RAG 서비스 단독 실행 테스트")
    get_vector_db()
    sample_q = "검사업무 절차를 알려줘"
    context, score, docs = retrieve_context(sample_q)
    print(f"컨텍스트:\n{context}\n\n유사도 점수: {score:.3f}\n참고 문서: {docs}")

