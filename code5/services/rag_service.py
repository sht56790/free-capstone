"""RAG(검색 증강 생성) 서비스 모듈.

문서 임베딩은 `scripts/embed_documents.py`를 통해 미리 수행하고,
여기서는 구축된 Chroma 벡터 DB를 로드하여 질의에 맞는 컨텍스트를 검색한다.
"""
from __future__ import annotations

import os
import time
import traceback
from typing import List, Optional

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


def retrieve_context(question: str, k: int = 3) -> str:
    """질의에 맞는 상위 k개 컨텍스트를 검색하여 문자열로 반환한다."""
    try:
        db = get_vector_db()
        if db is None:
            return "참고: Vector DB가 로드되지 않아 내부 문서를 참조할 수 없습니다."

        snippet = (question or "")[:50]
        _log(f"질문 검색: {snippet}...")

        docs: List[Document] = db.similarity_search(question, k=k)
        if not docs:
            _log("관련 문서를 찾지 못했습니다.")
            return "참고: 질문과 관련된 내부 문서를 찾지 못했습니다."

        context_lines: List[str] = []
        sources = set()
        for idx, doc in enumerate(docs, start=1):
            source = os.path.basename(doc.metadata.get("source", "알 수 없음"))
            sources.add(source)
            context_lines.append(f"--- 참고자료 {idx} (출처: {source}) ---")
            context_lines.append(doc.page_content)
            context_lines.append("------------------------------------------------")

        _log(f"{len(docs)}개 문서 조각 사용 (출처: {sorted(sources)})")
        return "\n".join(context_lines)

    except Exception as exc:  # pragma: no cover - 방어적 로깅
        _log(f"[오류] Context 검색 실패: {exc}")
        traceback.print_exc()
        return f"참고: 내부 문서를 검색하는 중 오류가 발생했습니다. ({exc})"


if __name__ == "__main__":  # pragma: no cover - 수동 테스트 용도
    _log("RAG 서비스 단독 실행 테스트")
    get_vector_db()
    sample_q = "검사업무 절차를 알려줘"
    print(retrieve_context(sample_q))

