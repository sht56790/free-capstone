"""문서 임베딩 스크립트.

`scripts/rag_docs` 폴더의 PDF 파일을 로드해 벡터화한 뒤
`vector_db/` 경로에 Chroma DB를 생성한다.
"""
from __future__ import annotations

import glob
import os
import time
from typing import List

from langchain_community.document_loaders import PyPDFLoader
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "vector_db")
DOCS_DIR = os.path.join(SCRIPT_DIR, "rag_docs")
EMBED_MODEL = "jhgan/ko-sbert-nli"


def load_pdf_documents() -> List:
    """`DOCS_DIR` 하위의 PDF 문서를 모두 로드한다."""
    print(f"[embed_documents] '{DOCS_DIR}'에서 PDF 탐색 중...")
    documents: List = []
    pdf_files = glob.glob(os.path.join(DOCS_DIR, "**", "*.pdf"), recursive=True)

    if not pdf_files:
        print(f"[embed_documents] PDF 파일이 없습니다. '{DOCS_DIR}'에 문서를 추가하세요.")
        return documents

    print(f"[embed_documents] {len(pdf_files)}개 PDF 로드 시도")
    for path in pdf_files:
        try:
            loader = PyPDFLoader(path)
            pages = loader.load()
            documents.extend(pages)
            print(f"  ✓ {path} (페이지 {len(pages)})")
        except Exception as exc:  # pragma: no cover - 파일 오류 방어
            print(f"  ⚠️ PDF 로드 실패: {path} ({exc})")
    return documents


def build_vector_db() -> None:
    start_total = time.time()
    documents = load_pdf_documents()
    if not documents:
        print("[embed_documents] 로드된 문서가 없어 종료합니다.")
        return

    print(f"[embed_documents] 총 {len(documents)}개 페이지 로드 완료")

    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    chunks = splitter.split_documents(documents)
    print(f"[embed_documents] {len(chunks)}개 청크로 분할")

    device = "cuda" if os.environ.get("CUDA_VISIBLE_DEVICES") else "cpu"
    embeddings = HuggingFaceEmbeddings(
        model_name=EMBED_MODEL,
        model_kwargs={"device": device},
        encode_kwargs={"normalize_embeddings": True},
    )
    print(f"[embed_documents] 임베딩 모델 '{EMBED_MODEL}' 로드 완료 (device={device})")

    os.makedirs(DB_DIR, exist_ok=True)
    vector_db = Chroma.from_documents(chunks, embedding=embeddings, persist_directory=DB_DIR)
    vector_db.persist()
    print(f"[embed_documents] Vector DB 생성 완료 → {DB_DIR}")
    print(f"[embed_documents] 총 소요 시간: {time.time() - start_total:.2f}s")


if __name__ == "__main__":
    if not os.path.exists(DOCS_DIR):
        os.makedirs(DOCS_DIR, exist_ok=True)
        print(f"[embed_documents] '{DOCS_DIR}'를 생성했습니다. PDF 파일을 여기에 추가하세요.")
    build_vector_db()

