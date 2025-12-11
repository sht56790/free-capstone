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
from langchain_core.documents import Document

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "vector_db")
DOCS_DIR = os.path.join(SCRIPT_DIR, "rag_docs")
EMBED_MODEL = "jhgan/ko-sbert-nli"


def load_pdf_documents() -> List:
    """`DOCS_DIR` 하위의 PDF와 Markdown 문서를 모두 로드한다."""
    print(f"[embed_documents] '{DOCS_DIR}'에서 문서 탐색 중...")
    documents: List = []
    
    # PDF 파일 로드
    pdf_files = glob.glob(os.path.join(DOCS_DIR, "**", "*.pdf"), recursive=True)
    print(f"[embed_documents] {len(pdf_files)}개 PDF 발견")
    for path in pdf_files:
        try:
            loader = PyPDFLoader(path)
            pages = loader.load()
            documents.extend(pages)
            print(f"  [OK] {path} (페이지 {len(pages)})")
        except Exception as exc:  # pragma: no cover - 파일 오류 방어
            print(f"  [ERROR] PDF 로드 실패: {path} ({exc})")
    
    # Markdown 파일 로드
    md_files = glob.glob(os.path.join(DOCS_DIR, "**", "*.md"), recursive=True)
    # README.md 제외
    md_files = [f for f in md_files if not f.endswith("README.md")]
    print(f"[embed_documents] {len(md_files)}개 Markdown 발견")
    for path in md_files:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            doc = Document(page_content=content, metadata={"source": path, "page": 0})
            documents.append(doc)
            print(f"  [OK] {path} ({len(content)} 문자)")
        except Exception as exc:
            print(f"  [ERROR] Markdown 로드 실패: {path} ({exc})")
    
    if not documents:
        print(f"[embed_documents] 문서 파일이 없습니다. '{DOCS_DIR}'에 PDF 또는 Markdown 파일을 추가하세요.")
    
    return documents


def safe_remove_directory(dir_path: str) -> bool:
    """디렉토리를 안전하게 제거합니다. (파일 잠금 시 이름 변경)"""
    import shutil
    
    if not os.path.exists(dir_path):
        print(f"[embed_documents] 제거할 디렉토리가 없습니다: {dir_path}")
        return True
    
    try:
        # 먼저 삭제 시도
        shutil.rmtree(dir_path)
        print(f"[embed_documents] 디렉토리 삭제 완료: {dir_path}")
        return True
    except (PermissionError, OSError) as e:
        # 삭제 실패 시 이름 변경 (파일 잠금 우회)
        print(f"[embed_documents] 삭제 실패 (파일 사용 중): {e}")
        print(f"[embed_documents] 대체 방법: 기존 디렉토리 이름 변경")
        
        try:
            # 타임스탬프로 백업 이름 생성
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{dir_path}_old_{timestamp}"
            
            os.rename(dir_path, backup_path)
            print(f"[embed_documents] 기존 디렉토리 이름 변경: {backup_path}")
            print(f"[embed_documents] 서버 재시작 후 수동으로 삭제 가능합니다.")
            return True
        except Exception as rename_err:
            print(f"[embed_documents] 이름 변경도 실패: {rename_err}")
            print(f"[embed_documents] 경고: 서버를 재시작해야 할 수 있습니다.")
            return False


def build_vector_db() -> None:
    start_total = time.time()
    documents = load_pdf_documents()
    
    if not documents:
        print("[embed_documents] 로드된 문서가 없습니다.")
        # 기존 vector_db 제거
        if os.path.exists(DB_DIR):
            print(f"[embed_documents] 기존 Vector DB 제거 시도: {DB_DIR}")
            if safe_remove_directory(DB_DIR):
                print("[embed_documents] 기존 Vector DB가 제거되었습니다.")
            else:
                print("[embed_documents] 기존 Vector DB 제거 실패 (이름 변경 또는 서버 재시작 필요)")
        else:
            print("[embed_documents] 제거할 Vector DB가 없습니다.")
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

    # 기존 DB 제거 후 새로 생성
    if os.path.exists(DB_DIR):
        print(f"[embed_documents] 기존 Vector DB 제거 시도: {DB_DIR}")
        safe_remove_directory(DB_DIR)
    
    os.makedirs(DB_DIR, exist_ok=True)
    print(f"[embed_documents] 새 Vector DB 디렉토리 생성: {DB_DIR}")
    
    vector_db = Chroma.from_documents(chunks, embedding=embeddings, persist_directory=DB_DIR)
    vector_db.persist()
    print(f"[embed_documents] Vector DB 생성 완료 → {DB_DIR}")
    print(f"[embed_documents] 총 소요 시간: {time.time() - start_total:.2f}s")


if __name__ == "__main__":
    if not os.path.exists(DOCS_DIR):
        os.makedirs(DOCS_DIR, exist_ok=True)
        print(f"[embed_documents] '{DOCS_DIR}'를 생성했습니다. PDF 파일을 여기에 추가하세요.")
    build_vector_db()

