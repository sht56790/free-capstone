# scripts/embed_documents.py
import os
import time
import glob 

# --- 필요한 로더만 직접 임포트 ---
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

# 0. 현재 스크립트 파일(embed_documents.py)의 절대 경로
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 1. Vector DB를 저장할 경로 (scripts 폴더의 부모 폴더, 즉 'code' 폴더)
DB_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "vector_db")
# 2. "학습"시킬 문서가 있는 폴더 경로 (스크립트 폴더 내부의 'rag_docs')
DOCS_DIR = os.path.join(SCRIPT_DIR, "rag_docs")

# 3. 텍스트를 벡터로 변환할 Embedding 모델
EMBED_MODEL = "jhgan/ko-sbert-nli"

def load_pdf_documents():
    """
    DOCS_DIR 폴더 및 하위 폴더에서 .pdf 파일만 '직접' 찾아 로드합니다.
    """
    print(f"'{DOCS_DIR}' 폴더에서 PDF 문서를 스캔합니다...")
    all_documents = []
    
    # .pdf 파일 경로 목록을 직접 찾기
    pdf_files = glob.glob(os.path.join(DOCS_DIR, "**/*.pdf"), recursive=True)

    # --- PDF 파일 처리 ---
    if pdf_files:
        print(f"총 {len(pdf_files)}개의 PDF 파일을 찾았습니다. 로드를 시도합니다...")
        for file_path in pdf_files:
            try:
                # PyPDFLoader를 파일 경로에 직접 사용
                loader = PyPDFLoader(file_path)
                docs = loader.load() # 페이지별로 나뉘어 로드됨
                all_documents.extend(docs)
                print(f"  [성공] {file_path} (페이지 수: {len(docs)})")
            except Exception as e:
                print(f"  [경고] PDF 파일 로드 실패: {file_path} (오류: {e})")
    else:
        print(f"'{DOCS_DIR}' 폴더에서 PDF 파일을 찾지 못했습니다.")

    return all_documents


def build_vector_db():
    start_total_time = time.time()
    
    documents = load_pdf_documents()
    
    if not documents:
        print(f"\n[경고] '{DOCS_DIR}' 폴더에 PDF 파일이 없거나 로드에 실패했습니다. 스크립트를 종료합니다.")
        return

    print(f"\n총 {len(documents)}개의 문서(페이지 기준)를 성공적으로 로드했습니다.")

    # 1. 문서 분할 (Chunking)
    print("문서를 청크(Chunk) 단위로 분할합니다...")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000, 
        chunk_overlap=100
    )
    chunks = text_splitter.split_documents(documents)
    print(f"총 {len(chunks)}개의 텍스트 청크로 분할되었습니다.")

    # 2. Embedding 모델 로드
    print(f"'{EMBED_MODEL}' 임베딩 모델을 로드합니다... (최초 실행 시 시간이 걸릴 수 있습니다)")
    start_time = time.time()
    model_kwargs = {'device': 'cuda' if os.environ.get('CUDA_VISIBLE_DEVICES') else 'cpu'}
    encode_kwargs = {'normalize_embeddings': True}
    embeddings = HuggingFaceEmbeddings(
        model_name=EMBED_MODEL,
        model_kwargs=model_kwargs,
        encode_kwargs=encode_kwargs
    )
    print(f"임베딩 모델 로드 완료. (소요 시간: {time.time() - start_time:.2f}초)")

    # 3. Vector DB (ChromaDB)에 저장
    print(f"'{DB_DIR}' 경로에 Vector DB를 구축합니다...")
    start_time = time.time()
    vector_db = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=DB_DIR 
    )
    vector_db.persist()
    print(f"Vector DB 구축 및 저장 완료! (소요 시간: {time.time() - start_time:.2f}초)")
    print(f"=== 총 소요 시간: {time.time() - start_total_time:.2f}초 ===")


if __name__ == "__main__":
    if not os.path.exists(DOCS_DIR):
         os.makedirs(DOCS_DIR)
         print(f"'{DOCS_DIR}' 폴더를 생성했습니다. 여기에 .pdf 파일을 넣어주세요.")
    
    build_vector_db()