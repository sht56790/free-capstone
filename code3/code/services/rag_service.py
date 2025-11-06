# services/rag_service.py
import os
import time
import traceback
from typing import List
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document

# --- 1. embed_documents.py와 동일한 설정 사용 ---

# Vector DB가 저장된 경로 (app.py 기준 상대 경로)
# app.py가 'code' 폴더에 있으므로, 'code' 폴더 내의 'vector_db'를 가리킴
DB_DIR = "vector_db" 

# 텍스트를 벡터로 변환할 Embedding 모델
EMBED_MODEL = "jhgan/ko-sbert-nli" 

# --- 2. 전역 변수로 Vector DB와 Embedding 모델 로드 ---
# 앱 실행 시 1번만 로드하도록 전역 변수로 관리

_db = None
_embeddings = None

def get_embeddings():
    """임베딩 모델을 로드 (최초 1회)"""
    global _embeddings
    if _embeddings is None:
        print(f"[RAG Service] '{EMBED_MODEL}' 임베딩 모델을 로드합니다...")
        start_time = time.time()
        # CUDA 사용 가능 여부 확인 (Ollama와 동일)
        model_kwargs = {'device': 'cuda' if os.environ.get('CUDA_VISIBLE_DEVICES') else 'cpu'}
        encode_kwargs = {'normalize_embeddings': True}
        _embeddings = HuggingFaceEmbeddings(
            model_name=EMBED_MODEL,
            model_kwargs=model_kwargs,
            encode_kwargs=encode_kwargs
        )
        print(f"[RAG Service] 임베딩 모델 로드 완료. (소요 시간: {time.time() - start_time:.2f}초)")
    return _embeddings

def get_vector_db():
    """Vector DB를 로드 (최초 1회)"""
    global _db
    if _db is None:
        if not os.path.exists(DB_DIR):
            print(f"[RAG Service] [경고] '{DB_DIR}' 폴더를 찾을 수 없습니다.")
            print("    먼저 'python scripts/embed_documents.py' 스크립트를 실행하여 Vector DB를 구축해야 합니다.")
            return None
        
        print(f"[RAG Service] '{DB_DIR}' 경로에서 Vector DB를 로드합니다...")
        start_time = time.time()
        _db = Chroma(
            persist_directory=DB_DIR, 
            embedding_function=get_embeddings()
        )
        print(f"[RAG Service] Vector DB 로드 완료. (소요 시간: {time.time() - start_time:.2f}초)")
    return _db

# --- 3. 핵심 검색 함수 (app.py가 호출할 함수) ---

def retrieve_context(question: str, k: int = 3) -> str:
    """
    사용자의 질문(question)을 받아 Vector DB에서 가장 유사한 k개의 문서를 검색하고,
    하나의 텍스트(Context)로 합쳐서 반환합니다.
    """
    try:
        db = get_vector_db()
        if db is None:
            return "참고: Vector DB가 로드되지 않았습니다. 내부 문서를 참조할 수 없습니다."

        print(f"[RAG Service] 질문 검색: {question[:50]}...")
        
        # 1. Vector DB에서 유사도 검색 (k개 결과 반환)
        retrieved_docs: List[Document] = db.similarity_search(question, k=k)
        
        if not retrieved_docs:
            print("[RAG Service] 검색된 관련 문서가 없습니다.")
            return "참고: 질문과 관련된 내부 문서를 찾지 못했습니다."

        # 2. 검색된 문서 조각들을 하나의 텍스트로 결합
        context = ""
        sources = set()
        for i, doc in enumerate(retrieved_docs):
            source = doc.metadata.get('source', '알 수 없음')
            sources.add(os.path.basename(source)) # 파일명만 추출
            
            context += f"--- 참고자료 {i+1} (출처: {os.path.basename(source)}) ---\n"
            context += doc.page_content
            context += "\n------------------------------------------------\n"
        
        print(f"[RAG Service] {len(retrieved_docs)}개의 문서 조각을 Context로 생성 (출처: {sources})")
        return context

    except Exception as e:
        print(f"[RAG Service] [오류] Context 검색 중 오류 발생: {e}")
        traceback.print_exc()
        return f"참고: 내부 문서를 검색하는 중 오류가 발생했습니다. ({e})"

# --- 4. (선택적) 모듈 로딩 확인용 테스트 코드 ---
if __name__ == "__main__":
    print("RAG 서비스 모듈 단독 테스트...")
    
    # Vector DB와 임베딩 모델 로드 시도
    get_vector_db() 
    
    # 테스트 질문
    test_question = "검사업무 프로세스가 뭐야?"
    context = retrieve_context(test_question)
    
    print("\n--- 테스트 검색 결과 ---")
    print(context)
    print("------------------------")