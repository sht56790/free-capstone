# 서버 실행 방법
python app.py

# 주소
http://localhost:8080/Chat%20Proxy.html

# RAG 라이브러리 설치
## RAG 파이프라인(문서 로드, 분할, DB 연동)을 위한 핵심 프레임워크
pip install langchain

## 1. Vector DB (ChromaDB): 로컬에 벡터를 저장하는 DB
pip install chromadb

## 2. Embedding Model (Sentence Transformers): 텍스트를 벡터로 변환
pip install sentence-transformers

## 3. PDF Loader: PDF 문서를 읽기 위한 라이브러리
pip install pypdf

## 라이브러리 설치
pip install langchain langchain_community chromadb sentence-transformers pypdf

