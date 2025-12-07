# code4 변경사항 요약 (free-capstone-main 대비)

## 🔧 주요 변경사항

### 1. Ollama 모델 지원 추가

**Gemini 모델 선택 로직 수정**
- `model_id`가 `ollama:`로 시작하면 Ollama 모델 사용 (예: `ollama:qwen3:8b`)
- Ollama 모델 선택 시 Gemini API 키 불필요
- `call_ollama_generate()` 함수 추가: 대화 히스토리를 컨텍스트로 포함하여 생성

**변경 위치**: `app.py` - `/chat` 라우트 (약 148줄, 267줄)
```python
# Gemini 모델 확인 로직 변경
if model_id != "demo-local" and not model_id.startswith("ollama:") and not (hasattr(app, 'GMODEL') and app.GMODEL):
    return jsonify({"error": "AI 모델이 설정되지 않았습니다."}), 503

# 모델 라우팅
if model_id.startswith("ollama:"):
    llm_resp = call_ollama_generate(model_id, sanitized_messages)
else:
    llm_resp = call_gemini_generate(model_id, sanitized_messages, app.GMODEL)
```

---

### 2. 직원 보조 모드 및 답변 프롬프트 마스킹

#### 2.1. 직원 보조 모드 (차단 완화)
- 계좌번호/전화번호/고객번호를 `block` → `mask`로 완화하여 상담 진행 가능
- Ollama 판정에서도 `block` → `mask`로 완화

**변경 위치**: `app.py` - `/chat` 라우트 (약 201줄, 248줄)

#### 2.2. 답변 프롬프트 마스킹 구성

**입력 요약 마스킹 처리**
- `format_counselor_response()`: LLM 응답의 "입력 요약" 부분을 `create_masked_summary()`로 마스킹
- `create_masked_summary()`: 사용자 입력을 마스킹된 요약으로 변환
  - 생년월일: `1995년생` → `1990년대생`
  - 전화번호: `010-1234-5678` → `[PHONE]`
  - 계좌번호: `123-456-789012` → `[ACCOUNT]`
  - 고객번호: `123456789` → `[CUSTOMER_ID]`
  - 주소: 한국 주소 패턴 → `[ADDRESS]`

**응답 마스킹 처리**
- `apply_patterns_for_output_excluding_summary()`: "입력 요약:" 섹션은 보호하고 나머지 부분만 마스킹
- 어시스턴트 응답에서 민감정보 탐지 시 마스킹 처리 (차단하지 않음)

**처리 흐름**:
1. LLM 응답 생성 → `format_counselor_response()`로 "입력 요약" 마스킹
2. `apply_patterns_for_output_excluding_summary()`로 응답 본문 마스킹 (입력 요약 제외)
3. 중복 제거 및 정리 함수들 적용

**변경 위치**: `app.py` (약 271줄, 274줄, 529줄, 770줄)

---

### 3. 민감정보 패턴 수정 (금융 도메인 특화)

**patterns.json** - 금융에서 사용될만한 민감정보만 추려서 정규식 수정

**추가/수정된 패턴**:
- 계좌번호: 10자리 연속 숫자 추가, 하이픈 있음/없음 모두 지원
- 고객번호: "고객 번호" 띄어쓰기 형식, 문맥 키워드 추가
- 전화번호: 하이픈 없이 연속된 숫자 형식 지원
- 주소: 지역명+도로명/길+번지 패턴, 우편번호 패턴
- **금리 확정 표현**: 차단 패턴 추가 (예: "금리는 3.5%입니다")
- **수수료 확정 표현**: 차단 패턴 추가 (예: "수수료는 5,000원입니다")
- **계좌 이체 요청**: 차단 패턴 추가
- **대출 신청**: 차단 패턴 추가

**변경 위치**: `patterns.json` (루트 디렉토리)

---

## 📁 추가된 파일/디렉토리

- `services/` - 코드 모듈화
  - `ollama_service.py`: Ollama 관련 함수
  - `policy_service.py`: 민감정보 필터링 로직
- `patterns.json` - 민감정보 패턴 정의
- `requirements.txt` - Python 패키지 의존성
- `services/rag_service.py` - RAG 컨텍스트 검색 (Week 2)
- `scripts/embed_documents.py` - RAG 문서 임베딩 스크립트 (Week 2)
- `scripts/rag_docs/` - RAG 참고 문서 저장 경로 (Week 2)
- `vector_db/` - Chroma Vector DB 저장소 (Week 2)
- 기타: `config/`, `docs/`, `scripts/`, `db_migrations/` 디렉토리

---

## 💡 주요 개선점

1. **Ollama 모델 지원**: 로컬 모델 사용 가능, API 키 불필요
2. **직원 보조 모드**: 차단 대신 마스킹으로 상담 진행 가능
3. **답변 마스킹**: 입력 요약과 응답 본문 모두 마스킹 처리
4. **금융 도메인 특화**: 금리/수수료 확정 표현, 거래 요청 차단
5. **RAG 컨텍스트 주입**: 내부 문서를 활용한 답변 및 출처 안내 (Week 2)
6. **출력 재검열 강화**: RAG 결과 포함 상태에서도 금리/수수료 확정 표현 재검열 (Week 2)

