import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
from typing import List, Dict, Any

# 한국어 NER 모델
# 주의: klue/roberta-base는 기본 언어모델이라 NER 레이블이 제대로 안 나옵니다.
# 실제 NER로 파인튜닝된 모델을 사용해야 합니다.
#
# 옵션 1: KoELECTRA 기반 (더 빠름)
# MODEL_NAME = "monologg/koelectra-base-v3-discriminator"
#
# 옵션 2: KLUE-BERT 기반 (더 정확함, 하지만 NER 전용 모델 필요)
# MODEL_NAME = "klue/bert-base"
#
# 일단은 기본 모델로 테스트 (나중에 NER 전용 모델로 교체 필요)
MODEL_NAME = "klue/roberta-base"

_device = 0 if torch.cuda.is_available() else -1

_tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
_model = AutoModelForTokenClassification.from_pretrained(MODEL_NAME)

_ner = pipeline(
    "token-classification",
    model=_model,
    tokenizer=_tokenizer,
    aggregation_strategy="simple",
    device=_device,
)


def run_ner(text: str) -> List[Dict[str, Any]]:
    """
    한국어 회의록/메일 등 한 뭉치 텍스트에 대해 NER 실행.

    반환 예시:
    [
        {"label": "PERSON", "word": "홍길동", "start": 10, "end": 13, "score": 0.98},
        ...
    ]
    """
    if not text:
        return []

    results = _ner(text)
    entities: List[Dict[str, Any]] = []
    for ent in results:
        label = ent.get("entity_group") or ent.get("entity", "")
        word = ent.get("word", "")

        # 기본 모델의 제네릭 레이블을 의미 있는 레이블로 매핑 시도
        # (실제 NER 모델 사용 시 이 부분은 불필요)
        if label.startswith("LABEL_"):
            # 한국어 이름 패턴 체크 (간단한 휴리스틱)
            if any(
                char in word
                for char in "김이박최정강조윤장임한오서신권황안송류전홍고문양손배조백허유남심노정하곽성길주우진민지"
            ):
                label = "PERSON"
            # 기관명 패턴 체크
            elif any(keyword in word for keyword in ["은행", "회사", "기업", "그룹", "전자", "텔레콤"]):
                label = "ORG"
            else:
                label = "ETC"  # 기타

        entities.append(
            {
                "label": label,
                "word": word,
                "start": int(ent.get("start", 0)),
                "end": int(ent.get("end", 0)),
                "score": float(ent.get("score", 0.0)),
            }
        )
    return entities


