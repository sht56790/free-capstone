"""
Ollama 응답 캐싱 시스템
동일한 입력에 대해 재요청하지 않도록 메모리 캐시 추가
- LRU 캐시로 메모리 관리
- 해시 기반 빠른 조회
"""
import hashlib
from functools import lru_cache
from typing import List, Dict, Any

class OllamaCache:
    """Ollama 판정 결과를 캐싱하는 클래스"""
    
    def __init__(self, max_size: int = 1000):
        self.cache: Dict[str, List[Dict[str, Any]]] = {}
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
    
    def _hash_text(self, text: str, model: str) -> str:
        """텍스트와 모델을 조합하여 해시 생성"""
        combined = f"{model}:{text}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    def get(self, text: str, model: str) -> List[Dict[str, Any]] | None:
        """캐시에서 결과 조회"""
        key = self._hash_text(text, model)
        if key in self.cache:
            self.hits += 1
            return self.cache[key]
        self.misses += 1
        return None
    
    def set(self, text: str, model: str, result: List[Dict[str, Any]]) -> None:
        """캐시에 결과 저장"""
        if len(self.cache) >= self.max_size:
            # LRU: 가장 오래된 항목 제거
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        
        key = self._hash_text(text, model)
        self.cache[key] = result
    
    def clear(self) -> None:
        """캐시 초기화"""
        self.cache.clear()
        self.hits = 0
        self.misses = 0
    
    def stats(self) -> Dict[str, Any]:
        """캐시 통계"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate
        }

# 전역 캐시 인스턴스
_ollama_cache = OllamaCache(max_size=1000)

def get_cache() -> OllamaCache:
    """전역 캐시 인스턴스 반환"""
    return _ollama_cache
