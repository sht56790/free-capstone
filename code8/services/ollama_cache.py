"""
Ollama 서비스용 캐싱 시스템
- 동일한 입력에 대한 반복 호출 방지
- 메모리 기반 LRU 캐시 사용
"""
import hashlib
import json
from typing import Any, Dict, List, Optional
from functools import lru_cache


class OllamaCache:
    """Ollama API 응답 캐싱 클래스"""
    
    def __init__(self, max_size: int = 1000):
        """
        Args:
            max_size: 캐시에 저장할 최대 항목 수
        """
        self.max_size = max_size
        self._cache: Dict[str, List[Dict[str, Any]]] = {}
    
    def _make_key(self, text: str, model: str) -> str:
        """텍스트와 모델명으로 캐시 키 생성"""
        combined = f"{model}:{text}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    def get(self, text: str, model: str) -> Optional[List[Dict[str, Any]]]:
        """캐시에서 결과 조회
        
        Args:
            text: 입력 텍스트
            model: 모델명
            
        Returns:
            캐시된 결과 또는 None
        """
        key = self._make_key(text, model)
        return self._cache.get(key)
    
    def set(self, text: str, model: str, result: List[Dict[str, Any]]):
        """캐시에 결과 저장
        
        Args:
            text: 입력 텍스트
            model: 모델명
            result: 저장할 결과
        """
        key = self._make_key(text, model)
        
        # 캐시 크기 제한 초과 시 오래된 항목 제거 (간단한 FIFO)
        if len(self._cache) >= self.max_size:
            # 첫 번째 항목 제거
            first_key = next(iter(self._cache))
            del self._cache[first_key]
        
        self._cache[key] = result
    
    def clear(self):
        """캐시 전체 삭제"""
        self._cache.clear()
    
    def size(self) -> int:
        """현재 캐시 크기 반환"""
        return len(self._cache)
    
    def stats(self) -> Dict[str, Any]:
        """캐시 통계 반환"""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "usage_percent": (len(self._cache) / self.max_size * 100) if self.max_size > 0 else 0
        }


# 싱글톤 인스턴스
_cache_instance: Optional[OllamaCache] = None


def get_cache() -> OllamaCache:
    """캐시 싱글톤 인스턴스 반환"""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = OllamaCache(max_size=1000)
    return _cache_instance


def clear_cache():
    """캐시 초기화"""
    cache = get_cache()
    cache.clear()


def get_cache_stats() -> Dict[str, Any]:
    """캐시 통계 조회"""
    cache = get_cache()
    return cache.stats()

