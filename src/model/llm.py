from __future__ import annotations
from typing import Any
from src.model.gemini import GeminiModel
try:
    from src.model.ollama import OllamaModel
    _HAS_OLLAMA = True
except Exception:
    _HAS_OLLAMA = False

def create_model(model_name: str, **kwargs: Any):
    name = (model_name or "").lower()
    if name.startswith("gemini") or name.startswith("models/gemini"):
        m = GeminiModel(model_name, **kwargs)
        m.supports_cache = True
        return m
    if not _HAS_OLLAMA:
        raise RuntimeError("Ollama backend requested but dependencies missing.")
    return OllamaModel(model_name, **kwargs)