from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
from src.genai_helper import (
    _client_for_key,
    _safe_text,
    _usage_counts,
    _safety_block_none,
)
from src.rotate_API_key import APIKeyRotator

try:
    from google.genai import types as gen_types
except Exception as e:
    raise RuntimeError("Missing google-genai. Install with: pip install -U google-genai") from e

_MODEL_ALIASES: Dict[str, str] = {
    "gemini-2.5-flash": "gemini-2.5-flash",
}

def _normalize_model_name(name: str) -> str:
    if name in _MODEL_ALIASES:
        return _MODEL_ALIASES[name]
    if name.startswith("models/"):
        return name.split("/", 1)[1]
    return name


class GeminiModel:
    def __init__(self, model_name: str, **kwargs: Any) -> None:
        self.model = _normalize_model_name(model_name)

        self.temperature: float = kwargs.get("temperature", 0.0)
        self.max_output_tokens: Optional[int] = kwargs.get("max_output_tokens", None)
        self.top_p: float = kwargs.get("top_p", 1.0)
        self.top_k: int = kwargs.get("top_k", 32)
        self.response_mime_type: str = kwargs.get("response_mime_type", "text/plain")

        keys: Optional[List[str]] = kwargs.get("keys")
        rot_kwargs = dict(
            per_key_attempts=kwargs.get("per_key_attempts", 1),
            total_attempts=kwargs.get("total_attempts", None),
            backoff_base=kwargs.get("backoff_base", 1.5),
            backoff_jitter=kwargs.get("backoff_jitter", 0.3),
            verbose=kwargs.get("verbose", False),
        )
        if keys:
            self.rotator = APIKeyRotator(keys=keys, **rot_kwargs)
        else:
            self.rotator = APIKeyRotator.from_llm_secret(
                per_key_attempts=rot_kwargs["per_key_attempts"],
                total_attempts=rot_kwargs["total_attempts"],
                verbose=rot_kwargs["verbose"],
            )
        self.last_key_used: Optional[str] = None
        self.supports_cache: bool = True

    def _call_once(
        self,
        api_key: str,
        combined_prompt: str,
        *,
        config_override: Optional["gen_types.GenerateContentConfig"] = None,
        contents_override: Optional[List["gen_types.Content"]] = None,
    ) -> Dict[str, Any]:
        client = _client_for_key(api_key)

        contents = contents_override or [
            gen_types.Content(role="user", parts=[gen_types.Part.from_text(text=combined_prompt)])
        ]

        cfg = config_override or gen_types.GenerateContentConfig(
            temperature=self.temperature,
            top_p=self.top_p,
            top_k=self.top_k,
            response_mime_type=self.response_mime_type,
            safety_settings=_safety_block_none(),
            **({"max_output_tokens": self.max_output_tokens} if self.max_output_tokens else {}),
        )

        resp = client.models.generate_content(model=self.model, contents=contents, config=cfg)

        text = _safe_text(resp) or getattr(resp, "text", None) or ""
        p_tok, o_tok, t_tok = _usage_counts(resp)
        usage = {
            "prompt_tokens": int(p_tok) if p_tok not in (None, "") else None,
            "output_tokens": int(o_tok) if o_tok not in (None, "") else None,
            "total_tokens": int(t_tok) if t_tok not in (None, "") else None,
        }
        return {"text": text, "usage": usage, "raw": resp}

    def invoke(
        self,
        system_prompt: str,
        user_prompt: str,
        few_shot_examples: Optional[str] = None,
        *,
        config_override: Optional["gen_types.GenerateContentConfig"] = None,
        contents_override: Optional[List["gen_types.Content"]] = None,
    ) -> Tuple[str, str, Dict[str, Optional[int]]]:
        combined_prompt = (
            f"{system_prompt}\n\n{few_shot_examples}\n\n{user_prompt}"
            if few_shot_examples else f"{system_prompt}\n\n{user_prompt}"
        )

        def _runner(key: str):
            return self._call_once(
                key,
                combined_prompt,
                config_override=config_override,
                contents_override=contents_override,
            )

        result = self.rotator.run(_runner)
        self.last_key_used = getattr(self.rotator, "current_key", None)
        key_suffix = self.last_key_used[-4:] if self.last_key_used else "NA"
        return result["text"], key_suffix, result["usage"]

    def call_gemini_with_rotation(self, *args, **kwargs):
        return self.invoke(*args, **kwargs)

    def predict(
        self,
        combined_prompt: str,
        return_usage: bool = False,
        *,
        config_override: Optional["gen_types.GenerateContentConfig"] = None,
        contents_override: Optional[List["gen_types.Content"]] = None,
    ):
        def _runner(key: str):
            return self._call_once(
                key,
                combined_prompt,
                config_override=config_override,
                contents_override=contents_override,
            )
        result = self.rotator.run(_runner)
        self.last_key_used = getattr(self.rotator, "current_key", None)
        return result if return_usage else result["text"]
