import time
import re
import random
from typing import Callable, List, Optional


def _load_keys_from_llm_secret() -> List[str]:
    """Load keys from LLM_secret.py (GEMINI_KEY, GEMINI_KEY_1..10)."""
    keys: List[str] = []
    try:
        import LLM_secret  # type: ignore
        # primary
        if hasattr(LLM_secret, "GEMINI_KEY"):
            v = getattr(LLM_secret, "GEMINI_KEY")
            if isinstance(v, str) and v.strip():
                keys.append(v.strip())
        # indexed
        for i in range(1, 11):
            name = f"GEMINI_KEY_{i}"
            if hasattr(LLM_secret, name):
                v = getattr(LLM_secret, name)
                if isinstance(v, str) and v.strip():
                    keys.append(v.strip())
    except Exception:
        pass

    # de-duplicate, preserve order
    seen = set()
    uniq: List[str] = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq


# Rotate-worthy error hints (keep minimal & generic)
_ROTATE_HINTS = [
    r"\b401\b", r"\b403\b", r"\b429\b", r"\b5\d{2}\b",
    r"unauthorized", r"permission denied", r"forbidden",
    r"rate[- ]?limit", r"too many requests",
    r"quota", r"exceeded", r"exhausted", r"billing",
    r"resource exhausted",
]

# Do-NOT-rotate (client error) hints
_NO_ROTATE_HINTS = [
    r"\b400\b", r"invalid argument", r"bad request",
    r"response_schema", r"schema", r"malformed", r"unsupported",
]

# High-priority: force-rotate when API key itself is invalid/expired
# (Ưu tiên cao hơn _NO_ROTATE_HINTS để xử lý các lỗi 400 INVALID_ARGUMENT do key hết hạn)
KEY_INVALID_HINTS = [
    r"api[_\s-]?key[_\s-]?invalid",
    r"api[_\s-]?key[_\s-]?expired",
    r"\bapi_key_invalid\b",
    r"\bkey\b.*\b(expired|revoked)\b",
]


class APIKeyRotator:
    def __init__(
        self,
        keys: List[str],
        start_index: int = 0,
        per_key_attempts: int = 1,
        total_attempts: Optional[int] = None,
        backoff_base: float = 1.5,
        backoff_jitter: float = 0.3,
        verbose: bool = True,
    ) -> None:
        if not keys or not all(isinstance(k, str) and k.strip() for k in keys):
            raise ValueError("APIKeyRotator: Provide a non-empty list of keys.")
        self.keys = keys
        self.i = max(0, min(start_index, len(keys) - 1))
        self.per_key_attempts = max(1, per_key_attempts)
        self.total_attempts = total_attempts or (self.per_key_attempts * len(keys))
        self.backoff_base = backoff_base
        self.backoff_jitter = backoff_jitter
        self.verbose = verbose
        self._attempt = 0

    @classmethod
    def from_llm_secret(cls, **kwargs) -> "APIKeyRotator":
        keys = _load_keys_from_llm_secret()
        if not keys:
            raise ValueError("No keys found in LLM_secret.py (GEMINI_KEY or GEMINI_KEY_1..10).")
        return cls(keys, **kwargs)

    @property
    def current_key(self) -> str:
        return self.keys[self.i]

    def rotate(self) -> str:
        self.i = (self.i + 1) % len(self.keys)
        if self.verbose:
            print(f"[rotate_API_key] -> switched to key {self.i+1}/{len(self.keys)}")
        return self.current_key

    # ---- error classification (generic, no SDK imports) ----
    def _text(self, exc: BaseException) -> str:
        for attr in ("message", "detail", "args"):
            try:
                v = getattr(exc, attr, None)
                if isinstance(v, str) and v:
                    return v
                if isinstance(v, (list, tuple)) and v and isinstance(v[0], str):
                    return v[0]
            except Exception:
                pass
        return str(exc)

    def _status_code(self, exc: BaseException) -> Optional[int]:
        for attr in ("code", "status_code", "http_status"):
            try:
                v = getattr(exc, attr, None)
                if isinstance(v, int):
                    return v
            except Exception:
                pass
        try:
            status = getattr(exc, "status", None)
            if isinstance(status, str):
                mapping = {
                    "UNAUTHENTICATED": 401,
                    "PERMISSION_DENIED": 403,
                    "RESOURCE_EXHAUSTED": 429,
                }
                return mapping.get(status.upper())
        except Exception:
            pass
        return None

    def should_rotate(self, exc: BaseException) -> bool:
        msg = self._text(exc).lower()
        code = self._status_code(exc)

        # (A) Key invalid/expired: ALWAYS rotate (even if it's a 400 INVALID_ARGUMENT)
        if any(re.search(p, msg) for p in KEY_INVALID_HINTS):
            return True

        # (B) Obvious auth/rate/server codes: rotate
        if code in (401, 403, 429) or (isinstance(code, int) and 500 <= code < 600):
            return True

        # (C) Non-rotate client errors (schema/bad request...) — keep existing behavior
        if any(re.search(p, msg) for p in _NO_ROTATE_HINTS):
            return False

        # (D) Generic rotate-worthy hints (quota/rate/billing...)
        if any(re.search(p, msg) for p in _ROTATE_HINTS):
            return True

        return False

    # ---- runner ----
    def run(self, fn: Callable, *args, **kwargs):
        """Call `fn(api_key, *args, **kwargs)` with rotation & simple backoff."""
        attempts_left = max(1, self.total_attempts)
        last_err: Optional[BaseException] = None

        while attempts_left > 0:
            attempts_left -= 1
            api_key = self.current_key
            try:
                if self.verbose:
                    print(f"[rotate_API_key] using key {self.i+1}/{len(self.keys)}")
                return fn(api_key, *args, **kwargs)
            except BaseException as e:
                last_err = e
                if self.should_rotate(e) and attempts_left > 0:
                    self._attempt += 1
                    delay = max(
                        0.4,
                        (self.backoff_base ** (self._attempt - 1))
                        * (1 + random.uniform(-self.backoff_jitter, self.backoff_jitter)),
                    )
                    if self.verbose:
                        print(f"[rotate_API_key] rotate due to: {e}. Backoff {delay:.2f}s")
                    time.sleep(delay)
                    self.rotate()
                    continue
                raise

        if last_err:
            raise last_err
        raise RuntimeError("Rotation runner exhausted without raising an error (unexpected).")
