import os
import json
import time
import hashlib
from typing import Optional
from google import genai  # type: ignore
from google.genai import types, errors  # type: ignore

DEFAULT_RENEW_MARGIN_S = 60

def _hash_key(model: str, system_text: Optional[str], fewshot_text: Optional[str]) -> str:
    h = hashlib.sha256()
    h.update((model or "").encode("utf-8"))
    h.update(b"::SYS::")
    h.update((system_text or "").encode("utf-8"))
    h.update(b"::FEW::")
    h.update((fewshot_text or "").encode("utf-8"))
    return h.hexdigest()

def _load_meta(meta_path: str) -> dict:
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _save_meta(meta_path: str, meta: dict) -> None:
    os.makedirs(os.path.dirname(meta_path) or ".", exist_ok=True)
    tmp = meta_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    os.replace(tmp, meta_path)


def get_or_create_cached_content(
    *,
    client,
    model: str,
    system_text: Optional[str] = None,
    fewshot_text: Optional[str] = None,
    ttl_s: int = 3600,
    meta_path: str = ".genai_cache_meta.json",
    display_prefix: str = "dast-cache",
    renew_margin_s: int = DEFAULT_RENEW_MARGIN_S,
    force_new: bool = False,
) -> Optional[str]:
    """Ensure an explicit cache for the selected prompt parts exists; return its name.

    Args:
        client: genai.Client instance (new google-genai SDK).
        model: model name, e.g. "models/gemini-2.5-flash".
        system_text: SYSTEM prompt to cache (optional).
        fewshot_text: FEW_SHOT examples to cache as a single user content (optional).
        ttl_s: cache TTL in seconds.
        meta_path: path to a JSON metadata file to keep cache mappings (per project/file).
        display_prefix: a readable prefix for the cache display name in Gemini UI.
        renew_margin_s: renew before actual TTL by this many seconds.
        force_new: if True, create a new cache, ignoring existing mapping.

    Returns:
        The `cached.name` string if at least one of the fields is provided; otherwise None.
    """
    if not (system_text or fewshot_text):
        return None

    key = _hash_key(model, system_text, fewshot_text)
    meta = _load_meta(meta_path)
    now = time.time()

    # Reuse existing cache entry if still fresh
    if not force_new:
        entry = meta.get(key)
        if entry:
            created = float(entry.get("created_at", 0))
            ttl = int(entry.get("ttl", ttl_s))
            if now - created < max(0, ttl - int(renew_margin_s)):
                return entry.get("name")

    # Compose CreateCachedContentConfig exactly like your scripts
    cfg_kwargs = {}
    # Only include fields the caller asked to cache:
    if system_text and str(system_text).strip():
        cfg_kwargs["system_instruction"] = system_text
    if fewshot_text and str(fewshot_text).strip():
        # In your scripts, FEW_SHOT is stored as a single user message
        cfg_kwargs["contents"] = [
            types.Content(role="user", parts=[types.Part.from_text(text=fewshot_text)])
        ]

    # If nothing is set (texts empty after strip), return None
    if not cfg_kwargs:
        return None

    cached = client.caches.create(
        model=model,
        config=types.CreateCachedContentConfig(
            display_name=f"{display_prefix}-{key[:8]}",
            ttl=f"{int(ttl_s)}s",
            **cfg_kwargs,
        ),
    )

    meta[key] = {"name": cached.name, "created_at": now, "ttl": int(ttl_s)}
    _save_meta(meta_path, meta)
    return cached.name


# Optional helper: build a request config dict including cached_content if present
def attach_cache_to_config(cached_name: Optional[str], base_cfg: Optional[dict] = None) -> dict:
    """Return a config dict you can pass to types.GenerateContentConfig(**cfg)."""
    cfg = dict(base_cfg or {})
    if cached_name:
        cfg["cached_content"] = cached_name
    return cfg
