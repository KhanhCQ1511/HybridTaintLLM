from typing import Optional, Tuple

def _client_for_key(api_key: Optional[str]):
    """Return a genai.Client configured with api_key (or default creds if None)."""
    from google import genai  # local import to avoid hard dependency on import
    return genai.Client(api_key=api_key) if api_key else genai.Client()

def _safe_text(resp) -> str:
    try:
        if getattr(resp, "text", None):
            return resp.text
        cands = getattr(resp, "candidates", None) or []
        if not cands:
            return ""
        parts = getattr(cands[0].content, "parts", None) or []
        out = []
        for p in parts:
            t = getattr(p, "text", None)
            if t:
                out.append(t)
        return "".join(out).strip()
    except Exception:
        return ""

def _usage_counts(resp) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Extract (prompt, output, total) token counters from response (best-effort)."""
    u = getattr(resp, "usage_metadata", None)
    def pick(keys):
        if u is None:
            return None
        for k in keys:
            if isinstance(u, dict) and k in u:
                return u[k]
            v = getattr(u, k, None)
            if v is not None:
                return v
        return None
    prompt = pick(("prompt_token_count", "promptTokens", "promptTokenCount", "input_tokens", "inputTokens"))
    output = pick(("candidates_token_count", "candidatesTokens", "candidatesTokenCount", "output_tokens", "outputTokens", "outputTokenCount"))
    total = pick(("total_token_count", "totalTokens", "totalTokenCount"))
    try:
        if (output is None) and (prompt is not None) and (total is not None):
            output = int(total) - int(prompt)
    except Exception:
        pass
    return (int(prompt) if prompt is not None else None,
            int(output) if output is not None else None,
            int(total) if total is not None else None)

def _finish_reason(resp) -> str:
    """Return finish_reason as friendly string; handles numeric/enums."""
    try:
        cands = getattr(resp, "candidates", None) or []
        if not cands:
            return ""
        fr = getattr(cands[0], "finish_reason", "") or ""
        mapping = {
            0: "UNSPECIFIED",
            1: "STOP",
            2: "MAX_TOKENS",
            3: "SAFETY",
            4: "RECITATION",
            5: "OTHER",
            6: "BLOCKLIST",
            7: "MALFORMED_FUNCTION_CALL",
            8: "SPII",
        }
        try:
            fr_i = int(fr)
            return mapping.get(fr_i, str(fr))
        except Exception:
            return str(fr)
    except Exception:
        return ""

def _safety_block_none():
    """Return a list of SafetySetting with BLOCK_NONE for common categories."""
    try:
        from google.genai import types  # local import
    except Exception:
        return []
    desired = [
        "HARM_CATEGORY_HARASSMENT",
        "HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "HARM_CATEGORY_DANGEROUS_CONTENT",
        "HARM_CATEGORY_CIVIC_INTEGRITY",
    ]
    out = []
    HarmCategory = getattr(types, "HarmCategory", None)
    HarmBlockThreshold = getattr(types, "HarmBlockThreshold", None)
    if HarmCategory is None or HarmBlockThreshold is None:
        return out
    for name in desired:
        if hasattr(HarmCategory, name):
            out.append(types.SafetySetting(
                category=getattr(HarmCategory, name),
                threshold=HarmBlockThreshold.BLOCK_NONE
            ))
    return out
