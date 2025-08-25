import os
import sys
import csv
import time
import argparse
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from directory import GALETTE_INSTRUMENT_RESULTS
from DAST_Module.src.prompt_instrument import PROMPT_SYSTEM_TASK_TAGGING, FEW_SHOT_EXAMPLES
import LLM_secret as SECRET
from src.model.llm import create_model
from caching import get_or_create_cached_content, attach_cache_to_config

try:
    from google.genai import types as gen_types
    _HAS_GOOGLE_GENAI = True
except Exception:
    _HAS_GOOGLE_GENAI = False

CACHE_DIR = os.getenv("DAST_CACHE_DIR", ".dast_cache")
os.makedirs(CACHE_DIR, exist_ok=True)
CACHE_META = os.path.join(CACHE_DIR, "genai_cache_meta.json")

DEFAULT_TTL = int(os.getenv("GEMINI_CACHE_TTL", "3600"))
DEFAULT_MAX_OUT = int(os.getenv("GEMINI_MAX_OUT", "800"))

def _ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)

def _ensure_csv(csv_path: str) -> None:
    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                "file","start_time","end_time","elapsed_ms",
                "prompt_tokens","output_tokens","total_tokens",
                "cache_mode","api_backend"
            ])

def _finish_is_max_tokens(resp_raw) -> bool:
    if not resp_raw:
        return False
    try:
        cand = resp_raw.candidates[0]
    except Exception:
        return False
    fr = getattr(cand, "finish_reason", None)
    if fr is None:
        return False
    if isinstance(fr, int):
        return fr == 2
    return str(fr).upper() == "MAX_TOKENS"

def _call_once_with_prefix(llm, combined_prompt: str, max_output_tokens: Optional[int]):
    config = None
    if max_output_tokens is not None and max_output_tokens > 0 and _HAS_GOOGLE_GENAI:
        config = gen_types.GenerateContentConfig(max_output_tokens=int(max_output_tokens))
    res_text, backend, usage = llm.invoke(
        system_prompt="", user_prompt=combined_prompt, few_shot_examples=None,
        config_override=config, contents_override=None,
    )
    return res_text, backend, usage

def _call_cached_once(llm, cached_name: Optional[str], user_prompt: str, max_output_tokens: Optional[int]):
    supports_cache = getattr(llm, "supports_cache", False) and cached_name is not None and _HAS_GOOGLE_GENAI
    if supports_cache:
        cfg_dict = {"temperature": 0.0, "response_mime_type": "text/plain"}
        if max_output_tokens and max_output_tokens > 0:
            cfg_dict["max_output_tokens"] = int(max_output_tokens)
        gen_cfg = gen_types.GenerateContentConfig(**attach_cache_to_config(cached_name, cfg_dict))
        res_text, backend, usage = llm.invoke(
            system_prompt="",
            user_prompt=user_prompt,
            few_shot_examples=None,
            config_override=gen_cfg,
            contents_override=None,
        )
        return res_text, backend, usage, "cached"
    else:
        prefix = f"{PROMPT_SYSTEM_TASK_TAGGING}\n\n{FEW_SHOT_EXAMPLES}\n\n"
        combined = prefix + (user_prompt or "")
        res_text, backend, usage = _call_once_with_prefix(llm, combined, max_output_tokens)
        return res_text, backend, usage, "fallback"

def _call_until_done(llm, cached_name: Optional[str], user_prompt: str, max_output_tokens: int):
    if max_output_tokens and max_output_tokens > 0 or not getattr(llm, "supports_cache", False):
        text, backend, usage, mode = _call_cached_once(llm, cached_name, user_prompt, max_output_tokens)
        return text, mode, backend, usage

    full_text = []
    total_usage = {"prompt_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    mode = "cached"
    backend_name = "gemini"

    while True:
        text, backend, usage, mode = _call_cached_once(llm, cached_name, user_prompt, None)
        backend_name = backend
        full_text.append(text)
        for k in total_usage:
            if usage.get(k):
                total_usage[k] += int(usage[k])

        res = llm.predict(
            combined_prompt=user_prompt,
            return_usage=True,
            config_override=None,
            contents_override=None,
        )
        raw = res.get("raw") if isinstance(res, dict) else None
        if not _finish_is_max_tokens(raw):
            break
        if len(full_text) >= 8:
            break

    return "".join(full_text), mode, backend_name, total_usage

def run_prompts_for_cwe(cwe_id: str, model_name: str, ttl_seconds: int = DEFAULT_TTL, max_output_tokens: int = DEFAULT_MAX_OUT) -> None:
    is_demo = cwe_id.strip().lower() == "demo"
    cwe_folder = "cwe-demo" if is_demo else f"cwe-{cwe_id.strip().zfill(3)}"
    user_prompt_dir = os.path.join(GALETTE_INSTRUMENT_RESULTS, "user_prompt_rs", cwe_folder)
    output_dir      = os.path.join(GALETTE_INSTRUMENT_RESULTS, "LLM_prompt_rs",  cwe_folder)
    _ensure_dir(output_dir)
    metrics_csv = os.path.join(output_dir, "metrics.csv")
    _ensure_csv(metrics_csv)

    llm = create_model(model_name, temperature=0.0, max_output_tokens=(max_output_tokens if max_output_tokens > 0 else None))

    cached_name = None
    if getattr(llm, "supports_cache", False) and _HAS_GOOGLE_GENAI:
        try:
            from genai_helper import _client_for_key
            key = getattr(getattr(llm, "rotator", None), "current_key", None)
            if not key:
                try:
                    llm.predict(" ", return_usage=True)
                    key = getattr(getattr(llm, "rotator", None), "current_key", None)
                except Exception:
                    key = None
            if key:
                client = _client_for_key(key)
                cached_name = get_or_create_cached_content(
                    client=client,
                    model=llm.model,
                    system_text=PROMPT_SYSTEM_TASK_TAGGING,
                    fewshot_text=FEW_SHOT_EXAMPLES,
                    ttl_s=ttl_seconds,
                    meta_path=CACHE_META,
                    display_prefix="dast-prefix",
                )
        except Exception:
            cached_name = None

    processed = 0
    for file in sorted(os.listdir(user_prompt_dir)):
        if not file.endswith(".txt"):
            continue

        in_path  = os.path.join(user_prompt_dir, file)
        out_path = os.path.join(output_dir, file)
        with open(in_path, "r", encoding="utf-8") as f:
            user_prompt = f.read()
        if not user_prompt.strip():
            print(f"[x] Skip empty: {file}")
            continue

        start_iso = datetime.now().isoformat(timespec="seconds")
        t0 = time.perf_counter()

        text, cache_mode, backend_name, usage = _call_until_done(
            llm, cached_name, user_prompt, max_output_tokens=max_output_tokens
        )

        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)

        with open(metrics_csv, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                file, start_iso, datetime.now().isoformat(timespec="seconds"), elapsed_ms,
                usage.get("prompt_tokens"), usage.get("output_tokens"), usage.get("total_tokens"),
                cache_mode, backend_name,
            ])

        print(f"[✓] Saved: {out_path}  ({elapsed_ms} ms, cache={cache_mode}, backend={backend_name})")
        processed += 1

    print(f"\n[!] Done. Processed {processed} file(s) for {cwe_folder}.")
    print(f"[!] Metrics CSV: {metrics_csv}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="LLM tagging (cache when supported)")
    ap.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 078, 089, or 'demo')")
    default_model = getattr(SECRET, "MODEL_NAME", "gemini-2.5-flash")
    ap.add_argument("--model", default=default_model)
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    ap.add_argument("--max_out", type=int, default=DEFAULT_MAX_OUT)
    args = ap.parse_args()
    run_prompts_for_cwe(args.cwe, model_name=args.model, ttl_seconds=args.ttl, max_output_tokens=args.max_out)
