import os
import sys
import csv
import time
import json
import argparse
import re
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from directory import LLM_OUTPUT_DIR
from directory import LLM_OUTPUT_USER_DIR
from LLM.src.prompt import PROMPT_SYSTEM_TASK
from src.model.llm import create_model

def _ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def _ensure_csv(path):
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                "file","start_time","end_time","elapsed_ms",
                "prompt_tokens","output_tokens","total_tokens","api_key_suffix_or_backend"
            ])

def _map_usage(u):
    if not isinstance(u, dict):
        return None, None, None
    def pick(d, *keys):
        for k in keys:
            if k in d and d[k] is not None and str(d[k]).strip() != "":
                return d[k]
        return None
    p = pick(u, "prompt_tokens","promptTokenCount","input_tokens","inputTokens")
    o = pick(u, "output_tokens","candidatesTokenCount","output_tokens_count","outputTokens")
    t = pick(u, "total_tokens","totalTokenCount","total_tokens_count","totalTokens","billable_tokens")
    try: p = int(p) if p is not None else None
    except: p = None
    try: o = int(o) if o is not None else None
    except: o = None
    try: t = int(t) if t is not None else None
    except: t = None
    return p, o, t

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)

def _strip_fences(s):
    if not isinstance(s, str):
        return s
    return _FENCE_RE.sub("", s.strip())

def _normalize_quotes(s: str) -> str:
    return (s.replace("\u201c", '"').replace("\u201d", '"')
             .replace("\u2018", "'").replace("\u2019", "'"))

def _clean_trailing_commas(s: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", s)

def _extract_json_string(text):
    if not isinstance(text, str):
        return None
    s = _strip_fences(text)
    s = _normalize_quotes(s)
    try:
        json.loads(s)
        return s
    except Exception:
        pass
    first_obj, last_obj = s.find("{"), s.rfind("}")
    first_arr, last_arr = s.find("["), s.rfind("]")
    ranges = []
    if first_obj != -1 and last_obj != -1 and last_obj > first_obj:
        ranges.append((first_obj, last_obj+1))
    if first_arr != -1 and last_arr != -1 and last_arr > first_arr:
        ranges.append((first_arr, last_arr+1))
    ranges.sort(key=lambda x: (s[x[0]] != "{", x[0]))
    for i, j in ranges:
        core = _clean_trailing_commas(s[i:j])
        try:
            json.loads(core)
            return core
        except Exception:
            try:
                import json5
                obj = json5.loads(core)
                return json.dumps(obj, ensure_ascii=False)
            except Exception:
                continue
    return None

def _run_model(model, system_prompt, user_prompt, model_name_hint):
    backend = getattr(model, "model", None) or getattr(model, "name", None) or model_name_hint or "unknown"
    usage = {}
    if hasattr(model, "invoke"):
        out = model.invoke(system_prompt, user_prompt)
        if isinstance(out, tuple):
            text = out[0]
            if len(out) >= 2 and out[1]:
                backend = out[1]
            if len(out) >= 3 and isinstance(out[2], dict):
                usage = out[2]
            return str(text), backend, usage
        return str(out), backend, usage
    if hasattr(model, "predict"):
        res = model.predict(
            combined_prompt=f"{system_prompt}\n\n{user_prompt}",
            return_usage=True,
            config_override={"response_mime_type": "application/json"},
            contents_override=None,
        )
        if isinstance(res, dict):
            text = res.get("text") or res.get("output") or res.get("content") or res.get("response") or ""
            usage = res.get("usage") or {}
            b = getattr(model, "model", None) or getattr(model, "name", None) or backend
            return str(text), b, usage
        return str(res), backend, usage
    if hasattr(model, "generate"):
        res = model.generate(system_prompt, user_prompt)
        return (str(res), backend, usage)
    raise AttributeError(f"{type(model).__name__} has no supported generation method")

def run_prompts_for_cwe(cwe_id, model_name):
    cwe = str(cwe_id).strip().lower()
    cwe_dirname = "cwe-demo" if cwe == "demo" else f"cwe-{cwe.zfill(3)}"
    user_prompt_dir = os.path.join(LLM_OUTPUT_USER_DIR, cwe_dirname, "user_prompt_rs")
    output_dir = os.path.join(LLM_OUTPUT_DIR, cwe_dirname)
    _ensure_dir(output_dir)
    raw_fail_dir = os.path.join(output_dir, "_failed_raw")
    _ensure_dir(raw_fail_dir)
    metrics_csv = os.path.join(output_dir, "metrics.csv")
    _ensure_csv(metrics_csv)
    if not os.path.isdir(user_prompt_dir):
        print(f"[!] Can't find user prompt folder: {user_prompt_dir}")
        return
    model = create_model(model_name)
    files = sorted([f for f in os.listdir(user_prompt_dir) if f.lower().endswith(".txt")])
    print(f"[!] Found {len(files)} prompt files in: {user_prompt_dir}")
    for fname in files:
        fpath = os.path.join(user_prompt_dir, fname)
        print(f"\n[⚙] Processing: {fname}")
        with open(fpath, "r", encoding="utf-8") as f:
            user_prompt = f.read()
        if not user_prompt.strip():
            print("[!] Skipped empty prompt")
            continue
        start_iso = datetime.now().isoformat(timespec="seconds")
        t0 = time.perf_counter()
        backend_label = getattr(model, "model", None) or getattr(model, "name", None) or model_name
        p_tok = o_tok = t_tok = None
        try:
            text, backend, usage = _run_model(model, PROMPT_SYSTEM_TASK, user_prompt, model_name)
            backend_label = backend or backend_label
            p_tok, o_tok, t_tok = _map_usage(usage)
            json_str = _extract_json_string(text)
            end_iso = datetime.now().isoformat(timespec="seconds")
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            if json_str is None:
                with open(metrics_csv, "a", newline="", encoding="utf-8") as mf:
                    csv.writer(mf).writerow([
                        fname, start_iso, end_iso, elapsed_ms,
                        p_tok, o_tok, t_tok, backend_label
                    ])
                raw_fail_path = os.path.join(raw_fail_dir, fname.replace(".txt", ".raw.txt"))
                with open(raw_fail_path, "w", encoding="utf-8") as rf:
                    rf.write(text if isinstance(text, str) else str(text))
                print(f"[!] Failed JSON parse, saved raw to: {raw_fail_path}")
                continue
            try:
                obj = json.loads(json_str)
            except Exception:
                import json5
                obj = json5.loads(json_str)
            json_str = json.dumps(obj, ensure_ascii=False, indent=2)
            out_path = os.path.join(output_dir, fname.replace(".txt", ".json"))
            with open(out_path, "w", encoding="utf-8") as outf:
                outf.write(json_str)
            with open(metrics_csv, "a", newline="", encoding="utf-8") as mf:
                csv.writer(mf).writerow([
                    fname, start_iso, end_iso, elapsed_ms,
                    p_tok, o_tok, t_tok, backend_label
                ])
            print(f"[!] Saved JSON: {out_path} ({elapsed_ms} ms)")
        except Exception as e:
            end_iso = datetime.now().isoformat(timespec="seconds")
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            with open(metrics_csv, "a", newline="", encoding="utf-8") as mf:
                csv.writer(mf).writerow([
                    fname, start_iso, end_iso, elapsed_ms,
                    p_tok, o_tok, t_tok, backend_label
                ])
            raw_fail_path = os.path.join(raw_fail_dir, fname.replace(".txt", ".raw.txt"))
            with open(raw_fail_path, "w", encoding="utf-8") as failf:
                failf.write(user_prompt)
            print(f"[!] Failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwe", required=True)
    parser.add_argument("--model", required=True)
    args = parser.parse_args()
    run_prompts_for_cwe(args.cwe, args.model)