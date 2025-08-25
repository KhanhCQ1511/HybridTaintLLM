#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import csv
import math
import re
from typing import Tuple, Optional, List, Dict, DefaultDict
from collections import defaultdict

def _ensure_on_sys_path(path: str) -> None:
    if path not in sys.path:
        sys.path.insert(0, path)

def _find_repo_root(start: Optional[str] = None) -> str:
    here = os.path.abspath(start or os.path.dirname(__file__))
    for up in range(0, 7):
        cand = os.path.abspath(os.path.join(here, *(['..'] * up)))
        if os.path.exists(os.path.join(cand, 'directory.py')):
            return cand
        if os.path.isdir(os.path.join(cand, 'DAST_Module')):
            return cand
    return os.path.abspath(os.path.join(here))

REPO_ROOT = _find_repo_root()
_ensure_on_sys_path(REPO_ROOT)

DEFAULT_FILTER_ROOT = os.path.join(REPO_ROOT, 'DAST_Module', 'filter')
DEFAULT_USER_PROMPT_ROOT = os.path.join(
    REPO_ROOT,
    'DAST_Module',
    'script',
    'instrument',
    'galette_instrument_prompt_results',
    'user_prompt_rs'
)

try:
    import directory  # type: ignore
    FILTER_ROOT = getattr(directory, 'GALETTE_FILTER', DEFAULT_FILTER_ROOT)
    USER_PROMPT_ROOT = getattr(directory, 'GALETTE_USER_PROMPT_RS', DEFAULT_USER_PROMPT_ROOT)
except Exception:
    FILTER_ROOT = DEFAULT_FILTER_ROOT
    USER_PROMPT_ROOT = DEFAULT_USER_PROMPT_ROOT

def _import_prompt_lib() -> object:
    mod = None
    try:
        import importlib
        mod = importlib.import_module('DAST_Module.script.filter.prompt_instrument_v2')
        return mod
    except Exception:
        pass
    fallback_path = os.path.join(REPO_ROOT, 'DAST_Module', 'script', 'filter')
    _ensure_on_sys_path(fallback_path)
    try:
        import importlib
        mod = importlib.import_module('prompt_instrument_v2')
        return mod
    except Exception as e:
        raise SystemExit(
            f"[!] Cannot import prompt library at 'DAST_Module/script/filter/prompt_instrument_v2.py'. Error: {e}"
        )

def _load_prompts() -> Tuple[str, str, str, str]:
    mod = _import_prompt_lib()
    candidates = [
        ('PROMPT_SYSTEM', 'FEW_SHOT_STRING', 'FEW_SHOT_LIST', 'FEW_SHOT_SQL'),
        ('PROMPT_SYSTEM_TASK_TAGGING', 'FEW_SHOT_STRING', 'FEW_SHOT_LIST', 'FEW_SHOT_SQL'),
    ]
    for a,b,c,d in candidates:
        try:
            system = getattr(mod, a)
            fstr   = getattr(mod, b)
            flst   = getattr(mod, c)
            fsql   = getattr(mod, d)
            return str(system), str(fstr), str(flst), str(fsql)
        except Exception:
            continue
    raise SystemExit("[!] Missing constants in prompt_instrument_v2.py: need PROMPT_SYSTEM + FEW_SHOT_STRING + FEW_SHOT_LIST + FEW_SHOT_SQL")

def _ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)

def _cwe_folder(cwe: int) -> str:
    return f"cwe-{cwe:03d}"

def _read_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8') as f:
        return [ln.strip() for ln in f if ln.strip()]

def _base_from_java(java_name: str) -> str:
    if java_name.lower().endswith('.java'):
        return java_name[:-5]
    return java_name

def _user_prompt_dirs(cwe: int) -> List[str]:
    cwe2 = f"cwe-{cwe:02d}"
    cwe3 = f"cwe-{cwe:03d}"
    return [
        os.path.join(USER_PROMPT_ROOT, cwe3),
        os.path.join(USER_PROMPT_ROOT, cwe2),
        os.path.join(USER_PROMPT_ROOT, str(cwe)),
        os.path.join(USER_PROMPT_ROOT),
    ]

def _iter_txt_files(root: str) -> List[str]:
    files: List[str] = []
    for base, _, fs in os.walk(root):
        for name in fs:
            if name.lower().endswith('.txt'):
                files.append(os.path.join(base, name))
    return files

def _pick_best_match(base: str, cwe: int, files: List[str]) -> Optional[str]:
    pat_exact_2 = re.compile(rf"^{re.escape(base)}_user_prompt_{cwe:02d}\.txt$", re.IGNORECASE)
    pat_exact_3 = re.compile(rf"^{re.escape(base)}_user_prompt_{cwe:03d}\.txt$", re.IGNORECASE)
    for p in files:
        if pat_exact_2.match(os.path.basename(p)) or pat_exact_3.match(os.path.basename(p)):
            return p
    pat_any = re.compile(rf"^{re.escape(base)}_user_prompt_\d+\.txt$", re.IGNORECASE)
    nums: List[Tuple[int, str]] = []
    for p in files:
        name = os.path.basename(p)
        m = pat_any.match(name)
        if m:
            num = int(re.findall(r"(\d+)\.txt$", name)[0])
            nums.append((num, p))
    if nums:
        nums.sort()
        return nums[0][1]
    sub_matches = [p for p in files if base.lower() in os.path.basename(p).lower()]
    if sub_matches:
        return sorted(sub_matches)[0]
    for suffix in [f"{base}_user_prompt.txt", f"{base}.txt"]:
        for p in files:
            if os.path.basename(p).lower() == suffix.lower():
                return p
    return files[0] if files else None

def _build_content_index(cwe: int) -> Dict[str, List[str]]:
    index: DefaultDict[str, List[str]] = defaultdict(list)
    for d in _user_prompt_dirs(cwe):
        if not os.path.isdir(d):
            continue
        for path in _iter_txt_files(d):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    text = f.read()
            except Exception:
                continue
            for m in re.finditer(r'([A-Za-z0-9_$\.]+)\.java', text):
                base = m.group(1).split('.')[-1]
                if base:
                    index[base].append(path)
    return index

def _read_user_prompt_any(base: str, cwe: int, content_index: Optional[Dict[str, List[str]]] = None) -> Tuple[Optional[str], Optional[str]]:
    candidates: List[str] = []
    for d in _user_prompt_dirs(cwe):
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if not name.lower().endswith('.txt'):
                continue
            if ('_user_prompt' in name.lower()) or (name.lower().startswith(base.lower())) or (name.lower() == f"{base.lower()}.txt"):
                candidates.append(os.path.join(d, name))
        if candidates:
            chosen = _pick_best_match(base, cwe, candidates)
            if chosen and os.path.exists(chosen):
                with open(chosen, 'r', encoding='utf-8') as f:
                    return f.read(), chosen
    if content_index is None:
        content_index = _build_content_index(cwe)
    paths = content_index.get(base, [])
    if paths:
        chosen = _pick_best_match(base, cwe, paths) or paths[0]
        try:
            with open(chosen, 'r', encoding='utf-8') as f:
                return f.read(), chosen
        except Exception:
            pass
    return None, None

def _estimate_gemini_tokens(text: str, chars_per_token: float = 4.0) -> int:
    if not text:
        return 0
    return max(1, math.ceil(len(text) / max(1e-9, chars_per_token)))

def build_and_save_prompts(cwe: int) -> str:
    system, few_string, few_list, few_sql = _load_prompts()

    cwe_dir = _cwe_folder(cwe)
    filter_dir = os.path.join(FILTER_ROOT, cwe_dir)
    string_list_path = os.path.join(filter_dir, 'string_gr.txt')
    list_list_path   = os.path.join(filter_dir, 'list_gr.txt')

    out_dir = os.path.join(FILTER_ROOT, 'result', cwe_dir)
    _ensure_dir(out_dir)

    string_names = _read_lines(string_list_path)
    list_names   = _read_lines(list_list_path)

    content_index = _build_content_index(cwe)

    chars_per_token = float(os.getenv('CHARS_PER_TOKEN', '4.0'))
    metrics_csv = os.path.join(out_dir, 'prompt_token_usage.csv')
    with open(metrics_csv, 'w', encoding='utf-8', newline='') as m:
        writer = csv.writer(m)
        writer.writerow([
            'file', 'variant', 'cwe',
            'len_system', 'len_fewshot', 'len_user', 'len_total',
            'tok_system', 'tok_fewshot', 'tok_user', 'tok_total',
            'output_path', 'user_prompt_found', 'user_prompt_path', 'match_mode'
        ])

        def _compose_and_save(java_file: str, variant: str) -> None:
            base = _base_from_java(java_file)

            user_text, user_path = _read_user_prompt_any(base, cwe, content_index=content_index)
            match_mode = 'content' if (user_text and os.path.basename(user_path or '').lower().find(base.lower()) == -1) else 'name'

            if cwe == 89:
                few = few_sql
                out_name = f"{base}_string.txt"
                variant_label = 'string'
            else:
                if variant == 'list':
                    few = few_list
                    out_name = f"{base}_list.txt"
                    variant_label = 'list'
                else:
                    few = few_string
                    out_name = f"{base}_string.txt"
                    variant_label = 'string'

            combined = f"{system}\n\n{few}\n\n{user_text or ''}"
            out_path = os.path.join(out_dir, out_name)
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(combined)

            Ls = len(system)
            Lf = len(few)
            Lu = len(user_text or '')
            Lt = len(combined)

            Ts = _estimate_gemini_tokens(system, chars_per_token)
            Tf = _estimate_gemini_tokens(few, chars_per_token)
            Tu = _estimate_gemini_tokens(user_text or '', chars_per_token)
            Tt = _estimate_gemini_tokens(combined, chars_per_token)

            writer.writerow([
                java_file, variant_label, cwe,
                Ls, Lf, Lu, Lt,
                Ts, Tf, Tu, Tt,
                out_path,
                'yes' if user_text else 'no',
                user_path or '',
                match_mode if user_text else ''
            ])

        for name in sorted(set(string_names)):
            if not name:
                continue
            _compose_and_save(name, 'string')

        if cwe != 89:
            for name in sorted(set(list_names)):
                if not name:
                    continue
                _compose_and_save(name, 'list')

    return metrics_csv

def main():
    parser = argparse.ArgumentParser(
        description="Generate combined prompts (SYSTEM + FEW-SHOT + USER) and token-usage CSV for a given CWE."
    )
    parser.add_argument('-cwe', '--cwe', type=int, required=True, choices=[22,78,89],
                        help='CWE id (22, 78, or 89)')
    args = parser.parse_args()

    metrics_csv = build_and_save_prompts(args.cwe)
    print(f"[✓] Done. Metrics CSV: {metrics_csv}")

if __name__ == '__main__':
    main()
