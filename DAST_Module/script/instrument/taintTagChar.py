import argparse
import csv
import glob
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3] 
sys.path.insert(0, str(PROJECT_ROOT))
import directory as D

def _silent_print(*args, **kwargs):
    return

def cwe89_run():
    CSV_DIR = os.path.join(D.CODEQL_REUSLT, "cwe-089")
    JAVA_BASE_DIR = os.path.join(
        D.PROJECT_SOURCE_CODE_DIR,
        "src/main/java/org/owasp/benchmark/testcode"
    )

    IMPORT_BLOCK = (
        "import edu.neu.ccs.prl.galette.internal.runtime.Tag;\n"
        "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;\n"
    )
    SINK_MARKER_PREFIX = "// [GAL-AUTO-INSERT: SQLI_SINK]"
    SRC_MARKER_PREFIX  = "// [GAL-AUTO-INSERT: SQLI_SOURCE]"
    SAFE_ANCHOR_PATTERNS = [
        r'^\s*(?:java\.sql\.)?PreparedStatement\b.*=',
        r'^\s*(?:java\.sql\.)?CallableStatement\b.*=',
        r'^\s*(?:java\.sql\.)?Statement\b.*=',
        r'^\s*(?:java\.sql\.)?Connection\b.*=',
        r'^\s*\w+\s*=\s*\w+\.prepareStatement\(',
        r'^\s*\w+\s*=\s*\w+\.prepareCall\(',
        r'^\s*connection\.prepareStatement\(',
        r'^\s*connection\.prepareCall\(',
        r'^\s*\w+\.prepareStatement\(',
        r'^\s*\w+\.prepareCall\(',
        r'^\s*\w+\.execute(?:Update|Query)?\(',
        r'^\s*stmt\.execute(?:Update|Query)?\(',
    ]
    _TERMINATOR_RE = re.compile(r'[;{}]\s*$')

    def find_latest_csv(directory: str) -> str:
        paths = glob.glob(os.path.join(directory, "*.csv"))
        if not paths:
            raise FileNotFoundError(f"[!] Not find file .csv in {directory}")
        return max(paths, key=os.path.getmtime)

    def get_indent(line: str) -> str:
        return line[:len(line) - len(line.lstrip(' '))]

    def class_to_filename(qualified: str):
        short = qualified.split(".")[-1].strip()
        return short + ".java", short

    def read_csv_rows(csv_path: str):
        rows = []
        with open(csv_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if row and row[0].strip().lower() == "col0":
                    continue
                if len(row) < 8:
                    continue
                rows.append(row)
        return rows

    def load_java_lines(java_path: str):
        with open(java_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()

    def save_java_lines(java_path: str, lines):
        with open(java_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

    def ensure_imports_after_package(lines):
        text = "".join(lines)
        if "edu.neu.ccs.prl.galette.internal.runtime.Tag" in text and \
           "edu.neu.ccs.prl.galette.internal.runtime.Tainter" in text:
            return lines
        for i, line in enumerate(lines):
            if line.strip().startswith("package "):
                return lines[:i+1] + [IMPORT_BLOCK] + lines[i+1:]
        return [IMPORT_BLOCK] + lines

    def already_has_sink(lines, java_file):
        txt = "".join(lines)
        return (SINK_MARKER_PREFIX in txt) or ("for (char c : sql.toCharArray())" in txt and "SQL Injection" in txt)

    def already_has_source(lines, java_file):
        txt = "".join(lines)
        return (SRC_MARKER_PREFIX in txt) or (f'Tag.of("SOURCE: {java_file}' in txt) or ("Tainter.setTag(new String(newChars)" in txt and "SOURCE:" in txt)

    def build_sink_block(java_file, indent):
        body = (
            f"{SINK_MARKER_PREFIX}\n"
            f"for (char c : sql.toCharArray()) {{\n"
            f"    Tag cTag = Tainter.getTag(c);\n"
            f"    if (cTag != null) {{\n"
            f"        System.out.println(\"🔥 [GAL] SQL Injection at {java_file} char '\" + c + \"' carries tag: \" + cTag);\n"
            f"    }}\n"
            f"}}\n"
        )
        return "\n".join([(indent + ln) if ln else ln for ln in body.splitlines()]) + "\n"

    def build_source_block(java_file, indent):
        body = (
            f"{SRC_MARKER_PREFIX}\n"
            f"char[] chars = param.toCharArray();\n"
            f"char[] newChars = new char[chars.length];\n"
            f"for (int l = 0; l < chars.length; l++) {{\n"
            f"    newChars[l] = Tainter.setTag(chars[l], Tag.of(\"SOURCE: {java_file} param at index \" + l));\n"
            f"}}\n"
            f"param = Tainter.setTag(new String(newChars), Tag.of(\"SOURCE: {java_file}\"));\n"
        )
        return "\n".join([(indent + ln) if ln else ln for ln in body.splitlines()]) + "\n"

    def find_statement_start(lines, idx):
        i = idx
        while i > 0:
            prev = lines[i-1].rstrip()
            if _TERMINATOR_RE.search(prev) or prev == "":
                break
            i -= 1
        return i

    def find_safe_anchor_index(lines, approx_idx, lookback=30):
        anchors = [re.compile(p) for p in SAFE_ANCHOR_PATTERNS]
        start = max(0, approx_idx - lookback)
        for i in range(approx_idx, start - 1, -1):
            s = lines[i].rstrip()
            for rgx in anchors:
                if rgx.search(s):
                    return i
        return approx_idx

    def insert_sink_before_line(lines, line_no, java_file):
        approx_idx = max(0, min(len(lines), line_no - 1))
        anchor_idx = find_safe_anchor_index(lines, approx_idx, lookback=40)
        stmt_start = find_statement_start(lines, anchor_idx)
        indent = get_indent(lines[stmt_start]) if stmt_start < len(lines) else ""
        sink_block = build_sink_block(java_file, indent)
        return lines[:stmt_start] + [sink_block] + lines[stmt_start:]

    def insert_source_blocks(lines, java_file):
        for i, line in enumerate(lines):
            if "String bar = " in line:
                indent = get_indent(line)
                block = build_source_block(java_file, indent)
                return lines[:i] + [block] + lines[i:]
        for i, line in enumerate(lines):
            if line.lstrip().startswith("param ="):
                indent = get_indent(line)
                block = build_source_block(java_file, indent)
                return lines[:i+1] + [block] + lines[i+1:]
        return lines

    try:
        csv_path = find_latest_csv(CSV_DIR)
    except FileNotFoundError:
        return
    rows = read_csv_rows(csv_path)
    for row in rows:
        try:
            java_file, _ = class_to_filename(row[4].strip())
            java_path = os.path.join(JAVA_BASE_DIR, java_file)
            if not os.path.exists(java_path):
                continue
            lines = load_java_lines(java_path)
            lines = ensure_imports_after_package(lines)
            sink_line = int(row[7])
            if sink_line <= 0:
                sink_line = 1
            if not already_has_sink(lines, java_file):
                lines = insert_sink_before_line(lines, sink_line, java_file)
            if row[0].strip() == row[4].strip() and not already_has_source(lines, java_file):
                lines = insert_source_blocks(lines, java_file)
            save_java_lines(java_path, lines)
        except Exception:
            pass

def cwe78_run():
    CSV_DIR = os.path.join(D.CODEQL_REUSLT, "cwe-078")
    JAVA_BASE_DIR = os.path.join(
        D.PROJECT_SOURCE_CODE_DIR,
        "src/main/java/org/owasp/benchmark/testcode"
    )

    IMPORT_BLOCK = (
        "import edu.neu.ccs.prl.galette.internal.runtime.Tag;\n"
        "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;\n"
    )
    SINK_ARGS_MARKER  = "// [GAL-AUTO-INSERT: CMDI_SINK_ARGS]"
    SINK_PARAM_MARKER = "// [GAL-AUTO-INSERT: CMDI_SINK_PARAM]"
    SINK_BAR_MARKER   = "// [GAL-AUTO-INSERT: CMDI_SINK_BAR]"
    SRC_MARKER        = "// [GAL-AUTO-INSERT: CMDI_SOURCE]"

    RE_CMD_PARAM = re.compile(r'cmd\s*\+\s*param')
    RE_CMD_BAR   = re.compile(r'cmd\s*\+\s*bar')
    _TERMINATOR_RE = re.compile(r'[;{}]\s*$')

    def find_latest_csv(directory: str) -> str:
        paths = glob.glob(os.path.join(directory, "*.csv"))
        if not paths:
            raise FileNotFoundError(f"[!] No find file .csv in {directory}")
        return max(paths, key=os.path.getmtime)

    def read_csv_rows(csv_path: str):
        rows = []
        with open(csv_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row: continue
                if row[0].strip().lower() == "col0": continue
                if len(row) < 8: continue
                rows.append([c.strip() for c in row])
        return rows

    def class_to_filename(qualified: str):
        short = qualified.split(".")[-1]
        return short + ".java", short

    def load_java_lines(java_path: str):
        with open(java_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()

    def save_java_lines(java_path: str, lines):
        with open(java_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

    def ensure_imports_after_package(lines):
        txt = "".join(lines)
        if "edu.neu.ccs.prl.galette.internal.runtime.Tag" in txt and \
           "edu.neu.ccs.prl.galette.internal.runtime.Tainter" in txt:
            return lines
        for i, line in enumerate(lines):
            if line.strip().startswith("package "):
                return lines[:i+1] + [IMPORT_BLOCK] + lines[i+1:]
        return [IMPORT_BLOCK] + lines

    def get_indent(line: str) -> str:
        return line[:len(line) - len(line.lstrip(' '))]

    def find_statement_start(lines, idx):
        i = idx
        while i > 0:
            prev = lines[i-1].rstrip()
            if _TERMINATOR_RE.search(prev) or prev == "":
                break
            i -= 1
        return i

    def insert_block_before_statement_at_index(lines, idx, raw_block_str: str):
        stmt_start = find_statement_start(lines, idx)
        indent = get_indent(lines[stmt_start]) if stmt_start < len(lines) else ""
        block = "\n".join([(indent + ln) if ln else ln for ln in raw_block_str.splitlines()]) + "\n"
        return lines[:stmt_start] + [block] + lines[stmt_start:]

    def find_nearby_line_index(lines, approx_idx, pattern, radius=5):
        if 0 <= approx_idx < len(lines) and pattern.search(lines[approx_idx]):
            return approx_idx
        for d in range(1, radius+1):
            up = approx_idx - d
            if 0 <= up < len(lines) and pattern.search(lines[up]):
                return up
            down = approx_idx + d
            if 0 <= down < len(lines) and pattern.search(lines[down]):
                return down
        return -1

    def has_sink_args(lines) -> bool:
        txt = "".join(lines)
        return (SINK_ARGS_MARKER in txt) or ("📌 [GAL] Checking args item:" in txt) or ("📌 [GAL] Checking argList item:" in txt) or ("📌 [GAL] Checking argsEnv item:" in txt)

    def has_sink_param(lines) -> bool:
        txt = "".join(lines)
        return (SINK_PARAM_MARKER in txt) or ("📌 [GAL] Checking cmd + param item:" in txt)

    def has_sink_bar(lines) -> bool:
        txt = "".join(lines)
        return (SINK_BAR_MARKER in txt) or ("📌 [GAL] Checking cmd + bar item:" in txt)

    def has_source(lines, java_filename_literal: str) -> bool:
        txt = "".join(lines)
        return (SRC_MARKER in txt) or (f'Tag.of("SOURCE: {java_filename_literal}' in txt)

    def block_sink_args(java_filename_literal: str, varname: str) -> str:
        return (
            f"{SINK_ARGS_MARKER}\n"
            f"for (String arg : {varname}) {{\n"
            f"    System.out.println(\"📌 [GAL] Checking {varname} item: \" + arg);\n"
            f"    for (char c : arg.toCharArray()) {{\n"
            f"        Tag cTag = Tainter.getTag(c);\n"
            f"        if (cTag != null) {{\n"
            f"            System.out.println(\"🔥 [GAL] Command Injection at {java_filename_literal} char '\" + c + \"' carries tag: \" + cTag);\n"
            f"        }}\n"
            f"    }}\n"
            f"}}\n"
        )

    def block_sink_param(java_filename_literal: str) -> str:
        return (
            f"{SINK_PARAM_MARKER}\n"
            f"String finalCommand = cmd + param;\n"
            f"System.out.println(\"📌 [GAL] Checking cmd + param item: \" + finalCommand);\n"
            f"for (char c : finalCommand.toCharArray()) {{\n"
            f"    Tag cTag = Tainter.getTag(c);\n"
            f"    if (cTag != null) {{\n"
            f"        System.out.println(\"🔥 [GAL] Command Injection at {java_filename_literal} char '\" + c + \"' carries tag: \" + cTag);\n"
            f"    }}\n"
            f"}}\n"
        )

    def block_sink_bar(java_filename_literal: str) -> str:
        return (
            f"{SINK_BAR_MARKER}\n"
            f"String finalCommand = cmd + bar;\n"
            f"System.out.println(\"📌 [GAL] Checking cmd + bar item: \" + finalCommand);\n"
            f"for (char c : finalCommand.toCharArray()) {{\n"
            f"    Tag cTag = Tainter.getTag(c);\n"
            f"    if (cTag != null) {{\n"
            f"        System.out.println(\"🔥 [GAL] Command Injection at {java_filename_literal} char '\" + c + \"' carries tag: \" + cTag);\n"
            f"    }}\n"
            f"}}\n"
        )

    def block_source_before_bar(java_filename_literal: str) -> str:
        return (
            f"{SRC_MARKER}\n"
            f"char[] chars = param.toCharArray();\n"
            f"char[] newChars = new char[chars.length];\n"
            f"for (int l = 0; l < chars.length; l++) {{\n"
            f"    newChars[l] = Tainter.setTag(chars[l], Tag.of(\"SOURCE: {java_filename_literal} param at index \" + l));\n"
            f"}}\n\n"
            f"param = Tainter.setTag(new String(newChars), Tag.of(\"SOURCE: {java_filename_literal}\"));\n\n"
            f"for (char c : param.toCharArray()) {{\n"
            f"    Tag cTag = Tainter.getTag(c);\n"
            f"    if (cTag != null) {{\n"
            f"        System.out.println(\"🔥 [GAL] Char '\" + c + \"' carries tag: \" + cTag);\n"
            f"    }}\n"
            f"}}\n"
        )

    def insert_source_blocks(lines, java_filename_literal: str):
        for i, line in enumerate(lines):
            if "String bar = " in line:
                if not has_source(lines, java_filename_literal):
                    indent = get_indent(line)
                    raw = block_source_before_bar(java_filename_literal)
                    block = "\n".join([(indent + ln) if ln else ln for ln in raw.splitlines()]) + "\n"
                    return lines[:i] + [block] + lines[i:]
                return lines
        for i, line in enumerate(lines):
            if line.lstrip().startswith("param ="):
                if not has_source(lines, java_filename_literal):
                    indent = get_indent(line)
                    raw = block_source_before_bar(java_filename_literal)
                    block = "\n".join([(indent + ln) if ln else ln for ln in raw.splitlines()]) + "\n"
                    return lines[:i+1] + [block] + lines[i+1:]
                return lines
        return lines

    try:
        csv_path = find_latest_csv(CSV_DIR)
    except FileNotFoundError:
        return
    rows = read_csv_rows(csv_path)
    for row in rows:
        try:
            col0, _, _, _, col4, _, col6, col7 = row
            sink_line = int(col7)
            java_filename, _ = class_to_filename(col4)
            java_path = os.path.join(JAVA_BASE_DIR, java_filename)
            if not os.path.exists(java_path):
                continue
            lines = load_java_lines(java_path)
            lines = ensure_imports_after_package(lines)
            approx_idx = max(0, min(len(lines)-1, sink_line-1))

            if col6 in {"args", "argList", "argsEnv"}:
                if not has_sink_args(lines):
                    raw = block_sink_args(java_filename, col6)
                    lines = insert_block_before_statement_at_index(lines, approx_idx, raw)
            else:
                idx_param = find_nearby_line_index(lines, approx_idx, RE_CMD_PARAM, radius=5)
                idx_bar   = find_nearby_line_index(lines, approx_idx, RE_CMD_BAR,   radius=5)
                if idx_param != -1 and not has_sink_param(lines):
                    raw = block_sink_param(java_filename)
                    lines = insert_block_before_statement_at_index(lines, idx_param, raw)
                if idx_bar != -1 and not has_sink_bar(lines):
                    raw = block_sink_bar(java_filename)
                    lines = insert_block_before_statement_at_index(lines, idx_bar, raw)

            if col0 == col4 and not has_source(lines, java_filename):
                lines = insert_source_blocks(lines, java_filename)

            save_java_lines(java_path, lines)
        except Exception:
            pass

def cwe22_run():
    CSV_DIR = os.path.join(D.CODEQL_REUSLT, "cwe-022")
    JAVA_BASE_DIR = os.path.join(
        D.PROJECT_SOURCE_CODE_DIR,
        "src/main/java/org/owasp/benchmark/testcode"
    )

    SINK_FILENAME_MARKER   = "// [GAL-AUTO-INSERT: PT_SINK_FILENAME]"
    SINK_FILETARGET_MARKER = "// [GAL-AUTO-INSERT: PT_SINK_FILETARGET]"
    SINK_PATH_MARKER       = "// [GAL-AUTO-INSERT: PT_SINK_PATH]"
    SRC_MARKER             = "// [GAL-AUTO-INSERT: PT_SOURCE]"

    IMPORT_BLOCK = (
        "import edu.neu.ccs.prl.galette.internal.runtime.Tag;\n"
        "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;\n"
    )

    RE_HEADER = re.compile(r'^\s*"?col0"?\s*$', re.IGNORECASE)
    RE_PARAM_ASSIGN_START = re.compile(r'^\s*param\s*=')
    RE_FILENAME_ASSIGN = re.compile(r'^\s*(?:[\w.<>\[\]\s]+\s+)?fileName\s*=')
    RE_PATH_DECLARE = re.compile(r'^\s*(?:java\.nio\.file\.)?Path\s+path\s*=')
    RE_FILES_NEW_INPUTSTREAM = re.compile(r'java\.nio\.file\.Files\.newInputStream\s*\(\s*path\b')
    RE_FILENAME_SINKS = [
        re.compile(r'new\s+java\.io\.(?:FileOutputStream|FileInputStream|FileReader|FileWriter|RandomAccessFile)\s*\(\s*new\s+java\.io\.FileInputStream\s*\(\s*fileName\b.*\)\s*\)'),
        re.compile(r'new\s+java\.io\.(?:FileOutputStream|FileInputStream|FileReader|FileWriter|RandomAccessFile)\s*\(\s*fileName\b'),
        re.compile(r'new\s+java\.io\.File\s*\(\s*fileName\b'),
    ]
    RE_IF_FILETARGET_GUARD = re.compile(r'^\s*if\s*\([^)]*fileTarget\.(?:exists|isFile|isDirectory)\s*\(\)\s*\)\s*\{?')

    def find_latest_csv(directory: str) -> str:
        files = glob.glob(os.path.join(directory, "*.csv"))
        if not files:
            raise FileNotFoundError(f"[!] No find file .csv in {directory}")
        return max(files, key=os.path.getmtime)

    def read_csv_rows(csv_path: str):
        rows = []
        with open(csv_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                c0 = row[0].strip().strip('"')
                if RE_HEADER.match(c0):
                    continue
                if any("org.owasp.benchmark.report.sonarqube.SonarReport" in (c or "") for c in row):
                    continue
                if len(row) < 8:
                    continue
                rows.append([c.strip().strip('"') for c in row[:8]])
        return rows

    def class_to_filename(qualified: str):
        short = qualified.split(".")[-1]
        return short + ".java", short

    def load_lines(p: str):
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()

    def save_lines(p: str, lines):
        with open(p, "w", encoding="utf-8") as f:
            f.writelines(lines)

    def ensure_imports_after_package(lines):
        txt = "".join(lines)
        if "edu.neu.ccs.prl.galette.internal.runtime.Tag" in txt and \
           "edu.neu.ccs.prl.galette.internal.runtime.Tainter" in txt:
            return lines
        pkg_idx = None
        for i, line in enumerate(lines):
            if line.strip().startswith("package "):
                pkg_idx = i; break
        if pkg_idx is None:
            return [IMPORT_BLOCK] + lines
        return lines[:pkg_idx+1] + [IMPORT_BLOCK] + lines[pkg_idx+1:]

    def indent_of(line: str) -> str:
        return line[:len(line) - len(line.lstrip(' '))]

    def strip_comments_for_paren_count(s: str, in_block: bool):
        i = 0; out = []
        while i < len(s):
            if not in_block and i+1 < len(s) and s[i] == '/' and s[i+1] == '*':
                in_block = True; i += 2; continue
            if in_block and i+1 < len(s) and s[i] == '*' and s[i+1] == '/':
                in_block = False; i += 2; continue
            if not in_block and i+1 < len(s) and s[i] == '/' and s[i+1] == '/':
                break
            if not in_block: out.append(s[i])
            i += 1
        return "".join(out), in_block

    def find_try_header_containing_index(lines, idx, lookback=120, lookforward=400):
        min_j = max(0, idx - lookback)
        for j in range(idx, min_j - 1, -1):
            s, _ = strip_comments_for_paren_count(lines[j], False)
            if "try" not in s: continue
            mtry = re.search(r'\btry\b', s)
            if not mtry: continue
            depth = 0; saw_open = False; in_block = False
            seg = s[mtry.end():]
            for ch in seg:
                if ch == '(': depth += 1; saw_open = True
                elif ch == ')': depth = max(0, depth - 1)
            if saw_open and depth == 0:
                end_k = j
            else:
                end_k = None
                for k in range(j+1, min(len(lines), j + lookforward)):
                    s2, in_block = strip_comments_for_paren_count(lines[k], in_block)
                    for ch in s2:
                        if ch == '(': depth += 1; saw_open = True
                        elif ch == ')': depth = max(0, depth - 1)
                    if saw_open and depth == 0:
                        end_k = k; break
            if saw_open and end_k is not None and j <= idx <= end_k:
                return j, end_k
        return None, None

    def insert_block_before_line(lines, idx, raw_block: str):
        if idx < 0: idx = 0
        if idx > len(lines): idx = len(lines)
        try_start, _ = find_try_header_containing_index(lines, idx)
        if try_start is not None:
            idx = try_start
        base_indent = indent_of(lines[idx]) if 0 <= idx < len(lines) else ""
        block = "\n".join([(base_indent + ln) if ln else ln for ln in raw_block.splitlines()]) + "\n"
        return lines[:idx] + [block] + lines[idx:]

    def insert_block_after_line(lines, idx, raw_block: str):
        if idx < 0: idx = 0
        if idx >= len(lines): idx = len(lines) - 1
        base_indent = indent_of(lines[idx]) if 0 <= idx < len(lines) else ""
        block = "\n".join([(base_indent + ln) if ln else ln for ln in raw_block.splitlines()]) + "\n"
        return lines[:idx+1] + [block] + lines[idx+1:]

    def remove_block_from_marker(lines, marker_idx):
        depth = 0; started = False; i = marker_idx + 1
        while i < len(lines):
            depth += lines[i].count("{"); depth -= lines[i].count("}")
            if not started and "{" in lines[i]: started = True
            i += 1
            if started and depth <= 0: break
        end = i
        return lines[:marker_idx] + lines[end:], end - marker_idx

    def remove_all_blocks_by_marker(lines, marker):
        i = 0
        while i < len(lines):
            if marker in lines[i]:
                lines, _ = remove_block_from_marker(lines, i)
                continue
            i += 1
        return lines

    def match_any_filename_sink(s: str) -> bool:
        return any(p.search(s) for p in RE_FILENAME_SINKS)

    def find_filename_sink_line(lines, approx_idx, radius=200):
        n = len(lines)
        if 0 <= approx_idx < n and match_any_filename_sink(lines[approx_idx]): return approx_idx
        for d in range(1, radius+1):
            up = approx_idx - d
            if 0 <= up < n and match_any_filename_sink(lines[up]): return up
            down = approx_idx + d
            if 0 <= down < n and match_any_filename_sink(lines[down]): return down
        for i, ln in enumerate(lines):
            if match_any_filename_sink(ln): return i
        return -1

    def find_files_new_inputstream_line(lines, approx_idx, radius=120):
        n = len(lines)
        if 0 <= approx_idx < n and RE_FILES_NEW_INPUTSTREAM.search(lines[approx_idx]): return approx_idx
        for d in range(1, radius+1):
            up = approx_idx - d
            if 0 <= up < n and RE_FILES_NEW_INPUTSTREAM.search(lines[up]): return up
            down = approx_idx + d
            if 0 <= down < n and RE_FILES_NEW_INPUTSTREAM.search(lines[down]): return down
        for i, ln in enumerate(lines):
            if RE_FILES_NEW_INPUTSTREAM.search(ln): return i
        return -1

    def find_filetarget_if_guard(lines, approx_idx, radius=160):
        n = len(lines)
        if 0 <= approx_idx < n and RE_IF_FILETARGET_GUARD.search(lines[approx_idx]): return approx_idx
        for d in range(0, radius+1):
            down = approx_idx + d
            if 0 <= down < n and RE_IF_FILETARGET_GUARD.search(lines[down]): return down
            up = approx_idx - d
            if 0 <= up < n and RE_IF_FILETARGET_GUARD.search(lines[up]): return up
        for i, ln in enumerate(lines):
            if RE_IF_FILETARGET_GUARD.search(ln): return i
        return -1

    def already_has_filename_sink(lines, java_file_literal: str) -> bool:
        txt = "".join(lines)
        return (SINK_FILENAME_MARKER in txt) or \
               ("for (char c : fileName.toCharArray()) {" in txt and \
                f"🔥 [GAL] Path Traversal at {java_file_literal} char" in txt)

    def already_has_filetarget_sink(lines, java_file_literal: str) -> bool:
        txt = "".join(lines)
        return (SINK_FILETARGET_MARKER in txt) or \
               ("fileTarget.getPath().toCharArray()" in txt and \
                f"🔥 [GAL] Path Traversal at {java_file_literal} char" in txt)

    def already_has_path_sink(lines, java_file_literal: str) -> bool:
        txt = "".join(lines)
        return (SINK_PATH_MARKER in txt) or \
               ("path.toString().toCharArray()" in txt and \
                f"🔥 [GAL] Path Traversal at {java_file_literal} char" in txt)

    def already_has_source(lines, java_file_literal: str) -> bool:
        txt = "".join(lines)
        return (SRC_MARKER in txt) or (f'Tag.of("SOURCE: {java_file_literal} param at index ' in txt)

    def block_sink_filename(java_file_literal: str) -> str:
        return (
            f"{SINK_FILENAME_MARKER}\n"
            f"for (char c : fileName.toCharArray()) {{\n"
            f"    Tag cTag = Tainter.getTag(c);\n"
            f"    if (cTag != null) {{\n"
            f"        System.out.println(\n"
            f"                \"🔥 [GAL] Path Traversal at {java_file_literal} char '\"\n"
            f"                        + c\n"
            f"                        + \"' carries tag: \"\n"
            f"                        + cTag);\n"
            f"    }}\n"
            f"}}\n"
        )

    def block_sink_filetarget(java_file_literal: str) -> str:
        return (
            f"{SINK_FILETARGET_MARKER}\n"
            f"for (char c : fileTarget.getPath().toCharArray()) {{\n"
            f"    Tag cTag = Tainter.getTag(c);\n"
            f"    if (cTag != null) {{\n"
            f"        System.out.println(\n"
            f"                \"🔥 [GAL] Path Traversal at {java_file_literal} char '\"\n"
            f"                        + c\n"
            f"                        + \"' carries tag: \"\n"
            f"                        + cTag);\n"
            f"    }}\n"
            f"}}\n"
        )

    def block_sink_path(java_file_literal: str) -> str:
        return (
            f"{SINK_PATH_MARKER}\n"
            f"for (char c : path.toString().toCharArray()) {{\n"
            f"    Tag cTag = Tainter.getTag(c);\n"
            f"    if (cTag != null) {{\n"
            f"        System.out.println(\n"
            f"                \"🔥 [GAL] Path Traversal at {java_file_literal} char '\"\n"
            f"                        + c\n"
            f"                        + \"' carries tag: \"\n"
            f"                        + cTag);\n"
            f"    }}\n"
            f"}}\n"
        )

    def block_source(java_file_literal: str) -> str:
        return (
            f"{SRC_MARKER}\n"
            f"char[] chars = param.toCharArray();\n"
            f"char[] newChars = new char[chars.length];\n"
            f"for (int l = 0; l < chars.length; l++) {{\n"
            f"    newChars[l] =\n"
            f"            Tainter.setTag(\n"
            f"                    chars[l], Tag.of(\"SOURCE: {java_file_literal} param at index \" + l));\n"
            f"}}\n\n"
            f"param = Tainter.setTag(new String(newChars), Tag.of(\"SOURCE: {java_file_literal}\"));\n\n"
            f"for (char c : param.toCharArray()) {{\n"
            f"    Tag cTag = Tainter.getTag(c);\n"
            f"    if (cTag != null) {{\n"
            f"        System.out.println(\"🔥 [GAL] Char '\" + c + \"' carries tag: \" + cTag);\n"
            f"    }}\n"
            f"}}\n"
        )

    def insert_source_if_needed(lines, java_file_literal: str):
        if already_has_source(lines, java_file_literal):
            return lines, False
        for i, line in enumerate(lines):
            if "String bar" in line:
                raw = block_source(java_file_literal)
                return insert_block_before_line(lines, i, raw), True
        for i, line in enumerate(lines):
            if RE_PARAM_ASSIGN_START.match(line):
                raw = block_source(java_file_literal)
                return insert_block_after_line(lines, i, raw), True
        return lines, False

    def process_sink(lines, java_file_literal: str, col6: str, tgt_idx: int):
        if col6 in ("fileName", "new File(...)"):
            if SINK_FILENAME_MARKER in "".join(lines):
                lines = remove_all_blocks_by_marker(lines, SINK_FILENAME_MARKER)
            raw = block_sink_filename(java_file_literal)
            assign_idxs = [i for i, ln in enumerate(lines) if RE_FILENAME_ASSIGN.match(ln)]
            if assign_idxs:
                before = [i for i in assign_idxs if i <= tgt_idx]
                ai = before[-1] if before else assign_idxs[0]
                lines = insert_block_after_line(lines, ai, raw)
                return lines, True
            sink_idx = find_filename_sink_line(lines, tgt_idx, radius=200)
            if sink_idx != -1:
                try_start, _ = find_try_header_containing_index(lines, sink_idx)
                anchor = try_start if try_start is not None else sink_idx
                lines = insert_block_before_line(lines, anchor, raw)
                return lines, True
            lines = insert_block_before_line(lines, tgt_idx, raw)
            return lines, True

        if col6 == "fileTarget":
            if SINK_FILETARGET_MARKER in "".join(lines):
                lines = remove_all_blocks_by_marker(lines, SINK_FILETARGET_MARKER)
            raw = block_sink_filetarget(java_file_literal)
            guard_idx = find_filetarget_if_guard(lines, approx_idx=tgt_idx, radius=160)
            if guard_idx != -1:
                lines = insert_block_before_line(lines, guard_idx, raw)
                return lines, True
            lines = insert_block_before_line(lines, tgt_idx, raw)
            return lines, True

        if col6 == "path":
            if SINK_PATH_MARKER in "".join(lines):
                lines = remove_all_blocks_by_marker(lines, SINK_PATH_MARKER)
            raw = block_sink_path(java_file_literal)
            use_idx = find_files_new_inputstream_line(lines, approx_idx=tgt_idx, radius=160)
            if use_idx == -1:
                return lines, False
            decl_idx = -1
            for i in range(use_idx, -1, -1):
                if RE_PATH_DECLARE.match(lines[i]):
                    decl_idx = i
                    break
            if decl_idx == -1:
                return lines, False
            lines = insert_block_after_line(lines, decl_idx, raw)
            return lines, True

        return lines, False

    try:
        csv_path = find_latest_csv(CSV_DIR)
    except FileNotFoundError:
        return
    rows = read_csv_rows(csv_path)
    for row in rows:
        try:
            col0, _, _, _, col4, _, col6, col7 = row
            tgt_line_1b = int(col7)
            java_file, _short = class_to_filename(col4)
            java_path = os.path.join(JAVA_BASE_DIR, java_file)
            if not os.path.exists(java_path):
                continue

            lines = load_lines(java_path)
            lines = ensure_imports_after_package(lines)
            java_literal = java_file
            tgt_idx = max(0, min(len(lines)-1, tgt_line_1b - 1))

            lines, _ = process_sink(lines, java_literal, col6, tgt_idx)

            if col0 == col4:
                lines, _ = insert_source_if_needed(lines, java_literal)

            save_lines(java_path, lines)
        except Exception:
            pass

def run_patch_separate_class_request():
    JAVA_PATH = os.path.join(
        D.PROJECT_SOURCE_CODE_DIR,
        "src/main/java/org/owasp/benchmark/helpers/SeparateClassRequest.java"
    )

    IMPORT_BLOCK = (
        "import edu.neu.ccs.prl.galette.internal.runtime.Tag;\n"
        "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;\n"
    )

    if not os.path.exists(JAVA_PATH):
        return

    with open(JAVA_PATH, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()

    if "edu.neu.ccs.prl.galette.internal.runtime.Tag" not in src or \
       "edu.neu.ccs.prl.galette.internal.runtime.Tainter" not in src:
        m = re.search(r'^(package\s+[^\n;]+;\s*\n)', src, flags=re.MULTILINE)
        if m:
            src = src[:m.end(1)] + IMPORT_BLOCK + src[m.end(1):]
        else:
            src = IMPORT_BLOCK + src

    if "SOURCE: SeparateClassRequest.java" not in src:
        # Thay thân phương thức getTheParameter(String p)
        pattern = re.compile(
            r'^([ \t]*)public\s+String\s+getTheParameter\s*\(\s*String\s+p\s*\)\s*\{\s*(?:\r?\n|\r)(.*?)^[ \t]*\}\s*$',
            flags=re.MULTILINE | re.DOTALL
        )
        def repl(m):
            base_indent = m.group(1)
            body_indent = base_indent + " " * 4
            new_body = (
                f"{body_indent}String taintedValue = request.getParameter(p);\n"
                f"{body_indent}if (taintedValue != null) {{\n"
                f"{body_indent}    char[] chars = taintedValue.toCharArray();\n"
                f"{body_indent}    char[] newChars = new char[chars.length];\n"
                f"{body_indent}    for (int l = 0; l < chars.length; l++) {{\n"
                f"{body_indent}        newChars[l] =\n"
                f"{body_indent}                Tainter.setTag(\n"
                f"{body_indent}                        chars[l],\n"
                f"{body_indent}                        Tag.of(\"SOURCE: SeparateClassRequest.java param at index \" + l));\n"
                f"{body_indent}    }}\n\n"
                f"{body_indent}    taintedValue =\n"
                f"{body_indent}            Tainter.setTag(\n"
                f"{body_indent}                    new String(newChars), Tag.of(\"SOURCE: SeparateClassRequest.java\"));\n\n"
                f"{body_indent}    for (char c : taintedValue.toCharArray()) {{\n"
                f"{body_indent}        Tag cTag = Tainter.getTag(c);\n"
                f"{body_indent}        if (cTag != null) {{\n"
                f"{body_indent}            System.out.println(\"🔥 [GAL] Char '\" + c + \"' carries tag: \" + cTag);\n"
                f"{body_indent}        }}\n"
                f"{body_indent}    }}\n"
                f"{body_indent}}}\n"
                f"{body_indent}return taintedValue;\n"
            )
            return f"{base_indent}public String getTheParameter(String p) {{\n{new_body}{base_indent}}}\n"
        src = pattern.sub(repl, src, count=1)

    with open(JAVA_PATH, "w", encoding="utf-8") as f:
        f.write(src)

def main():
    parser = argparse.ArgumentParser()
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--cwe89", action="store_true")
    g.add_argument("--cwe78", action="store_true")
    g.add_argument("--cwe22", action="store_true")
    args = parser.parse_args()

    print("[!] Tagging Running")

    if args.cwe89:
        cwe89_run()
    elif args.cwe78:
        cwe78_run()
    elif args.cwe22:
        cwe22_run()

    run_patch_separate_class_request()

    print("[!] Done")

if __name__ == "__main__":
    main()

