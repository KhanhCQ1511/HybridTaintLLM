import csv
import os
import re
import argparse
from glob import glob
from typing import List, Optional

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
import sys
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
import directory as D


CSV_COLUMN = "col4"
ROOT_DIR = D.PROJECT_SOURCE_CODE_JAVA_DIR

QL_RESULTS = {
    "cwe89": os.path.join(D.CODEQL_REUSLT, "cwe-089"),
    "cwe22": os.path.join(D.CODEQL_REUSLT, "cwe-022"),
    "cwe78": os.path.join(D.CODEQL_REUSLT, "cwe-078"),
}

SEPARATE_CLASS_REQUEST = os.path.join(D.PROJECT_SOURCE_CODE_JAVA_DIR, "helpers", "SeparateClassRequest.java")

def _extract_classname(full_classname: str) -> str:
    return full_classname.strip().split(".")[-1]

def _find_java_file(classname: str) -> Optional[str]:
    for root, _, files in os.walk(ROOT_DIR):
        for file in files:
            if file == f"{classname}.java":
                return os.path.join(root, file)
    return None

def _pick_csv_in_dir(dir_path: str) -> Optional[str]:
    if not os.path.isdir(dir_path):
        print(f"[!] Folder CSV not found: {dir_path}")
        return None
    candidates = sorted(
        glob(os.path.join(dir_path, "*.csv")),
        key=lambda p: os.path.getmtime(p),
        reverse=True,
    )
    if not candidates:
        print(f"[!] No find file .csv in: {dir_path}")
        return None
    chosen = candidates[0]
    print(f"[!] Using CSV: {chosen}")
    return chosen

def _get_indent(line: str) -> str:
    m = re.match(r"\s*", line)
    return m.group(0) if m else ""

def _read_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        return f.readlines()

def _write_lines(path: str, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)

def _ensure_imports_after_package(lines: List[str], imports: List[str]) -> None:
    content = "".join(lines)
    missing = [imp for imp in imports if imp not in content]
    if not missing:
        return
    pkg_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("package"):
            pkg_idx = i
            break
    if pkg_idx is not None:
        ins = pkg_idx + 1
        for imp in missing:
            lines.insert(ins, imp + "\n")
            ins += 1

def _cmdi_extract_test_name(filename: str) -> str:
    m = re.search(r"BenchmarkTest0*(\d+)\.java$", filename)
    if not m:
        return "BenchmarkTest00000.java"
    return f"BenchmarkTest{m.group(1).zfill(5)}.java"

def _cmdi_insert_once(lines: List[str], keyword: str, snippet_lines: List[str]) -> bool:
    for i, line in enumerate(lines):
        if keyword in line:
            context = "".join(lines[max(i-3, 0): i+3])
            if snippet_lines and snippet_lines[0] in context:
                return True
            indent = _get_indent(line)
            snippet = [indent + l + "\n" for l in snippet_lines]
            lines[i:i] = snippet
            return True
    return False

def _cmdi_sink_snippet(var: str, test_name: str) -> List[str]:
    return [
        f'Tag tagSink = Tainter.getTag({var});',
        'if (tagSink != null) {',
        f'    System.out.println("🔥 [GAL] Command Injection at {test_name} carries tag: " + tagSink);',
        '} else {',
        f'    System.out.println("❌ [GAL] No taint detected at sink {test_name}.");',
        '}'
    ]

def _cmdi_source_snippet(test_name: str) -> List[str]:
    return [
        'Tag tag = Tag.of("source: Tainted");',
        'param = Tainter.setTag(param, tag);',
        f'System.out.println("✅ [GAL] Taint set at source {test_name}! Tag = " + tag);'
    ]

def _cmdi_fix_source_after_decode(lines: List[str], test_name: str) -> bool:
    for i, line in enumerate(lines):
        if 'param = java.net.URLDecoder.decode(param, "UTF-8");' in line:
            context = ''.join(lines[i+1:i+5])
            if 'Tainter.setTag(param' in context:
                return True
            indent = _get_indent(line)
            snippet = [
                f'{indent}Tag tag = Tag.of("source: Tainted");',
                f'{indent}param = Tainter.setTag(param, tag);',
                f'{indent}System.out.println("✅ [GAL] Taint set at source {test_name}! Tag = " + tag);'
            ]
            lines[i+1:i+1] = [l + "\n" for l in snippet]
            return True
    return False

def inject_cmdi(java_file: str) -> None:
    if not os.path.exists(java_file):
        print(f"[!] File not found: {java_file}")
        return

    test_name = _cmdi_extract_test_name(os.path.basename(java_file))
    lines = _read_lines(java_file)
    content = ''.join(lines)

    _ensure_imports_after_package(
        lines,
        [
            "import edu.neu.ccs.prl.galette.internal.runtime.Tag;",
            "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;"
        ]
    )

    has_param = 'String param = scr.getTheParameter' in content
    has_bar = 'bar' in content

    if has_param:
        success = (
            _cmdi_insert_once(lines, 'String[] args = {a1, a2, "echo " + bar};', _cmdi_sink_snippet("bar", test_name)) or
            _cmdi_insert_once(lines, 'args = new String[] {a1, a2, cmd, bar};',  _cmdi_sink_snippet("bar", test_name))
        )
        _cmdi_insert_once(lines, 'args = new String[] {a1, a2, cmd + bar};',     _cmdi_sink_snippet("bar", test_name))
        if not success:
            success |= _cmdi_insert_once(lines, 'argList.add("echo " + bar);',   _cmdi_sink_snippet("bar", test_name))
        if not success:
            success |= _cmdi_insert_once(lines, 'String[] argsEnv = {bar};',     _cmdi_sink_snippet("bar", test_name))
        if not success:
            _cmdi_insert_once(lines, 'try',                                      _cmdi_sink_snippet("bar", test_name))

    else:
        if not has_bar:
            _cmdi_fix_source_after_decode(lines, test_name)
            success = _cmdi_insert_once(lines, 'argList.add("echo " + param);',     _cmdi_sink_snippet("param", test_name))
            if not success:
                success |= _cmdi_insert_once(lines, 'String[] argsEnv = {param};',  _cmdi_sink_snippet("param", test_name))
            if not success:
                _cmdi_insert_once(lines, 'try',                                     _cmdi_sink_snippet("param", test_name))
        else:
            _cmdi_insert_once(lines, 'String bar',                                   _cmdi_source_snippet(test_name))
            success = _cmdi_insert_once(lines, 'argList.add("echo " + bar);',        _cmdi_sink_snippet("bar", test_name))
            if not success:
                success |= _cmdi_insert_once(lines, 'String[] args = {a1, a2, "echo " + bar};', _cmdi_sink_snippet("bar", test_name))
            if not success:
                success |= _cmdi_insert_once(lines, 'String cmd',                    _cmdi_sink_snippet("bar", test_name))
            if not success:
                _cmdi_insert_once(lines, 'try',                                      _cmdi_sink_snippet("bar", test_name))

    _write_lines(java_file, lines)
    print(f"[!] Done: {java_file}")

def _pt_extract_tag_id(filename: str) -> str:
    m = re.search(r"BenchmarkTest0*(\d+)\.java$", filename)
    return m.group(1).zfill(5) if m else "00000"

def _pt_ensure_imports(lines: List[str]) -> None:
    _ensure_imports_after_package(
        lines,
        [
            "import edu.neu.ccs.prl.galette.internal.runtime.Tag;",
            "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;",
        ],
    )

def _pt_insert_before(lines: List[str], keyword: str, snippet: List[str], check_duplicate: bool = True) -> bool:
    for i, line in enumerate(lines):
        if keyword in line:
            indent = _get_indent(line)
            if check_duplicate and any(snippet[0].strip() in l for l in lines[max(i - 5, 0): i + 5]):
                return False
            for s in reversed(snippet):
                lines.insert(i, indent + s + "\n")
            return True
    return False

def _pt_insert_after(lines: List[str], keyword: str, snippet: List[str], check_duplicate: bool = True) -> bool:
    for i, line in enumerate(lines):
        if keyword in line:
            indent = _get_indent(line)
            if check_duplicate and any(snippet[0].strip() in l for l in lines[i: i + 5]):
                return False
            for s in reversed(snippet):
                lines.insert(i + 1, indent + s + "\n")
            return True
    return False

def _pt_create_sink_lines(var: str, test_name: str, varname: str = "tag") -> List[str]:
    return [
        f"Tag {varname} = Tainter.getTag({var});",
        f"if ({varname} != null) {{",
        f'    System.out.println("🔥 [GAL] Path Traversal at {test_name} carries tag: " + {varname});',
        "} else {",
        f'    System.out.println("❌ [GAL] No taint detected at sink {test_name}.");',
        "}",
    ]

def _pt_create_source_lines(test_name: str) -> List[str]:
    return [
        'Tag tag = Tag.of("source: Tainted");',
        "param = Tainter.setTag(param, tag);",
        f'System.out.println("✅ [GAL] Taint set for source {test_name}! Tag = " + tag);',
    ]

def inject_path_traversal(java_file: str) -> None:
    tagid = _pt_extract_tag_id(os.path.basename(java_file))
    test_name = f"BenchmarkTest{tagid}.java"

    lines = _read_lines(java_file)
    content = "".join(lines)
    _pt_ensure_imports(lines)

    has_param_line = "String param = scr.getTheParameter" in content
    has_bar = "bar" in content
    has_try = "try" in content

    keywords_sink_order = [
        ("java.io.File fileTarget =", "before"),
        ("java.io.FileOutputStream fos = null;", "after"),
        ("String fileName =", "before"),
        ("java.io.FileInputStream fis = null;", "after"),
        ("try", "before"),
        ("response.getWriter()", "before"),
    ]

    if has_param_line:
        var = "bar" if has_bar else "param"
        sink_lines = _pt_create_sink_lines(var, test_name)
        for keyword, mode in keywords_sink_order:
            if mode == "before":
                if _pt_insert_before(lines, keyword, sink_lines):
                    break
            else:
                if _pt_insert_after(lines, keyword, sink_lines):
                    break
    else:
        if has_bar:
            src_lines = _pt_create_source_lines(test_name)
            sink_lines = _pt_create_sink_lines("bar", test_name, "tagSink")
            if has_try:
                _pt_insert_before(lines, "String bar", src_lines)
                _pt_insert_before(lines, "try", sink_lines)
            else:
                _pt_insert_before(lines, "String bar", src_lines)
                _pt_insert_before(lines, "java.io.File fileTarget =", sink_lines)
        else:
            src_lines = _pt_create_source_lines(test_name)
            sink_lines = _pt_create_sink_lines("param", test_name, "tagSink")
            if has_try:
                _pt_insert_before(lines, "try", sink_lines)
                if not _pt_insert_before(lines, "String fileName =", src_lines):
                    _pt_insert_before(lines, 'param = java.net.URLDecoder.decode(param, "UTF-8");', src_lines)
            else:
                if not _pt_insert_before(lines, "String fileName =", src_lines):
                    _pt_insert_before(lines, 'param = java.net.URLDecoder.decode(param, "UTF-8");', src_lines)
                _pt_insert_before(lines, "java.io.File fileTarget =", sink_lines)

    _write_lines(java_file, lines)
    print(f"[!] Done: {java_file}")

def _sqli_extract_file_id(filename: str) -> str:
    m = re.search(r"BenchmarkTest0*(\d+)", filename)
    return m.group(1).zfill(5) if m else "00000"

def _sqli_insert_imports(lines: List[str]) -> None:
    _ensure_imports_after_package(
        lines,
        [
            "import edu.neu.ccs.prl.galette.internal.runtime.Tag;",
            "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;",
        ],
    )

def _sqli_find_sql_block_end(lines: List[str], start_idx: int) -> int:
    for i in range(start_idx, len(lines)):
        if ";" in lines[i]:
            return i
    return start_idx

def _sqli_insert_after_sql_block(lines: List[str], snippet_lines: List[str]) -> None:
    for i, line in enumerate(lines):
        if "String sql" in line:
            end_idx = _sqli_find_sql_block_end(lines, i)
            indent = _get_indent(lines[end_idx])
            snippet = [(indent + l + "\n") for l in snippet_lines]
            for j in range(end_idx + 1, min(end_idx + 6, len(lines))):
                if snippet_lines[0] in lines[j]:
                    return
            lines[end_idx + 1: end_idx + 1] = snippet
            return

def _sqli_insert_after(lines: List[str], keyword: str, snippet_lines: List[str]) -> None:
    for i, line in enumerate(lines):
        if keyword in line:
            indent = _get_indent(line)
            snippet = [(indent + l + "\n") for l in snippet_lines]
            for j in range(i + 1, min(i + 5, len(lines))):
                if snippet_lines[0] in lines[j]:
                    return
            lines[i + 1: i + 1] = snippet
            return

def _sqli_insert_before(lines: List[str], keyword: str, snippet_lines: List[str]) -> None:
    for i, line in enumerate(lines):
        if keyword in line:
            indent = _get_indent(line)
            snippet = [(indent + l + "\n") for l in snippet_lines]
            for j in range(max(i - 5, 0), i):
                if snippet_lines[0] in lines[j]:
                    return
            lines[i: i] = snippet
            return

def inject_sqli(java_file: str) -> None:
    if not os.path.exists(java_file):
        print("[!] File not found")
        return

    file_id = _sqli_extract_file_id(os.path.basename(java_file))
    test_name = f"BenchmarkTest{file_id}.java"

    lines = _read_lines(java_file)
    _sqli_insert_imports(lines)
    content = "".join(lines)

    has_param_get = "String param = scr.getTheParameter" in content
    has_bar = "bar" in content

    if has_param_get:
        target_var = "bar" if has_bar else "param"
        snippet = [
            f"Tag tagCheck = Tainter.getTag({target_var});",
            "if (tagCheck != null) {",
            f'    System.out.println("🔥 [GAL] SQL Injection at {test_name} carries tag: " + tagCheck);',
            "} else {",
            f'    System.out.println("❌ [GAL] No taint detected at sink {test_name}.");',
            "}",
        ]
        _sqli_insert_after_sql_block(lines, snippet)

    else:
        if not has_bar:
            tag_code_default = [
                'Tag tag = Tag.of("source: Tainted");',
                "param = Tainter.setTag(param, tag);",
                f'System.out.println("✅ [GAL] Taint set at source {test_name}! Tag = " + Tainter.getTag(param));',
            ]

            decode_line = 'param = java.net.URLDecoder.decode(param, "UTF-8");'
            request_line = "String param = request.getParameter"
            values_line = "if (values != null) param = values[0];"
            name_line = "param = name;"

            inserted = False
            if decode_line in content:
                _sqli_insert_after(lines, decode_line, tag_code_default)
                inserted = True
            elif request_line in content:
                _sqli_insert_after(lines, request_line, tag_code_default)
                inserted = True
            elif values_line in content:
                _sqli_insert_after(lines, values_line, tag_code_default)
                inserted = True
            elif name_line in content:
                tag_code_name = [
                    'Tag tag = Tag.of("source: Tainted");',
                    "name = Tainter.setTag(name, tag);",
                    f'System.out.println("✅ [GAL] Taint set at source {test_name}! Tag = " + Tainter.getTag(name));',
                ]
                _sqli_insert_before(lines, name_line, tag_code_name)
                inserted = True

            if inserted:
                check_snippet = [
                    "Tag tagCheck = Tainter.getTag(param);",
                    "if (tagCheck != null) {",
                    f'    System.out.println("🔥 [GAL] SQL Injection at {test_name} carries tag: " + tagCheck);',
                    "} else {",
                    f'    System.out.println("❌ [GAL] No taint detected at sink {test_name}.");',
                    "}",
                ]
                _sqli_insert_after_sql_block(lines, check_snippet)

        else:
            source_snippet = [
                'Tag tag = Tag.of("source: Tainted");',
                "param = Tainter.setTag(param, tag);",
                f'System.out.println("✅ [GAL] Taint set at source {test_name}! Tag = " + Tainter.getTag(param));',
            ]
            _sqli_insert_before(lines, "String bar", source_snippet)

            sink_snippet = [
                "Tag tagCheck = Tainter.getTag(bar);",
                "if (tagCheck != null) {",
                f'    System.out.println("🔥 [GAL] SQL Injection at {test_name} carries tag: " + tagCheck);',
                "} else {",
                f'    System.out.println("❌ [GAL] No taint detected at sink {test_name}.");',
                "}",
            ]
            _sqli_insert_after_sql_block(lines, sink_snippet)

    _write_lines(java_file, lines)
    print(f"[!] Done tagging in {java_file} success.")

# ====== UPDATE getTheParameter ======
_NEW_GET_PARAM_METHOD = '''    public String getTheParameter(String p) {
        String param = request.getParameter(p);

        // Gán tag
        Tag tag = Tag.of("source: getParameter");
        param = Tainter.setTag(param, tag);

        // In tag ra console
        Tag confirmTag = Tainter.getTag(param);
        System.out.println("✅ [GAL] Taint set at source! Tag = " + confirmTag);

        return param;
    }
'''

def update_get_parameter(java_file_path: str) -> None:
    filename = os.path.basename(java_file_path)
    if filename != "SeparateClassRequest.java":
        print("[!] File name is not SeparateClassRequest.java, ignore.")
        return

    with open(java_file_path, "r", encoding="utf-8") as f:
        content = f.read()

    if "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;" not in content:
        content = content.replace(
            "import javax.servlet.http.HttpServletRequest;",
            "import javax.servlet.http.HttpServletRequest;\n"
            "import edu.neu.ccs.prl.galette.internal.runtime.Tag;\n"
            "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;",
        )

    pattern = r"(?s) {4}public String getTheParameter\(String p\) \{.*?^ {4}\}"
    new_content = re.sub(pattern, _NEW_GET_PARAM_METHOD, content, flags=re.MULTILINE)

    with open(java_file_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    print("[!] Updated getTheParameter in", java_file_path)

def process_csv_and_inject(handler_name: str, csv_file: str) -> None:
    if not csv_file or not os.path.exists(csv_file):
        print(f"[!] CSV not found: {csv_file}")
        return

    handlers = {
        "cwe78": inject_cmdi,
        "cwe22": inject_path_traversal,
        "cwe89": inject_sqli,
    }
    handler = handlers[handler_name]

    with open(csv_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if CSV_COLUMN not in reader.fieldnames:
            print(f"[!] Column '{CSV_COLUMN}' not found in {csv_file}.")
            return
        seen = set()
        for row in reader:
            cls = _extract_classname(row[CSV_COLUMN])
            if not cls or cls in seen:
                continue
            seen.add(cls)
            java_file = _find_java_file(cls)
            if java_file:
                handler(java_file)
            else:
                print(f"[!] File {cls}.java not found in {ROOT_DIR}")

def main():
    parser = argparse.ArgumentParser(description="Insert Galette code in CSV (col4) for each CWE. (Minimal print mode)")
    parser.add_argument("--cwe22", action="store_true", help="Chạy Path Traversal (CWE-22)")
    parser.add_argument("--cwe78", action="store_true", help="Chạy Command Injection (CWE-78)")
    parser.add_argument("--cwe89", action="store_true", help="Chạy SQL Injection (CWE-89)")
    parser.add_argument("--root", default=D.PROJECT_SOURCE_CODE_JAVA_DIR,
                        help=f"Root directory to find .java files (default: {D.PROJECT_SOURCE_CODE_JAVA_DIR})")
    args = parser.parse_args()

    import io, contextlib

    global ROOT_DIR
    ROOT_DIR = args.root

    if args.cwe22:
        chosen = "cwe22"
        label = "CWE-22"
    elif args.cwe78:
        chosen = "cwe78"
        label = "CWE-78"
    elif args.cwe89:
        chosen = "cwe89"
        label = "CWE-89"
    else:
        print("[!] You must select 1 CWE: --cwe22 or --cwe78 or --cwe89")
        return

    print(f"Tagging in progress {label}")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        csv_dir = QL_RESULTS[chosen]
        csv_file = _pick_csv_in_dir(csv_dir)
        process_csv_and_inject(chosen, csv_file)
        if os.path.exists(SEPARATE_CLASS_REQUEST):
            update_get_parameter(SEPARATE_CLASS_REQUEST)
    print(f"[!] Complete tagging for {label}")

if __name__ == "__main__":
    main()

