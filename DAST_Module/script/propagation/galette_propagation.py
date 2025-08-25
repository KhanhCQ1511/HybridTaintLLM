import os
import sys
import signal
import subprocess as sb
import argparse
import xml.etree.ElementTree as ET
import pandas as pd
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from directory import PROJECT_SOURCE_CODE_LOG, GALETTE_PROPAGATION_LOG_CURL, PROJECT_SOURCE_CODE_DIR, CODEQL_REUSLT, GALETTE_JDK_INSTRUMENT, GALETTE_DIR, DAST_DIR, GALETTE_RESULTS
from galette_curl_info import PathTraversal, CommandInjection, SQLInjection

LOG_FILE = os.path.join(PROJECT_SOURCE_CODE_LOG, "cargo-output.log")
LOG_CURL_FILE = os.path.join(GALETTE_PROPAGATION_LOG_CURL, "curl_output.log")

KEYWORDS = {
    "PathTraversal": "Path Traversal at",
    "SQLInjection": "SQL Injection at",
    "CommandInjection": "Command Injection at"
}

CWE_TO_KEYWORD = {
    "022": KEYWORDS["PathTraversal"],
    "089": KEYWORDS["SQLInjection"],
    "078": KEYWORDS["CommandInjection"]
}

OUTPUT_FILES = {
    "PathTraversal": os.path.join(GALETTE_PROPAGATION_LOG_CURL, "PathTraversal.txt"),
    "SQLInjection": os.path.join(GALETTE_PROPAGATION_LOG_CURL, "SQLInject.txt"),
    "CommandInjection": os.path.join(GALETTE_PROPAGATION_LOG_CURL, "CommandInject.txt")
}

CWE_TO_CURL = {
    "022": ("PathTraversal", PathTraversal),
    "078": ("CommandInjection", CommandInjection),
    "089": ("SQLInjection", SQLInjection)
}

CWE_TO_OUTPUT_FILE = {
    "022": OUTPUT_FILES["PathTraversal"],
    "078": OUTPUT_FILES["CommandInjection"],
    "089": OUTPUT_FILES["SQLInjection"]
}

CWE_TO_PATTERN = {
    "022": "Path Traversal at",
    "078": "Command Injection at",
    "089": "SQL Injection at"
}

def setup_galette_env():
    os.environ["JAVA_HOME"] = GALETTE_JDK_INSTRUMENT
    agent_path = os.path.join(GALETTE_DIR, "galette-agent", "target", "galette-agent-1.0.0-SNAPSHOT.jar")
    maven_opts = f"-Xbootclasspath/a:{agent_path} -javaagent:{agent_path}"
    os.environ["MAVEN_OPTS"] = maven_opts
    print(f"[!] JAVA_HOME set to: {GALETTE_JDK_INSTRUMENT}")
    print(f"[!] MAVEN_OPTS set to: {maven_opts}")

def reset_logs(cwe_id):
    os.makedirs(PROJECT_SOURCE_CODE_LOG, exist_ok=True)
    os.makedirs(GALETTE_PROPAGATION_LOG_CURL, exist_ok=True)

    if os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()
        print(f"[!] Reset log file: {LOG_FILE}")

    if os.path.exists(LOG_CURL_FILE):
        open(LOG_CURL_FILE, "w").close()
        print(f"[!] Reset log file: {LOG_CURL_FILE}")

    cwe_output_path = CWE_TO_OUTPUT_FILE.get(cwe_id)
    if cwe_output_path and os.path.exists(cwe_output_path):
        open(cwe_output_path, "w").close()
        print(f"[!] Reset log file: {cwe_output_path}")

def ensure_galette_dependency():
    pom_path = os.path.join(PROJECT_SOURCE_CODE_DIR, "pom.xml")
    if not os.path.exists(pom_path):
        print(f"[!] Can't find pom.xml in {pom_path}")
        return
    tree = ET.parse(pom_path)
    root = tree.getroot()
    mvn_ns = root.tag.split("}")[0].strip("{")
    ns = {"mvn": mvn_ns}
    ET.register_namespace('', mvn_ns)
    deps_node = root.find("mvn:dependencies", ns)
    if deps_node is None:
        deps_node = ET.SubElement(root, f"{{{mvn_ns}}}dependencies")

    for dep in deps_node.findall("mvn:dependency", ns):
        gid = dep.find("mvn:groupId", ns)
        if gid is not None and gid.text == "edu.neu.ccs.prl.galette":
            print("[!] Galette agent is already in pom.xml, skip it")
            return

    new_dep = ET.SubElement(deps_node, f"{{{mvn_ns}}}dependency")
    gid = ET.SubElement(new_dep, f"{{{mvn_ns}}}groupId")
    gid.text = "edu.neu.ccs.prl.galette"
    aid = ET.SubElement(new_dep, f"{{{mvn_ns}}}artifactId")
    aid.text = "galette-agent"
    ver = ET.SubElement(new_dep, f"{{{mvn_ns}}}version")
    ver.text = "1.0.0-SNAPSHOT"
    scope = ET.SubElement(new_dep, f"{{{mvn_ns}}}scope")
    scope.text = "provided"
    tree.write(pom_path, encoding="utf-8", xml_declaration=True)
    print("[!] Added Galette agent dependency to pom.xml")

def start_maven_server():
    print("[!] Running BenchJava (cargo:run)!")
    proc = sb.Popen(
        ["mvn", "clean", "package", "cargo:run", "-Pdeploy"],
        cwd=PROJECT_SOURCE_CODE_DIR,
        stdout=sb.PIPE,
        stderr=sb.STDOUT,
        text=True,
        bufsize=1
    )
    for line in proc.stdout:
        print(line, end="")
        if ("Started" in line
            or "Started Jetty Server" in line
            or "Tomcat started" in line
            or "Press Ctrl-C to stop the container" in line):
            print("[!] Success Running BenchJava!")
            break
    proc.stdout.close()
    return proc

def clean_curl_command(raw: str) -> str:
    cleaned = raw.replace("\\", "")
    cleaned = " ".join(cleaned.splitlines())
    return cleaned.strip()

def run_curls_for_cwe(cwe_id):
    cwe_key = "022" if cwe_id == "demo" else cwe_id
    cwe_info = CWE_TO_CURL.get(cwe_key)
    if not cwe_info:
        print(f"[!] Can't find mapping for CWE-{cwe_id}")
        return

    group_name, commands = cwe_info
    with open(LOG_CURL_FILE, "w", encoding="utf-8") as curl_log:
        print(f"\n[!] Running CURL for {group_name}")
        if not commands:
            print(f"[!] Not found CURL for {group_name}")
            curl_log.write(f"\n=== {group_name}: EMPTY ===\n")
            return

        total = len(commands)
        last_cmd = None
        last_idx = 0
        last_ok = None

        for idx, (key, curl_cmd) in enumerate(commands.items(), start=1):
            cmd = clean_curl_command(curl_cmd)
            curl_log.write(f"\n=== [{group_name}] CURL {idx}/{total} ===\n{cmd}\n")
            result = sb.run(cmd, shell=True, capture_output=True, text=True)

            if result.stdout.strip():
                curl_log.write("[!] STDOUT:\n" + result.stdout + "\n")
            if result.stderr.strip():
                curl_log.write("[!] STDERR:\n" + result.stderr + "\n")

            last_cmd = cmd
            last_idx = idx
            last_ok = (result.returncode == 0)

        if last_cmd is not None:
            print(f'\n[!] [{group_name} – CURL {last_idx}] {last_cmd}')
            if last_ok:
                print(f'[!] [{group_name}] CURL {last_idx} success!')
            else:
                print(f'[!] [{group_name}] CURL {last_idx} error!')

        print(f"\n[!] Recorded all CURL results for CWE-{cwe_id} in: {LOG_CURL_FILE}")

def check_log_for_taint(cwe_id):
    check_key = "022" if cwe_id == "demo" else cwe_id
    if not os.path.exists(LOG_FILE):
        print(f"[!] Can't find file: {LOG_FILE}")
        return

    pattern = CWE_TO_PATTERN.get(check_key)
    if not pattern:
        print(f"[!] No pattern for CWE-{check_key}")
        return

    matched_lines = []
    seen_tests = set()

    with open(LOG_FILE, "r", encoding="utf-8") as log_file:
        for line in log_file:
            stripped_line = line.strip()
            if f"[GAL] {pattern}" in stripped_line:
                match = re.search(r"(BenchmarkTest\d+\.java)", stripped_line)
                if match:
                    test_file = match.group(1)
                    if test_file not in seen_tests:
                        matched_lines.append(stripped_line)
                        seen_tests.add(test_file)

    target_key = "PathTraversal"
    out_path = OUTPUT_FILES[target_key]

    if matched_lines:
        with open(out_path, "w", encoding="utf-8") as f:
            for l in matched_lines:
                f.write(l + "\n")
            f.write(f"\n[!] Total unique BenchmarkTest matched for {pattern}: {len(matched_lines)}\n")

        print(f"[!] Saved result to: {out_path} ({len(matched_lines)} unique tests)")
    else:
        print(f"[!] No matching GAL log lines for CWE-{cwe_id} ({pattern})")

def merge_sast_dast(cwe_id):
    merge_key = "022" if cwe_id == "demo" else str(cwe_id).zfill(3)
    print(f"[!] Start merging results for CWE-{merge_key}")

    dast_txt_path = CWE_TO_OUTPUT_FILE.get(merge_key)
    if not dast_txt_path or not os.path.exists(dast_txt_path):
        print(f"[!] TXT log not found for CWE-{merge_key}: {dast_txt_path}")
        return

    keyword = CWE_TO_KEYWORD.get(merge_key)
    if not keyword:
        print(f"[!] No keyword mapping for CWE-{merge_key}")
        return

    with open(dast_txt_path, "r", encoding="utf-8") as f:
        dast_lines = [line.strip() for line in f if line.strip()]

    benchmark_hits = set()
    for line in dast_lines:
        if keyword in line:
            match = re.search(r'BenchmarkTest(\d+)', line)
            if match:
                benchmark_hits.add(match.group(1).zfill(4))

    if not benchmark_hits:
        print(f"[!] TXT log ({dast_txt_path}) has NO benchmark with '{keyword}'")
    else:
        print(f"[!] Found {len(benchmark_hits)} benchmark in log for CWE-{merge_key}: {sorted(benchmark_hits)}")

    csv_dir = os.path.join(CODEQL_REUSLT, f"cwe-{merge_key}")
    if not os.path.exists(csv_dir):
        print(f"[!] CSV directory not found: {csv_dir}")
        return

    csv_files = [f for f in os.listdir(csv_dir) if f.endswith(".csv")]
    if not csv_files:
        print(f"[!] No CSV file in: {csv_dir}")
        return

    csv_path = os.path.join(csv_dir, csv_files[0])
    print(f"[!] Reading CSV: {csv_path}")
    df = pd.read_csv(csv_path)

    if benchmark_hits:
        df["DAST"] = df["col4"].apply(
            lambda x: True if any(f"BenchmarkTest{bid}" in str(x) for bid in benchmark_hits) else False
        )
    else:
        df["DAST"] = False

    output_base = os.path.join(GALETTE_RESULTS)
    output_folder = os.path.join(output_base, f"cwe-{cwe_id}")
    os.makedirs(output_folder, exist_ok=True)
    output_csv = os.path.join(output_folder, f"CWE-{cwe_id}_Merged.csv")
    df.to_csv(output_csv, index=False, encoding="utf-8-sig")

    true_count = df["DAST"].sum()
    false_count = len(df) - true_count
    print(f"[!] New CSV created: {output_csv}")
    print(f"[!] DAST=True: {true_count} | DAST=False: {false_count}")

def run_for_cwe(cwe_id):
    cwe_id = str(cwe_id).strip().lower()
    print(f"[!] Start test propagation for CWE-{cwe_id}")
    reset_logs("022")
    setup_galette_env()
    ensure_galette_dependency()
    server = start_maven_server()
    try:
        run_curls_for_cwe(cwe_id)
        check_log_for_taint(cwe_id)
        merge_sast_dast(cwe_id)
        print("\n[!] Complete CURL and check log!")
    except KeyboardInterrupt:
        print("\n[!] Stop running BenchJava")
    finally:
        if server:
            server.terminate()
        print("[!] Server stopped, continuing pipeline.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Galette Propagation Test for CWE")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 078, 089, or demo)")
    args = parser.parse_args()
    run_for_cwe(args.cwe)