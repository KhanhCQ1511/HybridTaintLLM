import os
import subprocess as sb
import sys
import shutil

# Load ROOT_DIR and paths from directory.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import directory

# Define paths and constants
galette_git_url = "https://github.com/neu-se/galette.git"
galette_path = os.path.join(directory.DAST_DIR, "galette")
agent_jar_path = os.path.join(galette_path, "galette-agent", "target", "galette-agent-1.0.0-SNAPSHOT.jar")
instrument_jar_path = os.path.join(galette_path, "galette-instrument", "target", "galette-instrument-1.0.0-SNAPSHOT.jar")
instrumented_jdk_path = directory.GALETTE_JDK_INSTRUMENT

# JDK download info (Adoptium Temurin)
jdk_version = "17.0.11_9"
jdk_archive_name = f"OpenJDK17U-jdk_x64_linux_hotspot_{jdk_version}.tar.gz"
jdk_download_url = "https://eclipse.c3sl.ufpr.br/temurin-compliance/temurin/17/jdk-17.0.11+9/OpenJDK17U-jdk_x64_linux_hotspot_17.0.11_9.tar.gz"
jdk_install_path = os.path.join(directory.DAST_DIR, "jdk-17.0.11")

# Clone Galette if not already cloned
if not os.path.exists(galette_path):
    print(f"[!] Cloning Galette into: {galette_path}")
    try:
        sb.run(["git", "clone", galette_git_url, galette_path], check=True)
    except sb.CalledProcessError:
        print("[!] Failed to clone Galette.")
        sys.exit(1)
else:
    print("[!] Galette already exists. Skipping clone.")

# Build Galette using Maven
print("[!] Building Galette with Maven...")
try:
    sb.run(["mvn", "clean", "package"], cwd=galette_path, check=True)
    print("[!] Galette built successfully!")
except sb.CalledProcessError:
    print("[!] Failed to build Galette.")
    sys.exit(1)

# Install Galette Agent into local Maven repo
print("[!] Installing Galette agent into local Maven repository...")
try:
    sb.run([
        "mvn", "install:install-file",
        f"-Dfile={agent_jar_path}",
        "-DgroupId=edu.neu.ccs.prl.galette",
        "-DartifactId=galette-agent",
        "-Dversion=1.0.0-SNAPSHOT",
        "-Dpackaging=jar"
    ], check=True)
    print("[!] Galette agent installed to local Maven repository.")
except sb.CalledProcessError:
    print("[!] Failed to install Galette agent.")
    sys.exit(1)

# Download and extract specific JDK if not present
if not os.path.exists(jdk_install_path):
    print(f"[!] Downloading JDK {jdk_version} from Adoptium...")
    try:
        sb.run(["wget", "-O", jdk_archive_name, jdk_download_url], check=True)
        sb.run(["tar", "-xzf", jdk_archive_name, "-C", directory.DAST_DIR], check=True)

        # Find extracted directory (name may include +9)
        extracted_dir = [d for d in os.listdir(directory.DAST_DIR) if d.startswith("jdk-17.0.11")][0]
        extracted_path = os.path.join(directory.DAST_DIR, extracted_dir)

        # Rename to a clean directory name for consistency
        shutil.move(extracted_path, jdk_install_path)
        print(f"[!] JDK extracted to {jdk_install_path}")
    except sb.CalledProcessError:
        print("[!] Failed to download or extract JDK.")
        sys.exit(1)
else:
    print(f"[!] JDK {jdk_version} already exists at {jdk_install_path}")

jdk_path = jdk_install_path
print(f"[!] Using downloaded JDK at: {jdk_path}")

# Set JAVA_HOME and MAVEN_OPTS
os.environ["JAVA_HOME"] = jdk_path
os.environ["MAVEN_OPTS"] = (
    f"-Xbootclasspath/a:{agent_jar_path} "
    f"-javaagent:{agent_jar_path}"
)
print(f"[!] Set JAVA_HOME = {jdk_path}")
print(f"[!] Set MAVEN_OPTS with Galette agent")

# Instrument JDK using Galette Instrument JAR
print("[!] Instrumenting JDK 17 using Galette Instrument JAR...")
if not os.path.exists(instrument_jar_path):
    print(f"[!] Galette Instrument JAR not found at: {instrument_jar_path}")
    sys.exit(1)
# Check JDK path exists
if not os.path.exists(jdk_path):
    print(f"[!] JDK path not found: {jdk_path}")
    sys.exit(1)
# Delete destination if exists
if os.path.exists(instrumented_jdk_path):
    print(f"[!] Output directory already exists. Deleting: {instrumented_jdk_path}")
    shutil.rmtree(instrumented_jdk_path)
# Run Galette Instrument
try:
    sb.run([
        os.path.join(jdk_path, "bin", "java"),
        "-jar", instrument_jar_path,
        "--java-home", jdk_path,
        "--output-dir", instrumented_jdk_path
    ], check=True)
    print(f"[!] Instrumented JDK saved to: {instrumented_jdk_path}")
except sb.CalledProcessError:
    print("[!] Failed to instrument JDK.")
    sys.exit(1)

