"""
Script for defining and organizing project directories.

This module consists of several directory path definitions used in the project. It
helps in managing paths for static analysis, dynamic analysis, logs, backups, and
other necessary scripts and data. Paths are pre-configured to ensure consistency
and ease of access during the project's execution.
"""

import os

# ROOT_DIR: Root directory of the project (where this script is located)
ROOT_DIR = os.path.join(os.path.dirname(__file__), "")

# SAST_DIR: Directory for the Static Analysis module (SAST)
SAST_DIR = f"{ROOT_DIR}/SAST_Module"

# DAST_DIR: Directory for the Dynamic Analysis module (DAST)
DAST_DIR = f"{ROOT_DIR}/DAST_Module"

# LLM_DIR: Directory for all LLM-related scripts/data
LLM_DIR = f"{ROOT_DIR}/LLM"

# PROJECT_SOURCE_CODE_DIR: Directory containing all Java benchmark projects (main working dir)
PROJECT_SOURCE_CODE_DIR = f"{ROOT_DIR}/BenchmarkJava"

# PROJECT_SOURCE_CODE_DIR_BU: Backup directory for Java benchmark projects
PROJECT_SOURCE_CODE_DIR_BU = f"{ROOT_DIR}/BenchmarkJava_Backup"

# PROJECT_SOURCE_CODE_JAVA_DIR: Main Java source code directory for OWASP Benchmark inside project
PROJECT_SOURCE_CODE_JAVA_DIR = f"{PROJECT_SOURCE_CODE_DIR}/src/main/java/org/owasp/benchmark"

# PROJECT_SOURCE_CODE_JAVA_DIR_BU: Java source code directory for backup OWASP Benchmark
PROJECT_SOURCE_CODE_JAVA_DIR_BU = f"{PROJECT_SOURCE_CODE_DIR_BU}/src/main/java/org/owasp/benchmark"

# PROJECT_SOURCE_CODE_LOG: Log output directory for Java project's execution (target/log/)
PROJECT_SOURCE_CODE_LOG = f"{PROJECT_SOURCE_CODE_DIR}/target/log/"

# CODEQL_DIR: Path to the patched CodeQL binary (provided by Iris or your static analysis tool)
CODEQL_DIR = f"{SAST_DIR}/codeql"

# CODEQL_DB_PATH: Path to folder containing all CodeQL databases
CODEQL_DB_PATH = f"{ROOT_DIR}/SAST_Module/ql_dbs"

# CODEQL_QUERY: Path to directory containing CodeQL query (.ql) files
CODEQL_QUERY = f"{SAST_DIR}/src/query"

# CODEQL_RESULT: Path to folder where CodeQL query result CSVs will be saved
CODEQL_RESULT = f"{SAST_DIR}/ql_results"

# SAST_RESULT_SARIF_DIR: Path to folder containing CodeQL results in SARIF format
SAST_RESULT_SARIF_DIR = f"{SAST_DIR}/src/sarif"

# GALETTE_DIR: Directory containing the Galette agent and core tool for dynamic instrumentation
GALETTE_DIR = f"{DAST_DIR}/galette"

# GALETTE_JDK_INSTRUMENT: Path where instrumented JDK (by Galette) is stored
GALETTE_JDK_INSTRUMENT = f"{DAST_DIR}/galette_jdk_instrument"

# GALETTE_INSTRUMENT_RESULTS: Path to store result files after Galette agent instrumentation (prompts, logs)
GALETTE_INSTRUMENT_RESULTS = f"{DAST_DIR}/script/instrument/galette_instrument_prompt_results"

# GALETTE_INSTRUMENT_RESULTS_LLM: Path to store LLM-generated code (after prompt tagging for Galette)
GALETTE_INSTRUMENT_RESULTS_LLM = f"{DAST_DIR}/script/instrument/galette_instrument_prompt_results/LLM_prompt_rs"

# GALETTE_PROPAGATION: Directory for Galette propagation scripts (to run propagation test)
GALETTE_PROPAGATION = f"{DAST_DIR}/script/propagation"

# GALETTE_PROPAGATION_LOG_CURL: Directory to store propagation logs and curl outputs (for API testing/tracking)
GALETTE_PROPAGATION_LOG_CURL = f"{DAST_DIR}/script/propagation/log_curl_info"

# GALETTE_RESULTS: Directory to store final dynamic analysis results by Galette
GALETTE_RESULTS = f"{DAST_DIR}/gallet_result"
