import os

ROOT_DIR = os.path.join(os.path.dirname(__file__), "")

SAST_DIR = f"{ROOT_DIR}/SAST_Module"

DAST_DIR = f"{ROOT_DIR}/DAST_Module"

LLM_DIR = f"{ROOT_DIR}/LLM"

PROJECT_SOURCE_CODE_DIR = f"{ROOT_DIR}/BenchmarkJava"

PROJECT_SOURCE_CODE_DIR_BU = f"{ROOT_DIR}/BenchmarkJava_Backup"

PROJECT_SOURCE_CODE_JAVA_DIR = f"{PROJECT_SOURCE_CODE_DIR}/src/main/java/org/owasp/benchmark"

PROJECT_SOURCE_CODE_JAVA_DIR_BU = f"{PROJECT_SOURCE_CODE_DIR_BU}/src/main/java/org/owasp/benchmark"

PROJECT_SOURCE_CODE_LOG = f"{PROJECT_SOURCE_CODE_DIR}/target/log/"

CODEQL_DIR = f"{ROOT_DIR}/SAST_Module/codeql"

CODEQL_DB_PATH = f"{ROOT_DIR}/SAST_Module/ql_dbs"

CODEQL_QUERY = f"{ROOT_DIR}/SAST_Module/src/query"

CODEQL_REUSLT = f"{ROOT_DIR}/SAST_Module/ql_results"

SAST_RESULT_SARIF_DIR = f"{ROOT_DIR}/SAST_Module/ql_results/sarif"

GALETTE_DIR = f"{ROOT_DIR}/DAST_Module/galette"

GALETTE_JDK_INSTRUMENT = f"{DAST_DIR}/galette_jdk_instrument"

GALETTE_INSTRUMENT_RESULTS = f"{DAST_DIR}/script/instrument/galette_instrument_prompt_results"

GALETTE_INSTRUMENT_RESULTS_LLM = f"{DAST_DIR}/script/instrument/galette_instrument_prompt_results/LLM_prompt_rs"

GALETTE_PROPAGATION = f"{DAST_DIR}/script/propagation"

GALETTE_PROPAGATION_LOG_CURL = f"{DAST_DIR}/script/propagation/log_curl_info"

GALETTE_RESULTS = f"{DAST_DIR}/gallet_result"

LLM_OUTPUT_DIR = f"{LLM_DIR}/result/LLM_Results"

LLM_OUTPUT_USER_DIR = f"{LLM_DIR}/result"

GALETTE_FILTER = f"{DAST_DIR}/filter"