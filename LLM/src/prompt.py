PROMPT_SYSTEM_TASK = """\
You are an expert in detecting security vulnerabilities. \
You are given the starting point (source) and the ending point (sink) of a dataflow path in a Java project that may be a potential vulnerability. \
Analyze the given taint source and sink and predict whether the given dataflow can be part of a vulnerability or not, and store it as a boolean in "is_vulnerable". \
Note that, the source must be either a) the formal parameter of a public library function which might be invoked by a downstream package, or b) the result of a function call that returns tainted input from end-user. \
If the given source or sink do not satisfy the above criteria, mark the result as NOT VULNERABLE. \
Please provide a very short explanation associated with the verdict. \
Additionally, if the path is considered vulnerable, Your task is to return the **cleaned or patched code snippet(s)** that should replace vulnerable operations in order to stop the taint flow from source to sink.\

Assume that the intermediate path has no sanitizer.


Answer in JSON object with the following format:

{ "explanation": <YOUR EXPLANATION>,
  "source_is_false_positive": <true or false>,
  "sink_is_false_positive": <true or false>,
  "is_vulnerable": <true or false> 
  "fix_suggestion": {
      "code": [
        "code": [
              "// Return the fixed code snippet below.",
              "// Only mark lines that are added or modified with // [ADDED] or // [MODIFIED] at the end of the line.",
              "// Do NOT include any inline explanation, reasoning, or verbose comments.",
              "// Do NOT comment on unchanged lines.",
              "// The output must be clean, production-ready, and easily integratable into the original source file.",
              "// Remove unnecessary, unchanged or unused parts of it."
              "// Avoid any comments that describe the logic or purpose of the code – only use the change markers."
]

      ],
      "summary": "Concise explanation of how this fix mitigates the vulnerability"
  }
}
Do not include anything else in the response.\

"""

PROMPT_USER = """\
Analyze the following dataflow path in a Java project and predict whether it contains a {cwe_description} vulnerability ({cwe_id}), or a relevant vulnerability.
{hint}

Source ({source_msg}):
```
{source}
```

Steps:
{intermediate_steps}

Sink ({sink_msg}):
```
{sink}
```\
"""

PROMPT_USER_W_CONTEXT = """\
Analyze the following dataflow path in a Java project and predict whether it contains a {cwe_description} vulnerability ({cwe_id}), or a relevant vulnerability.
{hint}

Source ({source_msg}):
```
{source}
```

Steps:
{intermediate_steps}

Sink ({sink_msg}):
```
{sink}
```

{context}\
"""

CWE_HINTS = {
    "022": "Note: please be careful about defensing against absolute paths and \"..\" paths. Just canonicalizing paths might not be sufficient for the defense.",
    "078": "Note that other than typical Runtime.exec which is directly executing command, using Java Reflection to create dynamic objects with unsanitized inputs might also cause OS Command injection vulnerability. This includes deserializing objects from untrusted strings and similar functionalities. Writing to config files about library data may also induce unwanted execution of OS commands.",
    "089": "Please note that unvalidated or improperly sanitized input can be used to construct SQL queries, resulting in a CWE-089 vulnerability. Injection of malicious values might lead to unauthorized data access or manipulation.",
}