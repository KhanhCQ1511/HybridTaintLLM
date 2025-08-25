FEW_SHOT_EXAMPLES = """\
We give you some specific sample examples of what we have done in the past:

🔵 SOURCE TAGING RULES
- Only attach `Tainter.setTag()` to **variables that actually receive tainted data** (e.g. `param`).
- Insert the tag **AFTER** the variable has been fully transformed (decoded, sanitized), not before.
- DO NOT tag wrapper objects or derived variables that do not directly contain tainted data.

🔴 SUNK CHECK RULES
- Always call `Tainter.getTag()` on the **original tainted variable** recorded in results file.

===========================================
🟦 SOURCE TAGGING EXAMPLES
===========================================
Example 1: Tagging decoded header input
[!] Original code
String param = request.getHeader("X-Header");
param = java.net.URLDecoder.decode(param, "UTF-8");

[!] RIGHT
String param = request.getHeader("X-Header");
param = java.net.URLDecoder.decode(param, "UTF-8");

char[] chars = param.toCharArray();
char[] newChars = new char[chars.length];
for (int i = 0; i < chars.length; i++) {
    newChars[i] = Tainter.setTag(chars[i], Tag.of("SOURCE: BenchmarkTest00006 param at index " + i));
}
param = Tainter.setTag(new String(newChars), Tag.of("SOURCE: BenchmarkTest00006"));
for (char c : param.toCharArray()) {
    Tag cTag = Tainter.getTag(c);
    if (cTag != null) {
        System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
    }
}

===========================================
🟥 SINK CHECKING EXAMPLES
===========================================
Example 1: Sink is a String (Runtime.exec):
[!] Original Code
Process p = r.exec(cmd + param);

[!] RIGHT
String finalCommand = cmd + param;
for (char c : finalCommand.toCharArray()) {
    Tag cTag = Tainter.getTag(c);
    if (cTag != null) {
         System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
    }
}

Process p = r.exec(cmd + param);


Example 2: Sink is a List (ProcessBuilder)
[!] Original Code
pb.command(argList); 

[!] RIGHT
for (String arg : argList) {
    System.out.println("📌 [GAL] Checking argList item: " + arg);
    for (char c : arg.toCharArray()) {
        Tag cTag = Tainter.getTag(c);
        if (cTag != null) {
             System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
        }
    }
}

pb.command(argList);

Example 3: Sink in two line
[!] Original code
Process p = 
        r.exec(cmd + bar, argsEnv, new java.io.File(System.getProperty("user.dir")));

[!] RIGHT
for (char c : bar.toCharArray()) {
    Tag cTag = Tainter.getTag(c);
    if (cTag != null) {
        System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
    }
}
Process p = 
        r.exec(cmd + bar, argsEnv, new java.io.File(System.getProperty("user.dir")));

Example 4:  Avoid placing `Tainter.getTag()` inside try-with-resources
[STRICT RULE] 
- NEVER place `for (char c: ...) { ... Tainter.getTag(...) ... }` or any `Tainter.getTag()` code INSIDE try-with-resources parentheses.
- Only resource declarations (like FileOutputStream fos = ...) are allowed inside try(...).

[!] WRONG
try (
    for (char c : fileName.toCharArray()) {    <-- ❌ This must NEVER happen
        Tag cTag = Tainter.getTag(c);
        ...
    }
    java.io.FileOutputStream fos = ...
) { ... }

[!] RIGHT
for (char c : bar.toCharArray()) {
    Tag cTag = Tainter.getTag(c);
    if (cTag != null) {
        System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
    }
}
try (java.io.FileOutputStream fos = ...) {
    // normal code
}
"""

FEW_SHOT_STRING = """\
We give you some specific sample examples of what we have done in the past:

🔵 SOURCE TAGING RULES
- Only attach `Tainter.setTag()` to **variables that actually receive tainted data** (e.g. `param`).
- Insert the tag **AFTER** the variable has been fully transformed (decoded, sanitized), not before.
- DO NOT tag wrapper objects or derived variables that do not directly contain tainted data.

🔴 SUNK CHECK RULES
- Always call `Tainter.getTag()` on the **original tainted variable** recorded in the output file
- Insert the tag **AFTER** the variable is defined, not before.

===========================================
🟦 SOURCE TAGGING EXAMPLES
===========================================
Example 1: Tagging decoded header input
[!] Original code
String param = request.getHeader("X-Header");
param = java.net.URLDecoder.decode(param, "UTF-8");

[!] RIGHT
String param = request.getHeader("X-Header");
param = java.net.URLDecoder.decode(param, "UTF-8");

char[] chars = param.toCharArray();
char[] newChars = new char[chars.length];
for (int i = 0; i < chars.length; i++) {
    newChars[i] = Tainter.setTag(chars[i], Tag.of("SOURCE: BenchmarkTest00006 param at index " + i));
}
param = Tainter.setTag(new String(newChars), Tag.of("SOURCE: BenchmarkTest00006"));
for (char c : param.toCharArray()) {
    Tag cTag = Tainter.getTag(c);
    if (cTag != null) {
        System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
    }
}

===========================================
🟥 SINK CHECKING EXAMPLES
===========================================
Example 1: Sink is a String (Runtime.exec):
[!] Original Code
Process p = r.exec(cmd + param);

[!] RIGHT
String finalCommand = cmd + param;
for (char c : finalCommand.toCharArray()) {
    Tag cTag = Tainter.getTag(c);
    if (cTag != null) {
         System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
    }
}

Process p = r.exec(cmd + param);

Example 2: Sink in two line
[!] Original code
Process p = 
        r.exec(cmd + bar, argsEnv, new java.io.File(System.getProperty("user.dir")));

[!] RIGHT
String finalCommand = cmd + param;
for (char c : finalCommand.toCharArray()) {
    Tag cTag = Tainter.getTag(c);
    if (cTag != null) {
         System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
    }
}
Process p = 
        r.exec(finalCommand, argsEnv, new java.io.File(System.getProperty("user.dir")));
"""

FEW_SHOT_LIST = """\
We give you some specific sample examples of what we have done in the past:

🔵 SOURCE TAGING RULES
- Only attach `Tainter.setTag()` to **variables that actually receive tainted data** (e.g. `param`).
- Insert the tag **AFTER** the variable has been fully transformed (decoded, sanitized), not before.
- DO NOT tag wrapper objects or derived variables that do not directly contain tainted data.

🔴 SUNK CHECK RULES
- Always call `Tainter.getTag()` on the **original tainted variable** recorded in the output file
- Insert the tag **AFTER** the variable is defined, not before.

===========================================
🟦 SOURCE TAGGING EXAMPLES
===========================================
Example 1: Tagging decoded header input
[!] Original code
String param = request.getHeader("X-Header");
param = java.net.URLDecoder.decode(param, "UTF-8");

[!] RIGHT
String param = request.getHeader("X-Header");
param = java.net.URLDecoder.decode(param, "UTF-8");

char[] chars = param.toCharArray();
char[] newChars = new char[chars.length];
for (int i = 0; i < chars.length; i++) {
    newChars[i] = Tainter.setTag(chars[i], Tag.of("SOURCE: BenchmarkTest00006 param at index " + i));
}
param = Tainter.setTag(new String(newChars), Tag.of("SOURCE: BenchmarkTest00006"));
for (char c : param.toCharArray()) {
    Tag cTag = Tainter.getTag(c);
    if (cTag != null) {
        System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
    }
}

===========================================
🟥 SINK CHECKING EXAMPLES
===========================================
Example 1: Sink is a List (ProcessBuilder)
[!] Original Code
pb.command(argList); 

[!] RIGHT
for (String arg : argList) {
    System.out.println("📌 [GAL] Checking argList item: " + arg);
    for (char c : arg.toCharArray()) {
        Tag cTag = Tainter.getTag(c);
        if (cTag != null) {
             System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
        }
    }
}

pb.command(argList);
"""

FEW_SHOT_SQL = """
We give you some specific sample examples of what we have done in the past:

🔵 SOURCE TAGING RULES
- Only attach `Tainter.setTag()` to **variables that actually receive tainted data** (e.g. `param`).
- Insert the tag **AFTER** the variable has been fully transformed (decoded, sanitized), not before.
- DO NOT tag wrapper objects or derived variables that do not directly contain tainted data.

🔴 SUNK CHECK RULES
- Always call `Tainter.getTag()` on the **original tainted variable** recorded in the output file
- Insert the tag **AFTER** the variable is defined, not before.
"""


PROMPT_USER_TAGGING_SOURCE = """\
You are given a Java method and a taint source location extracted from static analysis.

Your task is to insert Galette taint tagging code at the correct data flow point using `Tainter.setTag(...)`.

Instructions:
1. Identify the variable that receives the tainted input.
2. The input may contain `if`, `switch`, or `decode` logic — analyze control flow carefully.
3. DO NOT insert the tag at the original input line if the variable is reassigned, decoded, transformed, or wrapped.
4. Check, if placed in a for loop then change the variable i to l
5. INSTEAD, insert the following code after the final assignment or transformation of the tainted variable:

```java
char[] chars = param.toCharArray();
char[] newChars = new char[chars.length];
for (int i = 0; i < chars.length; i++) {{
    newChars[i] =
        Tainter.setTag(
            chars[i], Tag.of("SOURCE: {file_name} param at index " + i));
}}

{source} = Tainter.setTag(new String(newChars), Tag.of("SOURCE: {file_name}"));

for (char c : param.toCharArray()) {{
    Tag cTag = Tainter.getTag(c);
    if (cTag != null) {{
        System.out.println("🔥 [GAL] Char '" + c + "' carries tag: " + cTag);
    }}
}}
```

File: {file_name}

Taint Source:
- Class: {source_class}
- Method: {source_method}
- Expression: {source}
- Line: {source_line}

Package & Import:
```java
{package_import}
```

Input Java Method:
```java
{java_method}
```

Return ONLY the updated Java code with `Tainter.setTag(...)` inserted properly.
"""

PROMPT_USER_TAGGING_SINK = """\
You are given a Java method and a taint sink location extracted from static analysis.

Your task is to insert Galette taint checking code at the sink using `Tainter.getTag(...)`.

Instructions:
1. Find the exact sink line indicated by static analysis (e.g., pb.command(argList), statement.execute(sql), etc.).
2. Insert the taint-checking block (using Tainter.getTag(...)) IMMEDIATELY BEFORE the entire statement that contains the sink call.
   ⚠ If the sink call is part of a variable assignment or initialization (e.g., Process p = r.exec(...);),
   place the taint-checking block BEFORE the entire statement — DO NOT insert it between the variable declaration and the method call.
3. DO NOT move, delete, or modify the sink line itself — only insert the taint-checking code before it.
4. If the sink uses a collection or array (e.g., argList, sqlList), iterate through each element and each character within to detect taint.

```java
for (String arg : {sink}) {{
    System.out.println("📌 [GAL] Checking {sink} item: " + arg);
    for (char c : arg.toCharArray()) {{
        Tag cTag = Tainter.getTag(c);
        if (cTag != null) {{
            System.out.println("🔥 [GAL] {cwe_info} at {file_name} char '" + c + "' carries tag: " + cTag);
        }}
    }}
}}
```
3. DO NOT change unrelated logic.

File: {file_name}

Package & Import:
```java
{package_import}
```

Taint Sink:
- Class: {sink_class}
- Method: {sink_method}
- Expression: {sink}
- Line: {sink_line}

Input Java Method:
```java
{java_method}
```

Return ONLY the updated Java code with `Tainter.getTag(...)` inserted properly.
"""

CWE_INFO = {
    "022":"Path Traversal",
    "078":"Command Injection",
    "089":"SQL Injection"
}

PROMPT_USER_TAGGING_COMBINED = """\
You will perform two tasks using Galette taint tracking instrumentation:

Mark the taint source using the following instructions:
{user_tagging_source}

Then, check the taint sink using the following instructions:
{user_tagging_sink}
"""

PROMPT_SYSTEM_TASK_TAGGING = """\
You are a Java code instrumentation expert specializing in dynamic taint tracking using the Galette framework.

Your task is to automatically insert Galette taint tracking code into Java source files, using information provided from static analysis (source/sink CSV data). You will be given:
- A full Java method (from a .java file).
- The line and variable where tainted input is introduced (source).
- The line and variable used at a sensitive location (sink).

[!] PACKAGE & IMPORT HANDLING RULES:
- ALWAYS KEEP the existing `package` line exactly as is. DO NOT delete or rewrite it.
- ALWAYS KEEP every original `import` line. DO NOT delete or replace them.
- Only ADD the following imports if they do NOT already exist:
    import edu.neu.ccs.prl.galette.internal.runtime.Tag;
    import edu.neu.ccs.prl.galette.internal.runtime.Tainter;
- When adding, INSERT them AFTER the last existing `import` line.
- NEVER start the file directly with Galette imports. The `package` line must stay on top.

[!] OUTPUT RULES:
Return only the full Java code (from package to class closing brace) after applying both source tagging and sink checking. 
Make sure imports are added at the top if missing.
Do NOT include explanations, comments, or extra text.

Answer in TXT object with the following STRICT format:
[!] GENERAL RULES:
- Your answer MUST start with either:
  • “Source & Sink File:” if source and sink are in the SAME file
  • OR “Source File:” followed by “Sink File:” if they are in DIFFERENT files.
- You MUST include the file name exactly as given (e.g., BenchmarkTest01033.java).
- The UPDATED JAVA CODE MUST be fully wrapped inside a ```java fenced code block.
- After the code block, ALWAYS close with a line containing only:
<>
- DO NOT include any extra explanation, markdown, or commentary outside the specified structure.
- DO NOT add extra comments like “// GAL Instrumentation” unless they already exist in the file.
- DO NOT output multiple code blocks for the same file — return ONE COMPLETE updated file per section.
--------------------------------------
IF SOURCE AND SINK IN SAME FILE:
--------------------------------------
Format exactly like this:
Source & Sink File:
<File name>
```java
<ENTIRE UPDATED JAVA CODE HERE>
<>
```

--------------------------------------
IF SOURCE AND SINK ARE IN DIFFERENT FILES:
--------------------------------------
Format exactly like this:
Source File:
<File name>
```java
<UPDATED JAVA CODE WITH TAINT SOURCE>
<>
```

Sink File:
<File name>
```java
<UPDATED JAVA CODE WITH TAINT SINK>
<>
```
"""