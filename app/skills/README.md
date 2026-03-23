# Security Compliance Skills

This folder contains **Claude AI skills** — one per supported language — that instruct Claude to analyze source code for compliance against the SecureByPolicy security standards.

Each skill file is a Markdown document containing:
- **Metadata** – language name, file extensions, and compliance baseline  
- **System Prompt** – the role definition and analysis instructions for Claude  
- **Security Rules** – a structured table of forbidden patterns, their severity, reasons, and remediations derived directly from the corresponding `../rules/<language>_policy.json`  
- **Output Format** – a consistent compliance report template  

---

## Available Skills

| Skill File | Language | File Extensions | Policy Reference |
|---|---|---|---|
| [python_skill.md](python_skill.md) | Python | `.py` | [python_policy.json](../rules/python_policy.json) |
| [java_skill.md](java_skill.md) | Java | `.java` | [java_policy.json](../rules/java_policy.json) |
| [javascript_skill.md](javascript_skill.md) | JavaScript | `.js`, `.mjs`, `.cjs` | [javascript_policy.json](../rules/javascript_policy.json) |
| [typescript_skill.md](typescript_skill.md) | TypeScript | `.ts` | [typescript_policy.json](../rules/typescript_policy.json) |
| [golang_skill.md](golang_skill.md) | Go (Golang) | `.go` | [golang_policy.json](../rules/golang_policy.json) |
| [rust_skill.md](rust_skill.md) | Rust | `.rs` | [rust_policy.json](../rules/rust_policy.json) |
| [c_skill.md](c_skill.md) | C | `.c`, `.h` | [c_policy.json](../rules/c_policy.json) |
| [cpp_skill.md](cpp_skill.md) | C++ | `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh` | [cpp_policy.json](../rules/cpp_policy.json) |
| [csharp_skill.md](csharp_skill.md) | C# (.NET) | `.cs` | [csharp_policy.json](../rules/csharp_policy.json) |
| [bash_skill.md](bash_skill.md) | Bash / Shell | `.sh`, `.bash` | [bash_policy.json](../rules/bash_policy.json) |
| [powershell_skill.md](powershell_skill.md) | PowerShell | `.ps1`, `.psm1`, `.psd1` | [powershell_policy.json](../rules/powershell_policy.json) |
| [angular_skill.md](angular_skill.md) | Angular | `.ts`, `.html` | [angular_policy.json](../rules/angular_policy.json) |
| [react_skill.md](react_skill.md) | React (JSX/TSX) | `.jsx`, `.tsx` | [react_policy.json](../rules/react_policy.json) |
| [ansisql_skill.md](ansisql_skill.md) | ANSI SQL (PostgreSQL/MySQL) | `.sql` | [ansisql_policy.json](../rules/ansisql_policy.json) |
| [plsql_skill.md](plsql_skill.md) | PL/SQL (Oracle) | `.sql`, `.plsql`, `.pkb`, `.pks`, `.prc`, `.fnc`, `.trg` | [plsql_policy.json](../rules/plsql_policy.json) |
| [tsql_skill.md](tsql_skill.md) | T-SQL (SQL Server) | `.sql`, `.tsql` | [tsql_policy.json](../rules/tsql_policy.json) |

---

## Compliance Baseline

All skills enforce the same compliance baseline:

| Standard | Controls Addressed |
|---|---|
| OWASP Top 10 (2021) | A01–A10 Injection, Broken Auth, Crypto Failures, Insecure Design, etc. |
| NIST SP 800-53 | AC-3, AU-12, CM-2, IA-5, SA-11, SC-8, SC-13, SI-7 |
| DISA STIG | V-222637, V-222640, V-222643, V-222645 |
| FIPS 140-3 | All hashing, signing, and TLS operations |
| CIS Level 2 | Least privilege, secure configurations, input validation |

---

## How to Use a Skill

1. Open the skill file for the target language (e.g., `python_skill.md`).
2. Copy the **System Prompt** section into your Claude conversation as the system prompt (or as the first user message prefixed with `[SYSTEM]`).
3. Paste the source code you want to audit as the next user message.
4. Claude will return a structured **Security Compliance Report** listing every violation, its severity, and its remediation.

### Example

```
[System Prompt from python_skill.md]

---

[User]
Please audit the following Python code for security compliance:

```python
import hashlib
import os

password = "supersecret123"
hash = hashlib.md5(password.encode()).hexdigest()
os.system(f"echo {hash}")
```
```

Claude will respond with a report identifying PY-006 (MD5 usage), PY-013 (hardcoded password), and PY-003 (os.system usage).

---

## Severity Levels

| Severity | Description |
|---|---|
| **Critical** | Must be remediated before code can be merged. Indicates exploitable vulnerability (RCE, injection, broken crypto). |
| **High** | Should be remediated before merge. Indicates significant risk (weak crypto, secrets exposure, insecure TLS). |
| **Medium** | Should be remediated in the current sprint. Indicates code quality or defence-in-depth concern. |
| **Low** | Address in backlog. Best-practice improvement with minor security impact. |
