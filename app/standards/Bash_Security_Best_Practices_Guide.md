# Bash Scripting Security Best Practices Guide

**Version:** 1.0  
**Date:** March 2026  
**Author:** Matrix Agent

---

## Executive Summary

This comprehensive guide provides security best practices for Bash scripting, aligned with major security frameworks including NIST SP 800-53, OWASP, DISA STIG, CIS Benchmarks, and FIPS 140-3. The document covers defensive programming techniques, input validation, command injection prevention, privilege management, and cryptographic compliance for shell scripts in enterprise and government environments.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Defensive Bash Programming Fundamentals](#2-defensive-bash-programming-fundamentals)
3. [Input Validation and Sanitization](#3-input-validation-and-sanitization)
4. [Command Injection Prevention](#4-command-injection-prevention)
5. [Secure Variable Handling and Quoting](#5-secure-variable-handling-and-quoting)
6. [File Operation Security](#6-file-operation-security)
7. [Privilege Management](#7-privilege-management)
8. [Secure Temporary File Handling](#8-secure-temporary-file-handling)
9. [Static Analysis with ShellCheck](#9-static-analysis-with-shellcheck)
10. [Security Standards Cross-Reference](#10-security-standards-cross-reference)
11. [Compliance Checklists](#11-compliance-checklists)
12. [References](#12-references)

---

## 1. Introduction

### 1.1 Purpose

Bash scripting remains a fundamental tool for system administration, automation, and DevOps workflows. However, shell scripts present unique security challenges due to their direct interaction with the operating system and their interpretive nature. This guide establishes security requirements and best practices for writing secure Bash scripts.

### 1.2 Scope

This guide applies to:
- Bash 4.x and 5.x scripts
- System administration scripts
- CI/CD pipeline automation
- Security tooling and compliance scripts
- Any shell script handling sensitive data or privileged operations

### 1.3 Bash 5.x Security-Relevant Features

Bash 5.x (released 2019, current stable 5.2+) introduces several features relevant to secure scripting:

| Feature | Version | Security Benefit |
|---------|---------|------------------|
| `BASH_ARGV0` | 5.0+ | Control `$0` for security logging |
| `EPOCHSECONDS` / `EPOCHREALTIME` | 5.0+ | Precise timestamps for audit logs |
| `SRANDOM` | 5.1+ | Cryptographically secure random numbers |
| `wait -p` | 5.1+ | Better subprocess tracking |
| `local -` | 5.0+ | Local scope for shell options |
| Improved `nameref` | 5.0+ | Safer variable references |

---

## 2. Defensive Bash Programming Fundamentals

### 2.1 The Defensive Header

Every secure Bash script MUST begin with a defensive header:

```bash
#!/usr/bin/env bash
#
# Script: secure_example.sh
# Purpose: [Description]
# Author: [Name]
# Date: [Date]
# Security Classification: [Level]

# Defensive programming options
set -euo pipefail
IFS=$'\n\t'

# Bash version check
if ((BASH_VERSINFO[0] < 4)); then
    echo "ERROR: Bash 4.0+ required" >&2
    exit 1
fi
```

### 2.2 Understanding `set -euo pipefail`

| Option | Flag | Behavior | Security Benefit |
|--------|------|----------|------------------|
| `errexit` | `-e` | Exit immediately on command failure | Prevents silent failures |
| `nounset` | `-u` | Treat unset variables as errors | Catches typos, prevents injection via unset vars |
| `pipefail` | `-o pipefail` | Pipeline fails if any command fails | Catches errors in piped commands |

### 2.3 Additional Defensive Options

```bash
# Extended defensive options
set -euo pipefail

# Prevent file clobbering
set -o noclobber

# Enable extended globbing for better pattern matching
shopt -s extglob

# Fail on glob expansion failures
shopt -s failglob

# Expand aliases (disabled in non-interactive by default)
shopt -s expand_aliases

# Inherit ERR trap in functions and subshells
set -o errtrace

# Inherit DEBUG and RETURN traps
set -o functrace
```

### 2.4 Error Handling Patterns

```bash
#!/usr/bin/env bash
set -euo pipefail

# Global error handler
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR

error_handler() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command=$4
    local func_trace=$5
    
    echo "ERROR: Command '${last_command}' failed" >&2
    echo "  Exit code: ${exit_code}" >&2
    echo "  Line: ${line_no}" >&2
    echo "  Function trace: ${func_trace}" >&2
    
    # Security: Log to syslog for audit
    logger -p user.err -t "${0##*/}" \
        "Script error: exit=${exit_code} line=${line_no} cmd='${last_command}'"
    
    exit "${exit_code}"
}

# Cleanup handler
cleanup() {
    local exit_code=$?
    # Remove temporary files securely
    [[ -n "${TEMP_DIR:-}" ]] && rm -rf "${TEMP_DIR}"
    exit "${exit_code}"
}
trap cleanup EXIT
```

---

## 3. Input Validation and Sanitization

### 3.1 Input Validation Principles

All external input MUST be validated before use:

1. **Define acceptable input** - Whitelist valid patterns
2. **Reject invalid input** - Fail closed, not open
3. **Sanitize before use** - Remove or escape dangerous characters
4. **Validate type and range** - Ensure correct data type and bounds

### 3.2 Input Validation Functions

```bash
#!/usr/bin/env bash
set -euo pipefail

# Validate alphanumeric input
validate_alphanum() {
    local input="$1"
    local max_length="${2:-255}"
    
    if [[ ! "$input" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "ERROR: Input contains invalid characters" >&2
        return 1
    fi
    
    if ((${#input} > max_length)); then
        echo "ERROR: Input exceeds maximum length of ${max_length}" >&2
        return 1
    fi
    
    return 0
}

# Validate integer input
validate_integer() {
    local input="$1"
    local min="${2:-}"
    local max="${3:-}"
    
    if [[ ! "$input" =~ ^-?[0-9]+$ ]]; then
        echo "ERROR: Input is not a valid integer" >&2
        return 1
    fi
    
    if [[ -n "$min" ]] && ((input < min)); then
        echo "ERROR: Input below minimum value of ${min}" >&2
        return 1
    fi
    
    if [[ -n "$max" ]] && ((input > max)); then
        echo "ERROR: Input exceeds maximum value of ${max}" >&2
        return 1
    fi
    
    return 0
}

# Validate file path (prevent path traversal)
validate_filepath() {
    local input="$1"
    local base_dir="$2"
    
    # Resolve to absolute path
    local resolved
    resolved="$(cd "${base_dir}" && realpath -m -- "${input}" 2>/dev/null)" || {
        echo "ERROR: Invalid path" >&2
        return 1
    }
    
    # Ensure path is within allowed directory
    if [[ "${resolved}" != "${base_dir}"/* ]]; then
        echo "ERROR: Path traversal attempt detected" >&2
        return 1
    fi
    
    printf '%s' "${resolved}"
}

# Validate IP address
validate_ipv4() {
    local ip="$1"
    local IFS='.'
    read -ra octets <<< "$ip"
    
    if [[ ${#octets[@]} -ne 4 ]]; then
        return 1
    fi
    
    for octet in "${octets[@]}"; do
        if [[ ! "$octet" =~ ^[0-9]+$ ]] || ((octet < 0 || octet > 255)); then
            return 1
        fi
    done
    
    return 0
}

# Validate hostname
validate_hostname() {
    local hostname="$1"
    
    # RFC 1123 compliant hostname validation
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo "ERROR: Invalid hostname format" >&2
        return 1
    fi
    
    if ((${#hostname} > 253)); then
        echo "ERROR: Hostname too long" >&2
        return 1
    fi
    
    return 0
}
```

### 3.3 Dangerous Metacharacters

The following characters MUST be handled carefully:

| Character | Risk | Mitigation |
|-----------|------|------------|
| `;` | Command separator | Quote or reject |
| `&` | Background/AND operator | Quote or reject |
| `\|` | Pipe operator | Quote or reject |
| `$` | Variable expansion | Quote or reject |
| `` ` `` | Command substitution | Quote or reject |
| `(` `)` | Subshell | Quote or reject |
| `>` `<` | Redirection | Quote or reject |
| `\n` | Newline injection | Reject or escape |
| `\0` | Null byte | Reject |
| `'` `"` | Quote manipulation | Escape properly |
| `\\` | Escape character | Double-escape |
| `!` | History expansion | Quote or disable |

---

## 4. Command Injection Prevention

### 4.1 OWASP Command Injection Defense

Per OWASP guidelines, command injection prevention follows a hierarchy:

**Defense Option 1: Avoid OS Commands (Preferred)**
```bash
# AVOID: Calling external commands with user input
# system("mkdir $user_dir")

# PREFER: Using built-in or safer alternatives
mkdir -p -- "${validated_dir}"
```

**Defense Option 2: Use Parameterized Commands**
```bash
# INSECURE: String concatenation
cmd="find /data -name ${user_input}"
eval "$cmd"  # NEVER DO THIS

# SECURE: Proper parameterization
find /data -name "${validated_input}" -print0 | \
    while IFS= read -r -d '' file; do
        process_file "${file}"
    done
```

**Defense Option 3: Input Validation with Allowlist**
```bash
# Allowlist validation pattern
validate_command_arg() {
    local arg="$1"
    # Only allow lowercase letters, numbers, 3-10 characters
    if [[ "$arg" =~ ^[a-z0-9]{3,10}$ ]]; then
        return 0
    fi
    return 1
}
```

### 4.2 Dangerous Patterns to Avoid

```bash
# NEVER USE THESE PATTERNS

# 1. eval with external input
eval "$user_input"                    # CRITICAL VULNERABILITY

# 2. Unquoted variable expansion
rm -rf $user_path                     # Path injection

# 3. Command substitution with user input
result=$(cat $user_file)              # File path injection

# 4. Here-string without quoting
cat <<< $user_data                    # Variable injection

# 5. printf with format string
printf "$user_format" "data"          # Format string vulnerability

# 6. Indirect variable references
eval "value=\${$user_varname}"        # Variable injection
```

### 4.3 Safe Command Execution Patterns

```bash
#!/usr/bin/env bash
set -euo pipefail

# Safe command execution wrapper
safe_exec() {
    local -a cmd=("$@")
    
    # Log command for audit
    logger -p user.info -t "${0##*/}" "Executing: ${cmd[*]}"
    
    # Execute with timeout
    timeout 300 "${cmd[@]}"
}

# Safe user input processing
process_user_file() {
    local user_input="$1"
    local safe_dir="/var/app/data"
    
    # Validate and resolve path
    local safe_path
    safe_path="$(validate_filepath "${user_input}" "${safe_dir}")" || {
        echo "ERROR: Invalid file path" >&2
        return 1
    }
    
    # Verify file exists and is readable
    if [[ ! -f "${safe_path}" ]] || [[ ! -r "${safe_path}" ]]; then
        echo "ERROR: File not accessible" >&2
        return 1
    fi
    
    # Process safely
    cat -- "${safe_path}"
}

# Use arrays for command construction
build_command() {
    local -a cmd=(find)
    local search_dir="$1"
    local pattern="$2"
    
    # Validate inputs first
    validate_filepath "${search_dir}" "/" >/dev/null || return 1
    validate_alphanum "${pattern}" 50 || return 1
    
    cmd+=("${search_dir}")
    cmd+=(-name "${pattern}")
    cmd+=(-type f)
    cmd+=(-print0)
    
    # Execute safely
    "${cmd[@]}"
}
```

### 4.4 The Double-Dash Convention

Always use `--` to separate options from arguments:

```bash
# Prevents argument injection via filenames starting with -
rm -- "${filename}"
cat -- "${filename}"
grep -- "${pattern}" "${file}"
find "${dir}" -name "${pattern}" -- 
```

---

## 5. Secure Variable Handling and Quoting

### 5.1 Quoting Rules

| Context | Recommended | Example |
|---------|-------------|---------|
| Variable assignment | Double quotes | `var="$input"` |
| Command arguments | Double quotes | `cmd "${arg}"` |
| Array elements | Double quotes | `arr=("${items[@]}")` |
| Literal strings | Single quotes | `pattern='[a-z]*'` |
| No expansion needed | Single quotes | `echo 'No $expansion'` |
| Command substitution | Double quotes | `result="$(cmd)"` |

### 5.2 Variable Expansion Security

```bash
#!/usr/bin/env bash
set -euo pipefail

# SECURE: Always quote variable expansions
filename="${1:-default.txt}"
echo "Processing: ${filename}"

# SECURE: Use parameter expansion defaults
config_file="${CONFIG_FILE:-/etc/app/default.conf}"

# SECURE: Array expansion with quotes
files=("${@}")
for file in "${files[@]}"; do
    process "${file}"
done

# SECURE: Substring extraction
username="${full_name:0:32}"  # Limit length

# SECURE: Pattern removal
clean_input="${raw_input//[^a-zA-Z0-9_-]/}"  # Remove dangerous chars
```

### 5.3 Preventing Variable Injection

```bash
#!/usr/bin/env bash
set -euo pipefail

# INSECURE: Dynamic variable names
# eval "${varname}=\${value}"  # DO NOT USE

# SECURE: Use associative arrays instead
declare -A config
config["user_setting"]="${user_value}"
echo "${config[user_setting]}"

# SECURE: If nameref required, validate name first
set_variable() {
    local varname="$1"
    local value="$2"
    
    # Strict validation of variable name
    if [[ ! "${varname}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
        echo "ERROR: Invalid variable name" >&2
        return 1
    fi
    
    # Use nameref (Bash 4.3+)
    local -n ref="${varname}"
    ref="${value}"
}
```

### 5.4 Environment Variable Security

```bash
#!/usr/bin/env bash
set -euo pipefail

# Clear dangerous environment variables
unset IFS
unset CDPATH
unset GLOBIGNORE
unset BASH_ENV

# Set secure PATH
export PATH="/usr/local/bin:/usr/bin:/bin"

# Validate required environment variables
required_vars=(HOME USER LOGNAME)
for var in "${required_vars[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo "ERROR: Required environment variable ${var} not set" >&2
        exit 1
    fi
done

# Sanitize LD_* variables
unset LD_LIBRARY_PATH
unset LD_PRELOAD
unset LD_AUDIT
```

---

## 6. File Operation Security

### 6.1 Path Traversal Prevention

```bash
#!/usr/bin/env bash
set -euo pipefail

# Secure file reading function
secure_read_file() {
    local base_dir="$1"
    local relative_path="$2"
    
    # Resolve to absolute path
    local abs_base abs_target
    abs_base="$(realpath -e "${base_dir}")" || {
        echo "ERROR: Base directory does not exist" >&2
        return 1
    }
    
    # Combine and resolve
    abs_target="$(realpath -m "${abs_base}/${relative_path}")" || {
        echo "ERROR: Invalid target path" >&2
        return 1
    }
    
    # Verify target is within base directory
    case "${abs_target}" in
        "${abs_base}"/*)
            ;;
        "${abs_base}")
            ;;
        *)
            echo "ERROR: Path traversal detected" >&2
            return 1
            ;;
    esac
    
    # Verify file exists and is a regular file
    if [[ ! -f "${abs_target}" ]]; then
        echo "ERROR: Target is not a regular file" >&2
        return 1
    fi
    
    cat -- "${abs_target}"
}
```

### 6.2 Secure File Permissions

```bash
#!/usr/bin/env bash
set -euo pipefail

# Set restrictive umask
umask 077

# Create file with specific permissions
create_secure_file() {
    local filepath="$1"
    local content="$2"
    local mode="${3:-0600}"
    
    # Create parent directory securely
    local dir
    dir="$(dirname "${filepath}")"
    install -d -m 0700 "${dir}"
    
    # Write content atomically
    local tmpfile
    tmpfile="$(mktemp "${filepath}.XXXXXX")"
    
    # Set permissions before writing content
    chmod "${mode}" "${tmpfile}"
    
    # Write content
    printf '%s' "${content}" > "${tmpfile}"
    
    # Move atomically
    mv -f "${tmpfile}" "${filepath}"
}

# Verify file ownership
verify_file_security() {
    local filepath="$1"
    local expected_owner="${2:-$(id -u)}"
    local max_permissions="${3:-0644}"
    
    local stat_info
    stat_info="$(stat -c '%u:%a' "${filepath}")"
    local file_owner="${stat_info%%:*}"
    local file_perms="${stat_info##*:}"
    
    if [[ "${file_owner}" != "${expected_owner}" ]]; then
        echo "ERROR: File owner mismatch" >&2
        return 1
    fi
    
    if ((8#${file_perms} > 8#${max_permissions})); then
        echo "ERROR: File permissions too permissive" >&2
        return 1
    fi
    
    return 0
}
```

### 6.3 Symlink Attack Prevention

```bash
#!/usr/bin/env bash
set -euo pipefail

# Safe file write that prevents symlink attacks
safe_write_file() {
    local filepath="$1"
    local content="$2"
    
    # Check if path exists
    if [[ -e "${filepath}" ]] || [[ -L "${filepath}" ]]; then
        # If symlink, refuse to write
        if [[ -L "${filepath}" ]]; then
            echo "ERROR: Refusing to write to symlink" >&2
            return 1
        fi
        
        # If not owned by us, refuse
        if [[ ! -O "${filepath}" ]]; then
            echo "ERROR: File not owned by current user" >&2
            return 1
        fi
    fi
    
    # Use O_NOFOLLOW equivalent behavior
    local dir
    dir="$(dirname "${filepath}")"
    local base
    base="$(basename "${filepath}")"
    
    # Create temp file in same directory
    local tmpfile
    tmpfile="$(mktemp "${dir}/.${base}.XXXXXX")"
    chmod 0600 "${tmpfile}"
    
    printf '%s' "${content}" > "${tmpfile}"
    
    # Rename (atomic on same filesystem)
    mv -f "${tmpfile}" "${filepath}"
}
```

---

## 7. Privilege Management

### 7.1 Principle of Least Privilege

```bash
#!/usr/bin/env bash
set -euo pipefail

# Check if running as root and drop privileges if possible
check_privileges() {
    if [[ "${EUID}" -eq 0 ]]; then
        echo "WARNING: Running as root" >&2
        
        # If possible, drop to unprivileged user
        if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER}" != "root" ]]; then
            exec sudo -u "${SUDO_USER}" "$0" "$@"
        fi
    fi
}

# Run command as specific user
run_as_user() {
    local target_user="$1"
    shift
    
    if [[ "${EUID}" -eq 0 ]]; then
        sudo -u "${target_user}" -- "$@"
    elif [[ "$(whoami)" == "${target_user}" ]]; then
        "$@"
    else
        echo "ERROR: Cannot run as ${target_user}" >&2
        return 1
    fi
}
```

### 7.2 Sudo Best Practices

```bash
#!/usr/bin/env bash
set -euo pipefail

# Define allowed sudo commands
declare -A ALLOWED_SUDO_COMMANDS=(
    ["systemctl"]="/usr/bin/systemctl"
    ["mount"]="/usr/bin/mount"
)

# Wrapper for safe sudo execution
safe_sudo() {
    local cmd_name="$1"
    shift
    
    if [[ -z "${ALLOWED_SUDO_COMMANDS[$cmd_name]:-}" ]]; then
        echo "ERROR: Command '${cmd_name}' not in allowed list" >&2
        return 1
    fi
    
    local full_path="${ALLOWED_SUDO_COMMANDS[$cmd_name]}"
    
    # Verify binary integrity (optional but recommended)
    # Example: check against known hash
    
    # Execute with full path
    sudo -- "${full_path}" "$@"
}

# Sudoers configuration recommendations
# Add to /etc/sudoers.d/app_script:
# app_user ALL=(root) NOPASSWD: /usr/bin/systemctl restart app.service
# Defaults:app_user !requiretty
# Defaults:app_user env_reset
# Defaults:app_user secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

### 7.3 Capability-Based Security

```bash
#!/usr/bin/env bash
set -euo pipefail

# Check for specific capabilities instead of root
check_capabilities() {
    local required_cap="$1"
    
    if ! capsh --has-p="${required_cap}" 2>/dev/null; then
        echo "ERROR: Missing capability: ${required_cap}" >&2
        echo "Grant with: setcap ${required_cap}=ep ${0}" >&2
        return 1
    fi
}

# Example: Check for network binding capability
# check_capabilities "cap_net_bind_service"
```

---

## 8. Secure Temporary File Handling

### 8.1 Creating Secure Temporary Files

```bash
#!/usr/bin/env bash
set -euo pipefail

# Set up secure temporary directory
setup_temp_dir() {
    # Create temp directory with restrictive permissions
    TEMP_DIR="$(mktemp -d -t "$(basename "$0").XXXXXXXXXX")" || {
        echo "ERROR: Failed to create temp directory" >&2
        exit 1
    }
    
    # Verify permissions
    chmod 0700 "${TEMP_DIR}"
    
    # Verify ownership
    if [[ ! -O "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
        echo "ERROR: Temp directory ownership mismatch" >&2
        exit 1
    fi
    
    # Set up cleanup trap
    trap 'cleanup_temp' EXIT INT TERM
    
    export TEMP_DIR
}

cleanup_temp() {
    if [[ -n "${TEMP_DIR:-}" ]] && [[ -d "${TEMP_DIR}" ]]; then
        # Secure deletion
        find "${TEMP_DIR}" -type f -exec shred -u {} \; 2>/dev/null || true
        rm -rf "${TEMP_DIR}"
    fi
}

# Create secure temp file
create_temp_file() {
    local prefix="${1:-temp}"
    local suffix="${2:-}"
    
    if [[ -z "${TEMP_DIR:-}" ]]; then
        setup_temp_dir
    fi
    
    local tmpfile
    tmpfile="$(mktemp "${TEMP_DIR}/${prefix}.XXXXXXXXXX${suffix}")"
    chmod 0600 "${tmpfile}"
    
    printf '%s' "${tmpfile}"
}
```

### 8.2 Avoiding Race Conditions

```bash
#!/usr/bin/env bash
set -euo pipefail

# INSECURE: Check-then-act race condition
# if [[ ! -f "${tmpfile}" ]]; then
#     echo "data" > "${tmpfile}"  # Race condition!
# fi

# SECURE: Atomic file creation
atomic_write() {
    local target="$1"
    local content="$2"
    
    local dir
    dir="$(dirname "${target}")"
    
    # Create temp file in same directory (same filesystem)
    local tmpfile
    tmpfile="$(mktemp "${dir}/.tmp.XXXXXXXXXX")"
    
    # Set permissions before writing
    chmod 0600 "${tmpfile}"
    
    # Write content
    printf '%s' "${content}" > "${tmpfile}"
    
    # Atomic rename
    mv -f "${tmpfile}" "${target}"
}

# SECURE: Use lock files properly
acquire_lock() {
    local lockfile="$1"
    local timeout="${2:-30}"
    
    local fd=200
    eval "exec ${fd}>${lockfile}"
    
    if ! flock -w "${timeout}" "${fd}"; then
        echo "ERROR: Could not acquire lock" >&2
        return 1
    fi
    
    # Lock acquired
    return 0
}

release_lock() {
    local fd=200
    flock -u "${fd}" 2>/dev/null || true
}
```

---

## 9. Static Analysis with ShellCheck

### 9.1 ShellCheck Integration

ShellCheck is a static analysis tool that identifies bugs and security issues in shell scripts.

**Installation:**
```bash
# Debian/Ubuntu
apt-get install shellcheck

# RHEL/CentOS
yum install ShellCheck

# macOS
brew install shellcheck
```

**Basic Usage:**
```bash
# Check a script
shellcheck myscript.sh

# Check with specific shell
shellcheck --shell=bash myscript.sh

# Output in different formats
shellcheck -f json myscript.sh    # JSON for CI/CD
shellcheck -f gcc myscript.sh     # GCC-style for editors
```

### 9.2 Important ShellCheck Warnings

| Code | Severity | Issue | Example Fix |
|------|----------|-------|-------------|
| SC2086 | Warning | Unquoted variable | `"${var}"` |
| SC2046 | Warning | Unquoted command sub | `"$(cmd)"` |
| SC2006 | Style | Legacy backticks | `$(cmd)` |
| SC2091 | Warning | Quotes in command | Use arrays |
| SC2068 | Warning | Unquoted array | `"${arr[@]}"` |
| SC2145 | Warning | Wrong array expansion | `"${arr[*]}"` |
| SC2034 | Warning | Unused variable | Remove or use |
| SC2155 | Warning | Declare+assign | Separate lines |
| SC2164 | Warning | cd without error check | `cd x \|\| exit` |
| SC2129 | Style | Repeated redirects | Use block |

### 9.3 CI/CD Integration

```yaml
# GitHub Actions example
name: Shell Script Security Check

on: [push, pull_request]

jobs:
  shellcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run ShellCheck
        uses: ludeeus/action-shellcheck@master
        with:
          severity: warning
          check_together: 'yes'
          scandir: './scripts'
          
      - name: Security-focused ShellCheck
        run: |
          find . -name '*.sh' -type f | while read -r script; do
            echo "Checking: ${script}"
            shellcheck -S warning -f gcc "${script}" || exit 1
          done
```

### 9.4 ShellCheck Directive Usage

```bash
#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC2034  # Intentionally unused variable

set -euo pipefail

# Disable specific check for one line
# shellcheck disable=SC2086
echo $intentionally_unquoted_var

# Source directive for external files
# shellcheck source=./lib/functions.sh
source "${LIB_DIR}/functions.sh"

# External sources
# shellcheck source=/dev/null
source "${DYNAMIC_CONFIG_FILE}"
```

---

## 10. Security Standards Cross-Reference

### 10.1 NIST SP 800-53 Rev 5 Controls

| Control ID | Control Name | Bash Script Requirement |
|------------|--------------|-------------------------|
| AC-3 | Access Enforcement | Validate user permissions before operations |
| AC-6 | Least Privilege | Run with minimal required permissions |
| AU-2 | Event Logging | Log security-relevant events |
| AU-12 | Audit Generation | Generate audit records for commands |
| CM-7 | Least Functionality | Remove unnecessary commands/functions |
| IA-5 | Authenticator Management | Never hardcode credentials |
| SC-4 | Information in Shared Resources | Clear sensitive data after use |
| SC-13 | Cryptographic Protection | Use FIPS-validated crypto modules |
| SC-28 | Protection of Information at Rest | Encrypt sensitive stored data |
| SI-3 | Malicious Code Protection | Validate all inputs |
| SI-10 | Information Input Validation | Sanitize and validate all inputs |
| SI-16 | Memory Protection | Clear variables containing secrets |

### 10.2 OWASP Top 10 Mapping

| OWASP Category | Shell Script Risk | Mitigation |
|----------------|-------------------|------------|
| A03:2021 Injection | Command Injection | Input validation, avoid eval |
| A01:2021 Broken Access Control | Privilege escalation | Least privilege, proper sudo |
| A02:2021 Cryptographic Failures | Weak crypto, hardcoded secrets | FIPS crypto, secure secret management |
| A04:2021 Insecure Design | Race conditions | Atomic operations, proper locking |
| A05:2021 Security Misconfiguration | Permissive settings | Restrictive umask, secure PATH |
| A07:2021 Identification and Authentication Failures | Credential exposure | Secure credential handling |
| A09:2021 Security Logging and Monitoring Failures | Missing audit trail | Comprehensive logging |

### 10.3 DISA STIG Requirements

| STIG ID | Requirement | Implementation |
|---------|-------------|----------------|
| RHEL-08-010380 | Protect audit tools | Restrict access to audit scripts |
| RHEL-08-010382 | Audit tool ownership | Set proper ownership on scripts |
| RHEL-08-020010 | Account lockout | Implement in auth scripts |
| RHEL-08-040160 | Disable core dumps | `ulimit -c 0` in scripts |
| RHEL-08-010121 | Encryption for transmission | Use TLS/SSH for network operations |
| RHEL-08-010672 | File permissions | Restrictive permissions on scripts |
| RHEL-08-030010 | Audit logging | Log all privileged operations |

### 10.4 CIS Benchmark Level 2 Controls

| CIS Control | Requirement | Script Implementation |
|-------------|-------------|----------------------|
| 1.1.1 | Disable unused filesystems | N/A (system config) |
| 5.1.1 | Ensure cron daemon enabled | Verify cron for scheduled scripts |
| 5.1.8 | Ensure cron is restricted | Restrict script scheduling |
| 5.2.1 | Ensure permissions on sshd_config | Verify before modifying |
| 5.4.1 | Ensure password hashing algorithm | Use appropriate algorithm |
| 6.1.1 | Audit system file permissions | Verify file permissions in scripts |
| 6.2.1 | Ensure password fields not empty | Validate in auth scripts |

### 10.5 FIPS 140-3 Compliance for Shell Scripts

**Approved Cryptographic Algorithms:**

| Category | Approved Algorithms | Deprecated/Prohibited |
|----------|--------------------|-----------------------|
| Hash | SHA-256, SHA-384, SHA-512, SHA3-* | MD5, SHA-1 (signing) |
| Symmetric | AES-128, AES-192, AES-256 | DES, 3DES, RC4, Blowfish |
| Asymmetric | RSA-2048+, ECDSA P-256+ | RSA-1024, DSA |
| Key Exchange | DH-2048+, ECDH P-256+ | DH-1024 |
| RNG | DRBG (SP 800-90A) | Non-approved RNGs |

**FIPS Compliance in Scripts:**

```bash
#!/usr/bin/env bash
set -euo pipefail

# Check FIPS mode
check_fips_mode() {
    local fips_enabled
    fips_enabled="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)"
    
    if [[ "${fips_enabled}" != "1" ]]; then
        echo "WARNING: FIPS mode not enabled" >&2
        return 1
    fi
    
    # Verify OpenSSL FIPS
    if ! openssl version | grep -qi "fips"; then
        echo "WARNING: OpenSSL not in FIPS mode" >&2
        return 1
    fi
    
    return 0
}

# FIPS-compliant hash
fips_hash() {
    local file="$1"
    sha256sum "${file}" | cut -d' ' -f1
}

# FIPS-compliant encryption
fips_encrypt() {
    local input_file="$1"
    local output_file="$2"
    local key_file="$3"
    
    openssl enc -aes-256-cbc -pbkdf2 -iter 100000 \
        -in "${input_file}" \
        -out "${output_file}" \
        -pass "file:${key_file}"
}

# FIPS-compliant random
fips_random() {
    local bytes="${1:-32}"
    openssl rand "${bytes}" | base64
}
```

---

## 11. Compliance Checklists

### 11.1 Pre-Deployment Security Checklist

```markdown
## Script Security Checklist

### Defensive Programming
- [ ] Script begins with `#!/usr/bin/env bash`
- [ ] `set -euo pipefail` is enabled
- [ ] IFS is set to safe value or unset
- [ ] Error handler trap is configured
- [ ] Cleanup trap is configured (EXIT, INT, TERM)
- [ ] Bash version check implemented

### Input Validation
- [ ] All external inputs validated
- [ ] Path traversal prevention implemented
- [ ] Integer bounds checking implemented
- [ ] Dangerous metacharacters handled
- [ ] Input length limits enforced

### Command Execution
- [ ] No use of `eval` with external input
- [ ] All variables properly quoted
- [ ] Double-dash (`--`) used to separate arguments
- [ ] Arrays used for command construction
- [ ] No shell expansion of user input

### File Operations
- [ ] Restrictive umask set (077)
- [ ] File permissions verified before operations
- [ ] Symlink attacks prevented
- [ ] Atomic file writes implemented
- [ ] Race conditions addressed

### Privilege Management
- [ ] Script runs with minimal privileges
- [ ] Root access avoided where possible
- [ ] Sudo usage minimized and validated
- [ ] Credentials never hardcoded
- [ ] Environment sanitized

### Temporary Files
- [ ] mktemp used for temp files
- [ ] Temp directory has 0700 permissions
- [ ] Cleanup handler implemented
- [ ] Sensitive data shredded on cleanup

### Cryptography (if applicable)
- [ ] FIPS mode verified
- [ ] Only approved algorithms used
- [ ] No deprecated crypto (MD5, SHA-1, DES)
- [ ] Secure random generation used

### Static Analysis
- [ ] ShellCheck passes with no warnings
- [ ] No SC2086 (unquoted variables)
- [ ] No SC2046 (unquoted command substitution)
- [ ] No SC2091 (unexpected quoting)

### Logging and Auditing
- [ ] Security events logged
- [ ] Timestamps included in logs
- [ ] Sensitive data not logged
- [ ] Log file permissions are restrictive
```

### 11.2 Code Review Security Checklist

```markdown
## Code Review Security Checklist

### Critical Items (Must Fix)
- [ ] No command injection vulnerabilities
- [ ] No hardcoded credentials or secrets
- [ ] No insecure temporary file handling
- [ ] No race conditions in file operations
- [ ] No unvalidated external input in commands

### High Priority Items
- [ ] All variables properly quoted
- [ ] Error handling complete
- [ ] Privilege escalation justified
- [ ] Input validation comprehensive
- [ ] Logging adequate for audit

### Medium Priority Items
- [ ] ShellCheck warnings addressed
- [ ] Code follows style guidelines
- [ ] Documentation adequate
- [ ] Dependencies documented
- [ ] Rollback procedure exists

### Low Priority Items
- [ ] Comments explain complex logic
- [ ] Variable names descriptive
- [ ] Functions modular and focused
- [ ] Code DRY (Don't Repeat Yourself)
```

### 11.3 NIST Compliance Matrix

| NIST Control | Implementation Status | Evidence |
|--------------|----------------------|----------|
| AC-3 | [ ] Implemented | |
| AC-6 | [ ] Implemented | |
| AU-2 | [ ] Implemented | |
| AU-12 | [ ] Implemented | |
| CM-7 | [ ] Implemented | |
| IA-5 | [ ] Implemented | |
| SC-4 | [ ] Implemented | |
| SC-13 | [ ] Implemented | |
| SC-28 | [ ] Implemented | |
| SI-3 | [ ] Implemented | |
| SI-10 | [ ] Implemented | |
| SI-16 | [ ] Implemented | |

---

## 12. References

### 12.1 Standards and Frameworks

1. [NIST SP 800-53 Rev. 5 - Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) - NIST - Authoritative source for security controls

2. [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) - OWASP Foundation - Command injection prevention guidance

3. [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection) - OWASP Foundation - Command injection attack description

4. [DISA STIG Red Hat Enterprise Linux](https://www.stigviewer.com/stigs/red_hat_enterprise_linux_8/2025-05-14/MAC-2_Public) - DISA - Security Technical Implementation Guide

5. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Center for Internet Security - System hardening guidelines

6. [FIPS 140-3 Security Requirements](https://www.ssh.com/academy/fips-minimum-security-requirements-for-crypotgraphic-module) - SSH.com - FIPS cryptographic requirements overview

### 12.2 Bash Documentation and Tools

7. [GNU Bash Reference Manual](https://www.gnu.org/s/bash/manual/bash.html) - GNU Project - Authoritative Bash documentation

8. [ShellCheck - Static Analysis Tool](https://www.shellcheck.net/) - ShellCheck Project - Shell script analysis tool

9. [ShellCheck GitHub Repository](https://github.com/koalaman/shellcheck) - GitHub - ShellCheck source and documentation

10. [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html) - MITRE - Common Weakness Enumeration entry

### 12.3 Best Practices Guides

11. [Writing Robust Shell Scripts](https://www.davidpashley.com/articles/writing-robust-shell-scripts/) - David Pashley - Defensive scripting techniques

12. [Bash Scripting Quirks and Safety Tips](https://jvns.ca/blog/2017/03/26/bash-quirks/) - Julia Evans - Practical safety guidance

13. [RHEL 9 Security Hardening Guide - FIPS Mode](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/switching-rhel-to-fips-mode_security-hardening) - Red Hat - FIPS configuration guide

14. [FIPS 140-3 Shell Script Compliance](https://hoop.dev/blog/writing-fips-140-3-compliant-shell-scripts/) - Hoop.dev - FIPS compliance for shell scripts

### 12.4 Additional Resources

15. [RHEL 8 STIG Configuration Guide](https://static.open-scap.org/ssg-guides/ssg-rhel8-guide-stig.html) - OpenSCAP - Comprehensive STIG implementation

16. [CIS Red Hat Enterprise Linux Benchmarks](https://www.cisecurity.org/benchmark/red_hat_linux) - CIS - CIS benchmark for RHEL

17. [PortSwigger OS Command Injection](https://portswigger.net/web-security/os-command-injection) - PortSwigger - Web security testing guide

---

## Appendix A: Complete Secure Script Template

```bash
#!/usr/bin/env bash
#===============================================================================
# Script Name: secure_template.sh
# Description: Template for secure Bash scripting
# Author: [Author Name]
# Date: [Date]
# Version: 1.0
# Security Level: [Classification]
#===============================================================================

#-------------------------------------------------------------------------------
# DEFENSIVE SETTINGS
#-------------------------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

# Bash version requirement
if ((BASH_VERSINFO[0] < 4)); then
    echo "ERROR: Bash 4.0+ required" >&2
    exit 1
fi

#-------------------------------------------------------------------------------
# CONSTANTS
#-------------------------------------------------------------------------------
readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_VERSION="1.0"

# Security constants
readonly MAX_INPUT_LENGTH=1024
readonly ALLOWED_PATH="/var/app/data"

#-------------------------------------------------------------------------------
# ENVIRONMENT SANITIZATION
#-------------------------------------------------------------------------------
unset IFS CDPATH GLOBIGNORE BASH_ENV
unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT
export PATH="/usr/local/bin:/usr/bin:/bin"
umask 077

#-------------------------------------------------------------------------------
# GLOBAL VARIABLES
#-------------------------------------------------------------------------------
TEMP_DIR=""
LOG_FILE="/var/log/${SCRIPT_NAME}.log"
VERBOSE="${VERBOSE:-false}"

#-------------------------------------------------------------------------------
# LOGGING
#-------------------------------------------------------------------------------
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%dT%H:%M:%S%z')"
    
    printf '%s [%s] %s: %s\n' \
        "${timestamp}" "${level}" "${SCRIPT_NAME}" "${message}" \
        | tee -a "${LOG_FILE}" >&2
    
    # Also log to syslog
    logger -p "user.${level,,}" -t "${SCRIPT_NAME}" "${message}"
}

log_info()  { log "INFO" "$@"; }
log_warn()  { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

#-------------------------------------------------------------------------------
# ERROR HANDLING
#-------------------------------------------------------------------------------
error_handler() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command=$4
    local func_trace=$5
    
    log_error "Command '${last_command}' failed with exit code ${exit_code}"
    log_error "  Line: ${line_no}"
    log_error "  Function trace: ${func_trace}"
    
    exit "${exit_code}"
}

trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR

#-------------------------------------------------------------------------------
# CLEANUP
#-------------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    
    log_info "Cleaning up..."
    
    # Remove temporary files
    if [[ -n "${TEMP_DIR:-}" ]] && [[ -d "${TEMP_DIR}" ]]; then
        find "${TEMP_DIR}" -type f -exec shred -u {} \; 2>/dev/null || true
        rm -rf "${TEMP_DIR}"
    fi
    
    log_info "Script completed with exit code ${exit_code}"
    
    exit "${exit_code}"
}

trap cleanup EXIT INT TERM

#-------------------------------------------------------------------------------
# INPUT VALIDATION
#-------------------------------------------------------------------------------
validate_input() {
    local input="$1"
    local pattern="$2"
    local max_len="${3:-${MAX_INPUT_LENGTH}}"
    
    if [[ -z "${input}" ]]; then
        log_error "Empty input provided"
        return 1
    fi
    
    if ((${#input} > max_len)); then
        log_error "Input exceeds maximum length of ${max_len}"
        return 1
    fi
    
    if [[ ! "${input}" =~ ${pattern} ]]; then
        log_error "Input does not match required pattern"
        return 1
    fi
    
    return 0
}

validate_filepath() {
    local input="$1"
    local base_dir="${2:-${ALLOWED_PATH}}"
    
    local resolved
    resolved="$(realpath -m "${base_dir}/${input}" 2>/dev/null)" || {
        log_error "Invalid path: ${input}"
        return 1
    }
    
    case "${resolved}" in
        "${base_dir}"/*)
            printf '%s' "${resolved}"
            return 0
            ;;
        *)
            log_error "Path traversal attempt detected"
            return 1
            ;;
    esac
}

#-------------------------------------------------------------------------------
# UTILITY FUNCTIONS
#-------------------------------------------------------------------------------
setup_temp_dir() {
    TEMP_DIR="$(mktemp -d -t "${SCRIPT_NAME}.XXXXXXXXXX")"
    chmod 0700 "${TEMP_DIR}"
    log_info "Created temporary directory: ${TEMP_DIR}"
}

require_non_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        log_error "This script should not be run as root"
        exit 1
    fi
}

#-------------------------------------------------------------------------------
# MAIN LOGIC
#-------------------------------------------------------------------------------
main() {
    log_info "Starting ${SCRIPT_NAME} v${SCRIPT_VERSION}"
    
    # Parse arguments
    local input_file=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--file)
                input_file="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE="true"
                shift
                ;;
            -h|--help)
                echo "Usage: ${SCRIPT_NAME} [-f FILE] [-v] [-h]"
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                exit 1
                ;;
        esac
    done
    
    # Validate required inputs
    if [[ -n "${input_file}" ]]; then
        validate_input "${input_file}" '^[a-zA-Z0-9._-]+$' 255 || exit 1
    fi
    
    # Setup
    require_non_root
    setup_temp_dir
    
    # Main logic here
    log_info "Processing..."
    
    log_info "Done"
}

#-------------------------------------------------------------------------------
# ENTRY POINT
#-------------------------------------------------------------------------------
main "$@"
```

---

## Appendix B: ShellCheck Configuration

**`.shellcheckrc` file:**
```ini
# ShellCheck configuration file

# Shell dialect
shell=bash

# Enable all checks
enable=all

# Disable specific checks with justification
# disable=SC2034  # Unused variables (if using as library)

# Source path for resolving sources
source-path=SCRIPTDIR

# External sources
external-sources=true

# Severity threshold (error, warning, info, style)
severity=style
```

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | March 2026 | Matrix Agent | Initial release |

---

*This document provides security guidance for Bash scripting. Organizations should adapt these recommendations to their specific security requirements and risk tolerance.*
