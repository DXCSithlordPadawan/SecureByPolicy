# Rust Security Best Practices Guide

**Version:** 1.0  
**Last Updated:** March 2026  
**Author:** Matrix Agent

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Introduction](#introduction)
3. [Rust 2024 Edition Security Features](#rust-2024-edition-security-features)
4. [Memory Safety and Unsafe Code](#memory-safety-and-unsafe-code)
5. [Error Handling Best Practices](#error-handling-best-practices)
6. [Secure Dependency Management](#secure-dependency-management)
7. [Cryptography in Rust](#cryptography-in-rust)
8. [WebAssembly Security Considerations](#webassembly-security-considerations)
9. [Security Standards Cross-Reference](#security-standards-cross-reference)
10. [Compliance Checklists](#compliance-checklists)
11. [References](#references)

---

## Executive Summary

Rust's design philosophy centers on memory safety without sacrificing performance, making it an ideal choice for security-critical systems programming. This guide provides comprehensive coverage of Rust security best practices, incorporating the latest Rust 2024 edition features and cross-referencing against major security standards including NIST SP 800-53, OWASP Top Ten, DISA STIG, CIS Benchmarks, and FIPS 140-3.

Key findings demonstrate that Rust adoption has resulted in significant security improvements, with Google reporting a **1000x reduction** in memory safety vulnerability density in Android's Rust code compared to C/C++ implementations. The Rust 2024 edition introduces enhanced safety requirements for unsafe operations, making security-conscious development the default behavior.

---

## Introduction

### Purpose

This guide serves as a comprehensive reference for developers, security engineers, and compliance officers implementing secure Rust applications. It bridges the gap between Rust's technical capabilities and enterprise security compliance requirements.

### Scope

This document covers:
- Rust 2024 edition security enhancements
- Memory safety patterns and unsafe code minimization
- Secure error handling strategies
- Dependency security with cargo audit
- Cryptographic implementation guidelines
- WebAssembly security considerations
- Mapping to NIST, OWASP, DISA STIG, CIS, and FIPS standards

### Audience

- Systems programmers developing security-critical applications
- Security architects evaluating language choices
- Compliance teams assessing Rust against security frameworks
- DevSecOps engineers implementing secure CI/CD pipelines

---

## Rust 2024 Edition Security Features

The Rust 2024 edition, released with Rust 1.85.0 on February 20, 2025, represents the most significant edition to date with substantial security enhancements.

### Unsafe Operations Improvements

| Feature | Description | Security Impact |
|---------|-------------|-----------------|
| **Unsafe `extern` blocks** | `extern` blocks now require the `unsafe` keyword | Explicit acknowledgment of FFI safety requirements |
| **Unsafe attributes** | `export_name`, `link_section`, `no_mangle` require `unsafe` | Prevents accidental exposure of unsafe linking |
| **`unsafe_op_in_unsafe_fn` warning** | Warns by default in unsafe functions | Forces explicit `unsafe {}` blocks within unsafe functions |
| **Static mut restrictions** | References to `static mut` generate deny-by-default errors | Eliminates one of Rust's most dangerous patterns |
| **Never type fallback** | `never_type_fallback_flowing_into_unsafe` is now deny | Prevents subtle type coercion bugs |

### Newly Unsafe Standard Library Functions

The following functions are now marked as `unsafe` in the 2024 edition:

```rust
// These now require unsafe blocks
unsafe {
    std::env::set_var("KEY", "value");     // Environment modification
    std::env::remove_var("KEY");           // Environment modification
}

// Unix-specific
#[cfg(unix)]
unsafe {
    use std::os::unix::process::CommandExt;
    command.before_exec(|| Ok(()));        // Pre-exec hooks
}
```

### Migration Example

```rust
// Rust 2021 (implicit unsafe in extern blocks)
extern "C" {
    fn external_function();
}

// Rust 2024 (explicit unsafe required)
unsafe extern "C" {
    fn external_function();
}

// Rust 2021 (implicit unsafe in unsafe fn body)
unsafe fn old_pattern() {
    dangerous_operation();  // Implicitly unsafe
}

// Rust 2024 (explicit unsafe blocks required)
unsafe fn new_pattern() {
    // SAFETY: Documented invariants
    unsafe {
        dangerous_operation();
    }
}
```

### Feature Summary Table

| Category | Rust 2021 | Rust 2024 | Security Benefit |
|----------|-----------|-----------|------------------|
| FFI declarations | Implicit unsafe | Explicit `unsafe extern` | Clear unsafe boundaries |
| Unsafe functions | Implicit body unsafe | Explicit blocks required | Precise unsafe scope |
| Static mutables | Allowed references | Denied by default | Eliminates data races |
| Link attributes | Safe attributes | Unsafe attributes | Prevents symbol hijacking |
| Environment vars | Safe functions | Unsafe functions | Thread safety awareness |

---

## Memory Safety and Unsafe Code

### Rust's Memory Safety Guarantees

Rust's ownership system provides compile-time guarantees that prevent:

| Vulnerability Class | Prevention Mechanism | Traditional Language Risk |
|--------------------|---------------------|---------------------------|
| Buffer overflows | Bounds checking, slices | Critical (CVE-heavy) |
| Use-after-free | Ownership/borrowing | Critical |
| Double-free | Single ownership | High |
| Null pointerdereference | Option<T> type | High |
| Data races | Send/Sync traits | High |
| Uninitialized memory | Constructor requirements | Medium |

### Minimizing Unsafe Code

#### Best Practices for Unsafe Blocks

```rust
// BAD: Large unsafe block with unclear scope
unsafe {
    let ptr = allocate_memory(1024);
    process_data(ptr);
    transform_data(ptr);
    validate_result(ptr);
    deallocate_memory(ptr);
}

// GOOD: Minimal unsafe scope with safety documentation
/// Allocates and processes data safely.
/// 
/// # Safety
/// - Memory is allocated before use
/// - Pointer is valid for the entire operation
/// - Memory is deallocated exactly once
fn safe_wrapper() -> Result<ProcessedData, Error> {
    // SAFETY: allocate_memory returns a valid, aligned pointer
    // for the requested size, or null on failure
    let ptr = unsafe { allocate_memory(1024) };
    
    if ptr.is_null() {
        return Err(Error::AllocationFailed);
    }
    
    // Safe processing using the pointer
    let result = process_safely(ptr)?;
    
    // SAFETY: ptr was allocated by allocate_memory and has not been freed
    unsafe { deallocate_memory(ptr) };
    
    Ok(result)
}
```

#### Safe Abstractions Over Unsafe Code

```rust
/// A safe wrapper around raw pointer operations
pub struct SafeBuffer {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

impl SafeBuffer {
    /// Creates a new buffer with the specified capacity.
    /// 
    /// # Panics
    /// Panics if allocation fails.
    pub fn with_capacity(cap: usize) -> Self {
        let layout = std::alloc::Layout::array::<u8>(cap).unwrap();
        // SAFETY: layout is valid and non-zero
        let ptr = unsafe { std::alloc::alloc(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Self { ptr, len: 0, cap }
    }
    
    /// Returns a slice view of the buffer contents.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for len bytes, properly aligned,
        // and not mutably borrowed elsewhere
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
    
    /// Writes data to the buffer.
    pub fn write(&mut self, data: &[u8]) -> Result<(), BufferError> {
        if self.len + data.len() > self.cap {
            return Err(BufferError::InsufficientCapacity);
        }
        // SAFETY: destination has sufficient capacity, no overlap
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.ptr.add(self.len),
                data.len()
            );
        }
        self.len += data.len();
        Ok(())
    }
}

impl Drop for SafeBuffer {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::array::<u8>(self.cap).unwrap();
        // SAFETY: ptr was allocated with this layout, being freed exactly once
        unsafe { std::alloc::dealloc(self.ptr, layout) };
    }
}

// The buffer is now safe to use without unsafe blocks
fn example_usage() {
    let mut buffer = SafeBuffer::with_capacity(1024);
    buffer.write(b"Hello, World!").unwrap();
    println!("Contents: {:?}", buffer.as_slice());
}
```

### Unsafe Code Audit Checklist

| Check | Description | Status |
|-------|-------------|--------|
| **Scope Minimization** | Unsafe blocks contain only unsafe operations | [ ] |
| **Safety Comments** | All unsafe blocks have `// SAFETY:` documentation | [ ] |
| **Invariant Documentation** | Function-level safety requirements documented | [ ] |
| **Pointer Validity** | All raw pointers verified valid before dereference | [ ] |
| **Bounds Checking** | Array/slice access verified within bounds | [ ] |
| **Alignment** | Memory access respects type alignment requirements | [ ] |
| **Aliasing Rules** | Mutable references don't alias | [ ] |
| **Lifetime Correctness** | References don't outlive their referents | [ ] |
| **Thread Safety** | Concurrent access properly synchronized | [ ] |
| **Resource Cleanup** | All allocated resources properly freed | [ ] |

---

## Error Handling Best Practices

### Result and Option Patterns

Rust's error handling via `Result<T, E>` and `Option<T>` provides type-safe error propagation without exceptions.

#### Secure Error Handling Patterns

```rust
use std::fs::File;
use std::io::{self, Read, BufReader};
use thiserror::Error;

/// Application-specific error types with security context
#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Authentication failed: invalid credentials")]
    AuthenticationFailed,
    
    #[error("Authorization denied: insufficient permissions for {resource}")]
    AuthorizationDenied { resource: String },
    
    #[error("Input validation failed: {reason}")]
    ValidationError { reason: String },
    
    #[error("Cryptographic operation failed")]
    CryptoError(#[from] CryptoError),
    
    #[error("I/O error occurred")]
    IoError(#[from] io::Error),
}

/// Secure file reading with proper error handling
pub fn read_sensitive_file(path: &str) -> Result<String, SecurityError> {
    // Validate path to prevent directory traversal
    if path.contains("..") || path.starts_with('/') {
        return Err(SecurityError::ValidationError {
            reason: "Invalid path: potential directory traversal".into(),
        });
    }
    
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut contents = String::new();
    reader.read_to_string(&mut contents)?;
    
    Ok(contents)
}

/// Secure credential validation
pub fn validate_credentials(
    username: &str,
    password: &str,
) -> Result<AuthToken, SecurityError> {
    // Input validation
    if username.is_empty() || password.len() < 12 {
        return Err(SecurityError::ValidationError {
            reason: "Invalid credential format".into(),
        });
    }
    
    // Constant-time comparison to prevent timing attacks
    let valid = constant_time_compare(
        password.as_bytes(),
        get_stored_hash(username)?.as_bytes(),
    );
    
    if valid {
        Ok(generate_token(username)?)
    } else {
        // Log attempt without revealing which part failed
        log::warn!("Authentication failed for user attempt");
        Err(SecurityError::AuthenticationFailed)
    }
}
```

#### Avoiding Common Anti-Patterns

```rust
// INSECURE: Using unwrap() exposes to denial-of-service
fn bad_parse(input: &str) -> i32 {
    input.parse().unwrap()  // Panics on invalid input!
}

// SECURE: Graceful error handling
fn good_parse(input: &str) -> Result<i32, ParseError> {
    input.parse().map_err(|_| ParseError::InvalidFormat)
}

// INSECURE: Exposing internal error details
fn bad_error_message(e: &DatabaseError) -> String {
    format!("Database error: {:?}", e)  // May leak schema info!
}

// SECURE: User-safe error messages
fn good_error_message(e: &DatabaseError) -> String {
    log::error!("Database error: {:?}", e);  // Log full details
    "An internal error occurred. Please try again.".to_string()
}

// INSECURE: Silent error swallowing
fn bad_optional(data: Option<&str>) -> &str {
    data.unwrap_or("")  // Silently returns empty string
}

// SECURE: Explicit handling of None
fn good_optional(data: Option<&str>) -> Result<&str, DataError> {
    data.ok_or(DataError::MissingRequired)
}
```

### Error Handling Security Matrix

| Pattern | Security Risk | Recommendation |
|---------|--------------|----------------|
| `.unwrap()` | Denial of Service via panic | Use `?` or explicit match |
| `.expect("msg")` | Information disclosure | Use in tests only |
| Error message formatting | Data leakage | Log details, return generic message |
| Silent `unwrap_or_default()` | Logic errors | Explicit error propagation |
| Panic in libraries | Caller instability | Return `Result` instead |

---

## Secure Dependency Management

### Cargo Audit Integration

The `cargo-audit` tool scans dependencies against the RustSec Advisory Database.

#### Installation and Usage

```bash
# Install cargo-audit
cargo install cargo-audit

# Basic vulnerability scan
cargo audit

# Generate JSON report for CI integration
cargo audit --json > audit-report.json

# Automatically fix vulnerable dependencies (when possible)
cargo audit fix

# Scan compiled binaries (requires cargo-auditable)
cargo install cargo-auditable
cargo auditable build --release
cargo audit bin target/release/myapp
```

#### CI/CD Integration

```yaml
# GitHub Actions workflow
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * *'  # Daily scan

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-action@stable
      
      - name: Install cargo-audit
        run: cargo install cargo-audit
      
      - name: Run security audit
        run: cargo audit --deny warnings
      
      - name: Upload audit report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: audit-report
          path: audit-report.json
```

### Dependency Vetting Best Practices

| Criterion | Check | Tool/Method |
|-----------|-------|-------------|
| **Known Vulnerabilities** | CVE/RustSec advisories | `cargo audit` |
| **Maintenance Status** | Recent updates, responsive maintainers | crates.io, GitHub |
| **Download Statistics** | Community adoption | crates.io |
| **Dependency Tree** | Transitive dependencies | `cargo tree` |
| **License Compliance** | Compatible licenses | `cargo-license` |
| **Code Quality** | Clippy warnings, test coverage | `cargo clippy`, CI badges |
| **Unsafe Usage** | Amount of unsafe code | `cargo geiger` |

#### Cargo Geiger for Unsafe Analysis

```bash
# Install cargo-geiger
cargo install cargo-geiger

# Analyze unsafe usage in dependencies
cargo geiger

# Output example:
# Functions  Coverage  Expressions  Crate
# 0/0        100%      0/0          my-app
# 2/10       80%       15/50        dependency-a
# 0/5        100%      0/30         dependency-b
```

### Cargo.toml Security Configuration

```toml
[package]
name = "secure-app"
version = "1.0.0"
edition = "2024"
rust-version = "1.85"  # Minimum supported version

[dependencies]
# Pin exact versions for reproducible builds
ring = "=0.17.7"
rustls = "=0.23.5"

# Specify features explicitly
serde = { version = "1.0", default-features = false, features = ["derive"] }

[profile.release]
# Enable overflow checks in release builds
overflow-checks = true

# Strip debug info for smaller binaries
strip = true

# LTO for better optimization (may catch more issues)
lto = "thin"

[profile.dev]
# Maximize debug assertions
debug-assertions = true
overflow-checks = true

[lints.rust]
# Deny unsafe code by default (explicit opt-in required)
unsafe_code = "deny"

[lints.clippy]
# Security-focused lints
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
```

---

## Cryptography in Rust

### Recommended Cryptographic Libraries

| Library | Use Case | FIPS Consideration | Maintenance |
|---------|----------|-------------------|-------------|
| **ring** | General crypto, TLS | Based on BoringSSL | Active |
| **RustCrypto** | Modular algorithms | Pure Rust, audited | Active |
| **rustls** | TLS implementation | Uses ring | Active |
| **aws-lc-rs** | AWS environments | FIPS-validated backend | Active |
| **boring** | BoringSSL bindings | FIPS-validated | Active |

### Secure Cryptographic Patterns

#### Hashing

```rust
use sha2::{Sha256, Sha384, Sha512, Digest};

/// Secure password hashing using Argon2
fn hash_password(password: &str, salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use argon2::{Argon2, Algorithm, Version, Params};
    
    // OWASP recommended parameters for Argon2id
    let params = Params::new(
        65536,  // 64 MiB memory
        3,      // 3 iterations
        4,      // 4 parallelism
        Some(32), // 32-byte output
    )?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let mut hash = vec![0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut hash)?;
    
    Ok(hash)
}

/// Generic data hashing for integrity verification
fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
```

#### Authenticated Encryption

```rust
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};

/// Encrypt data with AES-256-GCM
fn encrypt_data(
    key: &[u8; 32],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    
    // Generate random nonce - NEVER reuse with same key!
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        })
        .map_err(|_| CryptoError::EncryptionFailed)?;
    
    Ok((ciphertext, nonce_bytes))
}

/// Decrypt data with AES-256-GCM
fn decrypt_data(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: associated_data,
        })
        .map_err(|_| CryptoError::DecryptionFailed)
}
```

#### Secure Key Generation

```rust
use rand::rngs::OsRng;
use rand::RngCore;

/// Generate cryptographically secure random key
fn generate_key<const N: usize>() -> [u8; N] {
    let mut key = [0u8; N];
    OsRng.fill_bytes(&mut key);
    key
}

/// Secure key derivation using HKDF
fn derive_key(
    master_key: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut derived = [0u8; 32];
    hkdf.expand(info, &mut derived)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    Ok(derived)
}
```

### Cryptographic Anti-Patterns

```rust
// INSECURE: Hardcoded key
const ENCRYPTION_KEY: &[u8] = b"my-secret-key-123";

// INSECURE: Weak random source
use rand::thread_rng;  // Not cryptographically secure!

// INSECURE: ECB mode (reveals patterns)
// INSECURE: Unauthenticated encryption

// INSECURE: Custom crypto implementation
fn my_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().zip(key.iter().cycle())
        .map(|(d, k)| d ^ k)
        .collect()  // XOR cipher - trivially breakable!
}

// SECURE: Use established libraries
use aes_gcm::{Aes256Gcm, aead::Aead};
```

### FIPS 140-3 Compliance Considerations

| Requirement | Rust Implementation |
|-------------|-------------------|
| **Approved Algorithms** | AES, SHA-2, SHA-3, RSA, ECDSA, ECDH |
| **Key Sizes** | AES-128/192/256, RSA-2048+, P-256/384/521 |
| **Random Generation** | `OsRng` (system CSPRNG) |
| **Key Management** | Secure memory, zeroization |
| **Self-Tests** | Library-specific (ring, aws-lc-rs) |
| **Module Boundary** | FIPS-validated backend required |

```rust
// For FIPS compliance, use FIPS-validated backend
use aws_lc_rs as crypto_backend;  // FIPS 140-3 validated

// Zeroize sensitive data on drop
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretKey {
    key: [u8; 32],
}
```

---

## WebAssembly Security Considerations

### WASM Security Model

WebAssembly provides a sandboxed execution environment, but security considerations remain:

| Aspect | Security Characteristic | Mitigation |
|--------|------------------------|------------|
| **Memory Isolation** | Linear memory sandbox | Host controls memory limits |
| **Capability-Based** | No ambient authority | Explicit capability injection |
| **Deterministic** | Reproducible execution | Aids audit and verification |
| **Type-Safe** | Validated at load time | Prevents type confusion |

### Rust to WASM Security Best Practices

```rust
//! WASM module with security considerations
#![no_std]  // Minimal attack surface

use wasm_bindgen::prelude::*;

/// Validate all inputs from the host
#[wasm_bindgen]
pub fn process_user_data(input: &str) -> Result<String, JsValue> {
    // Input validation - WASM receives untrusted data
    if input.len() > 10_000 {
        return Err(JsValue::from_str("Input too large"));
    }
    
    // Sanitize input
    let sanitized: String = input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ')
        .take(1000)
        .collect();
    
    // Process safely
    let result = transform_data(&sanitized)?;
    
    Ok(result)
}

/// Avoid exposing internal state
#[wasm_bindgen]
pub struct SecureProcessor {
    // Private state not exposed to JS
    internal_key: [u8; 32],
}

#[wasm_bindgen]
impl SecureProcessor {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        // Initialize with secure random
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("RNG failed");
        Self { internal_key: key }
    }
    
    /// Process data without exposing key
    pub fn process(&self, data: &[u8]) -> Vec<u8> {
        // Key used internally, never returned
        encrypt_with_key(data, &self.internal_key)
    }
}
```

### WASM Security Checklist

| Check | Description | Status |
|-------|-------------|--------|
| **Input Validation** | All host inputs validated before use | [ ] |
| **Output Sanitization** | Sensitive data not leaked to host | [ ] |
| **Memory Limits** | Configure appropriate memory bounds | [ ] |
| **No Unbounded Loops** | Prevent denial-of-service | [ ] |
| **Error Handling** | Errors don't expose internal state | [ ] |
| **Minimal Exports** | Only necessary functions exported | [ ] |
| **No Unsafe** | Avoid unsafe in WASM when possible | [ ] |
| **Dependencies** | Minimal, audited WASM dependencies | [ ] |

---

## Security Standards Cross-Reference

### NIST SP 800-53 Rev. 5 Mapping

| Control Family | Control | Rust Implementation |
|---------------|---------|---------------------|
| **SI - System & Information Integrity** |||
| SI-2 | Flaw Remediation | `cargo audit`, `cargo update`, CI/CD scanning |
| SI-3 | Malicious Code Protection | Type safety, input validation, safe dependencies |
| SI-7 | Software Integrity | `cargo verify-project`, signed releases |
| SI-10 | Information Input Validation | Strong typing, validation functions, serde |
| SI-16 | Memory Protection | Ownership system, bounds checking |
| **SC - System & Communications Protection** |||
| SC-8 | Transmission Confidentiality | rustls, ring TLS |
| SC-12 | Cryptographic Key Management | zeroize, secure_key crates |
| SC-13 | Cryptographic Protection | ring, RustCrypto, aws-lc-rs |
| SC-28 | Protection of Information at Rest | aes-gcm, chacha20poly1305 |
| **SA - System & Services Acquisition** |||
| SA-10 | Developer Configuration Management | Cargo.lock, version pinning |
| SA-11 | Developer Security Testing | cargo test, fuzzing, clippy |
| SA-15 | Development Process | Rust safety guarantees, code review |

### OWASP Top Ten 2021 Rust Mitigations

| OWASP Risk | Description | Rust Mitigation |
|------------|-------------|-----------------|
| **A01: Broken Access Control** | Unauthorized access to resources | Type-safe authorization, session management |
| **A02: Cryptographic Failures** | Weak crypto, exposed data | ring/RustCrypto, proper key management |
| **A03: Injection** | SQL, command, code injection | Type safety, parameterized queries, validation |
| **A04: Insecure Design** | Architectural flaws | Rust's safe-by-default, threat modeling |
| **A05: Security Misconfiguration** | Default/weak settings | Explicit configuration, compile-time checks |
| **A06: Vulnerable Components** | Outdated dependencies | cargo audit, automated scanning |
| **A07: Authentication Failures** | Weak auth mechanisms | argon2, secure session, constant-time |
| **A08: Integrity Failures** | Unverified data/code | Type system, signature verification |
| **A09: Logging Failures** | Missing security logs | tracing, structured logging |
| **A10: SSRF** | Server-side request forgery | URL validation, allowlists |

#### A01: Broken Access Control - Implementation

```rust
use std::collections::HashSet;

/// Role-based access control using Rust's type system
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    Read,
    Write,
    Delete,
    Admin,
}

#[derive(Clone)]
pub struct User {
    id: UserId,
    permissions: HashSet<Permission>,
}

/// Type-safe resource access
pub struct ProtectedResource<T> {
    data: T,
    required_permission: Permission,
}

impl<T> ProtectedResource<T> {
    pub fn access(&self, user: &User) -> Result<&T, AccessError> {
        if user.permissions.contains(&self.required_permission) {
            Ok(&self.data)
        } else {
            // Log unauthorized access attempt
            log::warn!(
                "Access denied: user {} attempted to access protected resource",
                user.id
            );
            Err(AccessError::Unauthorized)
        }
    }
}
```

#### A03: Injection Prevention

```rust
use sqlx::{PgPool, Row};

/// Parameterized query prevents SQL injection
async fn get_user_by_name(
    pool: &PgPool,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    // Input validation
    if username.len() > 100 || !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Ok(None);
    }
    
    // Parameterized query - safe from injection
    let user = sqlx::query_as!(
        User,
        r#"SELECT id, username, email FROM users WHERE username = $1"#,
        username
    )
    .fetch_optional(pool)
    .await?;
    
    Ok(user)
}

/// Command execution with strict validation
fn execute_safe_command(command: AllowedCommand) -> Result<Output, CommandError> {
    // Only allow predefined commands (allowlist)
    let (program, args) = match command {
        AllowedCommand::ListFiles => ("ls", vec!["-la"]),
        AllowedCommand::DiskUsage => ("df", vec!["-h"]),
        AllowedCommand::SystemInfo => ("uname", vec!["-a"]),
    };
    
    std::process::Command::new(program)
        .args(&args)
        .output()
        .map_err(CommandError::ExecutionFailed)
}
```

### DISA STIG Application Security Requirements

| STIG ID | Requirement | Rust Implementation |
|---------|------------|---------------------|
| **APSC-DV-000460** | Restrict access to authenticated users | Type-safe session, middleware guards |
| **APSC-DV-001460** | Protect transmitted data | TLS 1.3 via rustls |
| **APSC-DV-001750** | Validate input for expected types | Strong typing, serde validation |
| **APSC-DV-001780** | Protect from buffer overflow | Memory safety guarantees |
| **APSC-DV-001995** | Generate audit records | tracing crate, structured logs |
| **APSC-DV-002010** | Implement FIPS algorithms | ring, aws-lc-rs |
| **APSC-DV-002150** | Protect session IDs | Cryptographic session tokens |
| **APSC-DV-002400** | Use TLS for data in transit | rustls configuration |
| **APSC-DV-002500** | Protect against injection | Type safety, validation |
| **APSC-DV-002560** | Sanitize file names | Path validation functions |

### CIS Benchmark Level 2 Controls

| Control | Requirement | Rust Implementation |
|---------|------------|---------------------|
| **5.1** | Establish secure coding standards | Clippy lints, cargo fmt |
| **5.2** | Secure development environment | Locked dependencies, signed crates |
| **5.3** | Security requirements in SDLC | Rust type system, tests |
| **5.4** | Security testing | cargo test, fuzzing, SAST |
| **16.1** | Maintain inventory of software | Cargo.lock, SBOM generation |
| **16.2** | Remove unauthorized software | Minimal dependencies |
| **16.4** | Establish secure configurations | Explicit Cargo.toml settings |
| **16.7** | Use standard security features | Ownership, borrowing, traits |

---

## Compliance Checklists

### Pre-Development Checklist

| Item | Description | Completed |
|------|-------------|-----------|
| [ ] | Rust 2024 edition configured in Cargo.toml | |
| [ ] | Security lints enabled (clippy pedantic) | |
| [ ] | `#![forbid(unsafe_code)]` where applicable | |
| [ ] | Dependency policy established | |
| [ ] | FIPS requirements identified if applicable | |
| [ ] | Threat model documented | |

### Development Phase Checklist

| Item | Description | Completed |
|------|-------------|-----------|
| [ ] | Input validation for all external data | |
| [ ] | Error handling without information disclosure | |
| [ ] | Cryptographic operations use approved libraries | |
| [ ] | No hardcoded secrets or credentials | |
| [ ] | Unsafe blocks documented and minimized | |
| [ ] | Concurrent access properly synchronized | |
| [ ] | Integer overflow protection enabled | |
| [ ] | All panics are intentional (not unwrap on user data) | |

### CI/CD Security Checklist

| Item | Description | Completed |
|------|-------------|-----------|
| [ ] | `cargo audit` in CI pipeline | |
| [ ] | `cargo clippy -- -D warnings` enforced | |
| [ ] | Dependency updates monitored | |
| [ ] | SBOM generated with each release | |
| [ ] | Binary signatures for releases | |
| [ ] | Fuzz testing integrated | |
| [ ] | SAST scanning configured | |

### Release Checklist

| Item | Description | Completed |
|------|-------------|-----------|
| [ ] | All dependencies at latest secure versions | |
| [ ] | No known vulnerabilities in dependency tree | |
| [ ] | Release build profile security settings | |
| [ ] | Debug symbols stripped | |
| [ ] | Version documented in changelog | |
| [ ] | Security advisory review completed | |

### FIPS 140-3 Compliance Checklist

| Item | Description | Completed |
|------|-------------|-----------|
| [ ] | FIPS-validated cryptographic module identified | |
| [ ] | Only approved algorithms used | |
| [ ] | Key sizes meet minimum requirements | |
| [ ] | CSPRNG used for all random generation | |
| [ ] | Keys zeroized after use | |
| [ ] | Cryptographic module operates in approved mode | |
| [ ] | Documentation of cryptographic boundaries | |

---

## References

### Official Documentation

1. [Rust 1.85.0 and Rust 2024 Edition Announcement](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/) - Official Rust Blog
2. [Rust 2024 Edition Guide](https://doc.rust-lang.org/edition-guide/rust-2024/index.html) - Rust Documentation
3. [The Rustonomicon - Unsafe Rust](https://doc.rust-lang.org/nomicon/) - Unsafe Rust reference

### Security Standards

4. [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) - Security and Privacy Controls
5. [OWASP Top Ten 2021](https://owasp.org/Top10/2021/) - Web Application Security Risks
6. [DISA STIGs](https://www.cyber.mil/stigs) - Security Technical Implementation Guides
7. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Center for Internet Security
8. [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) - Cryptographic Module Security Requirements

### Rust Security Resources

9. [RustSec Advisory Database](https://rustsec.org/) - Vulnerability database for Rust crates
10. [cargo-audit](https://crates.io/crates/cargo-audit) - Security vulnerability scanner
11. [Rust Secure Code Working Group](https://www.rust-lang.org/governance/wgs/wg-secure-code) - Official working group
12. [RustCrypto](https://github.com/RustCrypto) - Pure Rust cryptographic implementations
13. [Awesome Rust Cryptography](https://cryptography.rs/) - Curated list of crypto libraries

### Industry Reports

14. [Google Security Blog - Rust in Android](https://security.googleblog.com/2025/11/rust-in-android-move-fast-fix-things.html) - Memory safety analysis
15. [Rust Foundation - Unsafe Rust in the Wild](https://rustfoundation.org/media/unsafe-rust-in-the-wild-notes-on-the-current-state-of-unsafe-rust/) - Unsafe code study
16. [Corgea - Rust Security Best Practices 2025](https://corgea.com/Learn/rust-security-best-practices-2025) - Industry practices

### Tools

17. [cargo-geiger](https://crates.io/crates/cargo-geiger) - Unsafe code analyzer
18. [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) - Binary auditing
19. [clippy](https://github.com/rust-lang/rust-clippy) - Rust linter
20. [rust-analyzer](https://rust-analyzer.github.io/) - IDE support with security insights

---

## Appendix A: Quick Reference Cards

### Secure Coding Quick Reference

```
+------------------------------------------+
|         RUST SECURE CODING CARD          |
+------------------------------------------+
| ALWAYS:                                  |
| - Use Result/Option for error handling   |
| - Validate all external inputs           |
| - Use approved crypto libraries          |
| - Run cargo audit regularly              |
| - Document unsafe blocks with // SAFETY: |
| - Enable overflow-checks in release      |
+------------------------------------------+
| NEVER:                                   |
| - Use unwrap() on untrusted data         |
| - Implement custom cryptography          |
| - Expose internal error details          |
| - Use static mut without extreme care    |
| - Ignore cargo audit warnings            |
| - Skip input validation                  |
+------------------------------------------+
```

### Cryptography Selection Guide

```
+------------------------------------------+
|         ALGORITHM SELECTION GUIDE        |
+------------------------------------------+
| Symmetric Encryption:                    |
|   - AES-256-GCM (preferred)              |
|   - ChaCha20-Poly1305 (alternative)      |
+------------------------------------------+
| Hashing:                                 |
|   - SHA-256/384/512 (general)            |
|   - SHA-3 (post-quantum consideration)   |
|   - BLAKE3 (performance, non-FIPS)       |
+------------------------------------------+
| Password Hashing:                        |
|   - Argon2id (preferred)                 |
|   - bcrypt (legacy compatibility)        |
+------------------------------------------+
| Key Exchange:                            |
|   - X25519 (modern)                      |
|   - ECDH P-256/384 (FIPS)                |
+------------------------------------------+
| Digital Signatures:                      |
|   - Ed25519 (modern)                     |
|   - ECDSA P-256 (FIPS)                   |
|   - RSA-PSS 2048+ (legacy)               |
+------------------------------------------+
```

---

## Appendix B: Clippy Security Lints

Configure these lints in `Cargo.toml` or `clippy.toml`:

```toml
[lints.clippy]
# Deny potentially dangerous operations
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
unreachable = "deny"

# Security-sensitive lints
cast_possible_truncation = "warn"
cast_possible_wrap = "warn"
cast_sign_loss = "warn"
integer_division = "warn"
arithmetic_side_effects = "warn"

# Code quality for security
cognitive_complexity = "warn"
too_many_arguments = "warn"
too_many_lines = "warn"

# Documentation requirements
missing_docs = "warn"
missing_panics_doc = "warn"
missing_safety_doc = "deny"
```

---

*Document generated by Matrix Agent*  
*For questions or updates, consult the Rust Secure Code Working Group guidelines.*
