# Go (Golang) Security Best Practices Guide

**Version:** 1.0  
**Last Updated:** March 2026  
**Applicable Go Versions:** Go 1.22+, Go 1.23, Go 1.24+

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Go Coding Best Practices](#go-coding-best-practices)
   - [Latest Go Standards (Go 1.22+ Features)](#latest-go-standards-go-122-features)
   - [Memory Safety in Go](#memory-safety-in-go)
   - [Secure HTTP Handlers and Middleware](#secure-http-handlers-and-middleware)
   - [SQL Injection Prevention](#sql-injection-prevention-with-databasesql)
   - [Go Crypto Package Best Practices](#go-crypto-package-best-practices)
   - [Error Handling for Security](#error-handling-for-security)
   - [Race Condition Prevention](#race-condition-prevention)
   - [Static Analysis Tools](#static-analysis-tools)
3. [Security Standards Cross-Reference](#security-standards-cross-reference)
   - [NIST Controls](#nist-controls)
   - [OWASP Top Ten](#owasp-top-ten)
   - [DISA STIG Requirements](#disa-stig-requirements)
   - [CIS Benchmark Level 2](#cis-benchmark-level-2)
   - [FIPS 140-3 Compliance](#fips-140-3-compliance)
4. [Compliance Checklists](#compliance-checklists)
5. [References](#references)

---

## Executive Summary

This guide provides comprehensive security best practices for Go (Golang) developers, aligned with major security standards including NIST, OWASP Top Ten, DISA STIG, CIS Benchmark Level 2, and FIPS 140-3. Go's design philosophy emphasizes simplicity and safety, but developers must still follow security best practices to build robust, secure applications.

Key security features in modern Go (1.22+) include:
- Native FIPS 140-3 cryptographic module support (Go 1.24+)
- Built-in race condition detection
- Memory safety through garbage collection
- Strong typing and compile-time checks
- Official vulnerability scanning with `govulncheck`

---

## Go Coding Best Practices

### Latest Go Standards (Go 1.22+ Features)

#### Go 1.22 Security-Relevant Features

**Loop Variable Scoping Fix:**
Go 1.22 fixed a long-standing issue where loop variables were shared across iterations, which could cause security issues in concurrent code.

```go
// Pre-Go 1.22 (VULNERABLE - loop variable captured by reference)
for _, item := range items {
    go func() {
        process(item) // All goroutines may see the same item
    }()
}

// Go 1.22+ (SECURE - loop variable scoped per iteration)
for _, item := range items {
    go func() {
        process(item) // Each goroutine sees its own item
    }()
}
```

**Enhanced Routing Patterns in net/http:**
```go
// Go 1.22+ - Method-specific routing with path parameters
mux := http.NewServeMux()
mux.HandleFunc("GET /users/{id}", getUser)
mux.HandleFunc("POST /users", createUser)
mux.HandleFunc("DELETE /users/{id}", deleteUser)

func getUser(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id") // Secure parameter extraction
    // Validate and sanitize id before use
}
```

#### Go 1.23 Security Enhancements

- **Iterator support** for safer collection processing
- **Improved crypto/tls** with enhanced cipher suite handling
- **Enhanced runtime diagnostics** for debugging security issues

#### Go 1.24+ FIPS 140-3 Native Support

```go
// Check if FIPS mode is enabled
import "crypto/fips140"

func main() {
    if fips140.Enabled() {
        log.Println("FIPS 140-3 mode is active")
    }
}
```

**Build with FIPS mode:**
```bash
# Build with FIPS 140-3 mode enabled
GOFIPS140=v1.0.0 go build -o myapp ./...

# Or use 'latest' for the current frozen version
GOFIPS140=latest go build -o myapp ./...
```

---

### Memory Safety in Go

Go provides memory safety through garbage collection, but developers must still avoid common pitfalls.

#### Slice and Array Bounds

```go
// VULNERABLE - potential out-of-bounds access
func processData(data []byte, index int) byte {
    return data[index] // May panic if index >= len(data)
}

// SECURE - bounds checking
func processDataSafe(data []byte, index int) (byte, error) {
    if index < 0 || index >= len(data) {
        return 0, errors.New("index out of bounds")
    }
    return data[index], nil
}
```

#### Avoiding Memory Leaks

```go
// POTENTIAL LEAK - goroutine never terminates
func leakyFunction() {
    go func() {
        for {
            doWork() // No exit condition
        }
    }()
}

// SECURE - proper goroutine lifecycle management
func safeFunction(ctx context.Context) {
    go func() {
        for {
            select {
            case <-ctx.Done():
                return // Clean exit on context cancellation
            default:
                doWork()
            }
        }
    }()
}
```

#### Secure Buffer Management

```go
// SECURE - zeroing sensitive data after use
import "crypto/subtle"

func handleSensitiveData(secret []byte) {
    defer func() {
        // Zero out sensitive data when done
        for i := range secret {
            secret[i] = 0
        }
    }()
    
    // Process the secret...
}

// Using sync.Pool for buffer reuse (prevents data leakage)
var bufferPool = sync.Pool{
    New: func() interface{} {
        buf := make([]byte, 4096)
        return &buf
    },
}

func getBuffer() *[]byte {
    return bufferPool.Get().(*[]byte)
}

func putBuffer(buf *[]byte) {
    // Zero the buffer before returning to pool
    for i := range *buf {
        (*buf)[i] = 0
    }
    bufferPool.Put(buf)
}
```

---

### Secure HTTP Handlers and Middleware

#### Security Headers Middleware

```go
package middleware

import (
    "net/http"
)

// SecurityHeaders adds essential security headers to responses
func SecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Prevent MIME type sniffing
        w.Header().Set("X-Content-Type-Options", "nosniff")
        
        // Prevent clickjacking
        w.Header().Set("X-Frame-Options", "DENY")
        
        // Enable XSS filter
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        
        // Content Security Policy
        w.Header().Set("Content-Security-Policy", 
            "default-src 'self'; script-src 'self'; style-src 'self'")
        
        // Strict Transport Security (HTTPS only)
        w.Header().Set("Strict-Transport-Security", 
            "max-age=31536000; includeSubDomains; preload")
        
        // Referrer Policy
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        
        // Permissions Policy
        w.Header().Set("Permissions-Policy", 
            "geolocation=(), microphone=(), camera=()")
        
        next.ServeHTTP(w, r)
    })
}
```

#### Rate Limiting Middleware

```go
package middleware

import (
    "net/http"
    "sync"
    "time"
    
    "golang.org/x/time/rate"
)

type RateLimiter struct {
    visitors map[string]*rate.Limiter
    mu       sync.RWMutex
    rate     rate.Limit
    burst    int
}

func NewRateLimiter(r rate.Limit, burst int) *RateLimiter {
    rl := &RateLimiter{
        visitors: make(map[string]*rate.Limiter),
        rate:     r,
        burst:    burst,
    }
    
    // Cleanup old entries periodically
    go rl.cleanup()
    return rl
}

func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    limiter, exists := rl.visitors[ip]
    if !exists {
        limiter = rate.NewLimiter(rl.rate, rl.burst)
        rl.visitors[ip] = limiter
    }
    return limiter
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := r.RemoteAddr // Consider X-Forwarded-For behind proxy
        
        limiter := rl.getVisitor(ip)
        if !limiter.Allow() {
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

#### Secure Cookie Handling

```go
package auth

import (
    "net/http"
    "time"
)

// SetSecureCookie creates a secure session cookie
func SetSecureCookie(w http.ResponseWriter, name, value string) {
    http.SetCookie(w, &http.Cookie{
        Name:     name,
        Value:    value,
        Path:     "/",
        HttpOnly: true,                    // Prevents JavaScript access
        Secure:   true,                    // HTTPS only
        SameSite: http.SameSiteStrictMode, // CSRF protection
        MaxAge:   3600,                    // 1 hour expiration
    })
}

// ValidateSession validates a session token securely
func ValidateSession(r *http.Request) (string, error) {
    cookie, err := r.Cookie("session")
    if err != nil {
        return "", err
    }
    
    // Validate token format and signature
    // Use constant-time comparison for tokens
    return validateToken(cookie.Value)
}
```

#### Request Validation

```go
package handlers

import (
    "encoding/json"
    "io"
    "net/http"
    "unicode/utf8"
)

const (
    MaxBodySize   = 1 << 20 // 1 MB
    MaxFieldLen   = 1000
)

// DecodeJSONBody safely decodes JSON with size limits
func DecodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
    // Limit request body size
    r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)
    
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields() // Reject unknown fields
    
    if err := dec.Decode(dst); err != nil {
        return err
    }
    
    // Ensure only one JSON object
    if dec.More() {
        return errors.New("request body must contain only one JSON object")
    }
    
    return nil
}

// ValidateString ensures string input is safe
func ValidateString(s string, maxLen int) error {
    if len(s) > maxLen {
        return errors.New("string exceeds maximum length")
    }
    if !utf8.ValidString(s) {
        return errors.New("invalid UTF-8 encoding")
    }
    return nil
}
```

---

### SQL Injection Prevention with database/sql

#### Using Parameterized Queries

```go
package database

import (
    "context"
    "database/sql"
    "fmt"
)

// VULNERABLE - Never do this!
func getUserUnsafe(db *sql.DB, userID string) (*User, error) {
    // SQL INJECTION VULNERABILITY!
    query := fmt.Sprintf("SELECT id, name, email FROM users WHERE id = '%s'", userID)
    row := db.QueryRow(query)
    // ...
}

// SECURE - Use parameterized queries
func getUserSafe(ctx context.Context, db *sql.DB, userID string) (*User, error) {
    query := "SELECT id, name, email FROM users WHERE id = $1"
    row := db.QueryRowContext(ctx, query, userID)
    
    var user User
    err := row.Scan(&user.ID, &user.Name, &user.Email)
    if err != nil {
        return nil, err
    }
    return &user, nil
}

// SECURE - Multiple parameters
func searchUsers(ctx context.Context, db *sql.DB, name string, status string, limit int) ([]User, error) {
    query := `
        SELECT id, name, email, status 
        FROM users 
        WHERE name LIKE $1 AND status = $2 
        ORDER BY name 
        LIMIT $3`
    
    rows, err := db.QueryContext(ctx, query, "%"+name+"%", status, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var users []User
    for rows.Next() {
        var u User
        if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.Status); err != nil {
            return nil, err
        }
        users = append(users, u)
    }
    return users, rows.Err()
}
```

#### Prepared Statements

```go
// SECURE - Reusable prepared statements
type UserRepository struct {
    db           *sql.DB
    getUserStmt  *sql.Stmt
    insertStmt   *sql.Stmt
}

func NewUserRepository(db *sql.DB) (*UserRepository, error) {
    getUserStmt, err := db.Prepare("SELECT id, name, email FROM users WHERE id = $1")
    if err != nil {
        return nil, err
    }
    
    insertStmt, err := db.Prepare("INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id")
    if err != nil {
        getUserStmt.Close()
        return nil, err
    }
    
    return &UserRepository{
        db:          db,
        getUserStmt: getUserStmt,
        insertStmt:  insertStmt,
    }, nil
}

func (r *UserRepository) GetUser(ctx context.Context, id int64) (*User, error) {
    var user User
    err := r.getUserStmt.QueryRowContext(ctx, id).Scan(&user.ID, &user.Name, &user.Email)
    return &user, err
}

func (r *UserRepository) Close() error {
    r.getUserStmt.Close()
    r.insertStmt.Close()
    return nil
}
```

#### Parameter Placeholders by Database

| Database | Placeholder Format | Example |
|----------|-------------------|---------|
| PostgreSQL (pq) | `$1`, `$2`, `$3` | `WHERE id = $1 AND status = $2` |
| MySQL | `?` | `WHERE id = ? AND status = ?` |
| SQLite | `?` or `$1` | `WHERE id = ? AND status = ?` |
| SQL Server | `@p1`, `@p2` | `WHERE id = @p1 AND status = @p2` |
| Oracle | `:name` | `WHERE id = :id AND status = :status` |

---

### Go Crypto Package Best Practices

#### Secure Random Number Generation

```go
package crypto

import (
    "crypto/rand"
    "encoding/hex"
    "math/big"
)

// GenerateSecureToken creates a cryptographically secure token
func GenerateSecureToken(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}

// GenerateSecureInt generates a secure random integer in range [0, max)
func GenerateSecureInt(max int64) (int64, error) {
    n, err := rand.Int(rand.Reader, big.NewInt(max))
    if err != nil {
        return 0, err
    }
    return n.Int64(), nil
}

// INSECURE - Never use math/rand for security!
// import "math/rand" // DO NOT USE FOR SECURITY
```

#### Password Hashing

```go
package auth

import (
    "crypto/subtle"
    "encoding/base64"
    "errors"
    "fmt"
    "strings"
    
    "golang.org/x/crypto/argon2"
    "crypto/rand"
)

type ArgonParams struct {
    Memory      uint32
    Iterations  uint32
    Parallelism uint8
    SaltLength  uint32
    KeyLength   uint32
}

// DefaultParams - OWASP recommended parameters
var DefaultParams = &ArgonParams{
    Memory:      64 * 1024, // 64 MB
    Iterations:  3,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32,
}

// HashPassword creates an Argon2id hash of the password
func HashPassword(password string, params *ArgonParams) (string, error) {
    salt := make([]byte, params.SaltLength)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }
    
    hash := argon2.IDKey(
        []byte(password),
        salt,
        params.Iterations,
        params.Memory,
        params.Parallelism,
        params.KeyLength,
    )
    
    // Encode to standard format
    b64Salt := base64.RawStdEncoding.EncodeToString(salt)
    b64Hash := base64.RawStdEncoding.EncodeToString(hash)
    
    return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
        argon2.Version, params.Memory, params.Iterations, 
        params.Parallelism, b64Salt, b64Hash), nil
}

// VerifyPassword compares password with hash using constant-time comparison
func VerifyPassword(password, encodedHash string) (bool, error) {
    params, salt, hash, err := decodeHash(encodedHash)
    if err != nil {
        return false, err
    }
    
    otherHash := argon2.IDKey(
        []byte(password), salt,
        params.Iterations, params.Memory, 
        params.Parallelism, params.KeyLength,
    )
    
    // Constant-time comparison prevents timing attacks
    return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}
```

#### AES-GCM Encryption

```go
package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "io"
)

// Encrypt encrypts data using AES-GCM
func Encrypt(plaintext, key []byte) ([]byte, error) {
    if len(key) != 32 {
        return nil, errors.New("key must be 32 bytes for AES-256")
    }
    
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

// Decrypt decrypts AES-GCM encrypted data
func Decrypt(ciphertext, key []byte) ([]byte, error) {
    if len(key) != 32 {
        return nil, errors.New("key must be 32 bytes for AES-256")
    }
    
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }
    
    return plaintext, nil
}
```

#### Cryptographic Algorithm Reference

| Use Case | Recommended Algorithm | Go Package |
|----------|----------------------|------------|
| Symmetric Encryption | AES-256-GCM | `crypto/aes`, `crypto/cipher` |
| Password Hashing | Argon2id | `golang.org/x/crypto/argon2` |
| General Hashing | SHA-256/SHA-512 | `crypto/sha256`, `crypto/sha512` |
| HMAC | HMAC-SHA256 | `crypto/hmac` |
| Digital Signatures | Ed25519, ECDSA P-256 | `crypto/ed25519`, `crypto/ecdsa` |
| Key Exchange | X25519, ECDH P-256 | `crypto/ecdh` |
| Random Numbers | crypto/rand | `crypto/rand` |
| TLS | TLS 1.3 | `crypto/tls` |

---

### Error Handling for Security

#### Secure Error Handling Patterns

```go
package errors

import (
    "errors"
    "log/slog"
    "net/http"
)

// Custom error types for internal use
var (
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrPermissionDenied   = errors.New("permission denied")
    ErrResourceNotFound   = errors.New("resource not found")
    ErrInternal           = errors.New("internal server error")
)

// INSECURE - Exposes internal details
func handleErrorUnsafe(w http.ResponseWriter, err error) {
    // DON'T DO THIS - exposes internal information
    http.Error(w, err.Error(), http.StatusInternalServerError)
}

// SECURE - Log details internally, return generic message
func handleErrorSecure(w http.ResponseWriter, err error, requestID string) {
    // Log detailed error internally with context
    slog.Error("request failed",
        "error", err,
        "request_id", requestID,
        "stack", captureStack(),
    )
    
    // Return generic message to client
    var statusCode int
    var message string
    
    switch {
    case errors.Is(err, ErrInvalidCredentials):
        statusCode = http.StatusUnauthorized
        message = "Authentication failed"
    case errors.Is(err, ErrPermissionDenied):
        statusCode = http.StatusForbidden
        message = "Access denied"
    case errors.Is(err, ErrResourceNotFound):
        statusCode = http.StatusNotFound
        message = "Resource not found"
    default:
        statusCode = http.StatusInternalServerError
        message = "An error occurred"
    }
    
    // Include request ID for correlation
    w.Header().Set("X-Request-ID", requestID)
    http.Error(w, message, statusCode)
}

// ErrorResponse for JSON APIs
type ErrorResponse struct {
    Error     string `json:"error"`
    RequestID string `json:"request_id,omitempty"`
}

func respondWithError(w http.ResponseWriter, code int, message, requestID string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    json.NewEncoder(w).Encode(ErrorResponse{
        Error:     message,
        RequestID: requestID,
    })
}
```

#### Error Wrapping Best Practices

```go
package service

import (
    "context"
    "errors"
    "fmt"
)

// Wrap errors with context but don't expose internals
func (s *UserService) GetUser(ctx context.Context, id int64) (*User, error) {
    user, err := s.repo.FindByID(ctx, id)
    if err != nil {
        // Wrap with context for debugging, but use sentinel errors
        if errors.Is(err, sql.ErrNoRows) {
            return nil, fmt.Errorf("user %d: %w", id, ErrResourceNotFound)
        }
        // Log the detailed error, return generic
        slog.ErrorContext(ctx, "database error", "error", err, "user_id", id)
        return nil, ErrInternal
    }
    return user, nil
}
```

---

### Race Condition Prevention

#### Using the Race Detector

```bash
# Run tests with race detection
go test -race ./...

# Build with race detection (development only)
go build -race -o myapp ./...

# Run with race detection
go run -race main.go
```

#### Mutex Best Practices

```go
package counter

import (
    "sync"
)

// Thread-safe counter using Mutex
type SafeCounter struct {
    mu    sync.Mutex
    count int64
}

func (c *SafeCounter) Increment() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.count++
}

func (c *SafeCounter) Value() int64 {
    c.mu.Lock()
    defer c.mu.Unlock()
    return c.count
}

// Read-heavy workloads: use RWMutex
type SafeCache struct {
    mu    sync.RWMutex
    items map[string]interface{}
}

func (c *SafeCache) Get(key string) (interface{}, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    item, ok := c.items[key]
    return item, ok
}

func (c *SafeCache) Set(key string, value interface{}) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.items[key] = value
}
```

#### Atomic Operations

```go
package counter

import (
    "sync/atomic"
)

// Lock-free counter using atomic operations
type AtomicCounter struct {
    count atomic.Int64
}

func (c *AtomicCounter) Increment() {
    c.count.Add(1)
}

func (c *AtomicCounter) Value() int64 {
    return c.count.Load()
}

// Atomic pointer for lock-free updates
type Config struct {
    MaxConnections int
    Timeout        int
}

type ConfigHolder struct {
    config atomic.Pointer[Config]
}

func (h *ConfigHolder) Get() *Config {
    return h.config.Load()
}

func (h *ConfigHolder) Update(cfg *Config) {
    h.config.Store(cfg)
}
```

#### Channel-Based Synchronization

```go
package worker

import (
    "context"
)

// Worker pool with channel synchronization
type WorkerPool struct {
    jobs    chan Job
    results chan Result
    workers int
}

func NewWorkerPool(workers int, bufferSize int) *WorkerPool {
    return &WorkerPool{
        jobs:    make(chan Job, bufferSize),
        results: make(chan Result, bufferSize),
        workers: workers,
    }
}

func (p *WorkerPool) Start(ctx context.Context) {
    for i := 0; i < p.workers; i++ {
        go p.worker(ctx, i)
    }
}

func (p *WorkerPool) worker(ctx context.Context, id int) {
    for {
        select {
        case <-ctx.Done():
            return
        case job, ok := <-p.jobs:
            if !ok {
                return
            }
            result := processJob(job)
            p.results <- result
        }
    }
}

func (p *WorkerPool) Submit(job Job) {
    p.jobs <- job
}

func (p *WorkerPool) Close() {
    close(p.jobs)
}
```

---

### Static Analysis Tools

#### gosec - Go Security Checker

**Installation:**
```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

**Basic Usage:**
```bash
# Scan entire project
gosec ./...

# Generate JSON report
gosec -fmt json -out results.json ./...

# Generate SARIF for GitHub Code Scanning
gosec -fmt sarif -out results.sarif ./...

# Run specific rules
gosec -include=G101,G401,G501 ./...

# Exclude specific rules
gosec -exclude=G104 ./...
```

**Key gosec Rules:**

| Rule ID | Description | Severity |
|---------|-------------|----------|
| G101 | Hardcoded credentials | High |
| G102 | Bind to all interfaces | Medium |
| G103 | Audit unsafe block usage | High |
| G104 | Audit unhandled errors | Medium |
| G107 | URL provided to HTTP request as taint input | Medium |
| G201 | SQL query construction using format string | High |
| G202 | SQL query construction using string concatenation | High |
| G301 | Poor file permissions | Medium |
| G302 | Poor file permissions for chmod | Medium |
| G304 | File path provided as taint input | High |
| G401 | Use of weak crypto (MD5/SHA1) | Medium |
| G402 | TLS InsecureSkipVerify | High |
| G403 | RSA keys < 2048 bits | Medium |
| G404 | Use of weak random (math/rand) | High |
| G501 | Import blocklist: crypto/md5 | Medium |
| G502 | Import blocklist: crypto/des | Medium |
| G601 | Implicit memory aliasing in for loop | Medium |

**Configuration File (gosec.json):**
```json
{
    "global": {
        "nosec": "enabled",
        "audit": "enabled"
    },
    "G101": {
        "pattern": "(?i)passwd|pass|password|pwd|secret|token|api_key"
    },
    "G301": "0750",
    "G302": "0750"
}
```

#### staticcheck

**Installation:**
```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
```

**Usage:**
```bash
# Run all checks
staticcheck ./...

# Run specific checks
staticcheck -checks "SA*" ./...

# Ignore specific checks
staticcheck -checks "all,-ST1000" ./...
```

#### govulncheck - Official Vulnerability Scanner

**Installation:**
```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

**Usage:**
```bash
# Scan source code
govulncheck ./...

# Scan binary
govulncheck -mode=binary ./myapp

# JSON output
govulncheck -json ./...
```

#### golangci-lint (Aggregated Linting)

**Configuration (.golangci.yml):**
```yaml
linters:
  enable:
    - gosec
    - staticcheck
    - errcheck
    - govet
    - ineffassign
    - unused
    - bodyclose
    - sqlclosecheck
    - exportloopref

linters-settings:
  gosec:
    excludes:
      - G104  # Unhandled errors (if needed)
    config:
      G301: "0750"
      G302: "0750"
      G306: "0600"

  staticcheck:
    checks:
      - all
      - -SA1019  # Deprecated usage warnings

issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - gosec
```

**Usage:**
```bash
golangci-lint run ./...
```

---

## Security Standards Cross-Reference

### NIST Controls

#### NIST SP 800-53 Rev 5 - Security Controls for Go Applications

| Control ID | Control Name | Go Implementation |
|------------|--------------|-------------------|
| AC-3 | Access Enforcement | Role-based access in middleware, context-based auth |
| AU-2 | Audit Events | Structured logging with `log/slog` |
| AU-3 | Audit Record Content | Include user, timestamp, action, resource, result |
| CM-7 | Least Functionality | Minimal imports, dependency review |
| IA-5 | Authenticator Management | Argon2id password hashing, secure token generation |
| SC-8 | Transmission Confidentiality | TLS 1.3, `crypto/tls` configuration |
| SC-12 | Cryptographic Key Management | Secure key storage, rotation support |
| SC-13 | Cryptographic Protection | AES-256-GCM, SHA-256, Ed25519 |
| SC-28 | Protection of Information at Rest | Encrypted database fields, secure file storage |
| SI-10 | Information Input Validation | Input validation, parameterized queries |
| SI-11 | Error Handling | Secure error messages, detailed internal logging |

#### NIST SP 800-218 - Secure Software Development Framework (SSDF)

| Practice | Go Implementation |
|----------|-------------------|
| PO.1 - Define Security Requirements | Document security requirements in design docs |
| PS.1 - Protect Code | Use `go mod verify`, signed commits |
| PW.1 - Design Secure Software | Threat modeling, security design reviews |
| PW.5 - Create Source Code | Follow Go security best practices |
| PW.6 - Configure Build/Deploy | Reproducible builds, minimal containers |
| PW.7 - Review Code | Mandatory code review, security-focused reviews |
| PW.8 - Test Code | `go test -race`, fuzzing, security testing |
| PW.9 - Configure Software | Secure defaults, environment-based config |
| RV.1 - Identify Vulnerabilities | `govulncheck`, `gosec`, dependency scanning |
| RV.2 - Assess Vulnerabilities | CVE tracking, risk assessment |
| RV.3 - Remediate Vulnerabilities | Timely patching, security releases |

---

### OWASP Top Ten

#### OWASP Top 10 2021/2025 - Go Mitigations

| Rank | Vulnerability | Go Mitigation |
|------|---------------|---------------|
| A01 | Broken Access Control | Context-based authorization, middleware checks |
| A02 | Cryptographic Failures | `crypto/` packages, avoid weak algorithms |
| A03 | Injection | Parameterized queries, template escaping |
| A04 | Insecure Design | Threat modeling, security design patterns |
| A05 | Security Misconfiguration | Secure defaults, configuration validation |
| A06 | Vulnerable Components | `govulncheck`, dependency updates |
| A07 | Authentication Failures | Secure session management, MFA support |
| A08 | Software/Data Integrity | `go mod verify`, code signing |
| A09 | Security Logging Failures | Structured logging with `slog` |
| A10 | SSRF | URL validation, allowlisting |

#### A01 - Broken Access Control

```go
package middleware

import (
    "context"
    "net/http"
)

type contextKey string

const userContextKey contextKey = "user"

// RequireRole middleware enforces role-based access
func RequireRole(requiredRole string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user, ok := r.Context().Value(userContextKey).(*User)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        
        if !user.HasRole(requiredRole) {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

// ResourceOwner checks if user owns the resource
func RequireResourceOwner(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user, _ := r.Context().Value(userContextKey).(*User)
        resourceID := r.PathValue("id")
        
        // Check ownership
        if !isResourceOwner(user.ID, resourceID) {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

#### A03 - Injection Prevention

```go
package handlers

import (
    "html/template"
    "os/exec"
    "regexp"
)

// SQL Injection - SECURE
func getUser(db *sql.DB, id string) (*User, error) {
    // Use parameterized queries
    return db.QueryRowContext(ctx, "SELECT * FROM users WHERE id = $1", id)
}

// XSS Prevention - SECURE
func renderPage(w http.ResponseWriter, data interface{}) {
    // html/template auto-escapes by default
    tmpl := template.Must(template.ParseFiles("page.html"))
    tmpl.Execute(w, data)
}

// Command Injection - SECURE
func runCommand(filename string) error {
    // Validate input
    if !regexp.MustCompile(`^[a-zA-Z0-9_-]+\.txt$`).MatchString(filename) {
        return errors.New("invalid filename")
    }
    
    // Use exec.Command with separate arguments, not shell
    cmd := exec.Command("cat", filename)
    return cmd.Run()
}

// Path Traversal - SECURE
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := filepath.Base(r.URL.Path) // Strip directory components
    filepath := filepath.Join("/safe/directory", filename)
    
    // Verify the resolved path is within allowed directory
    if !strings.HasPrefix(filepath, "/safe/directory/") {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }
    
    http.ServeFile(w, r, filepath)
}
```

#### A06 - Vulnerable and Outdated Components

```go
// go.mod - Use specific versions and regular updates
module myapp

go 1.24

require (
    github.com/lib/pq v1.10.9
    golang.org/x/crypto v0.31.0
)
```

**Dependency Security Commands:**
```bash
# Check for vulnerabilities
govulncheck ./...

# Verify module checksums
go mod verify

# Update dependencies
go get -u ./...

# Tidy and verify
go mod tidy
go mod verify
```

---

### DISA STIG Requirements

#### Application Security and Development STIG

| STIG ID | Requirement | Go Implementation |
|---------|-------------|-------------------|
| APSC-DV-000060 | Use approved cryptographic modules | FIPS140-3 mode (`GOFIPS140=v1.0.0`) |
| APSC-DV-000160 | Protect authentication data | Argon2id hashing, secure storage |
| APSC-DV-000460 | Audit security-relevant events | Structured logging with `slog` |
| APSC-DV-000500 | Validate all input | Input validation, type checking |
| APSC-DV-000560 | Encrypt data in transit | TLS 1.3 with proper configuration |
| APSC-DV-000580 | Protect data at rest | AES-256-GCM encryption |
| APSC-DV-000650 | Generate audit records | Comprehensive logging |
| APSC-DV-001000 | Perform code analysis | `gosec`, `staticcheck`, `govulncheck` |
| APSC-DV-001460 | Handle errors securely | Generic error messages, internal logging |
| APSC-DV-001680 | Session management | Secure cookies, session timeouts |
| APSC-DV-001995 | Use parameterized queries | `database/sql` placeholders |
| APSC-DV-002010 | Implement rate limiting | Rate limiting middleware |
| APSC-DV-002400 | Memory protection | Bounds checking, race detection |
| APSC-DV-002560 | Output encoding | `html/template` auto-escaping |

#### TLS Configuration for DISA STIG Compliance

```go
package server

import (
    "crypto/tls"
    "net/http"
)

// GetSTIGCompliantTLSConfig returns a TLS config meeting DISA STIG requirements
func GetSTIGCompliantTLSConfig() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS12, // Minimum TLS 1.2 (TLS 1.3 preferred)
        
        // STIG-approved cipher suites
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        },
        
        // Curve preferences
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP384,
            tls.CurveP256,
        },
        
        // Session security
        SessionTicketsDisabled: false,
        
        // Prefer server cipher suites
        PreferServerCipherSuites: true,
    }
}

func StartSecureServer() {
    server := &http.Server{
        Addr:      ":443",
        TLSConfig: GetSTIGCompliantTLSConfig(),
        Handler:   router,
    }
    
    server.ListenAndServeTLS("cert.pem", "key.pem")
}
```

---

### CIS Benchmark Level 2

#### CIS Critical Security Controls - Go Application Implementation

| CIS Control | Description | Go Implementation |
|-------------|-------------|-------------------|
| 1 | Inventory of Enterprise Assets | Document all Go services and dependencies |
| 2 | Inventory of Software Assets | `go.mod`, SBOM generation |
| 3 | Data Protection | Encryption at rest/transit, access controls |
| 4 | Secure Configuration | Environment-based config, secure defaults |
| 5 | Account Management | RBAC implementation, session management |
| 6 | Access Control Management | Context-based auth, least privilege |
| 7 | Continuous Vulnerability Management | `govulncheck` in CI/CD |
| 8 | Audit Log Management | `slog` structured logging |
| 10 | Malware Defenses | Input validation, file upload scanning |
| 11 | Data Recovery | Backup strategies, disaster recovery |
| 14 | Security Awareness Training | Developer security training |
| 16 | Application Software Security | SAST, DAST, code review |

#### CIS Level 2 - Application Hardening

```go
package config

import (
    "os"
    "strconv"
    "time"
)

// SecureConfig implements CIS Level 2 hardening
type SecureConfig struct {
    // Network hardening
    ListenAddress   string        // Bind to specific interface
    ReadTimeout     time.Duration // Prevent slowloris
    WriteTimeout    time.Duration
    IdleTimeout     time.Duration
    MaxHeaderBytes  int
    
    // Security settings
    TLSMinVersion   uint16
    EnableHSTS      bool
    HSTSMaxAge      int
    
    // Rate limiting
    RateLimitRPS    float64
    RateLimitBurst  int
    
    // Session management
    SessionTimeout  time.Duration
    SessionSecure   bool
}

func LoadSecureConfig() *SecureConfig {
    return &SecureConfig{
        // CIS 4.1 - Limit listening interfaces
        ListenAddress: getEnv("LISTEN_ADDR", "127.0.0.1:8443"),
        
        // CIS 9.4 - Connection timeouts
        ReadTimeout:    15 * time.Second,
        WriteTimeout:   15 * time.Second,
        IdleTimeout:    60 * time.Second,
        MaxHeaderBytes: 1 << 20, // 1 MB
        
        // CIS 3.10 - Encrypt sensitive data in transit
        TLSMinVersion: tls.VersionTLS12,
        EnableHSTS:    true,
        HSTSMaxAge:    31536000, // 1 year
        
        // CIS 13.1 - Rate limiting
        RateLimitRPS:   10,
        RateLimitBurst: 20,
        
        // CIS 5.2 - Session management
        SessionTimeout: 30 * time.Minute,
        SessionSecure:  true,
    }
}

func getEnv(key, defaultVal string) string {
    if val := os.Getenv(key); val != "" {
        return val
    }
    return defaultVal
}
```

---

### FIPS 140-3 Compliance

#### Go FIPS 140-3 Implementation (Go 1.24+)

**Overview:**
Starting with Go 1.24, Go provides native FIPS 140-3 compliance through the Go Cryptographic Module. The module is validated through CMVP and provides approved algorithms for use in regulated environments.

**Enabling FIPS Mode:**

```bash
# Build with FIPS 140-3 mode
GOFIPS140=v1.0.0 go build -o myapp ./...

# Or use latest frozen version
GOFIPS140=latest go build -o myapp ./...
```

**Runtime Configuration:**
```bash
# Enable FIPS mode at runtime
GODEBUG=fips140=on ./myapp

# Strict mode - errors on non-FIPS operations
GODEBUG=fips140=only ./myapp
```

**Programmatic Check:**
```go
package main

import (
    "crypto/fips140"
    "log"
)

func main() {
    if fips140.Enabled() {
        log.Println("FIPS 140-3 mode is active")
    } else {
        log.Println("FIPS 140-3 mode is NOT active")
    }
}
```

#### FIPS 140-3 Approved Algorithms in Go

| Category | Algorithm | Go Package | Status |
|----------|-----------|------------|--------|
| Symmetric | AES (128/192/256) | `crypto/aes` | Approved |
| Symmetric | AES-GCM | `crypto/cipher` | Approved |
| Hash | SHA-256/384/512 | `crypto/sha256`, `crypto/sha512` | Approved |
| Hash | SHA-3 | `crypto/sha3` (x/crypto) | Approved |
| MAC | HMAC-SHA256 | `crypto/hmac` | Approved |
| Signature | ECDSA (P-256, P-384) | `crypto/ecdsa` | Approved |
| Signature | Ed25519 | `crypto/ed25519` | Approved |
| Signature | RSA (2048+ bits) | `crypto/rsa` | Approved |
| Key Exchange | ECDH (P-256, P-384) | `crypto/ecdh` | Approved |
| Key Exchange | X25519 | `crypto/ecdh` | Approved |
| RNG | DRBG (SP 800-90A) | `crypto/rand` | Approved |
| KDF | HKDF | `golang.org/x/crypto/hkdf` | Approved |

#### Non-FIPS Algorithms (Avoid in FIPS Mode)

| Algorithm | Go Package | Status |
|-----------|------------|--------|
| MD5 | `crypto/md5` | NOT Approved |
| SHA-1 (signing) | `crypto/sha1` | NOT Approved |
| DES/3DES | `crypto/des` | NOT Approved |
| RC4 | `crypto/rc4` | NOT Approved |
| Blowfish | `golang.org/x/crypto/blowfish` | NOT Approved |

#### FIPS-Compliant TLS Configuration

```go
package server

import (
    "crypto/tls"
)

// GetFIPSCompliantTLSConfig returns TLS config for FIPS 140-3 compliance
func GetFIPSCompliantTLSConfig() *tls.Config {
    return &tls.Config{
        // TLS 1.2 minimum, TLS 1.3 preferred
        MinVersion: tls.VersionTLS12,
        
        // FIPS-approved cipher suites only
        // In FIPS mode, Go automatically filters to approved suites
        CipherSuites: []uint16{
            // TLS 1.3 suites (auto-negotiated, all FIPS-approved)
            
            // TLS 1.2 FIPS-approved suites
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
        
        // FIPS-approved curves
        CurvePreferences: []tls.CurveID{
            tls.CurveP384,
            tls.CurveP256,
            // X25519 is also FIPS-approved in Go 1.24+
            tls.X25519,
        },
    }
}
```

#### FIPS 140-3 Mode Behavior Changes

| Feature | Standard Mode | FIPS Mode |
|---------|--------------|-----------|
| Integrity Check | None | Automatic self-check at init |
| Algorithm Tests | None | Known-answer tests on first use |
| Key Pair Tests | None | Pairwise consistency tests |
| RNG | OS CSPRNG | DRBG + OS CSPRNG mixed |
| TLS | All suites | FIPS-approved suites only |
| RSA-PSS Salt | Auto-length | Capped at hash length |
| Key Generation | Standard | Up to 2x slower |

---

## Compliance Checklists

### Pre-Deployment Security Checklist

#### Code Security
- [ ] All dependencies scanned with `govulncheck`
- [ ] Code analyzed with `gosec` (no high/critical findings)
- [ ] Static analysis completed with `staticcheck`
- [ ] Race condition testing with `-race` flag
- [ ] Fuzz testing implemented for parsers/validators
- [ ] No hardcoded credentials (G101 check passed)
- [ ] All SQL queries use parameterized statements
- [ ] Input validation on all user inputs

#### Cryptography
- [ ] Using approved cryptographic algorithms
- [ ] Random numbers from `crypto/rand` only
- [ ] Passwords hashed with Argon2id or bcrypt
- [ ] TLS 1.2+ with approved cipher suites
- [ ] FIPS mode enabled if required (`GOFIPS140=v1.0.0`)
- [ ] No weak algorithms (MD5, SHA1 for security, DES)

#### Authentication & Authorization
- [ ] Secure session management implemented
- [ ] Cookies set with HttpOnly, Secure, SameSite
- [ ] Rate limiting on authentication endpoints
- [ ] Account lockout after failed attempts
- [ ] Role-based access control implemented
- [ ] Resource ownership verified

#### Error Handling & Logging
- [ ] Generic error messages to clients
- [ ] Detailed logging for internal debugging
- [ ] No stack traces in production responses
- [ ] Request IDs for log correlation
- [ ] Sensitive data not logged

#### Network Security
- [ ] Security headers implemented (HSTS, CSP, etc.)
- [ ] Request size limits enforced
- [ ] Timeouts configured (read, write, idle)
- [ ] Rate limiting implemented
- [ ] CORS properly configured

### CI/CD Security Pipeline

```yaml
# .github/workflows/security.yml
name: Security Checks

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      
      - name: Run govulncheck
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...
      
      - name: Run gosec
        uses: securego/gosec@master
        with:
          args: '-fmt sarif -out results.sarif ./...'
      
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      
      - name: Run staticcheck
        uses: dominikh/staticcheck-action@v1
        with:
          version: "latest"
      
      - name: Run race detector
        run: go test -race ./...
      
      - name: Run tests with coverage
        run: go test -coverprofile=coverage.out ./...
      
      - name: Verify dependencies
        run: go mod verify
```

### Compliance Mapping Summary

| Standard | Key Requirements | Go Tools/Features |
|----------|-----------------|-------------------|
| NIST 800-53 | Access control, audit, crypto | RBAC middleware, slog, crypto/tls |
| OWASP Top 10 | Injection, auth, components | Parameterized queries, govulncheck |
| DISA STIG | DoD security requirements | FIPS mode, TLS config, logging |
| CIS Level 2 | Hardening, monitoring | Secure config, timeouts, rate limits |
| FIPS 140-3 | Cryptographic compliance | GOFIPS140=v1.0.0, crypto/fips140 |

---

## References

### Official Go Security Resources
- [Go Security Best Practices](https://go.dev/doc/security/best-practices) - Official Go security documentation
- [FIPS 140-3 Compliance](https://go.dev/doc/security/fips140) - Go FIPS 140-3 implementation guide
- [SQL Injection Prevention](https://go.dev/doc/database/sql-injection) - Official SQL injection guidance
- [Go Vulnerability Database](https://pkg.go.dev/vuln/) - Official vulnerability database
- [Go Release History](https://go.dev/doc/devel/release) - Security patches and updates

### Security Tools
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - Official vulnerability scanner
- [gosec](https://github.com/securego/gosec) - Go security checker (8.7k+ stars)
- [staticcheck](https://github.com/dominikh/go-tools) - Advanced Go linter
- [golangci-lint](https://github.com/golangci/golangci-lint) - Aggregated linting tool

### Security Standards
- [NIST SP 800-53 Rev 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) - Security and Privacy Controls
- [NIST SP 800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final) - Secure Software Development Framework
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web Application Security Risks
- [OWASP Go-SCP](https://github.com/OWASP/Go-SCP) - Go Secure Coding Practices
- [DISA STIG](https://public.cyber.mil/stigs/) - Security Technical Implementation Guides
- [CIS Controls](https://www.cisecurity.org/controls) - Critical Security Controls

### Cryptography References
- [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final) - Cryptographic Module Validation
- [NIST SP 800-131A](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final) - Transitioning Cryptographic Algorithms

### Additional Resources
- [The Go Blog - Security](https://go.dev/blog/) - Official Go blog security posts
- [Trail of Bits - Go Security Assessment](https://blog.trailofbits.com/2019/11/07/attacking-go-vr-ttps/) - Security assessment techniques
- [JetBrains GoLand Blog - Secure Error Handling](https://blog.jetbrains.com/go/2026/03/02/secure-go-error-handling-best-practices/) - Error handling best practices

---

**Document Information:**
- **Author:** Matrix Agent
- **Created:** March 2026
- **Go Versions Covered:** 1.22, 1.23, 1.24+
- **Standards Referenced:** NIST SP 800-53 Rev 5, OWASP Top 10 2021/2025, DISA STIG V5, CIS Controls v8, FIPS 140-3

---

*This guide should be reviewed and updated regularly as Go releases new versions and security standards evolve.*
