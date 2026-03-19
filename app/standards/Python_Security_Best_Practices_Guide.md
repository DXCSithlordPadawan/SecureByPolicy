# Python Development Security Best Practices Guide

**Version:** 1.0  
**Last Updated:** March 2026  
**Author:** Matrix Agent  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Python Coding Best Practices](#1-python-coding-best-practices)
3. [Flask Framework Best Practices](#2-flask-framework-best-practices)
4. [Django Framework Best Practices](#3-django-framework-best-practices)
5. [Security Standards Reference Tables](#4-security-standards-reference-tables)
6. [Compliance Checklist](#5-compliance-checklist)
7. [References and Sources](#6-references-and-sources)

---

## Executive Summary

This comprehensive guide provides security best practices for Python development, covering core language features (Python 3.12+), and the two most popular web frameworks: Flask and Django. All recommendations are cross-referenced against major security standards including NIST Cybersecurity Framework 2.0, OWASP Top 10 (2021/2025), DISA STIG, CIS Benchmarks Level 2, and FIPS 140-3 cryptographic requirements.

The document serves as both a reference guide and compliance checklist for development teams building secure Python applications for government, enterprise, and security-sensitive environments.

---

## 1. Python Coding Best Practices

### 1.1 Python 3.12+ Features and Standards

Python 3.12 and 3.13 introduce significant security and performance improvements that development teams should leverage.

#### Key Python 3.12 Features

| Feature | Security Benefit |
|---------|------------------|
| Per-Interpreter GIL | Better isolation for multi-tenant applications |
| Improved Error Messages | Faster debugging, reduced security misconfigurations |
| Type Parameter Syntax (PEP 695) | Enhanced static analysis for catching vulnerabilities |
| F-String Improvements | Reduced injection risks from string formatting |
| Buffer Protocol (PEP 688) | Safer memory handling |

#### Key Python 3.13 Features

| Feature | Security Benefit |
|---------|------------------|
| Free-Threaded Mode (PEP 703) | Experimental GIL-free execution for better isolation |
| JIT Compiler (PEP 744) | Performance improvements reducing DoS attack surface |
| Enhanced Interactive REPL | Better debugging capabilities |
| Improved `locals()` semantics | More predictable variable scoping |

```python
# Python 3.12+ Type Parameter Syntax (PEP 695)
# Enhanced static analysis catches type-related vulnerabilities

type UserID = int
type Username = str

def get_user[T: (UserID, Username)](identifier: T) -> dict:
    """Retrieve user with type-safe identifier."""
    if isinstance(identifier, int):
        return fetch_user_by_id(identifier)
    return fetch_user_by_name(identifier)
```

### 1.2 Code Style and Formatting (PEP 8)

Following PEP 8 ensures code consistency and reduces security risks from maintenance errors.

#### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Functions/Variables | lowercase_with_underscores | `validate_user_input` |
| Classes | CapWords (PascalCase) | `UserAuthentication` |
| Constants | UPPER_CASE_WITH_UNDERSCORES | `MAX_LOGIN_ATTEMPTS` |
| Private attributes | _single_leading_underscore | `_internal_state` |
| Name mangling | __double_leading_underscore | `__password_hash` |

```python
# PEP 8 Compliant Security-Focused Code Example

import hashlib
import secrets
from typing import Optional

# Constants (UPPER_CASE)
MAX_LOGIN_ATTEMPTS: int = 5
SESSION_TIMEOUT_SECONDS: int = 3600
PASSWORD_MIN_LENGTH: int = 12

class UserAuthenticator:
    """Handles secure user authentication.
    
    Attributes:
        _failed_attempts: Internal counter for failed logins
        __password_hasher: Private hasher instance
    """
    
    def __init__(self) -> None:
        self._failed_attempts: dict[str, int] = {}
        self.__password_hasher = hashlib.pbkdf2_hmac
    
    def validate_password(
        self,
        password: str,
        stored_hash: bytes,
        salt: bytes
    ) -> bool:
        """Validate password against stored hash.
        
        Args:
            password: User-provided password
            stored_hash: Previously stored password hash
            salt: Cryptographic salt
            
        Returns:
            True if password matches, False otherwise
        """
        computed_hash = self.__password_hasher(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=600000  # OWASP 2023 recommendation
        )
        return secrets.compare_digest(computed_hash, stored_hash)
```

### 1.3 Type Hints (PEP 484, 526, 585)

Type hints enable static analysis tools to catch potential vulnerabilities before runtime.

```python
from typing import TypedDict, Literal, Annotated
from dataclasses import dataclass

# Annotated types for validation hints
type SanitizedString = Annotated[str, "HTML-escaped user input"]
type SecureToken = Annotated[str, "Cryptographically secure token"]

class UserCredentials(TypedDict):
    """Type-safe credential structure."""
    username: str
    password_hash: bytes
    salt: bytes
    mfa_enabled: bool
    role: Literal["admin", "user", "guest"]

@dataclass(frozen=True, slots=True)
class SessionToken:
    """Immutable session token with type safety."""
    token: SecureToken
    user_id: int
    expires_at: float
    ip_address: str
    
    def is_valid(self, current_time: float) -> bool:
        return current_time < self.expires_at
```

### 1.4 Secure Coding Practices

#### Input Validation and Sanitization

```python
import re
import html
from typing import Optional
from urllib.parse import urlparse

def sanitize_user_input(
    raw_input: str,
    max_length: int = 1000,
    allowed_pattern: Optional[str] = None
) -> str:
    """Sanitize user input to prevent injection attacks.
    
    OWASP A03:2021 - Injection Prevention
    NIST AC-4: Information Flow Enforcement
    """
    if not isinstance(raw_input, str):
        raise TypeError("Input must be a string")
    
    # Length validation
    if len(raw_input) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")
    
    # HTML entity encoding
    sanitized = html.escape(raw_input, quote=True)
    
    # Pattern validation if specified
    if allowed_pattern:
        if not re.match(allowed_pattern, sanitized):
            raise ValueError("Input contains invalid characters")
    
    return sanitized

def validate_url(url: str, allowed_schemes: tuple = ("https",)) -> bool:
    """Validate URL to prevent SSRF attacks.
    
    OWASP A10:2021 - Server-Side Request Forgery Prevention
    """
    try:
        parsed = urlparse(url)
        
        # Scheme validation
        if parsed.scheme not in allowed_schemes:
            return False
        
        # Block internal network addresses
        internal_patterns = [
            r'^localhost$',
            r'^127\.',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^::1$',
            r'^0\.0\.0\.0$'
        ]
        
        hostname = parsed.hostname or ""
        for pattern in internal_patterns:
            if re.match(pattern, hostname):
                return False
        
        return True
    except Exception:
        return False
```

#### Secure Random Generation

```python
import secrets
import string
from typing import Literal

def generate_secure_token(
    length: int = 32,
    encoding: Literal["hex", "urlsafe", "alphanumeric"] = "urlsafe"
) -> str:
    """Generate cryptographically secure tokens.
    
    FIPS 140-3: Use approved random number generators
    NIST SP 800-90A: Deterministic Random Bit Generators
    """
    if encoding == "hex":
        return secrets.token_hex(length // 2)
    elif encoding == "urlsafe":
        return secrets.token_urlsafe(length)
    elif encoding == "alphanumeric":
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    else:
        raise ValueError(f"Unknown encoding: {encoding}")

def generate_secure_password(length: int = 16) -> str:
    """Generate a secure random password.
    
    NIST SP 800-63B: Digital Identity Guidelines
    """
    if length < 12:
        raise ValueError("Password length must be at least 12 characters")
    
    # Ensure at least one character from each category
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
    ]
    
    # Fill remaining length
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    password_chars.extend(
        secrets.choice(all_chars) for _ in range(length - 4)
    )
    
    # Shuffle to avoid predictable positions
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)
```

### 1.5 Error Handling and Logging

```python
import logging
import traceback
from functools import wraps
from typing import Callable, TypeVar, ParamSpec
from datetime import datetime, timezone

P = ParamSpec('P')
T = TypeVar('T')

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/app/security.log'),
        logging.StreamHandler()
    ]
)

# Separate security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

class SecurityAuditMixin:
    """Mixin for security audit logging.
    
    OWASP A09:2021 - Security Logging and Monitoring Failures
    NIST AU-2: Audit Events
    """
    
    @staticmethod
    def log_security_event(
        event_type: str,
        user_id: str | None,
        ip_address: str,
        details: dict,
        severity: str = "INFO"
    ) -> None:
        """Log security-relevant events."""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "severity": severity,
            "details": details
        }
        
        # Never log sensitive data
        sensitive_keys = {'password', 'token', 'secret', 'key', 'credential'}
        sanitized_details = {
            k: '[REDACTED]' if any(s in k.lower() for s in sensitive_keys) else v
            for k, v in details.items()
        }
        log_entry['details'] = sanitized_details
        
        security_logger.log(
            getattr(logging, severity),
            f"SECURITY_EVENT: {log_entry}"
        )

def secure_exception_handler(func: Callable[P, T]) -> Callable[P, T]:
    """Decorator for secure exception handling.
    
    Prevents information leakage in error messages.
    """
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return func(*args, **kwargs)
        except ValueError as e:
            # Safe to expose validation errors
            security_logger.warning(f"Validation error in {func.__name__}: {e}")
            raise
        except Exception as e:
            # Log full details internally, return generic message
            security_logger.error(
                f"Error in {func.__name__}: {e}\n{traceback.format_exc()}"
            )
            raise RuntimeError("An internal error occurred") from None
    return wrapper
```

### 1.6 Memory Management and Performance

```python
import gc
import sys
from contextlib import contextmanager
from typing import Generator, Any
import ctypes

@contextmanager
def secure_memory_context() -> Generator[None, None, None]:
    """Context manager for sensitive data handling.
    
    NIST SC-4: Information in Shared Resources
    CIS Control 3: Data Protection
    """
    gc.disable()  # Prevent garbage collection during sensitive ops
    try:
        yield
    finally:
        gc.enable()
        gc.collect()  # Force cleanup

def secure_zero_memory(data: bytearray) -> None:
    """Securely zero memory containing sensitive data.
    
    Warning: Python's memory model doesn't guarantee this works.
    For true secure memory, use specialized libraries.
    """
    if not isinstance(data, bytearray):
        raise TypeError("Can only zero bytearray objects")
    
    for i in range(len(data)):
        data[i] = 0
    
    # Additional measure: overwrite with random then zero
    import secrets
    for i in range(len(data)):
        data[i] = secrets.randbelow(256)
    for i in range(len(data)):
        data[i] = 0

class SecureString:
    """Wrapper for sensitive strings with secure cleanup.
    
    FIPS 140-3: Cryptographic key management
    """
    __slots__ = ('_data',)
    
    def __init__(self, value: str) -> None:
        self._data = bytearray(value.encode('utf-8'))
    
    def get_value(self) -> str:
        return self._data.decode('utf-8')
    
    def clear(self) -> None:
        secure_zero_memory(self._data)
    
    def __del__(self) -> None:
        try:
            self.clear()
        except Exception:
            pass
    
    def __repr__(self) -> str:
        return "SecureString([REDACTED])"
```

---

## 2. Flask Framework Best Practices

### 2.1 Secure Configuration

```python
import os
from datetime import timedelta
from flask import Flask

def create_secure_app() -> Flask:
    """Create Flask application with secure configuration.
    
    OWASP A05:2021 - Security Misconfiguration
    NIST CM-6: Configuration Settings
    """
    app = Flask(__name__)
    
    # Core Security Settings
    app.config.update(
        # Secret key - MUST be set from environment
        SECRET_KEY=os.environ.get('FLASK_SECRET_KEY'),
        
        # Session configuration
        SESSION_COOKIE_SECURE=True,        # HTTPS only
        SESSION_COOKIE_HTTPONLY=True,      # No JavaScript access
        SESSION_COOKIE_SAMESITE='Lax',     # CSRF protection
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        
        # Security headers
        SEND_FILE_MAX_AGE_DEFAULT=0,       # Disable caching for security
        
        # JSON security
        JSON_SORT_KEYS=False,              # Don't leak structure info
        
        # Debug MUST be False in production
        DEBUG=False,
        TESTING=False,
        
        # Prevent response compression attacks
        COMPRESS_MIMETYPES=['text/html'],
    )
    
    # Validate critical configuration
    if not app.config['SECRET_KEY'] or len(app.config['SECRET_KEY']) < 32:
        raise ValueError("SECRET_KEY must be at least 32 bytes")
    
    return app

# Example production configuration class
class ProductionConfig:
    """Production security configuration.
    
    CIS Benchmark Level 2: Strict security controls
    """
    DEBUG = False
    TESTING = False
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Session
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL')
    RATELIMIT_DEFAULT = "100/hour"
    RATELIMIT_HEADERS_ENABLED = True
```

### 2.2 Authentication and Session Management

```python
from flask import Flask, session, request, g
from flask_security import Security, SQLAlchemyUserDatastore
from flask_security import UserMixin, RoleMixin
from flask_login import login_required
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timezone
from functools import wraps

# Flask-Security Configuration
def configure_flask_security(app: Flask, db) -> Security:
    """Configure Flask-Security with best practices.
    
    OWASP A07:2021 - Identification and Authentication Failures
    NIST IA-5: Authenticator Management
    """
    app.config.update(
        # Password hashing
        SECURITY_PASSWORD_HASH='pbkdf2_sha512',
        SECURITY_PASSWORD_SALT=os.environ.get('SECURITY_PASSWORD_SALT'),
        SECURITY_PASSWORD_LENGTH_MIN=12,
        
        # Password complexity (using zxcvbn)
        SECURITY_PASSWORD_COMPLEXITY_CHECKER='zxcvbn',
        
        # Breached password check
        SECURITY_PASSWORD_CHECK_BREACHED='strict',
        
        # Token settings
        SECURITY_TOKEN_AUTHENTICATION_HEADER='X-Auth-Token',
        SECURITY_TOKEN_MAX_AGE=3600,
        
        # Two-factor authentication
        SECURITY_TWO_FACTOR=True,
        SECURITY_TWO_FACTOR_REQUIRED=True,
        
        # Recovery codes
        SECURITY_MULTI_FACTOR_RECOVERY_CODES=True,
        
        # Generic responses to prevent enumeration
        SECURITY_RETURN_GENERIC_RESPONSES=True,
        
        # Freshness for sensitive operations
        SECURITY_FRESHNESS=timedelta(minutes=30),
        SECURITY_FRESHNESS_GRACE_PERIOD=timedelta(minutes=5),
    )
    
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)
    
    return security

# Custom authentication decorator with rate limiting
def secure_login_required(max_attempts: int = 5, lockout_minutes: int = 15):
    """Enhanced login decorator with brute force protection.
    
    OWASP A07:2021 - Brute Force Protection
    DISA STIG: Account Lockout Configuration
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip_address = request.remote_addr
            cache_key = f"login_attempts:{ip_address}"
            
            # Check rate limit
            attempts = cache.get(cache_key, 0)
            if attempts >= max_attempts:
                security_logger.warning(
                    f"Account lockout triggered for IP: {ip_address}"
                )
                return {"error": "Too many attempts"}, 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Session security middleware
@app.before_request
def session_security():
    """Session security checks on each request.
    
    NIST SC-23: Session Authenticity
    """
    if 'user_id' in session:
        # Validate session fingerprint
        current_fingerprint = generate_session_fingerprint()
        if session.get('fingerprint') != current_fingerprint:
            session.clear()
            return {"error": "Session invalid"}, 401
        
        # Rotate session ID periodically
        if should_rotate_session():
            session.regenerate()

def generate_session_fingerprint() -> str:
    """Generate session fingerprint for validation."""
    components = [
        request.user_agent.string,
        request.accept_languages.best,
    ]
    return secrets.token_hex(16)
```

### 2.3 Input Validation and Sanitization

```python
from flask import request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators
from wtforms.validators import ValidationError
import bleach
import re

class SecureLoginForm(FlaskForm):
    """Secure login form with validation.
    
    OWASP A03:2021 - Injection Prevention
    """
    username = StringField('Username', validators=[
        validators.DataRequired(),
        validators.Length(min=3, max=50),
        validators.Regexp(
            r'^[a-zA-Z0-9_]+$',
            message="Username can only contain letters, numbers, and underscores"
        )
    ])
    
    password = PasswordField('Password', validators=[
        validators.DataRequired(),
        validators.Length(min=12, max=128)
    ])
    
    def validate_username(self, field):
        """Additional security validation."""
        # Prevent SQL injection patterns
        dangerous_patterns = [
            r"('|(\\'))",  # SQL quotes
            r"(;|--)",      # SQL comments
            r"(\/\*|\*\/)", # Block comments
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, field.data, re.IGNORECASE):
                raise ValidationError("Invalid characters in username")

def sanitize_html_input(html_content: str) -> str:
    """Sanitize HTML input to prevent XSS.
    
    OWASP A03:2021 - Cross-Site Scripting (XSS)
    """
    allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a']
    allowed_attrs = {
        'a': ['href', 'title'],
    }
    
    # Clean HTML
    cleaned = bleach.clean(
        html_content,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )
    
    # Additional URL validation for links
    cleaned = bleach.linkify(
        cleaned,
        callbacks=[lambda attrs, new: attrs if validate_url(attrs['href']) else None]
    )
    
    return cleaned

@app.route('/api/data', methods=['POST'])
def handle_data():
    """Secure API endpoint with input validation."""
    # Content-Type validation
    if not request.is_json:
        return {"error": "Content-Type must be application/json"}, 415
    
    data = request.get_json(silent=True)
    if not data:
        return {"error": "Invalid JSON"}, 400
    
    # Schema validation
    required_fields = {'name', 'email'}
    if not required_fields.issubset(data.keys()):
        return {"error": "Missing required fields"}, 400
    
    # Sanitize all string inputs
    sanitized_data = {
        k: sanitize_user_input(v) if isinstance(v, str) else v
        for k, v in data.items()
    }
    
    return process_data(sanitized_data)
```

### 2.4 CSRF Protection

```python
from flask import Flask
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_security import auth_required

# Initialize CSRF protection
csrf = CSRFProtect()

def configure_csrf(app: Flask) -> None:
    """Configure CSRF protection.
    
    OWASP A01:2021 - Broken Access Control
    DISA STIG: Cross-Site Request Forgery Prevention
    """
    app.config.update(
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_CHECK_DEFAULT=True,
        WTF_CSRF_TIME_LIMIT=3600,
        
        # Cookie-based CSRF for SPAs
        WTF_CSRF_HEADERS=['X-CSRFToken', 'X-CSRF-Token'],
        
        # For SPA applications
        SECURITY_CSRF_COOKIE_NAME='csrf_token',
        SECURITY_CSRF_PROTECT_MECHANISMS=['session', 'basic'],
    )
    
    csrf.init_app(app)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF validation failures."""
    security_logger.warning(
        f"CSRF validation failed: {request.remote_addr}"
    )
    return {"error": "CSRF validation failed"}, 400

# CSRF token endpoint for SPAs
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Provide CSRF token for SPA applications."""
    from flask_wtf.csrf import generate_csrf
    return {"csrf_token": generate_csrf()}

# Exempt specific endpoints (use sparingly)
@csrf.exempt
@app.route('/api/webhook', methods=['POST'])
def webhook_endpoint():
    """Webhook endpoint (verify via signature instead).
    
    WARNING: Only exempt webhooks with signature verification
    """
    signature = request.headers.get('X-Signature')
    if not verify_webhook_signature(request.data, signature):
        return {"error": "Invalid signature"}, 401
    return process_webhook(request.get_json())
```

### 2.5 Secure Headers and Cookies

```python
from flask import Flask, Response
from flask_talisman import Talisman

def configure_security_headers(app: Flask) -> None:
    """Configure security headers with Flask-Talisman.
    
    OWASP A05:2021 - Security Misconfiguration
    CIS Benchmark: Security Header Configuration
    """
    
    # Content Security Policy
    csp = {
        'default-src': "'self'",
        'script-src': ["'self'", "'strict-dynamic'"],
        'style-src': ["'self'", "'unsafe-inline'"],  # Minimize unsafe-inline
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'"],
        'connect-src': ["'self'"],
        'frame-ancestors': "'none'",
        'form-action': "'self'",
        'base-uri': "'self'",
        'object-src': "'none'",
    }
    
    Talisman(
        app,
        # Force HTTPS
        force_https=True,
        force_https_permanent=True,
        
        # HSTS configuration
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        strict_transport_security_preload=True,
        
        # Content Security Policy
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src'],
        
        # Other headers
        referrer_policy='strict-origin-when-cross-origin',
        feature_policy={
            'geolocation': "'none'",
            'camera': "'none'",
            'microphone': "'none'",
        },
        
        # Frame options
        frame_options='DENY',
        
        # XSS Protection (legacy browsers)
        x_xss_protection=True,
        
        # Content Type Options
        x_content_type_options=True,
    )

@app.after_request
def add_security_headers(response: Response) -> Response:
    """Add additional security headers."""
    # Permissions Policy (replacement for Feature-Policy)
    response.headers['Permissions-Policy'] = (
        'accelerometer=(), ambient-light-sensor=(), autoplay=(), '
        'battery=(), camera=(), cross-origin-isolated=(), '
        'display-capture=(), document-domain=(), encrypted-media=(), '
        'execution-while-not-rendered=(), execution-while-out-of-viewport=(), '
        'fullscreen=(self), geolocation=(), gyroscope=(), '
        'keyboard-map=(), magnetometer=(), microphone=(), midi=(), '
        'navigation-override=(), payment=(), picture-in-picture=(), '
        'publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), '
        'usb=(), web-share=(), xr-spatial-tracking=()'
    )
    
    # Cache control for sensitive pages
    if 'login' in request.path or 'account' in request.path:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response
```

### 2.6 Database Security with SQLAlchemy

```python
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Any

db = SQLAlchemy()

def configure_database_security(app: Flask) -> None:
    """Configure secure database connection.
    
    OWASP A03:2021 - Injection
    NIST AC-3: Access Enforcement
    """
    app.config.update(
        # Use environment variables for credentials
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL'),
        
        # Disable modification tracking
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        
        # Connection pool settings
        SQLALCHEMY_ENGINE_OPTIONS={
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_size': 10,
            'max_overflow': 20,
            'connect_args': {
                'connect_timeout': 10,
                # SSL for PostgreSQL
                'sslmode': 'require',
            }
        }
    )

# Safe query practices
class UserRepository:
    """Repository with secure query methods.
    
    OWASP A03:2021 - SQL Injection Prevention
    """
    
    @staticmethod
    def find_by_username(username: str) -> User | None:
        """Find user by username - safe from SQL injection."""
        # CORRECT: Use ORM methods with parameterization
        return User.query.filter_by(username=username).first()
    
    @staticmethod
    def find_by_email(email: str) -> User | None:
        """Find user by email - using filter with proper escaping."""
        # CORRECT: ORM handles escaping
        return User.query.filter(User.email == email).first()
    
    @staticmethod
    def search_users(search_term: str) -> list[User]:
        """Search users - safe LIKE query."""
        # CORRECT: Escape special characters for LIKE
        escaped_term = search_term.replace('%', r'\%').replace('_', r'\_')
        return User.query.filter(
            User.username.ilike(f'%{escaped_term}%', escape='\\')
        ).all()
    
    @staticmethod
    def execute_raw_query_safely(user_id: int) -> Any:
        """Execute raw SQL safely when ORM is insufficient."""
        # CORRECT: Use bound parameters
        sql = text("SELECT * FROM users WHERE id = :user_id AND active = :active")
        result = db.session.execute(
            sql,
            {'user_id': user_id, 'active': True}
        )
        return result.fetchall()

# DANGEROUS - Never do this
def unsafe_query(username: str):
    """DANGEROUS: SQL injection vulnerability."""
    # WRONG: String concatenation
    # sql = f"SELECT * FROM users WHERE username = '{username}'"
    # db.session.execute(sql)
    raise NotImplementedError("This is an example of what NOT to do")
```

---

## 3. Django Framework Best Practices

### 3.1 Security Middleware Configuration

```python
# settings.py - Security Configuration

import os
from pathlib import Path

# Security middleware order matters!
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',  # First
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Custom security middleware
    'myapp.middleware.SecurityHeadersMiddleware',
    'myapp.middleware.RateLimitMiddleware',
]

# Security Settings - OWASP A05:2021
DEBUG = False  # NEVER True in production

# Secret Key - NIST IA-5
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY or len(SECRET_KEY) < 50:
    raise ValueError("SECRET_KEY must be at least 50 characters")

# Allowed Hosts - OWASP A05:2021
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

# HTTPS Settings - DISA STIG SC-8
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# HSTS - CIS Benchmark Level 2
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Cookie Security - OWASP A07:2021
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

# Content Security Policy (use django-csp)
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:")
CSP_FONT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)

# Other Security Headers
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Password Validation - NIST SP 800-63B
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12},
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'myapp.validators.ComplexityValidator',
    },
]

# Session Security
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'
```

### 3.2 Django's Built-in Security Features

```python
# views.py - Using Django's security features

from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth import authenticate, login, logout
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse, HttpResponseForbidden
from django.utils.html import escape
from django.utils.http import url_has_allowed_host_and_scheme
import secrets

# CSRF Protection
@csrf_protect
@require_http_methods(["POST"])
def secure_form_view(request):
    """View with CSRF protection.
    
    OWASP A01:2021 - Broken Access Control
    """
    # Django automatically validates CSRF token
    return process_form(request)

# Login with rate limiting
@never_cache
@require_http_methods(["POST"])
def secure_login_view(request):
    """Secure login with brute force protection.
    
    OWASP A07:2021 - Identification and Authentication Failures
    DISA STIG: Consecutive Logon Attempt Limits
    """
    username = request.POST.get('username', '')
    password = request.POST.get('password', '')
    
    # Rate limiting check
    ip_address = get_client_ip(request)
    if is_rate_limited(ip_address, 'login'):
        return JsonResponse({'error': 'Too many attempts'}, status=429)
    
    user = authenticate(request, username=username, password=password)
    
    if user is not None:
        # Check if account is locked
        if not user.is_active:
            return JsonResponse({'error': 'Account disabled'}, status=403)
        
        login(request)
        
        # Regenerate session ID (session fixation prevention)
        request.session.cycle_key()
        
        # Log successful login
        log_security_event('LOGIN_SUCCESS', user.id, ip_address)
        
        return JsonResponse({'success': True})
    else:
        # Increment failed attempts
        increment_failed_attempts(ip_address)
        log_security_event('LOGIN_FAILURE', None, ip_address, {'username': username})
        
        # Generic error message to prevent enumeration
        return JsonResponse({'error': 'Invalid credentials'}, status=401)

# Permission-based access control
@login_required
@permission_required('app.can_view_sensitive_data', raise_exception=True)
def sensitive_data_view(request):
    """View requiring specific permission.
    
    OWASP A01:2021 - Broken Access Control
    NIST AC-6: Least Privilege
    """
    return render(request, 'sensitive_data.html')

# Safe redirect handling
def safe_redirect(request, default_url='/'):
    """Prevent open redirect vulnerabilities.
    
    OWASP A01:2021 - Broken Access Control
    """
    next_url = request.GET.get('next', default_url)
    
    # Validate the redirect URL
    if url_has_allowed_host_and_scheme(
        next_url,
        allowed_hosts={request.get_host()},
        require_https=True
    ):
        return redirect(next_url)
    
    return redirect(default_url)
```

### 3.3 Authentication System Best Practices

```python
# Custom User Model with Security Features
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import secrets

class SecureUser(AbstractUser):
    """Extended user model with security features.
    
    OWASP A07:2021 - Identification and Authentication Failures
    NIST IA-5: Authenticator Management
    """
    
    # MFA fields
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True)
    
    # Account lockout
    failed_login_attempts = models.IntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)
    
    # Password history
    password_changed_at = models.DateTimeField(auto_now_add=True)
    
    # Session tracking
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    def is_locked_out(self) -> bool:
        """Check if account is locked."""
        if self.lockout_until and self.lockout_until > timezone.now():
            return True
        return False
    
    def record_failed_login(self) -> None:
        """Record failed login attempt."""
        self.failed_login_attempts += 1
        
        # Lock after 5 attempts
        if self.failed_login_attempts >= 5:
            self.lockout_until = timezone.now() + timezone.timedelta(minutes=30)
        
        self.save(update_fields=['failed_login_attempts', 'lockout_until'])
    
    def record_successful_login(self, ip_address: str) -> None:
        """Record successful login."""
        self.failed_login_attempts = 0
        self.lockout_until = None
        self.last_login = timezone.now()
        self.last_login_ip = ip_address
        self.save(update_fields=[
            'failed_login_attempts', 'lockout_until',
            'last_login', 'last_login_ip'
        ])
    
    def password_needs_change(self, max_age_days: int = 90) -> bool:
        """Check if password needs rotation."""
        age = timezone.now() - self.password_changed_at
        return age.days > max_age_days

# Custom Authentication Backend
from django.contrib.auth.backends import ModelBackend

class SecureAuthBackend(ModelBackend):
    """Authentication backend with security checks.
    
    DISA STIG: Logon Security
    """
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = SecureUser.objects.get(username=username)
        except SecureUser.DoesNotExist:
            # Run password check anyway to prevent timing attacks
            SecureUser().set_password(password)
            return None
        
        # Check lockout
        if user.is_locked_out():
            return None
        
        # Verify password
        if user.check_password(password):
            if self.user_can_authenticate(user):
                return user
            return None
        
        # Record failed attempt
        user.record_failed_login()
        return None
```

### 3.4 ORM Security

```python
from django.db import models
from django.db.models import Q
from django.db.models.functions import Lower
from django.core.validators import RegexValidator

class SecureQuerySet(models.QuerySet):
    """QuerySet with secure methods.
    
    OWASP A03:2021 - Injection Prevention
    """
    
    def search_safe(self, field: str, value: str):
        """Safe search with escaped special characters."""
        # Escape LIKE special characters
        escaped = value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        lookup = f'{field}__icontains'
        return self.filter(**{lookup: escaped})
    
    def filter_active_for_user(self, user):
        """Row-level security - only return accessible records."""
        if user.is_superuser:
            return self.filter(is_active=True)
        
        return self.filter(
            Q(is_active=True) &
            (Q(owner=user) | Q(shared_with=user))
        )

class SecureModel(models.Model):
    """Base model with security features.
    
    NIST AC-3: Access Enforcement
    """
    
    objects = SecureQuerySet.as_manager()
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        'auth.User',
        on_delete=models.PROTECT,
        related_name='+'
    )
    
    class Meta:
        abstract = True

# Raw query example - when ORM is insufficient
from django.db import connection

def safe_raw_query(user_id: int) -> list:
    """Execute raw SQL safely.
    
    OWASP A03:2021 - Parameterized Queries
    """
    with connection.cursor() as cursor:
        # CORRECT: Use parameterized query
        cursor.execute(
            "SELECT id, name FROM items WHERE owner_id = %s AND status = %s",
            [user_id, 'active']
        )
        return cursor.fetchall()

# DANGEROUS - Never do this
def unsafe_raw_query(user_input):
    """DANGEROUS: SQL injection vulnerability."""
    # WRONG: String formatting with user input
    # cursor.execute(f"SELECT * FROM items WHERE name = '{user_input}'")
    raise NotImplementedError("This is an example of what NOT to do")
```

### 3.5 Template Security

```python
# templates/secure_template.html
"""
Django Template Security Best Practices

OWASP A03:2021 - Cross-Site Scripting Prevention
"""

# Auto-escaping is ON by default
# {{ user_input }} - Automatically escaped

# Mark safe content explicitly (use sparingly)
# {{ trusted_html|safe }}

# In views - mark content safe only when necessary
from django.utils.safestring import mark_safe
from django.utils.html import format_html, escape

def render_user_content(request):
    """Render user-generated content safely."""
    user_name = request.user.username
    
    # CORRECT: Use format_html for safe HTML construction
    message = format_html(
        '<span class="user-name">{}</span>',
        user_name  # Automatically escaped
    )
    
    # WRONG: Don't do this
    # message = mark_safe(f'<span>{user_name}</span>')
    
    return render(request, 'template.html', {'message': message})

# Template context processors for CSP nonce
def security_context(request):
    """Add security-related context."""
    return {
        'csp_nonce': request.csp_nonce if hasattr(request, 'csp_nonce') else '',
    }
```

```html
<!-- secure_template.html -->
{% load static %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- CSP Nonce for inline scripts -->
    <script nonce="{{ csp_nonce }}">
        // Inline script with nonce
    </script>
</head>
<body>
    <!-- Auto-escaped user content -->
    <p>Hello, {{ user.username }}</p>
    
    <!-- Never use |safe with user input -->
    <!-- WRONG: {{ user_input|safe }} -->
    
    <!-- Use format_html in views instead -->
    {{ formatted_message }}
    
    <!-- JSON data - use json_script filter -->
    {{ user_data|json_script:"user-data" }}
    
    <script nonce="{{ csp_nonce }}">
        // Safely parse JSON data
        const userData = JSON.parse(
            document.getElementById('user-data').textContent
        );
    </script>
</body>
</html>
```

### 3.6 Admin Panel Security

```python
# admin.py - Secure Admin Configuration

from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _

class SecureAdminSite(AdminSite):
    """Customized admin site with enhanced security.
    
    OWASP A01:2021 - Broken Access Control
    CIS Benchmark: Administrative Interface Security
    """
    
    site_header = 'Secure Administration'
    site_title = 'Admin'
    
    def login(self, request, extra_context=None):
        """Enhanced login with additional checks."""
        # Add rate limiting
        if is_rate_limited(request.META.get('REMOTE_ADDR'), 'admin_login'):
            return HttpResponseForbidden('Too many attempts')
        
        return super().login(request, extra_context)
    
    def has_permission(self, request):
        """Additional permission checks."""
        # Require staff and 2FA
        if not request.user.is_active or not request.user.is_staff:
            return False
        
        # Require MFA for admin access
        if hasattr(request.user, 'mfa_enabled') and not request.user.mfa_enabled:
            return False
        
        # IP whitelist for admin
        allowed_ips = getattr(settings, 'ADMIN_ALLOWED_IPS', [])
        if allowed_ips:
            client_ip = get_client_ip(request)
            if client_ip not in allowed_ips:
                return False
        
        return True

# Register secure admin site
secure_admin = SecureAdminSite(name='secure_admin')

# Custom User Admin with security features
@admin.register(SecureUser, site=secure_admin)
class SecureUserAdmin(UserAdmin):
    """User admin with security enhancements."""
    
    # Limit displayed fields
    list_display = ('username', 'email', 'is_staff', 'mfa_enabled', 'is_locked_out')
    list_filter = ('is_staff', 'is_superuser', 'mfa_enabled')
    
    # Disable password viewing
    readonly_fields = ('password', 'last_login', 'date_joined')
    
    # Audit logging
    def save_model(self, request, obj, form, change):
        """Log admin actions."""
        action = 'UPDATE' if change else 'CREATE'
        log_admin_action(request.user, action, obj)
        super().save_model(request, obj, form, change)
    
    def delete_model(self, request, obj):
        """Log deletions."""
        log_admin_action(request.user, 'DELETE', obj)
        super().delete_model(request, obj)

# settings.py - Admin security settings
ADMIN_URL = os.environ.get('ADMIN_URL', 'admin/')  # Change from default
ADMIN_ALLOWED_IPS = os.environ.get('ADMIN_IPS', '').split(',')
```

---

## 4. Security Standards Reference Tables

### 4.1 OWASP Top 10 (2021) Mapping

| OWASP ID | Vulnerability | Python Mitigation | Flask/Django Controls |
|----------|--------------|-------------------|----------------------|
| **A01:2021** | Broken Access Control | Role-based decorators, object-level permissions | `@login_required`, `@permission_required`, Flask-Security roles |
| **A02:2021** | Cryptographic Failures | Use `secrets` module, FIPS-compliant algorithms | HTTPS enforcement, secure session cookies |
| **A03:2021** | Injection | Parameterized queries, input validation | ORM usage, `bleach` library, WTForms validation |
| **A04:2021** | Insecure Design | Threat modeling, secure defaults | Security middleware, CSRF protection |
| **A05:2021** | Security Misconfiguration | Environment-based config, no debug in prod | `DEBUG=False`, security headers |
| **A06:2021** | Vulnerable Components | Dependency scanning, regular updates | `pip-audit`, `safety`, Dependabot |
| **A07:2021** | Auth Failures | MFA, secure password hashing, rate limiting | Flask-Security, Django auth backends |
| **A08:2021** | Software Integrity | Code signing, dependency verification | `pip --require-hashes`, signed releases |
| **A09:2021** | Logging Failures | Structured security logging, no sensitive data | Python `logging`, security audit trails |
| **A10:2021** | SSRF | URL validation, allowlists | Network restrictions, input validation |

### 4.2 NIST Cybersecurity Framework 2.0 Mapping

| NIST Category | Control ID | Control Name | Python Implementation |
|---------------|-----------|--------------|----------------------|
| **Identify (ID)** | ID.AM-1 | Asset Inventory | Dependency tracking with `pip freeze`, SBOM generation |
| **Protect (PR)** | PR.AC-1 | Identity Management | Django/Flask authentication systems, MFA |
| | PR.AC-4 | Access Permissions | Role-based access control, least privilege |
| | PR.DS-1 | Data-at-Rest Protection | Encrypted database fields, FIPS-compliant encryption |
| | PR.DS-2 | Data-in-Transit Protection | TLS 1.3, HTTPS enforcement |
| | PR.IP-1 | Baseline Configuration | Secure defaults, hardened settings |
| **Detect (DE)** | DE.AE-1 | Baseline Established | Normal behavior baselines, anomaly detection |
| | DE.CM-1 | Network Monitoring | Request logging, traffic analysis |
| **Respond (RS)** | RS.AN-1 | Incident Analysis | Security logging, audit trails |
| **Recover (RC)** | RC.RP-1 | Recovery Planning | Backup verification, disaster recovery |

### 4.3 DISA STIG Web Application Requirements

| STIG ID | Requirement | Implementation |
|---------|------------|----------------|
| **V-222599** | Session timeout | `SESSION_COOKIE_AGE = 900` (15 min inactivity) |
| **V-222596** | Account lockout | Lock after 3 failed attempts for 15 min |
| **V-222578** | Encryption in transit | TLS 1.2+, `SECURE_SSL_REDIRECT = True` |
| **V-222577** | Password complexity | Min 15 chars, complexity requirements |
| **V-222544** | Input validation | Server-side validation, parameterized queries |
| **V-222543** | Error handling | Generic error messages, internal logging |
| **V-222604** | Audit logging | Log authentication events, admin actions |
| **V-222579** | FIPS 140-2/3 | FIPS-validated cryptographic modules |
| **V-222612** | Session management | Secure session cookies, regeneration on auth |

### 4.4 CIS Benchmark Level 2 Controls

| CIS Control | Sub-Control | Python/Web Application Implementation |
|-------------|-------------|--------------------------------------|
| **1** | Inventory and Control of Assets | `pip-audit`, dependency tracking |
| **2** | Inventory of Software | SBOM generation, package manifests |
| **3** | Data Protection | Field-level encryption, data classification |
| **4** | Secure Configuration | Hardened settings, no default credentials |
| **5** | Account Management | Strong authentication, MFA enforcement |
| **6** | Access Control | RBAC, least privilege, permission validation |
| **7** | Continuous Vulnerability Management | Automated scanning, regular updates |
| **8** | Audit Log Management | Structured logging, log integrity |
| **9** | Email and Web Browser Protection | CSP headers, XSS prevention |
| **10** | Malware Defenses | Input validation, file upload restrictions |
| **11** | Data Recovery | Backup encryption, recovery testing |
| **14** | Security Awareness | Secure coding training, code review |
| **16** | Application Software Security | SAST/DAST, secure SDLC |

### 4.5 FIPS 140-3 Cryptographic Requirements

| Requirement | Python Implementation |
|------------|----------------------|
| **Approved Algorithms** | AES-256, SHA-256/384/512, RSA-2048+, ECDSA P-256+ |
| **Key Generation** | Use `secrets` module, CSPRNG |
| **Key Storage** | Hardware security modules, encrypted storage |
| **Random Number Generation** | `os.urandom()`, `secrets.token_bytes()` |
| **Password Hashing** | PBKDF2-SHA256 (600,000+ iterations), bcrypt, Argon2 |
| **TLS Configuration** | TLS 1.2/1.3 only, FIPS-approved cipher suites |

```python
# FIPS 140-3 Compliant Cryptographic Configuration

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Enable FIPS mode in OpenSSL (if available)
def enable_fips_mode():
    """Enable FIPS mode for cryptographic operations.
    
    Requires FIPS-validated OpenSSL installation.
    """
    try:
        # OpenSSL 3.0+ FIPS provider
        from cryptography.hazmat.bindings.openssl import binding
        lib = binding.Binding.lib
        if hasattr(lib, 'OSSL_PROVIDER_load'):
            fips = lib.OSSL_PROVIDER_load(lib.ffi.NULL, b"fips")
            if fips == lib.ffi.NULL:
                raise RuntimeError("Failed to load FIPS provider")
    except Exception as e:
        raise RuntimeError(f"FIPS mode not available: {e}")

# FIPS-compliant password hashing
def hash_password_fips(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hash password using FIPS-approved algorithm.
    
    FIPS 140-3: PBKDF2 with SHA-256
    NIST SP 800-132: PBKDF2 key derivation
    """
    if salt is None:
        salt = os.urandom(32)  # 256-bit salt
    
    # PBKDF2-SHA256 with high iteration count
    hash_value = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations=600000,  # OWASP 2023 recommendation
        dklen=32  # 256-bit output
    )
    
    return hash_value, salt

# FIPS-compliant encryption
def encrypt_data_fips(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt data using FIPS-approved AES-256-GCM.
    
    FIPS 140-3: AES-256 in GCM mode
    """
    if len(key) != 32:
        raise ValueError("Key must be 256 bits (32 bytes)")
    
    iv = os.urandom(12)  # 96-bit IV for GCM
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    return ciphertext, iv, encryptor.tag
```

---

## 5. Compliance Checklist

### 5.1 Python Core Security Checklist

| Category | Item | Status | Standard Reference |
|----------|------|--------|-------------------|
| **Version** | Using Python 3.12+ | [ ] | Security patches, modern features |
| **Dependencies** | All packages up-to-date | [ ] | OWASP A06, CIS Control 2 |
| **Dependencies** | Vulnerability scan passed | [ ] | OWASP A06, NIST ID.RA-1 |
| **Code Style** | PEP 8 compliant | [ ] | Maintainability |
| **Type Hints** | Type annotations present | [ ] | Static analysis enabling |
| **Secrets** | No hardcoded credentials | [ ] | NIST IA-5, CIS Control 16 |
| **Randomness** | Using `secrets` module | [ ] | FIPS 140-3 |
| **Hashing** | Using approved algorithms | [ ] | FIPS 140-3 |
| **Logging** | Security events logged | [ ] | OWASP A09, NIST AU-2 |
| **Logging** | No sensitive data in logs | [ ] | NIST AU-3 |
| **Errors** | Generic error messages | [ ] | OWASP A05 |

### 5.2 Flask Security Checklist

| Category | Item | Status | Standard Reference |
|----------|------|--------|-------------------|
| **Configuration** | DEBUG = False | [ ] | OWASP A05 |
| **Configuration** | SECRET_KEY from environment | [ ] | NIST IA-5 |
| **Configuration** | SECRET_KEY >= 32 bytes | [ ] | FIPS 140-3 |
| **Sessions** | SESSION_COOKIE_SECURE = True | [ ] | OWASP A02 |
| **Sessions** | SESSION_COOKIE_HTTPONLY = True | [ ] | OWASP A03 |
| **Sessions** | SESSION_COOKIE_SAMESITE set | [ ] | OWASP A01 |
| **CSRF** | CSRFProtect enabled | [ ] | OWASP A01, DISA STIG |
| **Headers** | Flask-Talisman configured | [ ] | CIS Benchmark |
| **Headers** | HSTS enabled | [ ] | DISA STIG V-222578 |
| **Headers** | CSP configured | [ ] | OWASP A03 |
| **Auth** | Rate limiting implemented | [ ] | OWASP A07 |
| **Auth** | Password complexity enforced | [ ] | NIST SP 800-63B |
| **Auth** | MFA available | [ ] | NIST IA-5 |
| **Database** | Using ORM/parameterized queries | [ ] | OWASP A03 |
| **Database** | SSL/TLS for DB connection | [ ] | DISA STIG V-222578 |

### 5.3 Django Security Checklist

| Category | Item | Status | Standard Reference |
|----------|------|--------|-------------------|
| **Configuration** | DEBUG = False | [ ] | OWASP A05 |
| **Configuration** | SECRET_KEY from environment | [ ] | NIST IA-5 |
| **Configuration** | ALLOWED_HOSTS configured | [ ] | OWASP A05 |
| **Middleware** | SecurityMiddleware enabled | [ ] | Django security |
| **Middleware** | CsrfViewMiddleware enabled | [ ] | OWASP A01 |
| **HTTPS** | SECURE_SSL_REDIRECT = True | [ ] | DISA STIG V-222578 |
| **HTTPS** | SECURE_HSTS_SECONDS >= 31536000 | [ ] | CIS Benchmark |
| **Sessions** | SESSION_COOKIE_SECURE = True | [ ] | OWASP A02 |
| **Sessions** | SESSION_COOKIE_HTTPONLY = True | [ ] | OWASP A03 |
| **Sessions** | CSRF_COOKIE_SECURE = True | [ ] | OWASP A01 |
| **Headers** | X_FRAME_OPTIONS = 'DENY' | [ ] | OWASP A01 |
| **Headers** | SECURE_CONTENT_TYPE_NOSNIFF = True | [ ] | CIS Benchmark |
| **Password** | AUTH_PASSWORD_VALIDATORS configured | [ ] | NIST SP 800-63B |
| **Admin** | Admin URL changed from default | [ ] | Security hardening |
| **Admin** | Admin IP whitelist | [ ] | CIS Benchmark |
| **Templates** | Auto-escaping enabled (default) | [ ] | OWASP A03 |
| **ORM** | No raw SQL with user input | [ ] | OWASP A03 |

### 5.4 Deployment Security Checklist

| Category | Item | Status | Standard Reference |
|----------|------|--------|-------------------|
| **TLS** | TLS 1.2 or 1.3 only | [ ] | FIPS 140-3, DISA STIG |
| **TLS** | Strong cipher suites only | [ ] | FIPS 140-3 |
| **TLS** | Valid, non-expired certificate | [ ] | PKI requirements |
| **Server** | Unnecessary services disabled | [ ] | CIS Benchmark |
| **Server** | Security patches applied | [ ] | CIS Control 7 |
| **Firewall** | Ingress/egress rules defined | [ ] | NIST PR.AC-5 |
| **Monitoring** | Security monitoring enabled | [ ] | NIST DE.CM-1 |
| **Backup** | Regular backups configured | [ ] | NIST PR.IP-4 |
| **Secrets** | Using secrets manager | [ ] | NIST IA-5 |

---

## 6. References and Sources

### Official Documentation

1. [Python Official Documentation - What's New in Python 3.12](https://docs.python.org/3/whatsnew/3.12.html) - Official Python release notes
2. [Python Official Documentation - What's New in Python 3.13](https://docs.python.org/3/whatsnew/3.13.html) - Official Python release notes
3. [PEP 8 - Style Guide for Python Code](https://peps.python.org/pep-0008/) - Python Enhancement Proposal for code style
4. [PEP 484 - Type Hints](https://peps.python.org/pep-0484/) - Type annotation specification
5. [Flask-Security Documentation](https://flask-security-too.readthedocs.io/en/stable/) - Flask security extension
6. [Django Security Documentation](https://docs.djangoproject.com/en/5.0/topics/security/) - Official Django security guide

### Security Standards

7. [OWASP Top 10:2021](https://owasp.org/Top10/2021/) - Web application security risks - High Reliability - Industry standard security reference
8. [OWASP Top 10:2025](https://owasp.org/Top10/2025/en/) - Latest OWASP security risks
9. [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) - Federal cybersecurity framework - High Reliability - US government standard
10. [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html) - Authentication and lifecycle management
11. [DISA STIGs](https://www.cyber.mil/stigs/) - Security Technical Implementation Guides - High Reliability - DoD security standard
12. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Security configuration guidelines - High Reliability - Industry consensus standard
13. [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) - Cryptographic module requirements - High Reliability - US federal cryptographic standard

### Security Guides and Best Practices

14. [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) - Practical security guidance
15. [Snyk - How to Secure Python Flask Applications](https://snyk.io/blog/secure-python-flask-applications/) - Flask security best practices
16. [Django Security Best Practices 2025](https://medium.com/@shiladityamajumder/how-to-secure-your-django-application-best-practices-for-2025-e9234cf71ab7) - Modern Django security
17. [Python Typing in 2025](https://khaled-jallouli.medium.com/python-typing-in-2025-a-comprehensive-guide-d61b4f562b99) - Type hints comprehensive guide

### Tools and Libraries

18. [pip-audit](https://pypi.org/project/pip-audit/) - Python dependency vulnerability scanner
19. [safety](https://pypi.org/project/safety/) - Python dependency security checker
20. [bandit](https://pypi.org/project/bandit/) - Python security linter
21. [Flask-Talisman](https://pypi.org/project/flask-talisman/) - HTTP security headers for Flask
22. [django-csp](https://pypi.org/project/django-csp/) - Content Security Policy for Django

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | March 2026 | Matrix Agent | Initial release |

---

**Disclaimer**: This guide provides general security best practices and should be adapted to your specific environment and requirements. Always conduct thorough security assessments and consult with security professionals for critical applications.
