# JavaScript Security Best Practices Guide

**Version:** 1.0  
**Last Updated:** March 2026  
**Classification:** Security Reference Document  
**Author:** Matrix Agent

---

## Executive Summary

This comprehensive guide provides security-focused best practices for JavaScript development across both client-side and server-side (Node.js) environments. It addresses modern threats including Cross-Site Scripting (XSS), prototype pollution, insecure dependencies, and cryptographic vulnerabilities while aligning with industry standards including OWASP Top 10, NIST SP 800-53, DISA STIG, CIS Benchmarks, and FIPS 140-3.

The document covers ES2024 security-relevant features, practical code examples, compliance checklists, and reference tables for rapid implementation. Following these guidelines will significantly reduce the attack surface of JavaScript applications and ensure compliance with major security frameworks.

---

## Table of Contents

1. [ECMAScript 2024 Security-Relevant Features](#1-ecmascript-2024-security-relevant-features)
2. [Cross-Site Scripting (XSS) Prevention](#2-cross-site-scripting-xss-prevention)
3. [Prototype Pollution Prevention](#3-prototype-pollution-prevention)
4. [Secure DOM Manipulation](#4-secure-dom-manipulation)
5. [Node.js Security Best Practices](#5-nodejs-security-best-practices)
6. [npm/Package Security and Dependency Management](#6-npmpackage-security-and-dependency-management)
7. [Content Security Policy (CSP)](#7-content-security-policy-csp)
8. [Secure Storage Practices](#8-secure-storage-practices)
9. [Web Crypto API and FIPS 140-3 Compliance](#9-web-crypto-api-and-fips-140-3-compliance)
10. [Security Standards Cross-Reference](#10-security-standards-cross-reference)
11. [Compliance Checklists](#11-compliance-checklists)
12. [References](#12-references)

---

## 1. ECMAScript 2024 Security-Relevant Features

ECMAScript 2024 (ES15), finalized in June 2024, introduces several features with security implications. Understanding these features helps developers write more secure and maintainable code.

### 1.1 Key ES2024 Features

| Feature | Security Relevance | Description |
|---------|-------------------|-------------|
| `Object.groupBy()` / `Map.groupBy()` | Low | Safe data grouping without prototype chain risks |
| `Promise.withResolvers()` | Medium | Cleaner async handling, reduces callback complexity |
| `String.prototype.isWellFormed()` | High | Validates UTF-16 strings, prevents encoding attacks |
| `String.prototype.toWellFormed()` | High | Sanitizes malformed UTF-16 strings |
| `ArrayBuffer.prototype.resize()` | Medium | Controlled memory resizing with bounds checking |
| `ArrayBuffer.prototype.transfer()` | Medium | Safe buffer ownership transfer |
| RegExp `/v` flag (unicodeSets) | Medium | Enhanced Unicode matching for input validation |
| `Atomics.waitAsync()` | Low | Non-blocking synchronization for SharedArrayBuffer |

### 1.2 Security-Enhanced String Validation

ES2024's string validation methods help prevent encoding-based attacks:

```javascript
// ES2024: Validate string encoding before processing
function processUserInput(input) {
    // Check if string is well-formed UTF-16
    if (!input.isWellFormed()) {
        // Option 1: Reject malformed input
        throw new Error('Invalid input encoding detected');
        
        // Option 2: Sanitize the input
        // input = input.toWellFormed();
    }
    
    // Safe to process
    return sanitizeAndProcess(input);
}

// Example: Detecting potentially malicious lone surrogates
const maliciousInput = 'Hello\uD800World'; // Lone surrogate
console.log(maliciousInput.isWellFormed()); // false

const safeInput = 'Hello World';
console.log(safeInput.isWellFormed()); // true
```

### 1.3 Safe Data Grouping

`Object.groupBy()` provides a secure alternative to manual grouping that avoids prototype pollution:

```javascript
// ES2024: Safe grouping without prototype chain modification
const users = [
    { name: 'Alice', role: 'admin' },
    { name: 'Bob', role: 'user' },
    { name: 'Charlie', role: 'admin' }
];

// Safe grouping - creates a null-prototype object
const grouped = Object.groupBy(users, user => user.role);
// Result: { admin: [...], user: [...] }

// The result has no prototype, preventing pollution
console.log(Object.getPrototypeOf(grouped)); // null

// For Map-based grouping with object keys
const groupedMap = Map.groupBy(users, user => user.role);
```

### 1.4 Secure ArrayBuffer Operations

ES2024 introduces resizable and transferable ArrayBuffers with built-in bounds checking:

```javascript
// Create a resizable ArrayBuffer for secure data handling
const secureBuffer = new ArrayBuffer(1024, { maxByteLength: 4096 });

// Resize within allowed bounds
secureBuffer.resize(2048); // OK

try {
    secureBuffer.resize(8192); // Throws RangeError - exceeds maxByteLength
} catch (e) {
    console.error('Buffer resize rejected:', e.message);
}

// Transfer ownership (detaches original)
const transferredBuffer = secureBuffer.transfer();
// Original buffer is now detached and unusable
console.log(secureBuffer.detached); // true
```

---

## 2. Cross-Site Scripting (XSS) Prevention

Cross-Site Scripting remains one of the most prevalent web vulnerabilities (OWASP A03:2021 - Injection). This section provides comprehensive XSS prevention strategies.

### 2.1 XSS Attack Types

| Type | Vector | Mitigation |
|------|--------|------------|
| **Stored XSS** | Server-stored malicious content | Input validation, output encoding, CSP |
| **Reflected XSS** | URL parameters reflected in response | Input validation, output encoding |
| **DOM-based XSS** | Client-side script manipulation | Safe DOM APIs, input sanitization |

### 2.2 Output Encoding by Context

Different contexts require different encoding strategies:

```javascript
/**
 * Context-aware output encoding utilities
 */
const SecurityEncoder = {
    // HTML context encoding
    htmlEncode(str) {
        const htmlEntities = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;'
        };
        return String(str).replace(/[&<>"'/]/g, char => htmlEntities[char]);
    },
    
    // JavaScript string context
    jsEncode(str) {
        return String(str)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/"/g, '\\"')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r')
            .replace(/\t/g, '\\t');
    },
    
    // URL parameter encoding
    urlEncode(str) {
        return encodeURIComponent(String(str));
    },
    
    // CSS context encoding
    cssEncode(str) {
        return String(str).replace(/[^a-zA-Z0-9]/g, char => {
            return '\\' + char.charCodeAt(0).toString(16) + ' ';
        });
    },
    
    // Attribute context (when attribute is quoted)
    attrEncode(str) {
        return this.htmlEncode(str);
    }
};

// Usage examples
const userInput = '<script>alert("XSS")</script>';

// In HTML body
document.getElementById('output').textContent = userInput; // Safe - automatic encoding
// OR
element.innerHTML = SecurityEncoder.htmlEncode(userInput);

// In JavaScript string
const safeJS = `const userName = '${SecurityEncoder.jsEncode(userInput)}';`;

// In URL parameter
const safeURL = `/search?q=${SecurityEncoder.urlEncode(userInput)}`;
```

### 2.3 DOM-based XSS Prevention

```javascript
/**
 * Safe DOM manipulation utilities
 */
class SafeDOM {
    // SAFE: Use textContent for text insertion
    static setText(element, text) {
        element.textContent = text;
    }
    
    // SAFE: Create elements programmatically
    static createElement(tag, attributes = {}, textContent = '') {
        const allowedTags = ['div', 'span', 'p', 'a', 'button', 'input', 'label', 'ul', 'li'];
        
        if (!allowedTags.includes(tag.toLowerCase())) {
            throw new Error(`Tag '${tag}' is not allowed`);
        }
        
        const element = document.createElement(tag);
        
        // Set safe attributes
        for (const [key, value] of Object.entries(attributes)) {
            if (this.isSafeAttribute(key, value)) {
                element.setAttribute(key, value);
            }
        }
        
        if (textContent) {
            element.textContent = textContent;
        }
        
        return element;
    }
    
    // Validate attributes to prevent XSS
    static isSafeAttribute(name, value) {
        const dangerousAttributes = ['onclick', 'onerror', 'onload', 'onmouseover', 
                                      'onfocus', 'onblur', 'javascript:'];
        const lowerName = name.toLowerCase();
        const lowerValue = String(value).toLowerCase();
        
        // Block event handlers
        if (lowerName.startsWith('on')) {
            return false;
        }
        
        // Block javascript: URLs
        if (lowerValue.includes('javascript:')) {
            return false;
        }
        
        return true;
    }
    
    // UNSAFE operations to avoid
    static dangerousMethods() {
        return [
            'element.innerHTML = userInput',        // XSS risk
            'document.write(userInput)',            // XSS risk
            'element.outerHTML = userInput',        // XSS risk
            'element.insertAdjacentHTML(userInput)', // XSS risk
            'eval(userInput)',                      // Code injection
            'new Function(userInput)',              // Code injection
            'setTimeout(userInput, 0)',             // Code injection (string form)
            'setInterval(userInput, 1000)'          // Code injection (string form)
        ];
    }
}

// Example: Safe user content rendering
function renderUserComment(comment) {
    const container = SafeDOM.createElement('div', { class: 'comment' });
    const text = SafeDOM.createElement('p');
    SafeDOM.setText(text, comment.body);
    container.appendChild(text);
    return container;
}
```

### 2.4 HTML Sanitization with DOMPurify

For cases where HTML input is required, use a trusted sanitization library:

```javascript
// Install: npm install dompurify

import DOMPurify from 'dompurify';

/**
 * Secure HTML sanitization configuration
 */
const sanitizerConfig = {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'title', 'class'],
    ALLOW_DATA_ATTR: false,
    FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'input'],
    FORBID_ATTR: ['onerror', 'onclick', 'onload', 'onmouseover'],
    // Force all URLs to be safe
    ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
};

function sanitizeUserHTML(dirtyHTML) {
    return DOMPurify.sanitize(dirtyHTML, sanitizerConfig);
}

// Usage
const userHTML = '<p>Hello</p><script>alert("XSS")</script>';
const cleanHTML = sanitizeUserHTML(userHTML);
// Result: '<p>Hello</p>'

// For rich text editors
function setRichTextContent(element, content) {
    element.innerHTML = DOMPurify.sanitize(content, sanitizerConfig);
}
```

### 2.5 Trusted Types API

Modern browsers support Trusted Types for DOM XSS prevention:

```javascript
// Enable Trusted Types via CSP header:
// Content-Security-Policy: require-trusted-types-for'script'

// Create a Trusted Types policy
if (window.trustedTypes && trustedTypes.createPolicy) {
    const escapePolicy = trustedTypes.createPolicy('escapePolicy', {
        createHTML: (input) => DOMPurify.sanitize(input),
        createScript: (input) => {
            throw new Error('Script creation not allowed');
        },
        createScriptURL: (input) => {
            const url = new URL(input, window.location.origin);
            if (url.origin === window.location.origin) {
                return url.href;
            }
            throw new Error('External script URLs not allowed');
        }
    });
    
    // Use the policy
    element.innerHTML = escapePolicy.createHTML(userInput);
}
```

---

## 3. Prototype Pollution Prevention

Prototype pollution is a JavaScript-specific vulnerability where attackers manipulate object prototypes to inject malicious properties. This can lead to denial of service, property injection, and in some cases, remote code execution.

### 3.1 Understanding Prototype Pollution

```javascript
// Vulnerable pattern: Deep object merge without protection
function vulnerableMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            vulnerableMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attack payload
const maliciousPayload = JSON.parse('{"__proto__": {"isAdmin": true}}');
vulnerableMerge({}, maliciousPayload);

// Now ALL objects have isAdmin = true!
const user = {};
console.log(user.isAdmin); // true - POLLUTED!
```

### 3.2 Secure Object Operations

```javascript
/**
 * Secure object utilities preventing prototype pollution
 */
const SecureObject = {
    // Dangerous keys that should never be used
    FORBIDDEN_KEYS: ['__proto__', 'constructor', 'prototype'],
    
    // Check if key is safe
    isSafeKey(key) {
        return !this.FORBIDDEN_KEYS.includes(key) && 
               typeof key === 'string' &&
               !key.startsWith('__');
    },
    
    // Safe property setter with validation
    safeSet(obj, key, value) {
        if (!this.isSafeKey(key)) {
            throw new Error(`Unsafe property key: ${key}`);
        }
        
        // Use Object.defineProperty for better control
        Object.defineProperty(obj, key, {
            value: value,
            writable: true,
            enumerable: true,
            configurable: true
        });
        
        return obj;
    },
    
    // Safe deep merge with prototype pollution protection
    safeMerge(target, source, maxDepth = 10) {
        if (maxDepth <= 0) {
            throw new Error('Maximum merge depth exceeded');
        }
        
        // Create null-prototype object if target is new
        const result = target || Object.create(null);
        
        if (!source || typeof source !== 'object') {
            return result;
        }
        
        // Use Object.keys to skip inherited properties
        for (const key of Object.keys(source)) {
            // Skip dangerous keys
            if (!this.isSafeKey(key)) {
                console.warn(`Skipping unsafe key: ${key}`);
                continue;
            }
            
            const sourceValue = source[key];
            
            if (sourceValue !== null && typeof sourceValue === 'object' && !Array.isArray(sourceValue)) {
                result[key] = this.safeMerge(result[key], sourceValue, maxDepth - 1);
            } else {
                result[key] = sourceValue;
            }
        }
        
        return result;
    },
    
    // Create a safe object with no prototype
    createSafe(properties = {}) {
        const obj = Object.create(null);
        
        for (const [key, value] of Object.entries(properties)) {
            if (this.isSafeKey(key)) {
                obj[key] = value;
            }
        }
        
        return obj;
    },
    
    // Safe JSON parse
    safeJSONParse(jsonString) {
        const parsed = JSON.parse(jsonString);
        return this.sanitizeObject(parsed);
    },
    
    // Recursively sanitize an object
    sanitizeObject(obj, visited = new WeakSet()) {
        if (obj === null || typeof obj !== 'object') {
            return obj;
        }
        
        // Prevent circular reference infinite loops
        if (visited.has(obj)) {
            return obj;
        }
        visited.add(obj);
        
        // Handle arrays
        if (Array.isArray(obj)) {
            return obj.map(item => this.sanitizeObject(item, visited));
        }
        
        // Create safe object
        const safe = Object.create(null);
        
        for (const key of Object.keys(obj)) {
            if (this.isSafeKey(key)) {
                safe[key] = this.sanitizeObject(obj[key], visited);
            }
        }
        
        return safe;
    }
};

// Usage examples
const userInput = JSON.parse('{"name": "Alice", "__proto__": {"hacked": true}}');
const safeData = SecureObject.sanitizeObject(userInput);
console.log(safeData.__proto__); // undefined - blocked!
console.log(({}).hacked); // undefined - not polluted!
```

### 3.3 Object.freeze() for Prototype Protection

```javascript
// Freeze Object.prototype to prevent pollution
// WARNING: Do this early in application bootstrap
(function protectPrototypes() {
    'use strict';
    
    // Freeze built-in prototypes
    Object.freeze(Object.prototype);
    Object.freeze(Array.prototype);
    Object.freeze(String.prototype);
    Object.freeze(Number.prototype);
    Object.freeze(Function.prototype);
    
    // Note: This may break some libraries that extend prototypes
    // Test thoroughly before deploying
})();

// Alternative: Use Map instead of plain objects for user data
const userData = new Map();
userData.set('__proto__', 'value'); // Safe - Map keys don't affect prototypes
console.log(({}).isAdmin); // undefined - still safe
```

### 3.4 Schema Validation

Use schema validation to prevent unexpected properties:

```javascript
// Using a schema validator (e.g., Zod, Joi, Yup)
// npm install zod

import { z } from 'zod';

// Define strict schema
const userSchema = z.object({
    name: z.string().min(1).max(100),
    email: z.string().email(),
    age: z.number().int().min(0).max(150).optional()
}).strict(); // Reject unknown properties

function processUserData(input) {
    // Parse and validate - throws on invalid input
    const validated = userSchema.parse(input);
    
    // Safe to use - only expected properties present
    return validated;
}

// Attempt with prototype pollution
try {
    processUserData({
        name: 'Alice',
        email: 'alice@example.com',
        __proto__: { isAdmin: true }
    });
} catch (e) {
    console.error('Validation failed:', e.message);
    // Error: Unrecognized key(s) in object: '__proto__'
}
```

---

## 4. Secure DOM Manipulation

Secure DOM manipulation prevents XSS, UI redressing, and other client-side attacks.

### 4.1 Safe DOM API Reference

| Operation | Unsafe Method | Safe Alternative |
|-----------|---------------|------------------|
| Insert text | `innerHTML` | `textContent`, `innerText` |
| Insert HTML | `innerHTML` | `DOMPurify.sanitize()` |
| Create elements | String concatenation | `document.createElement()` |
| Set attributes | `setAttribute('onclick')` | Event listeners |
| Insert adjacent | `insertAdjacentHTML` | `insertAdjacentElement` |
| Write to document | `document.write()` | DOM methods |

### 4.2 Secure Element Creation

```javascript
/**
 * Secure element factory with comprehensive validation
 */
class SecureElementFactory {
    // Allowed elements whitelist
    static ALLOWED_ELEMENTS = new Set([
        'div', 'span', 'p', 'a', 'button', 'input', 'label', 'form',
        'ul', 'ol', 'li', 'table', 'tr', 'td', 'th', 'thead', 'tbody',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'img', 'section', 'article',
        'header', 'footer', 'nav', 'main', 'aside', 'figure', 'figcaption'
    ]);
    
    // Safe attributes per element type
    static SAFE_ATTRIBUTES = {
        '*': ['id', 'class', 'title', 'lang', 'dir', 'hidden', 'tabindex',
              'aria-label', 'aria-describedby', 'aria-hidden', 'role',
              'data-*'],
        'a': ['href', 'target', 'rel', 'download'],
        'img': ['src', 'alt', 'width', 'height', 'loading'],
        'input': ['type', 'name', 'value', 'placeholder', 'required',
                  'disabled', 'readonly', 'maxlength', 'minlength',
                  'pattern', 'autocomplete'],
        'button': ['type', 'disabled', 'name', 'value'],
        'form': ['action', 'method', 'enctype', 'novalidate'],
        'label': ['for']
    };
    
    static create(tagName, options = {}) {
        const tag = tagName.toLowerCase();
        
        // Validate element type
        if (!this.ALLOWED_ELEMENTS.has(tag)) {
            throw new Error(`Element '${tag}' is not allowed`);
        }
        
        const element = document.createElement(tag);
        
        // Set attributes safely
        if (options.attributes) {
            this.setAttributes(element, tag, options.attributes);
        }
        
        // Set text content (safe)
        if (options.text) {
            element.textContent = options.text;
        }
        
        // Add children
        if (options.children) {
            for (const child of options.children) {
                if (child instanceof Node) {
                    element.appendChild(child);
                }
            }
        }
        
        // Add event listeners (not inline handlers)
        if (options.events) {
            for (const [event, handler] of Object.entries(options.events)) {
                if (typeof handler === 'function') {
                    element.addEventListener(event, handler);
                }
            }
        }
        
        return element;
    }
    
    static setAttributes(element, tagName, attributes) {
        const globalAttrs = this.SAFE_ATTRIBUTES['*'];
        const elementAttrs = this.SAFE_ATTRIBUTES[tagName] || [];
        const allowedAttrs = [...globalAttrs, ...elementAttrs];
        
        for (const [name, value] of Object.entries(attributes)) {
            // Check for data-* attributes
            const isDataAttr = name.startsWith('data-');
            const isAllowed = allowedAttrs.includes(name) || 
                             (isDataAttr && allowedAttrs.includes('data-*'));
            
            if (!isAllowed) {
                console.warn(`Attribute '${name}' is not allowed on '${tagName}'`);
                continue;
            }
            
            // Validate attribute value
            if (!this.isValidAttributeValue(name, value)) {
                console.warn(`Invalid value for attribute '${name}'`);
                continue;
            }
            
            element.setAttribute(name, value);
        }
    }
    
    static isValidAttributeValue(name, value) {
        const strValue = String(value).toLowerCase();
        
        // Block javascript: URLs
        if (name === 'href' || name === 'src' || name === 'action') {
            if (strValue.startsWith('javascript:') || 
                strValue.startsWith('data:text/html')) {
                return false;
            }
        }
        
        // Block event handlers in any attribute
        if (strValue.includes('javascript:')) {
            return false;
        }
        
        return true;
    }
}

// Usage example
const button = SecureElementFactory.create('button', {
    attributes: {
        class: 'btn btn-primary',
        type: 'submit',
        'data-action': 'save'
    },
    text: 'Save Changes',
    events: {
        click: (e) => handleSave(e)
    }
});

document.getElementById('container').appendChild(button);
```

### 4.3 Safe URL Handling

```javascript
/**
 * Secure URL validation and handling
 */
class SecureURL {
    // Allowed protocols
    static SAFE_PROTOCOLS = ['https:', 'http:', 'mailto:', 'tel:'];
    
    // Validate URL for safe use
    static isValid(urlString, options = {}) {
        const {
            allowedProtocols = this.SAFE_PROTOCOLS,
            requireHTTPS = false,
            allowedHosts = null
        } = options;
        
        try {
            const url = new URL(urlString, window.location.origin);
            
            // Check protocol
            if (!allowedProtocols.includes(url.protocol)) {
                return false;
            }
            
            // Require HTTPS in production
            if (requireHTTPS && url.protocol !== 'https:') {
                return false;
            }
            
            // Check against allowed hosts whitelist
            if (allowedHosts && !allowedHosts.includes(url.hostname)) {
                return false;
            }
            
            return true;
        } catch {
            return false;
        }
    }
    
    // Sanitize URL for use in href/src attributes
    static sanitize(urlString, options = {}) {
        if (!this.isValid(urlString, options)) {
            return '#'; // Safe fallback
        }
        
        // Re-parse to normalize
        const url = new URL(urlString, window.location.origin);
        return url.href;
    }
    
    // Create safe anchor element
    static createLink(urlString, text, options = {}) {
        const href = this.sanitize(urlString, options);
        
        const link = document.createElement('a');
        link.href = href;
        link.textContent = text;
        
        // Set safe defaults for external links
        if (href !== '#') {
            const url = new URL(href);
            if (url.origin !== window.location.origin) {
                link.rel = 'noopener noreferrer';
                link.target = '_blank';
            }
        }
        
        return link;
    }
}

// Usage
const userURL = 'javascript:alert("XSS")';
console.log(SecureURL.isValid(userURL)); // false

const safeURL = 'https://example.com/page';
const link = SecureURL.createLink(safeURL, 'Visit Site', { requireHTTPS: true });
```

---

## 5. Node.js Security Best Practices

Server-side JavaScript introduces additional security considerations including file system access, process management, and network operations.

### 5.1 Input Validation and Sanitization

```javascript
// npm install validator express-validator

import { body, validationResult, param, query } from 'express-validator';
import validator from 'validator';

// Middleware for request validation
const validateUserRegistration = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Invalid email address'),
    body('password')
        .isLength({ min: 12 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must be at least 12 characters with uppercase, lowercase, number, and special character'),
    body('username')
        .trim()
        .isLength({ min: 3, max: 30 })
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username must be 3-30 alphanumeric characters'),
    body('age')
        .optional()
        .isInt({ min: 0, max: 150 })
        .toInt()
];

// Validation middleware handler
function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: 'Validation failed',
            details: errors.array().map(err => ({
                field: err.path,
                message: err.msg
            }))
        });
    }
    next();
}

// Usage in routes
app.post('/api/users/register', 
    validateUserRegistration, 
    handleValidationErrors, 
    async (req, res) => {
        // req.body is now validated and sanitized
        const { email, password, username, age } = req.body;
        // ... registration logic
    }
);
```

### 5.2 Secure HTTP Headers

```javascript
// npm install helmet

import helmet from 'helmet';
import express from 'express';

const app = express();

// Apply security headers
app.use(helmet({
    // Content Security Policy
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    // Strict Transport Security
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    },
    // Prevent clickjacking
    frameguard: { action: 'deny' },
    // Hide X-Powered-By
    hidePoweredBy: true,
    // XSS filter
    xssFilter: true,
    // Prevent MIME sniffing
    noSniff: true,
    // Referrer Policy
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Additional CORS configuration
import cors from 'cors';

app.use(cors({
    origin: ['https://trusted-domain.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400 // 24 hours
}));
```

### 5.3 Rate Limiting

```javascript
// npm install express-rate-limit

import rateLimit from 'express-rate-limit';

// General API rate limiter
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many requests',
        retryAfter: 'Please try again in 15 minutes'
    },
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        // Use X-Forwarded-For if behind proxy
        return req.ip || req.headers['x-forwarded-for']?.split(',')[0];
    }
});

// Strict limiter for authentication endpoints
const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 failed attempts
    skipSuccessfulRequests: true, // Only count failures
    message: {
        error: 'Too many authentication attempts',
        retryAfter: 'Account temporarily locked. Try again in 1 hour.'
    }
});

// Apply limiters
app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/password-reset', authLimiter);
```

### 5.4 Secure Session Management

```javascript
// npm install express-session connect-redis ioredis

import session from 'express-session';
import RedisStore from 'connect-redis';
import Redis from 'ioredis';

const redisClient = new Redis({
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
    tls: process.env.NODE_ENV === 'production' ? {} : undefined
});

const sessionConfig = {
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET, // Use strong, random secret
    name: 'sessionId', // Change from default 'connect.sid'
    resave: false,
    saveUninitialized: false,
    rolling: true, // Reset expiration on activity
    cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS only
        httpOnly: true, // No JavaScript access
        sameSite: 'strict', // CSRF protection
        maxAge: 30 * 60 * 1000, // 30 minutes
        path: '/',
        domain: process.env.COOKIE_DOMAIN
    }
};

// Enable trust proxy if behind reverse proxy
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

app.use(session(sessionConfig));

// Session regeneration on authentication
app.post('/api/auth/login', async (req, res) => {
    const user = await authenticateUser(req.body);
    
    if (user) {
        // Regenerate session to prevent fixation
        req.session.regenerate((err) => {
            if (err) {
                return res.status(500).json({ error: 'Session error' });
            }
            
            req.session.userId = user.id;
            req.session.loginTime = Date.now();
            
            res.json({ success: true });
        });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});
```

### 5.5 Path Traversal Prevention

```javascript
import path from 'path';
import fs from 'fs/promises';

/**
 * Secure file operations with path validation
 */
class SecureFileHandler {
    constructor(baseDir) {
        this.baseDir = path.resolve(baseDir);
    }
    
    // Validate that resolved path is within base directory
    isPathSafe(requestedPath) {
        const resolvedPath = path.resolve(this.baseDir, requestedPath);
        return resolvedPath.startsWith(this.baseDir + path.sep) || 
               resolvedPath === this.baseDir;
    }
    
    // Get safe absolute path
    getSafePath(requestedPath) {
        // Remove null bytes (poison null byte attack)
        const sanitized = requestedPath.replace(/\0/g, '');
        
        // Normalize and resolve
        const resolved = path.resolve(this.baseDir, sanitized);
        
        // Verify within base directory
        if (!resolved.startsWith(this.baseDir + path.sep) && 
            resolved !== this.baseDir) {
            throw new Error('Path traversal attempt detected');
        }
        
        return resolved;
    }
    
    // Safe file read
    async readFile(requestedPath) {
        const safePath = this.getSafePath(requestedPath);
        
        try {
            const stats = await fs.stat(safePath);
            
            if (!stats.isFile()) {
                throw new Error('Not a regular file');
            }
            
            return await fs.readFile(safePath, 'utf8');
        } catch (error) {
            if (error.code === 'ENOENT') {
                throw new Error('File not found');
            }
            throw error;
        }
    }
    
    // Safe file write
    async writeFile(requestedPath, content) {
        const safePath = this.getSafePath(requestedPath);
        
        // Ensure parent directory exists and is within base
        const parentDir = path.dirname(safePath);
        if (!parentDir.startsWith(this.baseDir)) {
            throw new Error('Invalid directory');
        }
        
        await fs.mkdir(parentDir, { recursive: true });
        await fs.writeFile(safePath, content, { mode: 0o644 });
    }
}

// Usage
const fileHandler = new SecureFileHandler('/app/uploads');

app.get('/api/files/:filename', async (req, res) => {
    try {
        const content = await fileHandler.readFile(req.params.filename);
        res.send(content);
    } catch (error) {
        if (error.message === 'Path traversal attempt detected') {
            return res.status(403).json({ error: 'Access denied' });
        }
        res.status(404).json({ error: 'File not found' });
    }
});
```

### 5.6 Secure Child Process Execution

```javascript
import { spawn, execFile } from 'child_process';

/**
 * Secure command execution utilities
 */
class SecureExec {
    // Whitelist of allowed commands
    static ALLOWED_COMMANDS = new Map([
        ['convert', '/usr/bin/convert'],  // ImageMagick
        ['ffmpeg', '/usr/bin/ffmpeg'],    // Video processing
        ['pdftotext', '/usr/bin/pdftotext'] // PDF extraction
    ]);
    
    // Execute command with arguments (safe from injection)
    static async exec(commandName, args = [], options = {}) {
        // Validate command is whitelisted
        const commandPath = this.ALLOWED_COMMANDS.get(commandName);
        if (!commandPath) {
            throw new Error(`Command '${commandName}' is not allowed`);
        }
        
        // Validate arguments (no shell metacharacters)
        const safeArgs = args.map(arg => {
            if (typeof arg !== 'string') {
                throw new Error('Arguments must be strings');
            }
            return arg;
        });
        
        return new Promise((resolve, reject) => {
            // Use execFile, NOT exec (exec uses shell)
            const child = execFile(
                commandPath,
                safeArgs,
                {
                    timeout: options.timeout || 30000,
                    maxBuffer: options.maxBuffer || 10 * 1024 * 1024,
                    shell: false, // Critical: no shell
                    env: { ...process.env, PATH: '' } // Restrict PATH
                },
                (error, stdout, stderr) => {
                    if (error) {
                        reject(error);
                    } else {
                        resolve({ stdout, stderr });
                    }
                }
            );
        });
    }
    
    // NEVER DO THIS - vulnerable to command injection
    static vulnerableExample(userInput) {
        // const exec = require('child_process').exec;
        // exec(`convert ${userInput} output.png`); // DANGEROUS!
    }
}

// Safe usage example
async function convertImage(inputPath, outputPath) {
    // Validate paths first
    if (!inputPath.match(/^[a-zA-Z0-9_\-./]+$/) || 
        !outputPath.match(/^[a-zA-Z0-9_\-./]+$/)) {
        throw new Error('Invalid file path');
    }
    
    return SecureExec.exec('convert', [
        inputPath,
        '-resize', '800x600',
        '-quality', '85',
        outputPath
    ]);
}
```

---

## 6. npm/Package Security and Dependency Management

Supply chain attacks through compromised npm packages are a significant threat vector. This section covers secure dependency management practices.

### 6.1 Dependency Security Workflow

```bash
# Regular security audit
npm audit

# Fix vulnerabilities automatically (when safe)
npm audit fix

# View detailed vulnerability report
npm audit --json > audit-report.json

# Check for outdated packages
npm outdated

# Update packages within semver constraints
npm update

# Use npm-check-updates for major updates
npx npm-check-updates
```

### 6.2 Package.json Security Configuration

```json
{
  "name": "secure-app",
  "version": "1.0.0",
  "engines": {
    "node": ">=20.0.0",
    "npm": ">=10.0.0"
  },
  "scripts": {
    "preinstall": "npx npm-force-resolutions",
    "prepare": "husky install",
    "audit": "npm audit --audit-level=high",
    "audit:fix": "npm audit fix",
    "security-check": "npm run audit && snyk test"
  },
  "resolutions": {
    "lodash": "^4.17.21",
    "minimist": "^1.2.8"
  },
  "overrides": {
    "semver": "^7.5.4"
  }
}
```

### 6.3 Lock File Security

```javascript
/**
 * Package integrity verification script
 * Run as part of CI/CD pipeline
 */

import { readFileSync, existsSync } from 'fs';
import { createHash } from 'crypto';
import { execSync } from 'child_process';

function verifyPackageLock() {
    const lockPath = 'package-lock.json';
    
    if (!existsSync(lockPath)) {
        throw new Error('package-lock.json not found. Run npm install first.');
    }
    
    // Parse lock file
    const lockFile = JSON.parse(readFileSync(lockPath, 'utf8'));
    
    // Verify integrity hashes exist
    const packages = lockFile.packages || {};
    const issues = [];
    
    for (const [name, details] of Object.entries(packages)) {
        if (name === '') continue; // Root package
        
        // Check for integrity hash
        if (!details.integrity) {
            issues.push(`Missing integrity hash: ${name}`);
        }
        
        // Check for http:// URLs (should be https://)
        if (details.resolved && details.resolved.startsWith('http://')) {
            issues.push(`Insecure URL: ${name} - ${details.resolved}`);
        }
        
        // Check for git dependencies (potential risk)
        if (details.resolved && details.resolved.includes('git')) {
            issues.push(`Git dependency (review needed): ${name}`);
        }
    }
    
    if (issues.length > 0) {
        console.error('Package security issues found:');
        issues.forEach(issue => console.error(`  - ${issue}`));
        process.exit(1);
    }
    
    console.log('Package lock file verification passed');
}

// Run npm ci for reproducible installs
function secureInstall() {
    try {
        // Use npm ci instead of npm install in CI/CD
        execSync('npm ci --ignore-scripts', { stdio: 'inherit' });
        
        // Run scripts explicitly after review
        // execSync('npm rebuild', { stdio: 'inherit' });
    } catch (error) {
        console.error('Secure install failed:', error.message);
        process.exit(1);
    }
}

verifyPackageLock();
```

### 6.4 .npmrc Security Settings

```ini
# .npmrc - Secure npm configuration

# Enforce HTTPS for registry
registry=https://registry.npmjs.org/

# Require package-lock.json
package-lock=true

# Strict SSL verification
strict-ssl=true

# Audit on install
audit=true

# Prevent install scripts by default (run explicitly)
ignore-scripts=true

# Save exact versions (not semver ranges)
save-exact=true

# Prevent publishing to public registry (for private projects)
# @mycompany:registry=https://npm.mycompany.com/

# Fund message disable (optional)
fund=false
```

### 6.5 Dependency Monitoring

```javascript
/**
 * Automated dependency security monitoring
 * Configure as a scheduled CI job
 */

import { execSync } from 'child_process';

async function runSecurityChecks() {
    const results = {
        timestamp: new Date().toISOString(),
        checks: []
    };
    
    // npm audit
    try {
        const auditResult = execSync('npm audit --json', { encoding: 'utf8' });
        const audit = JSON.parse(auditResult);
        
        results.checks.push({
            name: 'npm-audit',
            status: audit.metadata.vulnerabilities.total === 0 ? 'pass' : 'fail',
            vulnerabilities: audit.metadata.vulnerabilities
        });
    } catch (error) {
        const audit = JSON.parse(error.stdout || '{}');
        results.checks.push({
            name: 'npm-audit',
            status: 'fail',
            vulnerabilities: audit.metadata?.vulnerabilities || 'Parse error'
        });
    }
    
    // Check for deprecated packages
    try {
        const outdated = execSync('npm outdated --json', { encoding: 'utf8' });
        const packages = JSON.parse(outdated || '{}');
        
        results.checks.push({
            name: 'outdated-packages',
            status: Object.keys(packages).length === 0 ? 'pass' : 'warn',
            count: Object.keys(packages).length,
            packages: Object.keys(packages).slice(0, 10)
        });
    } catch (error) {
        // npm outdated exits with code 1 if packages are outdated
        const packages = JSON.parse(error.stdout || '{}');
        results.checks.push({
            name: 'outdated-packages',
            status: 'warn',
            count: Object.keys(packages).length,
            packages: Object.keys(packages).slice(0, 10)
        });
    }
    
    // Output results
    console.log(JSON.stringify(results, null, 2));
    
    // Exit with error if critical vulnerabilities found
    const npmAudit = results.checks.find(c => c.name === 'npm-audit');
    if (npmAudit?.vulnerabilities?.critical > 0 || 
        npmAudit?.vulnerabilities?.high > 0) {
        process.exit(1);
    }
}

runSecurityChecks();
```

### 6.6 Package Selection Criteria

| Criterion | Check | Tools |
|-----------|-------|-------|
| **Maintenance** | Last publish date, open issues, commit activity | npm info, GitHub |
| **Security** | Known vulnerabilities, security policy | npm audit, Snyk |
| **Popularity** | Weekly downloads, dependents count | npm info |
| **License** | Compatible with project | license-checker |
| **Size** | Bundle size, dependencies | bundlephobia.com |
| **Quality** | TypeScript support, tests, documentation | npms.io |

---

## 7. Content Security Policy (CSP)

Content Security Policy is a critical defense layer against XSS and data injection attacks.

### 7.1 CSP Directive Reference

| Directive | Purpose | Recommended Value |
|-----------|---------|-------------------|
| `default-src` | Fallback for other directives | `'self'` |
| `script-src` | JavaScript sources | `'self'` with nonce/hash |
| `style-src` | CSS sources | `'self'` (avoid `'unsafe-inline'`) |
| `img-src` | Image sources | `'self' data: https:` |
| `font-src` | Font sources | `'self'` |
| `connect-src` | Fetch, XHR, WebSocket | `'self'` |
| `frame-src` | Iframe sources | `'none'` |
| `object-src` | Plugin content | `'none'` |
| `base-uri` | Base URL restriction | `'self'` |
| `form-action` | Form submission targets | `'self'` |
| `frame-ancestors` | Embedding parents | `'none'` |
| `upgrade-insecure-requests` | Force HTTPS | (directive only) |

### 7.2 Strict CSP Implementation

```javascript
import crypto from 'crypto';

/**
 * CSP Nonce Generator Middleware
 */
function cspNonceMiddleware(req, res, next) {
    // Generate cryptographically secure nonce
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
}

/**
 * CSP Header Middleware
 */
function cspHeaderMiddleware(req, res, next) {
    const nonce = res.locals.cspNonce;
    
    const cspDirectives = {
        'default-src': ["'self'"],
        'script-src': [`'self'`, `'nonce-${nonce}'`, "'strict-dynamic'"],
        'style-src': [`'self'`, `'nonce-${nonce}'`],
        'img-src': ["'self'", 'data:', 'https:'],
        'font-src': ["'self'"],
        'connect-src': ["'self'", 'https://api.trusted-service.com'],
        'frame-src': ["'none'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'upgrade-insecure-requests': [],
        'block-all-mixed-content': []
    };
    
    // Build CSP header string
    const cspString = Object.entries(cspDirectives)
        .map(([directive, values]) => {
            if (values.length === 0) return directive;
            return `${directive} ${values.join(' ')}`;
        })
        .join('; ');
    
    res.setHeader('Content-Security-Policy', cspString);
    
    // Also set for older browsers
    res.setHeader('X-Content-Security-Policy', cspString);
    res.setHeader('X-WebKit-CSP', cspString);
    
    next();
}

// Apply middleware
app.use(cspNonceMiddleware);
app.use(cspHeaderMiddleware);

// Template usage (EJS example)
// <script nonce="<%= cspNonce %>">
//   // Inline script with nonce
// </script>
```

### 7.3 CSP Reporting

```javascript
/**
 * CSP Violation Report Handler
 */
app.post('/api/csp-report', express.json({ type: 'application/csp-report' }), (req, res) => {
    const report = req.body['csp-report'];
    
    if (report) {
        // Log violation for analysis
        console.warn('CSP Violation:', {
            blockedUri: report['blocked-uri'],
            violatedDirective: report['violated-directive'],
            originalPolicy: report['original-policy'],
            documentUri: report['document-uri'],
            referrer: report['referrer'],
            sourceFile: report['source-file'],
            lineNumber: report['line-number'],
            columnNumber: report['column-number'],
            timestamp: new Date().toISOString()
        });
        
        // Send to monitoring service
        // await sendToSecurityMonitoring(report);
    }
    
    res.status(204).end();
});

// Add report-uri to CSP
const cspWithReporting = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}';
    report-uri /api/csp-report;
    report-to csp-endpoint
`.replace(/\s+/g, ' ').trim();

// Report-To header for modern browsers
res.setHeader('Report-To', JSON.stringify({
    group: 'csp-endpoint',
    max_age: 10886400,
    endpoints: [{ url: '/api/csp-report' }]
}));
```

### 7.4 CSP for Single Page Applications

```javascript
/**
 * SPA-specific CSP configuration
 */
const spaCSP = {
    // Allow hash for initial inline script
    'script-src': [
        "'self'",
        "'sha256-abc123...'", // Hash of inline bootstrap script
        "'strict-dynamic'"    // Allow dynamically loaded scripts
    ],
    
    // For webpack chunk loading
    'connect-src': [
        "'self'",
        'https://api.example.com',
        'wss://websocket.example.com'
    ],
    
    // For CSS-in-JS (styled-components, emotion)
    // Prefer nonces over unsafe-inline
    'style-src': [
        "'self'",
        "'nonce-${nonce}'" // Pass nonce to CSS-in-JS library
    ],
    
    // For web workers
    'worker-src': ["'self'", 'blob:'],
    
    // For service workers
    'script-src-elem': ["'self'"]
};

// Webpack configuration for CSP
// webpack.config.js
module.exports = {
    output: {
        // Add nonce to dynamically loaded scripts
        crossOriginLoading: 'anonymous'
    },
    optimization: {
        // Generate integrity hashes
        realContentHash: true
    }
};
```

### 7.5 Trusted Types Integration

```javascript
// CSP header with Trusted Types
const cspWithTrustedTypes = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}';
    require-trusted-types-for 'script';
    trusted-types default dompurify
`;

// Client-side Trusted Types policy
if (window.trustedTypes && trustedTypes.createPolicy) {
    // Default policy for innerHTML, etc.
    trustedTypes.createPolicy('default', {
        createHTML: (input) => {
            // Use DOMPurify for sanitization
            return DOMPurify.sanitize(input, {
                RETURN_TRUSTED_TYPE: true
            });
        },
        createScript: () => {
            throw new Error('Script creation blocked by Trusted Types');
        },
        createScriptURL: (input) => {
            const url = new URL(input, location.origin);
            if (url.origin === location.origin) {
                return input;
            }
            throw new Error('External script URL blocked');
        }
    });
}
```

---

## 8. Secure Storage Practices

Client-side storage mechanisms have different security characteristics. This section covers secure data handling for each storage type.

### 8.1 Storage Comparison

| Storage Type | Capacity | Persistence | JS Access | Sent w/ Requests | XSS Vulnerable |
|--------------|----------|-------------|-----------|------------------|----------------|
| Cookies (HttpOnly) | 4KB | Configurable | No | Yes | No |
| Cookies (Standard) | 4KB | Configurable | Yes | Yes | Yes |
| localStorage | 5-10MB | Permanent | Yes | No | Yes |
| sessionStorage | 5-10MB | Tab session | Yes | No | Yes |
| IndexedDB | Large | Permanent | Yes | No | Yes |
| Memory (variables) | RAM | Page session | Yes | No | Yes |

### 8.2 Secure Token Storage Strategy

```javascript
/**
 * Secure token management
 * 
 * Strategy:
 * - Access tokens: Memory only (short-lived, ~15 min)
 * - Refresh tokens: HttpOnly cookie (long-lived, ~7 days)
 * - User preferences: localStorage (non-sensitive)
 */

class SecureTokenManager {
    #accessToken = null;
    #tokenExpiry = null;
    
    // Store access token in memory only
    setAccessToken(token, expiresIn) {
        this.#accessToken = token;
        this.#tokenExpiry = Date.now() + (expiresIn * 1000);
    }
    
    getAccessToken() {
        if (!this.#accessToken || Date.now() > this.#tokenExpiry) {
            return null;
        }
        return this.#accessToken;
    }
    
    clearAccessToken() {
        this.#accessToken = null;
        this.#tokenExpiry = null;
    }
    
    isTokenValid() {
        return this.#accessToken && Date.now() < this.#tokenExpiry;
    }
    
    // Token refresh using HttpOnly refresh token cookie
    async refreshAccessToken() {
        try {
            const response = await fetch('/api/auth/refresh', {
                method: 'POST',
                credentials: 'include', // Include HttpOnly cookies
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Token refresh failed');
            }
            
            const data = await response.json();
            this.setAccessToken(data.accessToken, data.expiresIn);
            
            return true;
        } catch (error) {
            this.clearAccessToken();
            return false;
        }
    }
}

// Server-side: Set refresh token as HttpOnly cookie
app.post('/api/auth/login', async (req, res) => {
    const user = await authenticateUser(req.body);
    
    if (user) {
        const accessToken = generateAccessToken(user, '15m');
        const refreshToken = generateRefreshToken(user, '7d');
        
        // Set refresh token as HttpOnly cookie
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/api/auth' // Limit to auth endpoints
        });
        
        // Return access token in response body
        res.json({
            accessToken,
            expiresIn: 900 // 15 minutes
        });
    }
});
```

### 8.3 Encrypted Local Storage

When localStorage must be used, encrypt sensitive data:

```javascript
/**
 * Encrypted storage wrapper using Web Crypto API
 * Note: Key derived from user password, not stored
 */
class EncryptedStorage {
    #key = null;
    #storagePrefix = 'enc_';
    
    // Derive encryption key from password
    async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        
        // Import password as key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveKey']
        );
        
        // Derive AES-GCM key
        this.#key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode(salt),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }
    
    // Encrypt and store
    async setItem(key, value) {
        if (!this.#key) {
            throw new Error('Key not initialized');
        }
        
        const encoder = new TextEncoder();
        const data = encoder.encode(JSON.stringify(value));
        
        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.#key,
            data
        );
        
        // Store IV + ciphertext
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        
        localStorage.setItem(
            this.#storagePrefix + key,
            btoa(String.fromCharCode(...combined))
        );
    }
    
    // Retrieve and decrypt
    async getItem(key) {
        if (!this.#key) {
            throw new Error('Key not initialized');
        }
        
        const stored = localStorage.getItem(this.#storagePrefix + key);
        if (!stored) return null;
        
        // Decode
        const combined = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);
        
        // Decrypt
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.#key,
            ciphertext
        );
        
        const decoder = new TextDecoder();
        return JSON.parse(decoder.decode(decrypted));
    }
    
    // Clear all encrypted items
    clearAll() {
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith(this.#storagePrefix)) {
                keysToRemove.push(key);
            }
        }
        keysToRemove.forEach(key => localStorage.removeItem(key));
        this.#key = null;
    }
}
```

### 8.4 Storage Security Guidelines

```javascript
/**
 * Storage security guidelines and validation
 */
const StorageGuidelines = {
    // Data classification
    classifications: {
        PUBLIC: {
            storage: ['localStorage', 'sessionStorage', 'indexedDB'],
            encryption: false,
            examples: ['theme', 'language', 'layout preferences']
        },
        INTERNAL: {
            storage: ['sessionStorage', 'memory'],
            encryption: true,
            examples: ['user profile (non-PII)', 'cached queries']
        },
        CONFIDENTIAL: {
            storage: ['memory', 'httpOnly cookies'],
            encryption: true,
            examples: ['tokens', 'session data']
        },
        RESTRICTED: {
            storage: ['backend only'],
            encryption: true,
            examples: ['passwords', 'PII', 'financial data']
        }
    },
    
    // Items that should NEVER be in client-side storage
    prohibited: [
        'passwords',
        'password hashes',
        'credit card numbers',
        'social security numbers',
        'encryption keys',
        'API secrets',
        'private keys',
        'full session tokens (use HttpOnly)',
        'medical records',
        'biometric data'
    ],
    
    // Validate storage usage
    validateStorage(dataType, storageMethod) {
        const classification = this.getClassification(dataType);
        if (!classification.storage.includes(storageMethod)) {
            throw new Error(
                `Data type '${dataType}' cannot be stored in '${storageMethod}'`
            );
        }
        return true;
    }
};
```

---

## 9. Web Crypto API and FIPS 140-3 Compliance

The Web Crypto API provides standardized cryptographic primitives that can meet FIPS 140-3 requirements when properly implemented.

### 9.1 FIPS 140-3 Approved Algorithms

| Algorithm | Web Crypto Support | FIPS Approved | Use Case |
|-----------|-------------------|---------------|----------|
| AES-GCM | Yes | Yes | Authenticated encryption |
| AES-CBC | Yes | Yes | Block cipher (use with HMAC) |
| RSA-OAEP | Yes | Yes | Asymmetric encryption |
| RSA-PSS | Yes | Yes | Digital signatures |
| ECDSA | Yes | Yes | Digital signatures |
| ECDH | Yes | Yes | Key exchange |
| SHA-256/384/512 | Yes | Yes | Hashing |
| HMAC | Yes | Yes | Message authentication |
| PBKDF2 | Yes | Yes | Key derivation |
| HKDF | Yes | Yes | Key derivation |

### 9.2 Cryptographic Best Practices

```javascript
/**
 * FIPS-compliant cryptographic utilities
 */
class SecureCrypto {
    // AES-GCM encryption (authenticated encryption)
    static async encryptAESGCM(plaintext, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        
        // 96-bit IV (NIST recommended for GCM)
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128 // 128-bit authentication tag
            },
            key,
            data
        );
        
        return { ciphertext, iv };
    }
    
    // AES-GCM decryption
    static async decryptAESGCM(ciphertext, key, iv) {
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            key,
            ciphertext
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }
    
    // Generate AES-256 key
    static async generateAESKey() {
        return crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256 // 256-bit key
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }
    
    // RSA-OAEP key pair generation
    static async generateRSAKeyPair() {
        return crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 4096, // FIPS minimum 2048, recommend 4096
                publicExponent: new Uint8Array([1, 0, 1]), // 65537
                hash: 'SHA-256'
            },
            true,
            ['encrypt', 'decrypt']
        );
    }
    
    // ECDSA key pair for signing
    static async generateECDSAKeyPair() {
        return crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-384' // FIPS approved curve
            },
            true,
            ['sign', 'verify']
        );
    }
    
    // Digital signature with ECDSA
    static async sign(data, privateKey) {
        const encoder = new TextEncoder();
        return crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: 'SHA-384'
            },
            privateKey,
            encoder.encode(data)
        );
    }
    
    // Verify signature
    static async verify(signature, data, publicKey) {
        const encoder = new TextEncoder();
        return crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: 'SHA-384'
            },
            publicKey,
            signature,
            encoder.encode(data)
        );
    }
    
    // Secure password hashing with PBKDF2
    static async hashPassword(password, salt) {
        const encoder = new TextEncoder();
        
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits']
        );
        
        const hash = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 600000, // OWASP 2023 recommendation
                hash: 'SHA-256'
            },
            keyMaterial,
            256
        );
        
        return new Uint8Array(hash);
    }
    
    // Generate cryptographically secure random values
    static getRandomBytes(length) {
        return crypto.getRandomValues(new Uint8Array(length));
    }
    
    // Generate secure random token
    static generateSecureToken(length = 32) {
        const bytes = this.getRandomBytes(length);
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}
```

### 9.3 Key Management

```javascript
/**
 * Secure key management utilities
 */
class KeyManager {
    // Export key for storage (wrap with password)
    static async exportKey(key, password) {
        // Generate salt for key derivation
        const salt = crypto.getRandomValues(new Uint8Array(16));
        
        // Derive wrapping key from password
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        
        const wrappingKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-KW', length: 256 },
            false,
            ['wrapKey']
        );
        
        // Wrap the key
        const wrapped = await crypto.subtle.wrapKey(
            'raw',
            key,
            wrappingKey,
            'AES-KW'
        );
        
        return {
            wrappedKey: new Uint8Array(wrapped),
            salt: salt
        };
    }
    
    // Import wrapped key
    static async importKey(wrappedKey, salt, password, algorithm) {
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        
        const unwrappingKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-KW', length: 256 },
            false,
            ['unwrapKey']
        );
        
        return crypto.subtle.unwrapKey(
            'raw',
            wrappedKey,
            unwrappingKey,
            'AES-KW',
            algorithm,
            true,
            ['encrypt', 'decrypt']
        );
    }
    
    // Secure key rotation
    static async rotateKey(oldKey, newKey, encryptedData, iv) {
        // Decrypt with old key
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            oldKey,
            encryptedData
        );
        
        // Re-encrypt with new key
        const newIv = crypto.getRandomValues(new Uint8Array(12));
        const newCiphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: newIv },
            newKey,
            plaintext
        );
        
        return { ciphertext: newCiphertext, iv: newIv };
    }
}
```

### 9.4 FIPS Compliance Checklist

| Requirement | Implementation | Verification |
|-------------|----------------|--------------|
| Use approved algorithms only | AES-GCM, RSA-OAEP, ECDSA, SHA-2 | Code review |
| Minimum key lengths | AES-256, RSA-2048+, EC P-256+ | Automated tests |
| Secure random generation | `crypto.getRandomValues()` | Security audit |
| Key protection | Wrap keys, no plaintext storage | Penetration test |
| Algorithm agility | Support key/algorithm rotation | Architecture review |
| Audit logging | Log crypto operations | Log analysis |

---

## 10. Security Standards Cross-Reference

This section maps JavaScript security practices to major compliance frameworks.

### 10.1 OWASP Top 10 (2021/2025) Mapping

| OWASP Risk | JavaScript Mitigation | Section Reference |
|------------|----------------------|-------------------|
| **A01: Broken Access Control** | Implement proper authorization checks, use HttpOnly cookies, validate JWT | [5.4](#54-secure-session-management) |
| **A02: Cryptographic Failures** | Use Web Crypto API with approved algorithms, secure key management | [9](#9-web-crypto-api-and-fips-140-3-compliance) |
| **A03: Injection** | Input validation, output encoding, parameterized queries, CSP | [2](#2-cross-site-scripting-xss-prevention), [7](#7-content-security-policy-csp) |
| **A04: Insecure Design** | Security by design, threat modeling, secure defaults | All sections |
| **A05: Security Misconfiguration** | Secure headers (Helmet), CSP, proper CORS | [5.2](#52-secure-http-headers), [7](#7-content-security-policy-csp) |
| **A06: Vulnerable Components** | npm audit, dependency management, SCA tools | [6](#6-npmpackage-security-and-dependency-management) |
| **A07: Authentication Failures** | Secure session management, rate limiting, MFA | [5.3](#53-rate-limiting), [5.4](#54-secure-session-management) |
| **A08: Software/Data Integrity** | Subresource Integrity, package lock files | [6.3](#63-lock-file-security) |
| **A09: Security Logging Failures** | CSP reporting, error logging, audit trails | [7.3](#73-csp-reporting) |
| **A10: SSRF** | URL validation, allowlists, request filtering | [4.3](#43-safe-url-handling) |

### 10.2 NIST SP 800-53 Rev. 5 Controls

| Control Family | Control ID | JavaScript Implementation |
|----------------|------------|--------------------------|
| **Access Control** | AC-3 | Authorization middleware, RBAC |
| **Access Control** | AC-4 | CSP, CORS configuration |
| **Audit & Accountability** | AU-2 | Security event logging |
| **Identification & Auth** | IA-5 | Secure credential storage, PBKDF2 |
| **System & Comms Protection** | SC-8 | HTTPS/TLS enforcement |
| **System & Comms Protection** | SC-12 | Web Crypto API key management |
| **System & Comms Protection** | SC-13 | FIPS-approved algorithms |
| **System & Comms Protection** | SC-28 | Encrypted storage |
| **System Integrity** | SI-3 | Input validation, sanitization |
| **System Integrity** | SI-10 | Input validation, encoding |
| **System Integrity** | SI-16 | Prototype pollution prevention |

### 10.3 DISA STIG Requirements

| STIG ID | Requirement | JavaScript Control |
|---------|-------------|-------------------|
| **SRG-APP-000001** | Session management | Secure session configuration |
| **SRG-APP-000014** | Account lockout | Rate limiting |
| **SRG-APP-000033** | Display security banner | CSP frame-ancestors |
| **SRG-APP-000141** | Data validation | Input validation/sanitization |
| **SRG-APP-000142** | Reject unauthorized input | Schema validation |
| **SRG-APP-000175** | Session timeout | Session maxAge |
| **SRG-APP-000179** | Encrypt data in transit | HTTPS, HSTS |
| **SRG-APP-000185** | Encrypt data at rest | Web Crypto API |
| **SRG-APP-000251** | Input validation | Parameterized queries |
| **SRG-APP-000266** | Error handling | Sanitized error messages |

### 10.4 CIS Benchmark Level 2 Controls

| CIS Control | Recommendation | Implementation |
|-------------|----------------|----------------|
| **4.1** | Secure configuration management | npm lock files, version pinning |
| **4.3** | Use of security headers | Helmet.js, CSP headers |
| **6.1** | Logging | Security event logging |
| **6.2** | Log management | Centralized log aggregation |
| **10.1** | Malware defense | Input sanitization, CSP |
| **13.1** | Data encryption | Web Crypto API, HTTPS |
| **13.6** | Encrypt sensitive data | Encrypted storage |
| **16.1** | Secure development | Secure coding practices |
| **16.9** | Train developers | Security awareness |

### 10.5 FIPS 140-3 Compliance Matrix

| Requirement | Level 1 | Level 2 | Level 3 | Web Crypto Support |
|-------------|---------|---------|---------|-------------------|
| Approved algorithms | Required | Required | Required | Full |
| Key management | Basic | Enhanced | Physical | Partial (software) |
| Physical security | N/A | Tamper-evident | Tamper-resistant | N/A (browser) |
| Operational environment | Documented | Limited | Isolated | Browser dependent |
| Self-tests | Power-up | Conditional | Continuous | Browser implemented |

---

## 11. Compliance Checklists

### 11.1 Development Security Checklist

```
[ ] Input Validation
    [ ] All user input validated on server-side
    [ ] Schema validation implemented
    [ ] Reject unexpected data types
    [ ] Sanitize special characters

[ ] Output Encoding
    [ ] Context-aware encoding implemented
    [ ] HTML encoding for user content
    [ ] JavaScript encoding in JS contexts
    [ ] URL encoding for query parameters

[ ] XSS Prevention
    [ ] Use textContent over innerHTML
    [ ] DOMPurify for HTML sanitization
    [ ] CSP implemented and tested
    [ ] Trusted Types enabled

[ ] Prototype Pollution
    [ ] Safe object merge functions
    [ ] __proto__ filtering
    [ ] Object.create(null) for data
    [ ] Schema validation for JSON

[ ] Authentication
    [ ] HttpOnly cookies for tokens
    [ ] Session regeneration on login
    [ ] Secure session configuration
    [ ] Rate limiting on auth endpoints

[ ] Cryptography
    [ ] Web Crypto API for all crypto
    [ ] FIPS-approved algorithms only
    [ ] Proper key lengths (AES-256, RSA-2048+)
    [ ] Secure random generation
```

### 11.2 Deployment Security Checklist

```
[ ] Dependencies
    [ ] npm audit passed (no critical/high)
    [ ] Package lock file committed
    [ ] Outdated packages reviewed
    [ ] License compliance verified

[ ] HTTP Security Headers
    [ ] Content-Security-Policy
    [ ] Strict-Transport-Security
    [ ] X-Content-Type-Options: nosniff
    [ ] X-Frame-Options: DENY
    [ ] Referrer-Policy
    [ ] Permissions-Policy

[ ] TLS/HTTPS
    [ ] TLS 1.2+ only
    [ ] Valid certificate
    [ ] HSTS preload ready
    [ ] Mixed content eliminated

[ ] Environment
    [ ] Debug mode disabled
    [ ] Stack traces hidden
    [ ] Secrets in environment variables
    [ ] Log levels appropriate
```

### 11.3 Code Review Security Checklist

```
[ ] No sensitive data in client-side storage
[ ] No eval() or Function() with user input
[ ] No document.write() with dynamic content
[ ] No innerHTML with unsanitized content
[ ] No dangerous DOM methods with user data
[ ] Proper error handling (no sensitive leaks)
[ ] HTTPS for all external requests
[ ] Origin validation for postMessage
[ ] Safe child process execution (Node.js)
[ ] Path traversal prevention (Node.js)
```

### 11.4 Security Testing Checklist

```
[ ] Static Analysis
    [ ] ESLint security plugins
    [ ] npm audit
    [ ] Snyk/Dependabot scan

[ ] Dynamic Testing
    [ ] XSS testing (OWASP ZAP)
    [ ] Injection testing
    [ ] Authentication testing
    [ ] Session management testing

[ ] Penetration Testing
    [ ] Annual penetration test
    [ ] Remediation verified
    [ ] Retest completed

[ ] Monitoring
    [ ] CSP violation monitoring
    [ ] Error rate monitoring
    [ ] Authentication failure alerts
    [ ] Rate limit alerts
```

---

## 12. References

### Official Documentation

1. [MDN Web Security Documentation](https://developer.mozilla.org/en-US/docs/Web/Security) - Mozilla Developer Network
2. [Node.js Security Best Practices](https://nodejs.org/en/learn/getting-started/security-best-practices) - Node.js Official Documentation
3. [Web Crypto API Specification](https://www.w3.org/TR/webcrypto-2/) - W3C
4. [ECMAScript 2024 Language Specification](https://tc39.es/ecma262/2024/) - TC39

### Security Standards

5. [OWASP Top 10:2021](https://owasp.org/Top10/2021/) - Open Web Application Security Project
6. [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
7. [OWASP Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
8. [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
9. [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) - Security and Privacy Controls
10. [NIST FIPS 140-3](https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards) - Cryptographic Module Validation
11. [DISA STIG Library](https://www.cyber.mil/stigs/downloads/) - Security Technical Implementation Guides
12. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Center for Internet Security

### Tools and Libraries

13. [DOMPurify](https://github.com/cure53/DOMPurify) - XSS Sanitizer Library
14. [Helmet.js](https://helmetjs.github.io/) - Express Security Middleware
15. [npm Audit Documentation](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities/)
16. [Snyk](https://snyk.io/) - Security Vulnerability Scanner

### Additional Resources

17. [PortSwigger Web Security Academy - Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
18. [Content Security Policy Reference](https://content-security-policy.com/)
19. [Node.js Best Practices Repository](https://github.com/goldbergyoni/nodebestpractices)
20. [5 JavaScript Security Best Practices for 2024](https://thenewstack.io/5-javascript-security-best-practices-for-2024/) - The New Stack

---

## Document History

| Version | Date |Author | Changes |
|---------|------|--------|---------|
| 1.0 | March 2026 | Matrix Agent | Initial release |

---

*This document should be reviewed and updated quarterly to address emerging threats and evolving security standards.*
