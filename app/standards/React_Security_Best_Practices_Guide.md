# React Security Best Practices Guide

**Version:** 1.0  
**Last Updated:** March 2026  
**Author:** Matrix Agent

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [React Coding Best Practices](#react-coding-best-practices)
   - [React 18/19 Security Features](#react-1819-security-features)
   - [XSS Prevention and Safe Rendering](#xss-prevention-and-safe-rendering)
   - [State Management Security](#state-management-security)
   - [Authentication Patterns](#authentication-patterns)
   - [Secure API Communication](#secure-api-communication)
   - [Dependencies and Supply Chain Security](#dependencies-and-supply-chain-security)
   - [Content Security Policy Implementation](#content-security-policy-implementation)
3. [Security Standards Cross-Reference](#security-standards-cross-reference)
   - [NIST SP 800-53 Controls](#nist-sp-800-53-controls)
   - [OWASP Top Ten Mapping](#owasp-top-ten-mapping)
   - [DISA STIG Requirements](#disa-stig-requirements)
   - [CIS Benchmark Level 2](#cis-benchmark-level-2)
   - [FIPS 140-3 Cryptographic Requirements](#fips-140-3-cryptographic-requirements)
4. [Compliance Checklists](#compliance-checklists)
5. [References](#references)

---

## Executive Summary

This guide provides comprehensive security best practices for React applications, aligned with major security frameworks including NIST SP 800-53, OWASP Top Ten 2025, DISA STIGs, CIS Benchmarks Level 2, and FIPS 140-3. React's design inherently provides protection against many common web vulnerabilities through automatic escaping of dynamic content, but developers must remain vigilant and follow established security patterns to build truly secure applications.

Key areas covered include XSS prevention, secure authentication with JWT and OAuth, state management security, Content Security Policy implementation, and supply chain security. Each section maps directly to applicable compliance requirements to facilitate audit readiness and regulatory compliance.

---

## React Coding Best Practices

### React 18/19 Security Features

React 18 and 19 introduce several features with security implications that developers must understand and properly implement.

#### React 18 Security Considerations

| Feature | Security Implications | Best Practice |
|---------|----------------------|---------------|
| Concurrent Rendering | Race conditions in state updates | Use proper state synchronization patterns |
| Automatic Batching | State consistency across renders | Validate state before sensitive operations |
| Suspense for SSR | Potential data exposure in streaming | Sanitize all server-rendered content |
| Strict Mode | Identifies unsafe lifecycles | Enable in development for security auditing |

#### React 19 Security Features

**Server Components Security (Critical):**

In December 2025, a critical vulnerability (CVE-2025-55182) was discovered in React 19 Server Actions. Applications using React Server Components must implement proper validation:

```jsx
// VULNERABLE: Direct use of Server Actions without validation
async function submitForm(formData) {
  'use server';
  // No validation - vulnerable to injection
  await db.insert(formData.get('data'));
}

// SECURE: Validated Server Action
import { z } from 'zod';

const FormSchema = z.object({
  data: z.string().max(1000).regex(/^[a-zA-Z0-9\s]+$/),
});

async function submitForm(formData) {
  'use server';
  const validated = FormSchema.parse({
    data: formData.get('data'),
  });
  await db.insert(validated.data);
}
```

**Server Actions Security Checklist:**

- [ ] Validate all Server Action inputs using schema validation (Zod, Yup)
- [ ] Implement rate limiting on Server Actions
- [ ] Use CSRF tokens for state-changing actions
- [ ] Avoid exposing internal IDs or sensitive data in action responses
- [ ] Log all Server Action invocations for audit trails

---

### XSS Prevention and Safe Rendering

React provides automatic XSS protection through JSX escaping, but several patterns can bypass this protection.

#### Default XSS Protection

React automatically escapes values embedded in JSX using curly braces:

```jsx
// SAFE: Automatic escaping prevents XSS
function SafeComponent({ userInput }) {
  // Even if userInput contains "<script>alert('xss')</script>",
  // it will be rendered as text, not executed
  return <div>{userInput}</div>;
}
```

#### Dangerous Patterns to Avoid

**1. dangerouslySetInnerHTML Without Sanitization:**

```jsx
// VULNERABLE: Direct HTML injection
function UnsafeComponent({ htmlContent }) {
  return <div dangerouslySetInnerHTML={{ __html: htmlContent }} />;
}

// SECURE: Sanitized HTML injection
import DOMPurify from 'dompurify';

function SafeComponent({ htmlContent }) {
  const sanitizedHTML = DOMPurify.sanitize(htmlContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'title'],
    ALLOW_DATA_ATTR: false,
  });
  return <div dangerouslySetInnerHTML={{ __html: sanitizedHTML }} />;
}
```

**2. JavaScript Protocol in URLs:**

```jsx
// VULNERABLE: JavaScript protocol injection
function UnsafeLink({ userUrl }) {
  return <a href={userUrl}>Click here</a>;
}

// SECURE: URL protocol validation
function SafeLink({ userUrl }) {
  const isValidUrl = (url) => {
    try {
      const parsed = new URL(url);
      return ['http:', 'https:', 'mailto:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  };

  return (
    <a href={isValidUrl(userUrl) ? userUrl : '#'}>
      Click here
    </a>
  );
}
```

**3. Direct DOM Manipulation:**

```jsx
// VULNERABLE: Bypasses React's protection
function UnsafeDOM() {
  const ref = useRef(null);
  
  useEffect(() => {
    // Direct innerHTML assignment - XSS risk
    ref.current.innerHTML = userContent;
  }, [userContent]);

  return <div ref={ref} />;
}

// SECURE: Use React's rendering with sanitization
function SafeDOM({ userContent }) {
  const sanitized = DOMPurify.sanitize(userContent);
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}
```

**4. SSR JSON Injection:**

```jsx
// VULNERABLE: Script breakout in SSR
function renderPage(state) {
  return `
    <script>
      window.__STATE__ = ${JSON.stringify(state)};
    </script>
  `;
}

// SECURE: Escape script-breaking characters
function renderPageSecure(state) {
  const safeState = JSON.stringify(state)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026');
  
  return `
    <script>
      window.__STATE__ = ${safeState};
    </script>
  `;
}
```

#### XSS Prevention Reference Table

| Attack Vector | Vulnerable Pattern | Secure Alternative |
|---------------|-------------------|-------------------|
| HTML Injection | `dangerouslySetInnerHTML` with raw input | DOMPurify sanitization |
| JavaScript URLs | Unvalidated `href` attributes | Protocol whitelist validation |
| DOM Manipulation | `element.innerHTML = userInput` | React controlled rendering |
| Event Handlers | `onClick={eval(userInput)}` | Static handler functions |
| SSR Injection | Unserialized JSON in `<script>` | Escape `<`, `>`, `&` characters |
| Attribute Injection | `<input value={userInput}>` without encoding | React's automatic attribute escaping |

---

### State Management Security

Secure state management requires protecting sensitive data in Redux, Context API, and other state solutions.

#### Redux Security Best Practices

```javascript
// store/securityMiddleware.js
export const securityMiddleware = (store) => (next) => (action) => {
  // 1. Sanitize action payloads
  const sanitizedAction = sanitizeAction(action);
  
  // 2. Log security-relevant actions
  if (isSecurityRelevant(action.type)) {
    securityLogger.log({
      type: action.type,
      timestamp: new Date().toISOString(),
      userId: store.getState().auth?.userId,
    });
  }
  
  // 3. Prevent sensitive data in Redux DevTools (production)
  if (process.env.NODE_ENV === 'production') {
    if (containsSensitiveData(action)) {
      return next({ ...action, payload: '[REDACTED]' });
    }
  }
  
  return next(sanitizedAction);
};

// Sensitive data patterns to redact
const SENSITIVE_PATTERNS = [
  /password/i,
  /token/i,
  /secret/i,
  /creditCard/i,
  /ssn/i,
];

function containsSensitiveData(action) {
  const actionString = JSON.stringify(action);
  return SENSITIVE_PATTERNS.some(pattern => pattern.test(actionString));
}
```

**Redux Store Configuration:**

```javascript
// store/index.js
import { configureStore } from '@reduxjs/toolkit';

const store = configureStore({
  reducer: rootReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      // Disable serializable check for sensitive data objects
      serializableCheck: {
        ignoredActions: ['auth/setCredentials'],
        ignoredPaths: ['auth.tokens'],
      },
    }).concat(securityMiddleware),
  devTools: process.env.NODE_ENV !== 'production', // Disable in production
});
```

#### Context API Security

```jsx
// contexts/AuthContext.jsx
import { createContext, useContext, useMemo, useCallback } from 'react';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [authState, setAuthState] = useState({
    isAuthenticated: false,
    user: null,
    // NEVER store tokens in Context state
  });

  // Memoize to prevent unnecessary re-renders that could leak data
  const value = useMemo(() => ({
    isAuthenticated: authState.isAuthenticated,
    user: authState.user,
    // Provide methods, not raw state setters
    login: async (credentials) => {
      const result = await authService.login(credentials);
      setAuthState({ isAuthenticated: true, user: result.user });
    },
    logout: async () => {
      await authService.logout();
      setAuthState({ isAuthenticated: false, user: null });
    },
  }), [authState]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// Secure context access
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
```

#### State Security Checklist

| Requirement | Implementation |
|-------------|----------------|
| Sensitive data isolation | Store tokens in httpOnly cookies, not state |
| DevTools protection | Disable Redux DevTools in production |
| State sanitization | Sanitize all user inputs before state updates |
| Memory cleanup | Clear sensitive state on logout |
| Type safety | Use TypeScript for state type enforcement |
| Audit logging | Log security-relevant state changes |

---

### Authentication Patterns

Secure authentication in React requires proper handling of JWT tokens, OAuth flows, and session management.

#### JWT Security Implementation

**Token Storage Hierarchy (Most to Least Secure):**

| Storage Method | Security Level | Vulnerabilities | Use Case |
|----------------|---------------|-----------------|----------|
| httpOnly Cookies | Highest | CSRF (mitigatable) | Recommended for web apps |
| Memory (closure) | High | Lost on refresh | SPAs with refresh token flow |
| sessionStorage | Medium | XSS attacks | Temporary sessions |
| localStorage | Lowest | XSS attacks | Avoid for sensitive tokens |

**Secure Token Management:**

```javascript
// services/tokenService.js
class SecureTokenService {
  #accessToken = null; // Private field - stored in memory
  #refreshPromise = null;

  setAccessToken(token) {
    this.#accessToken = token;
  }

  getAccessToken() {
    return this.#accessToken;
  }

  clearTokens() {
    this.#accessToken = null;
  }

  // Refresh token stored in httpOnly cookie (set by server)
  async refreshAccessToken() {
    // Prevent multiple simultaneous refresh requests
    if (this.#refreshPromise) {
      return this.#refreshPromise;
    }

    this.#refreshPromise = fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include', // Send httpOnly cookie
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error('Token refresh failed');
        }
        const { accessToken } = await response.json();
        this.setAccessToken(accessToken);
        return accessToken;
      })
      .finally(() => {
        this.#refreshPromise = null;
      });

    return this.#refreshPromise;
  }
}

export const tokenService = new SecureTokenService();
```

**Axios Interceptor for Token Management:**

```javascript
// api/axiosConfig.js
import axios from 'axios';
import { tokenService } from './tokenService';

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL,
  withCredentials: true, // Include cookies
});

// Request interceptor - attach access token
api.interceptors.request.use(
  (config) => {
    const token = tokenService.getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor - handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
originalRequest._retry = true;

      try {
        await tokenService.refreshAccessToken();
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh failed - redirect to login
        tokenService.clearTokens();
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;
```

#### OAuth 2.0 / OIDC Implementation

```jsx
// hooks/useOAuth.js
import { useCallback, useEffect } from 'react';

export function useOAuth(config) {
  const {
    authorizationEndpoint,
    clientId,
    redirectUri,
    scope,
    responseType = 'code',
  } = config;

  // Generate cryptographically secure state and PKCE values
  const generateAuthParams = useCallback(() => {
    const state = crypto.randomUUID();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Store in sessionStorage (cleared on tab close)
    sessionStorage.setItem('oauth_state', state);
    sessionStorage.setItem('oauth_code_verifier', codeVerifier);

    return { state, codeChallenge };
  }, []);

  const initiateLogin = useCallback(async () => {
    const { state, codeChallenge } = await generateAuthParams();

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: responseType,
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    window.location.href = `${authorizationEndpoint}?${params}`;
  }, [authorizationEndpoint, clientId, redirectUri, scope, generateAuthParams]);

  const handleCallback = useCallback(async (searchParams) => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const storedState = sessionStorage.getItem('oauth_state');
    const codeVerifier = sessionStorage.getItem('oauth_code_verifier');

    // Validate state to prevent CSRF
    if (state !== storedState) {
      throw new Error('Invalid state parameter - possible CSRF attack');
    }

    // Clear stored values
    sessionStorage.removeItem('oauth_state');
    sessionStorage.removeItem('oauth_code_verifier');

    // Exchange code for tokens (done server-side for security)
    const response = await fetch('/api/auth/oauth/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, codeVerifier }),
      credentials: 'include',
    });

    return response.json();
  }, []);

  return { initiateLogin, handleCallback };
}

// PKCE utilities
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(hash));
}

function base64URLEncode(buffer) {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

#### Protected Route Component

```jsx
// components/ProtectedRoute.jsx
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export function ProtectedRoute({ 
  children, 
  requiredRoles = [],
  requiredPermissions = [],
}) {
  const { isAuthenticated, user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <LoadingSpinner />;
  }

  if (!isAuthenticated) {
    // Preserve intended destination
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Role-based access control
  if (requiredRoles.length > 0) {
    const hasRequiredRole = requiredRoles.some(role => 
      user.roles?.includes(role)
    );
    if (!hasRequiredRole) {
      return <Navigate to="/unauthorized" replace />;
    }
  }

  // Permission-based access control
  if (requiredPermissions.length > 0) {
    const hasRequiredPermission = requiredPermissions.every(permission =>
      user.permissions?.includes(permission)
    );
    if (!hasRequiredPermission) {
      return <Navigate to="/unauthorized" replace />;
    }
  }

  return children;
}

// Usage
<Route
  path="/admin/*"
  element={
    <ProtectedRoute requiredRoles={['admin', 'superadmin']}>
      <AdminDashboard />
    </ProtectedRoute>
  }
/>
```

---

### Secure API Communication

Implement secure communication patterns between React frontend and backend APIs.

#### API Security Configuration

```javascript
// api/secureApi.js
import axios from 'axios';

const secureApi = axios.create({
  baseURL: process.env.REACT_APP_API_URL,
  timeout: 30000,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest', // CSRF protection indicator
  },
});

// CSRF Token handling
secureApi.interceptors.request.use((config) => {
  // Get CSRF token from meta tag or cookie
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content
    || getCookie('XSRF-TOKEN');
  
  if (csrfToken) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }
  
  return config;
});

// Response security validation
secureApi.interceptors.response.use(
  (response) => {
    // Validate content-type to prevent MIME sniffing attacks
    const contentType = response.headers['content-type'];
    if (contentType && !contentType.includes('application/json')) {
      console.warn('Unexpected content-type:', contentType);
    }
    return response;
  },
  (error) => {
    // Handle security-related errors
    if (error.response?.status === 403) {
      // Possible CSRF token expiration
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop().split(';').shift();
  }
  return null;
}

export default secureApi;
```

#### Input Validation Layer

```javascript
// utils/validators.js
import { z } from 'zod';
import DOMPurify from 'dompurify';

// Common validation schemas
export const schemas = {
  email: z.string().email().max(254),
  password: z.string()
    .min(12, 'Password must be at least 12 characters')
    .regex(/[A-Z]/, 'Password must contain uppercase letter')
    .regex(/[a-z]/, 'Password must contain lowercase letter')
    .regex(/[0-9]/, 'Password must contain number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain special character'),
  username: z.string()
    .min(3)
    .max(30)
    .regex(/^[a-zA-Z0-9_-]+$/, 'Invalid characters in username'),
  url: z.string().url().refine(
    (url) => ['http:', 'https:'].includes(new URL(url).protocol),
    'Only HTTP(S) URLs allowed'
  ),
  safeHtml: z.string().transform((val) => DOMPurify.sanitize(val)),
  uuid: z.string().uuid(),
  positiveInt: z.number().int().positive(),
};

// API request validator factory
export function createRequestValidator(schema) {
  return (data) => {
    const result = schema.safeParse(data);
    if (!result.success) {
      const errors = result.error.issues.map(issue => ({
        path: issue.path.join('.'),
        message: issue.message,
      }));
      throw new ValidationError('Invalid request data', errors);
    }
    return result.data;
  };
}

// Usage example
const loginSchema = z.object({
  email: schemas.email,
  password: z.string().min(1), // Don't validate password strength on login
  rememberMe: z.boolean().optional(),
});

export const validateLoginRequest = createRequestValidator(loginSchema);
```

#### Secure Data Fetching Hook

```jsx
// hooks/useSecureFetch.js
import { useState, useCallback, useRef, useEffect } from 'react';
import secureApi from '../api/secureApi';

export function useSecureFetch(url, options = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const abortControllerRef = useRef(null);

  const fetchData = useCallback(async (fetchOptions = {}) => {
    // Cancel previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    abortControllerRef.current = new AbortController();
    setIsLoading(true);
    setError(null);

    try {
      const response = await secureApi({
        url,
        signal: abortControllerRef.current.signal,
        ...options,
        ...fetchOptions,
      });

      // Validate response structure
      if (options.validateResponse) {
        options.validateResponse(response.data);
      }

      setData(response.data);
      return response.data;
    } catch (err) {
      if (err.name === 'AbortError') {
        return; // Request was cancelled
      }

      const errorMessage = err.response?.data?.message || err.message;
      setError(errorMessage);
      
      // Log for security monitoring (don't expose to users)
      console.error('API Error:', {
        url,
        status: err.response?.status,
        message: errorMessage,
      });
      
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [url, options]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  return { data, error, isLoading, fetchData, refetch: fetchData };
}
```

---

### Dependencies and Supply Chain Security

Protect against supply chain attacks targeting npm packages and dependencies.

#### Dependency Security Strategy

```json
// package.json security configuration
{
  "scripts": {
    "preinstall": "npx npm-force-resolutions",
    "postinstall": "npm audit --audit-level=high",
    "security:audit": "npm audit && npx snyk test",
    "security:check": "npx better-npm-audit audit",
    "security:licenses": "npx license-checker --onlyAllow 'MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC'",
    "security:outdated": "npm outdated --long"
  },
  "overrides": {
    "vulnerable-package": "^2.0.0"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  }
}
```

#### .npmrc Security Configuration

```ini
# .npmrc
# Require package-lock.json
package-lock=true

# Enforce strict SSL
strict-ssl=true

# Use specific registry (consider private registry)
registry=https://registry.npmjs.org/

# Disable install scripts for untrusted packages (enable per-package)
ignore-scripts=true

# Audit on every install
audit=true

# Require exact versions
save-exact=true
```

#### Lockfile Integrity

```yaml
# .github/workflows/security.yml
name: Security Checks

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          
      - name: Verify lockfile integrity
        run: |
          npm ci --ignore-scripts
          
      - name: Run npm audit
        run: npm audit --audit-level=high
        
      - name: Run Snyk security scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
          
      - name: Check for known vulnerabilities
        run: npx better-npm-audit audit
        
      - name: License compliance check
        run: |
          npx license-checker --production --onlyAllow \
            'MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC;CC0-1.0;Unlicense'
```

#### Subresource Integrity (SRI)

```html
<!-- For CDN-loaded resources -->
<script
  src="https://cdn.example.com/react.production.min.js"
  integrity="sha384-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
  crossorigin="anonymous"
></script>
```

```javascript
// webpack.config.js - Generate SRI hashes
const SriPlugin = require('webpack-subresource-integrity');

module.exports = {
  output: {
    crossOriginLoading: 'anonymous',
  },
  plugins: [
    new SriPlugin({
      hashFuncNames: ['sha384'],
      enabled: process.env.NODE_ENV === 'production',
    }),
  ],
};
```

#### Dependency Security Checklist

| Check | Frequency | Tool |
|-------|-----------|------|
| Vulnerability scan | Every commit | `npm audit`, Snyk |
| Outdated packages | Weekly | `npm outdated` |
| License compliance | Every commit | `license-checker` |
| Lockfile integrity | Every commit | `npm ci` |
| Dependency review | Before merge | GitHub Dependency Review |
| SBOM generation | Release | `cyclonedx-npm` |

---

### Content Security Policy Implementation

Implement CSP to prevent XSS, clickjacking, and code injection attacks.

#### CSP Directives Reference

| Directive | Purpose | Recommended Value |
|-----------|---------|-------------------|
| `default-src` | Fallback for other directives | `'self'` |
| `script-src` | JavaScript sources | `'self' 'nonce-{random}'` |
| `style-src` | CSS sources | `'self' 'nonce-{random}'` |
| `img-src` | Image sources | `'self' data: https:` |
| `font-src` | Font sources | `'self'` |
| `connect-src` | XHR/Fetch/WebSocket targets | `'self' https://api.example.com` |
| `frame-ancestors` | Embedding restrictions | `'none'` |
| `form-action` | Form submission targets | `'self'` |
| `base-uri` | Base URL restrictions | `'self'` |
| `object-src` | Plugin sources | `'none'` |
| `upgrade-insecure-requests` | Force HTTPS | (no value needed) |

#### Next.js CSP with Nonces

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';

export function middleware(request: NextRequest) {
  // Generate cryptographically secure nonce
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');

  const cspHeader = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic';
    style-src 'self' 'nonce-${nonce}';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self' https://api.yourapp.com wss://api.yourapp.com;
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'self';
    object-src 'none';
    upgrade-insecure-requests;
  `.replace(/\s{2,}/g, ' ').trim();

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });

  response.headers.set('Content-Security-Policy', cspHeader);
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  return response;
}

export const config = {
  matcher: [
    {
      source: '/((?!api|_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
```

```tsx
// app/layout.tsx
import { headers } from 'next/headers';
import Script from 'next/script';

export default function RootLayout({ children }) {
  const nonce = headers().get('x-nonce') ?? '';

  return (
    <html lang="en">
      <head>
        <Script
          strategy="afterInteractive"
          nonce={nonce}
        >
          {`console.log('Secure inline script with nonce');`}
        </Script>
      </head>
      <body>{children}</body>
    </html>
  );
}
```

#### Vite CSP Configuration

```javascript
// vite.config.js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { createHtmlPlugin } from 'vite-plugin-html';

export default defineConfig(({ mode }) => {
  const isDev = mode === 'development';

  // Development CSP (more permissive for HMR)
  const devCSP = `
    default-src 'self';
    script-src 'self' 'unsafe-eval' 'unsafe-inline';
    style-src 'self' 'unsafe-inline';
    connect-src 'self' ws: wss: http://localhost:*;
    img-src 'self' data: https:;
  `.replace(/\s{2,}/g, ' ').trim();

  // Production CSP (strict)
  const prodCSP = `
    default-src 'self';
    script-src 'self';
    style-src 'self';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self' https://api.yourapp.com;
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'self';
    object-src 'none';
    upgrade-insecure-requests;
  `.replace(/\s{2,}/g, ' ').trim();

  return {
    plugins: [
      react(),
      createHtmlPlugin({
        inject: {
          tags: [
            {
              tag: 'meta',
              attrs: {
                'http-equiv': 'Content-Security-Policy',
                content: isDev ? devCSP : prodCSP,
              },
              injectTo: 'head-prepend',
            },
          ],
        },
      }),
    ],
    build: {
      // Disable inline scripts/styles for stricter CSP
      assetsInlineLimit: 0,
    },
  };
});
```

#### CSS-in-JS with CSP (Styled Components)

```jsx
// App.jsx
import { StyleSheetManager, createGlobalStyle } from 'styled-components';
import { useNonce } from './hooks/useNonce';

export default function App() {
  const nonce = useNonce();

  return (
    <StyleSheetManager nonce={nonce}>
      <GlobalStyles />
      <MainContent />
    </StyleSheetManager>
  );
}
```

#### CSP Reporting

```javascript
// CSP with reporting
const cspWithReporting = `
  ${baseCSP}
  report-uri /api/csp-report;
  report-to csp-endpoint;
`;

// Report-To header
const reportToHeader = JSON.stringify({
  group: 'csp-endpoint',
  max_age: 10886400,
  endpoints: [{ url: '/api/csp-report' }],
});

// API endpoint to handle CSP violations
// pages/api/csp-report.js (Next.js)
export default function handler(req, res) {
  if (req.method === 'POST') {
    const violation = req.body;
    
    // Log to security monitoring system
    console.error('CSP Violation:', {
      documentUri: violation['document-uri'],
      violatedDirective: violation['violated-directive'],
      blockedUri: violation['blocked-uri'],
      sourceFile: violation['source-file'],
      lineNumber: violation['line-number'],
    });
    
    // Send to SIEM or logging service
    // await securityLogger.logViolation(violation);
    
    res.status(204).end();
  } else {
    res.status(405).end();
  }
}
```

---

## Security Standards Cross-Reference

### NIST SP 800-53 Controls

The following NIST SP 800-53 Rev. 5 controls are applicable to React frontend applications:

#### Access Control (AC) Family

| Control ID | Control Name | React Implementation |
|------------|--------------|---------------------|
| AC-2 | Account Management | User registration validation, role management in state |
| AC-3 | Access Enforcement | Protected routes, RBAC implementation |
| AC-4 | Information Flow Enforcement | API request filtering, CSP implementation |
| AC-6 | Least Privilege | Minimal state exposure, component-level permissions |
| AC-7 | Unsuccessful Logon Attempts | Frontend lockout indicators, attempt tracking |
| AC-11 | Session Lock | Idle timeout implementation, automatic logout |
| AC-12 | Session Termination | Secure logout, token invalidation |
| AC-14 | Permitted Actions Without Identification | Public vs authenticated route separation |

```jsx
// AC-7: Unsuccessful Login Attempt Handling
function LoginForm() {
  const [attempts, setAttempts] = useState(0);
  const [lockoutUntil, setLockoutUntil] = useState(null);
  const MAX_ATTEMPTS = 5;
  const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

  const handleLogin = async (credentials) => {
    if (lockoutUntil && Date.now() < lockoutUntil) {
      const remaining = Math.ceil((lockoutUntil - Date.now()) / 1000 / 60);
      throw new Error(`Account locked. Try again in ${remaining} minutes.`);
    }

    try {
      await authService.login(credentials);
      setAttempts(0);
    } catch (error) {
      const newAttempts = attempts + 1;
      setAttempts(newAttempts);
      
      if (newAttempts >= MAX_ATTEMPTS) {
        setLockoutUntil(Date.now() + LOCKOUT_DURATION);
        // Log security event
        securityLogger.log('ACCOUNT_LOCKOUT', { reason: 'max_attempts' });
      }
      throw error;
    }
  };

  return (/* ... */);
}
```

#### System and Communications Protection (SC) Family

| Control ID | Control Name | React Implementation |
|------------|--------------|---------------------|
| SC-8 | Transmission Confidentiality | HTTPS enforcement, TLS configuration |
| SC-12 | Cryptographic Key Establishment | Web Crypto API usage, secure key handling |
| SC-13 | Cryptographic Protection | AES-GCM encryption, FIPS-compliant algorithms |
| SC-23 | Session Authenticity | Session token validation, CSRF protection |
| SC-28 | Protection of Information at Rest | Encrypted localStorage (when necessary) |

```javascript
// SC-12/SC-13: FIPS-compliant cryptographic operations
async function encryptSensitiveData(data, key) {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
  
  const encryptedData = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128, // 128-bit authentication tag
    },
    key,
    encoder.encode(JSON.stringify(data))
  );

  // Return IV + ciphertext as base64
  const combined = new Uint8Array(iv.length + encryptedData.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encryptedData), iv.length);
  
  return btoa(String.fromCharCode(...combined));
}
```

#### System and Information Integrity (SI) Family

| Control ID | Control Name | React Implementation |
|------------|--------------|---------------------|
| SI-3 | Malicious Code Protection | CSP, input sanitization |
| SI-10 | Information Input Validation | Zod/Yup validation, DOMPurify |
| SI-11 | Error Handling | Secure error boundaries, no stack traces |
| SI-15 | Information Output Filtering | Output encoding, XSS prevention |
| SI-16 | Memory Protection | Avoid storing sensitive data in state |

---

### OWASP Top Ten Mapping

#### OWASP Top 10:2025 - React Mitigations

| Rank | Category | React Vulnerabilities | Mitigations |
|------|----------|----------------------|-------------|
| A01 | Broken Access Control | Improper route protection, client-side auth checks only | Server-side validation, protected routes, RBAC |
| A02 | Security Misconfiguration | Permissive CSP, exposed debug tools, CORS misconfig | Strict CSP, disable devtools in production, proper CORS |
| A03 | Software Supply Chain Failures | Vulnerable npm packages, typosquatting | npm audit, lockfiles, SRI, dependency scanning |
| A04 | Cryptographic Failures | Sensitive data in localStorage, weak algorithms | httpOnly cookies, Web Crypto API, FIPS algorithms |
| A05 | Injection | XSS via dangerouslySetInnerHTML, eval() | DOMPurify, avoid eval, CSP nonces |
| A06 | Insecure Design | No rate limiting, missing input validation | Design reviews, threat modeling, validation layers |
| A07 | Authentication Failures | Token exposure, weak session management | Secure token storage, proper JWT handling, MFA |
| A08 | Software/Data Integrity Failures | Unverified CDN resources, insecure deserialization | SRI, signed packages, JSON.parse validation |
| A09 | Security Logging Failures | No client-side security logging | Security event logging, error boundaries |
| A10 | Mishandling Exceptions | Stack traces in production, unhandled promise rejections | Error boundaries, generic error messages |

#### Detailed OWASP Mitigations

**A01:2025 - Broken Access Control:**

```jsx
// VULNERABLE: Client-side only access control
function AdminPanel() {
  const { user } = useAuth();
  // Attacker can modify this check in browser
  if (user.role !== 'admin') {
    return <Navigate to="/" />;
  }
  return <AdminContent />;
}

// SECURE: Server-validated access control
function AdminPanel() {
  const { data, error, isLoading } = useSecureFetch('/api/admin/data');
  
  // Server validates admin role and returns 403 if unauthorized
  if (error?.status === 403) {
    return <Navigate to="/unauthorized" />;
  }
  
  if (isLoading) return <Loading />;
  
  return <AdminContent data={data} />;
}
```

**A05:2025 - Injection (XSS):**

```jsx
// Comprehensive XSS prevention utility
import DOMPurify from 'dompurify';

const xssPrevention = {
  // Configure DOMPurify
  sanitizeHTML: (dirty) => {
    return DOMPurify.sanitize(dirty, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
      ALLOWED_ATTR: ['href', 'title', 'target'],
      ALLOW_DATA_ATTR: false,
      ADD_ATTR: ['target'], // Allow target="_blank"
      FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'input'],
      FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
    });
  },

  // Validate URL protocols
  sanitizeURL: (url) => {
    try {
      const parsed = new URL(url);
      const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:'];
      return allowedProtocols.includes(parsed.protocol) ? url : '#';
    } catch {
      return '#';
    }
  },

  // Escape HTML entities
  escapeHTML: (str) => {
    const escapeMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    };
    return str.replace(/[&<>"']/g, (char) => escapeMap[char]);
  },
};
```

**A07:2025 - Authentication Failures:**

```jsx
// Secure authentication implementation
const authSecurityConfig = {
  // Token settings
  accessTokenExpiry: 15 * 60 * 1000,  // 15 minutes
  refreshTokenExpiry: 7 * 24 * 60 * 60 * 1000, // 7 days
  
  // Session settings
  idleTimeout: 30 * 60 * 1000, // 30 minutes
  absoluteTimeout: 8 * 60 * 60 * 1000, // 8 hours
  
  // Security settings
  requireMFA: true,
  allowRememberMe: false,
  enforcePasswordComplexity: true,
};

function useSecureSession() {
  const [lastActivity, setLastActivity] = useState(Date.now());
  const { logout } = useAuth();

  useEffect(() => {
    const checkSession = () => {
      const now = Date.now();
      const idleTime = now - lastActivity;
      
      if (idleTime > authSecurityConfig.idleTimeout) {
        logout();
        // Redirect to login with session expired message
        window.location.href = '/login?reason=session_expired';
      }
    };

    const interval = setInterval(checkSession, 60000); // Check every minute
    return () => clearInterval(interval);
  }, [lastActivity, logout]);

  // Update activity on user interaction
  useEffect(() => {
    const updateActivity = () => setLastActivity(Date.now());
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    
    events.forEach(event => window.addEventListener(event, updateActivity));
    return () => {
      events.forEach(event => window.removeEventListener(event, updateActivity));
    };
  }, []);
}
```

---

### DISA STIG Requirements

Applicable DISA STIG requirements for React web applications:

#### Application Security and Development STIG

| STIG ID | Requirement | React Implementation |
|---------|-------------|---------------------|
| APSC-DV-000500 | Input validation | Zod/Yup schemas, server-side validation |
| APSC-DV-000700 | Output encoding | React automatic escaping, DOMPurify |
| APSC-DV-001000 | Session management | Secure cookie settings, timeout handling |
| APSC-DV-001500 | Error handling | Error boundaries, generic error messages |
| APSC-DV-002000 | Cryptographic controls | Web Crypto API, FIPS algorithms |
| APSC-DV-002500 | Authentication controls | MFA support, secure credential handling |
| APSC-DV-003000 | Access control | RBAC, protected routes |
| APSC-DV-003500 | Audit logging | Security event logging |

#### Web Server STIG Controls

| Requirement | Implementation |
|-------------|----------------|
| HTTP Security Headers | CSP, X-Frame-Options, X-Content-Type-Options |
| TLS Configuration | TLS 1.2+ only, strong cipher suites |
| Session Cookie Security | Secure, HttpOnly, SameSite=Strict |
| Error Pages | Custom error pages without sensitive info |

```javascript
// DISA STIG compliant security headers (server-side)
const stigSecurityHeaders = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
  'Pragma': 'no-cache',
  'Expires': '0',
};
```

---

### CIS Benchmark Level 2

#### CIS Controls v8.1 - Web Application Security

**CIS Control 16: Application Software Security (Level 2)**

| Safeguard | Description | React Implementation |
|-----------|-------------|---------------------|
| 16.1 | Secure development lifecycle | ESLint security rules, pre-commit hooks |
| 16.2 | Software architecture design | Component isolation, least privilege |
| 16.3 | Vulnerability management | npm audit, Snyk integration |
| 16.4 | Third-party validation | Dependency review, SBOM |
| 16.5 | Security training | Security-aware code reviews |
| 16.6 | Secure coding standards | This guide, OWASP guidelines |
| 16.7 | Threat modeling | Component-level threat analysis |
| 16.8 | Penetration testing | DAST, manual testing |
| 16.9 | Security testing in pipeline | CI/CD security gates |
| 16.10 | Security fixes | Patch management process |
| 16.11 | Vulnerability disclosure | Responsible disclosure policy |
| 16.12 | Separate environments | Dev/staging/prod isolation |

```javascript
// CIS 16.1/16.6: ESLint security configuration
// .eslintrc.js
module.exports = {
  extends: [
    'react-app',
    'plugin:security/recommended',
    'plugin:react-hooks/recommended',
  ],
  plugins: ['security', 'no-unsanitized'],
  rules: {
    // Prevent dangerous patterns
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error',
    
    // Security plugin rules
    'security/detect-eval-with-expression': 'error',
    'security/detect-non-literal-regexp': 'warn',
    'security/detect-object-injection': 'warn',
    'security/detect-possible-timing-attacks': 'warn',
    
    // React-specific security
    'react/no-danger': 'warn',
    'react/no-danger-with-children': 'error',
    'react/jsx-no-script-url': 'error',
    'react/jsx-no-target-blank': ['error', { enforceDynamicLinks: 'always' }],
    
    // No unsanitized DOM manipulation
    'no-unsanitized/method': 'error',
    'no-unsanitized/property': 'error',
  },
};
```

**CIS Control 9: Email and Web Browser Protections (Level 2)**

| Safeguard | Description | React Implementation |
|-----------|-------------|---------------------|
| 9.1 | Browser/email security | CSP, secure cookie settings |
| 9.2 | DNS filtering | External link validation |
| 9.3 | Network segmentation | API gateway isolation |
| 9.4 | URL filtering | URL sanitization |
| 9.5 | Browser extensions | Document security requirements |
| 9.6 | Block unnecessary scripts | CSP script-src restrictions |
| 9.7 | Browser isolation | Same-origin policy enforcement |

---

### FIPS 140-3 Cryptographic Requirements

For applications requiring FIPS 140-3 compliance, the following browser-based cryptographic implementations apply:

#### Web Crypto API - FIPS-Approved Algorithms

| Algorithm | Purpose | FIPS Status | Web Crypto Support |
|-----------|---------|-------------|-------------------|
| AES-GCM | Symmetric encryption | Approved | Yes |
| AES-CBC | Symmetric encryption | Approved | Yes |
| SHA-256/384/512 | Hashing | Approved | Yes |
| HMAC | Message authentication | Approved | Yes |
| RSA-OAEP | Asymmetric encryption | Approved | Yes |
| ECDSA (P-256/384/521) | Digital signatures | Approved | Yes |
| ECDH | Key agreement | Approved | Yes |
| PBKDF2 | Key derivation | Approved | Yes |

#### FIPS-Compliant Implementation

```javascript
// utils/fipsCrypto.js
// FIPS 140-3 compliant cryptographic operations using Web Crypto API

export const fipsCrypto = {
  // FIPS-approved key generation
  async generateKey() {
    return await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256, // FIPS requires 128, 192, or 256 bits
      },
      true, // extractable
      ['encrypt', 'decrypt']
    );
  },

  // FIPS-approved encryption (AES-256-GCM)
  async encrypt(plaintext, key) {
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
    
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128, // 128-bit tag (FIPS minimum)
      },
      key,
      encoder.encode(plaintext)
    );

    // Combine IV + ciphertext
    const result = new Uint8Array(iv.length + ciphertext.byteLength);
    result.set(iv);
    result.set(new Uint8Array(ciphertext), iv.length);
    
    return this.arrayBufferToBase64(result.buffer);
  },

  // FIPS-approved decryption
  async decrypt(encryptedData, key) {
    const data = this.base64ToArrayBuffer(encryptedData);
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      key,
      ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  },

  // FIPS-approved hashing (SHA-256)
  async hash(data) {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    return this.arrayBufferToHex(hashBuffer);
  },

  // FIPS-approved HMAC
  async hmac(data, key) {
    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(key),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
    return this.arrayBufferToBase64(signature);
  },

  // FIPS-approved key derivation (PBKDF2)
  async deriveKey(password, salt, iterations = 100000) {
    const encoder = new TextEncoder();
    
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode(salt),
        iterations: iterations, // NIST recommends >= 10,000
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // Utility functions
  arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  },

  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  },

  arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },
};
```

#### FIPS Compliance Notes

1. **Browser Limitations**: Web Crypto API implementations may not be FIPS-validated modules. For strict FIPS compliance, cryptographic operations should be performed server-side using validated modules.

2. **TLS Requirements**: All communications must use TLS 1.2 or higher with FIPS-approved cipher suites.

3. **Key Management**: Keys should not be stored in browser storage. Use server-side key management with FIPS-validated HSMs.

4. **Random Number Generation**: `crypto.getRandomValues()` is required for FIPS-compliant random number generation.

---

## Compliance Checklists

### Pre-Deployment Security Checklist

#### Code Security

- [ ] All user inputs are validated using schema validation (Zod, Yup)
- [ ] DOMPurify is used for any HTML rendering via `dangerouslySetInnerHTML`
- [ ] URL protocols are validated before rendering in `href` attributes
- [ ] No use of `eval()`, `new Function()`, or `innerHTML` assignments
- [ ] All API responses are validated before use
- [ ] Error boundaries implemented for graceful error handling
- [ ] No sensitive data logged to console
- [ ] No hardcoded secrets, API keys, or credentials

#### Authentication & Authorization

- [ ] JWT access tokens have short expiration (15-30 minutes)
- [ ] Refresh tokens stored in httpOnly cookies
- [ ] CSRF protection implemented for state-changing requests
- [ ] Protected routes validate authentication server-side
- [ ] Role-based access control implemented
- [ ] Session timeout and idle logout implemented
- [ ] Failed login attempt lockout implemented

#### Configuration Security

- [ ] Content Security Policy configured and tested
- [ ] HTTPS enforced via HSTS
- [ ] Security headers configured (X-Frame-Options, X-Content-Type-Options, etc.)
- [ ] CORS configured with specific origins (not `*`)
- [ ] Source maps disabled in production
- [ ] React DevTools disabled in production
- [ ] Debug logging disabled in production

#### Dependency Security

- [ ] `npm audit` shows no high/critical vulnerabilities
- [ ] All dependencies are at latest stable versions
- [ ] `package-lock.json` is committed and verified
- [ ] No packages with known security issues
- [ ] License compliance verified
- [ ] Subresource Integrity (SRI) for CDN resources

### OWASP Top 10 Compliance Matrix

| OWASP Category | Status | Evidence |
|----------------|--------|----------|
| A01: Broken Access Control | [ ] Compliant | |
| A02: Security Misconfiguration | [ ] Compliant | |
| A03: Supply Chain Failures | [ ] Compliant | |
| A04: Cryptographic Failures | [ ] Compliant | |
| A05: Injection | [ ] Compliant | |
| A06: Insecure Design | [ ] Compliant | |
| A07: Authentication Failures | [ ] Compliant | |
| A08: Integrity Failures | [ ] Compliant | |
| A09: Logging Failures | [ ] Compliant | |
| A10: Exception Handling | [ ] Compliant | |

### NIST SP 800-53 Control Mapping

| Control Family | Applicable Controls | Status |
|---------------|--------------------|----- |
| Access Control (AC) | AC-2, AC-3, AC-6, AC-7, AC-11, AC-12 | [ ] |
| System & Comms (SC) | SC-8, SC-12, SC-13, SC-23 | [ ] |
| System & Info Integrity (SI) | SI-3, SI-10, SI-11, SI-15 | [ ] |
| Audit & Accountability (AU) | AU-2, AU-3, AU-6 | [ ] |

---

## References

### Official Documentation

1. [React Security Documentation](https://react.dev/learn/security) - Official React security guidance
2. [OWASP Top Ten 2025](https://owasp.org/Top10/2025/) - Current OWASP Top 10 vulnerabilities
3. [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) - Security and Privacy Controls
4. [DISA STIGs](https://www.cyber.mil/stigs) - Security Technical Implementation Guides
5. [CIS Controls v8.1](https://www.cisecurity.org/controls) - Critical Security Controls
6. [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) - Cryptographic Module Requirements

### Security Tools

7. [DOMPurify](https://github.com/cure53/DOMPurify) - XSS sanitization library
8. [Snyk](https://snyk.io/) - Vulnerability scanning
9. [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) - Dependency auditing
10. [ESLint Security Plugin](https://github.com/nodesecurity/eslint-plugin-security) - Security linting
11. [Zod](https://zod.dev/) - TypeScript-first schema validation

### Additional Resources

12. [MDN Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) - CSP documentation
13. [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) - Browser cryptography
14. [Auth0 React Guide](https://auth0.com/blog/complete-guide-to-react-user-authentication/) - Authentication patterns
15. [LogRocket JWT Best Practices](https://blog.logrocket.com/jwt-authentication-best-practices/) - JWT security

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | March 2026 | Initial release |

---

*This document should be reviewed and updated quarterly to reflect evolving security threats and framework updates.*
