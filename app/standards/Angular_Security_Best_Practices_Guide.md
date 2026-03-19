# Angular Security Best Practices Guide

**Version:** 1.0  
**Date:** March 2026  
**Author:** Matrix Agent  
**Applicable Angular Versions:** Angular 17, 18, 19+

---

## Executive Summary

This comprehensive guide provides security best practices for Angular applications, cross-referenced against major security frameworks including NIST SP 800-53, OWASP Top 10, DISA STIGs, CIS Benchmarks, and FIPS 140-3. It covers built-in Angular security features, implementation patterns, and compliance mappings to help development teams build secure, standards-compliant applications.

---

## Table of Contents

1. [Angular Security Fundamentals](#1-angular-security-fundamentals)
2. [Built-in XSS Protection and Sanitization](#2-built-in-xss-protection-and-sanitization)
3. [Security Context and DomSanitizer](#3-security-context-and-domsanitizer)
4. [HTTP Interceptors for Security](#4-http-interceptors-for-security)
5. [Route Guards and Authentication](#5-route-guards-and-authentication)
6. [Strict Mode and AOT Compilation Security Benefits](#6-strict-mode-and-aot-compilation-security-benefits)
7. [Content Security Policy with Angular](#7-content-security-policy-with-angular)
8. [NIST SP 800-53 Compliance Mapping](#8-nist-sp-800-53-compliance-mapping)
9. [OWASP Top 10 and Angular Mitigations](#9-owasp-top-10-and-angular-mitigations)
10. [DISA STIG Web Application Requirements](#10-disa-stig-web-application-requirements)
11. [CIS Benchmark Level 2 Controls](#11-cis-benchmark-level-2-controls)
12. [FIPS 140-3 Cryptographic Requirements](#12-fips-140-3-cryptographic-requirements)
13. [Compliance Checklists](#13-compliance-checklists)
14. [References](#14-references)

---

## 1. Angular Security Fundamentals

### 1.1 Core Security Principles

Angular is designed with security as a core principle. The framework provides built-in protections against common web vulnerabilities while enabling developers to implement secure coding practices.

#### Key Security Features in Angular 17/18/19

| Feature | Description | Security Benefit |
|---------|-------------|------------------|
| **Automatic Sanitization** | All values treated as untrusted by default | Prevents XSS attacks |
| **AOT Compilation** | Templates compiled at build time | Eliminates template injection risks |
| **Strict Mode** | Enhanced TypeScript checks | Catches potential vulnerabilities at compile time |
| **HttpClient Security** | Built-in CSRF/XSSI protection | Prevents cross-site request attacks |
| **Signals (v17+)** | Reactive state management | Reduces side-effect vulnerabilities |
| **Deferrable Views (v17+)** | Lazy loading with security | Reduces attack surface |

### 1.2 General Best Practices

```typescript
// angular.json - Enable strict mode and AOT
{
  "projects": {
    "your-app": {
      "architect": {
        "build": {
          "options": {
            "aot": true,
            "optimization": true,
            "sourceMap": false,  // Disable in production
            "extractLicenses": true,
            "buildOptimizer": true
          }
        }
      }
    }
  }
}
```

**Essential Guidelines:**
1. Keep Angular libraries updated to the latest stable version
2. Never modify the Angular core - use official customization APIs
3. Avoid APIs marked as "Security Risk" in documentation
4. Use AOT compilation (default in Angular CLI) in production
5. Enable strict mode for enhanced type checking

---

## 2. Built-in XSS Protection and Sanitization

### 2.1 Angular's XSS Security Model

Angular treats **all values as untrusted by default**. When values are inserted into the DOM through template bindings or interpolation, they are automatically sanitized and escaped.

#### How Angular Protects Against XSS

```typescript
// Component with potentially dangerous user input
@Component({
  selector: 'app-xss-demo',
  template: `
    <!-- SAFE: Interpolation - Angular escapes all content -->
    <p>{{ userInput }}</p>
    
    <!-- SAFE: Property binding - Angular escapes -->
    <p [textContent]="userInput"></p>
    
    <!-- CAUTION: innerHTML - Angular sanitizes but allows safe HTML -->
    <p [innerHTML]="userInput"></p>
    
    <!-- SAFE: Attribute binding - Angular escapes -->
    <a [href]="userUrl">Link</a>
  `
})
export class XssDemoComponent {
  // Malicious input example
  userInput = 'Hello <script>alert("XSS")</script> World';
  userUrl = 'javascript:alert("XSS")';
}
```

**Output Behavior:**
- Interpolation `{{ }}`: Displays escaped text, script tags visible as text
- `[innerHTML]`: Strips `<script>` tags, keeps safe HTML like `<b>`, `<i>`
- `[href]` with javascript: URL: Angular blocks dangerous protocols

### 2.2 Security Contexts

Angular defines four security contexts for sanitization:

| Security Context | Usage | Sanitization Behavior |
|-----------------|-------|----------------------|
| **HTML** | `[innerHTML]`, DOM manipulation | Removes scripts, dangerous tags |
| **Style** | `[style]`, CSS bindings | Removes dangerous CSS functions |
| **URL** | `[href]`, `[src]` for links | Blocks dangerous protocols |
| **Resource URL** | `<script src>`, `<iframe src>` | Cannot be sanitized - must be trusted |

### 2.3 Safe Coding Patterns

```typescript
// RECOMMENDED: Use Angular bindings instead of direct DOM manipulation
@Component({
  selector: 'app-safe-binding',
  template: `
    <!-- Safe text display -->
    <div>{{ safeContent }}</div>
    
    <!-- Safe class binding -->
    <div [class.active]="isActive"></div>
    
    <!-- Safe style binding -->
    <div [style.backgroundColor]="bgColor"></div>
    
    <!-- Safe event binding -->
    <button (click)="handleClick()">Click</button>
  `
})
export class SafeBindingComponent {
  safeContent = 'User generated content';
  isActive = true;
  bgColor = '#ffffff';
  
  handleClick(): void {
    // Safe event handler
  }
}
```

### 2.4 What to Avoid

```typescript
// DANGEROUS: Avoid these patterns
@Component({
  selector: 'app-unsafe',
  template: `<div #container></div>`
})
export class UnsafeComponent implements OnInit {
  @ViewChild('container') container!: ElementRef;
  
  ngOnInit(): void {
    // DANGEROUS: Direct DOM manipulation with user input
    this.container.nativeElement.innerHTML = this.userInput; // XSS Risk!
    
    // DANGEROUS: Using eval or Function constructor
    eval(this.userCode); // Code injection risk!
    
    // DANGEROUS: Document.write
    document.write(this.userContent); // XSS Risk!
  }
}
```

---

## 3. Security Context and DomSanitizer

### 3.1 Understanding DomSanitizer

The `DomSanitizer` service provides methods to sanitize values for different security contexts and to bypass security when necessary (with extreme caution).

```typescript
import { Component, inject } from '@angular/core';
import { DomSanitizer, SafeHtml, SafeUrl, SafeResourceUrl, SecurityContext } from '@angular/platform-browser';

@Component({
  selector: 'app-sanitizer-demo',
  template: `
    <div [innerHTML]="sanitizedHtml"></div>
    <a [href]="sanitizedUrl">Safe Link</a>
    <iframe [src]="trustedVideoUrl"></iframe>
  `
})
export class SanitizerDemoComponent {
  private sanitizer = inject(DomSanitizer);
  
  sanitizedHtml: SafeHtml;
  sanitizedUrl: SafeUrl;
  trustedVideoUrl: SafeResourceUrl;
  
  constructor() {
    // Method 1: Manual sanitization with context
    const rawHtml = '<b>Bold</b><script>alert("xss")</script>';
    const cleanHtml = this.sanitizer.sanitize(SecurityContext.HTML, rawHtml);
    // Result: '<b>Bold</b>' - script removed
    
    // Method 2: Trust value only when verified safe
    this.sanitizedHtml = this.sanitizer.bypassSecurityTrustHtml(
      this.validateAndCleanHtml('<b>Trusted content</b>')
    );
    
    // Trust URL after validation
    this.sanitizedUrl = this.sanitizer.bypassSecurityTrustUrl(
      this.validateUrl('https://example.com')
    );
    
    // Trust resource URL (for iframes, scripts)
    this.trustedVideoUrl = this.sanitizer.bypassSecurityTrustResourceUrl(
      'https://www.youtube.com/embed/safe-video-id'
    );
  }
  
  // Custom validation before trusting
  private validateAndCleanHtml(html: string): string {
    // Implement server-side sanitization or use DOMPurify
    return html;
  }
  
  private validateUrl(url: string): string {
    const allowedDomains = ['example.com', 'trusted-domain.com'];
    const urlObj = new URL(url);
    if (!allowedDomains.includes(urlObj.hostname)) {
      throw new Error('Untrusted domain');
    }
    return url;
  }
}
```

### 3.2 DomSanitizer Methods Reference

| Method | Use Case | Risk Level |
|--------|----------|------------|
| `sanitize(context, value)` | Clean untrusted values | Low - Recommended |
| `bypassSecurityTrustHtml()` | Trusted HTML content | High - Use sparingly |
| `bypassSecurityTrustStyle()` | Trusted CSS | High - Use sparingly |
| `bypassSecurityTrustScript()` | Trusted scripts | Critical - Avoid |
| `bypassSecurityTrustUrl()` | Trusted URLs | High - Validate first |
| `bypassSecurityTrustResourceUrl()` | Trusted resource URLs | Critical - Validate strictly |

### 3.3 Secure Custom Pipe for HTML Sanitization

```typescript
import { Pipe, PipeTransform, inject } from '@angular/core';
import { DomSanitizer, SafeHtml, SecurityContext } from '@angular/platform-browser';

@Pipe({
  name: 'safeHtml',
  standalone: true
})
export class SafeHtmlPipe implements PipeTransform {
  private sanitizer = inject(DomSanitizer);
  
  transform(value: string, trustLevel: 'sanitize' | 'trust' = 'sanitize'): SafeHtml | string {
    if (!value) return '';
    
    if (trustLevel === 'sanitize') {
      // Default: sanitize the HTML
      return this.sanitizer.sanitize(SecurityContext.HTML, value) || '';
    }
    
    // Only use 'trust' when content is from a verified safe source
    return this.sanitizer.bypassSecurityTrustHtml(value);
  }
}

// Usage in template:
// <div [innerHTML]="content | safeHtml"></div>
// <div [innerHTML]="trustedContent | safeHtml:'trust'"></div>
```

---

## 4. HTTP Interceptors for Security

### 4.1 Authentication Interceptor (JWT Token)

```typescript
import { HttpInterceptorFn, HttpRequest, HttpHandlerFn, HttpEvent } from '@angular/common/http';
import { inject } from '@angular/core';
import { Observable } from 'rxjs';

// Token storage service
@Injectable({ providedIn: 'root' })
export class AuthTokenService {
  private readonly TOKEN_KEY = 'auth_token';
  
  getToken(): string | null {
    // Use sessionStorage for better security (cleared on tab close)
    return sessionStorage.getItem(this.TOKEN_KEY);
  }
  
  setToken(token: string): void {
    sessionStorage.setItem(this.TOKEN_KEY, token);
  }
  
  removeToken(): void {
    sessionStorage.removeItem(this.TOKEN_KEY);
  }
  
  isTokenExpired(): boolean {
    const token = this.getToken();
    if (!token) return true;
    
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp * 1000 < Date.now();
    } catch {
      return true;
    }
  }
}

// Functional interceptor (Angular 17+ recommended)
export const authInterceptor: HttpInterceptorFn = (
  req: HttpRequest<unknown>,
  next: HttpHandlerFn
): Observable<HttpEvent<unknown>> => {
  const authService = inject(AuthTokenService);
  const token = authService.getToken();
  
  // Skip authentication for public endpoints
  const publicEndpoints = ['/api/auth/login', '/api/auth/register', '/api/public'];
  const isPublicEndpoint = publicEndpoints.some(endpoint => req.url.includes(endpoint));
  
  if (!isPublicEndpoint && token && !authService.isTokenExpired()) {
    const authReq = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`,
        'X-Request-ID': crypto.randomUUID()
      }
    });
    return next(authReq);
  }
  
  return next(req);
};
```

### 4.2 Security Headers Interceptor

```typescript
import { HttpInterceptorFn } from '@angular/common/http';

export const securityHeadersInterceptor: HttpInterceptorFn = (req, next) => {
  const secureReq = req.clone({
    setHeaders: {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache'
    }
  });
  
  return next(secureReq);
};
```

### 4.3 Error Handling Interceptor with Security Logging

```typescript
import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, throwError } from 'rxjs';
import { Router } from '@angular/router';

@Injectable({ providedIn: 'root' })
export class SecurityLogService {
  logSecurityEvent(event: {
    type: string;
    url: string;
    status: number;
    timestamp: Date;
    details?: string;
  }): void {
    // Send to security monitoring service
    console.warn('[SECURITY EVENT]', event);
    // In production: send to SIEM or security logging service
  }
}

export const errorHandlerInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const securityLog = inject(SecurityLogService);
  
  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      const securityEvent = {
        type: 'HTTP_ERROR',
        url: req.url,
        status: error.status,
        timestamp: new Date(),
        details: ''
      };
      
      switch (error.status) {
        case 401:
          securityEvent.type = 'UNAUTHORIZED_ACCESS';
          securityEvent.details = 'Authentication required or token expired';
          router.navigate(['/login']);
          break;
          
        case 403:
          securityEvent.type = 'FORBIDDEN_ACCESS';
          securityEvent.details = 'Access denied - insufficient permissions';
          router.navigate(['/access-denied']);
          break;
          
        case 419:
          securityEvent.type = 'CSRF_TOKEN_MISMATCH';
          securityEvent.details = 'CSRF token validation failed';
          break;
          
        case 429:
          securityEvent.type = 'RATE_LIMIT_EXCEEDED';
          securityEvent.details = 'Too many requests';
          break;
      }
      
      securityLog.logSecurityEvent(securityEvent);
      return throwError(() => error);
    })
  );
};
```

### 4.4 CSRF Protection Interceptor

```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { DOCUMENT } from '@angular/common';

export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
  const document = inject(DOCUMENT);
  
  // Only add CSRF token for mutating requests
  const mutatingMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
  
  if (mutatingMethods.includes(req.method.toUpperCase())) {
    // Read CSRF token from cookie
    const csrfToken = getCookie('XSRF-TOKEN', document);
    
    if (csrfToken) {
      const csrfReq = req.clone({
        setHeaders: {
          'X-XSRF-TOKEN': csrfToken
        }
      });
      return next(csrfReq);
    }
  }
  
  return next(req);
};

function getCookie(name: string, document: Document): string | null {
  const match = document.cookie.match(new RegExp('(^|;\\s*)' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[2]) : null;
}
```

### 4.5 Configuring Interceptors

```typescript
// app.config.ts
import { ApplicationConfig } from '@angular/core';
import { provideHttpClient, withInterceptors, withXsrfConfiguration } from '@angular/common/http';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      // Add interceptors in order of execution
      withInterceptors([
        authInterceptor,
        securityHeadersInterceptor,
        csrfInterceptor,
        errorHandlerInterceptor
      ]),
      // Configure XSRF protection
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',
        headerName: 'X-XSRF-TOKEN'
      })
    )
  ]
};
```

---

## 5. Route Guards and Authentication

### 5.1 Authentication Guard

```typescript
import { inject } from '@angular/core';
import { Router, CanActivateFn, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private isAuthenticated = false;
  private userRoles: string[] = [];
  
  checkAuthentication(): boolean {
    // Verify token validity
    const token = sessionStorage.getItem('auth_token');
    if (!token) return false;
    
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      this.isAuthenticated = payload.exp * 1000 > Date.now();
      this.userRoles = payload.roles || [];
      return this.isAuthenticated;
    } catch {
      return false;
    }
  }
  
  hasRole(requiredRoles: string[]): boolean {
    return requiredRoles.some(role => this.userRoles.includes(role));
  }
  
  getRedirectUrl(): string {
    return sessionStorage.getItem('redirectUrl') || '/dashboard';
  }
  
  setRedirectUrl(url: string): void {
    sessionStorage.setItem('redirectUrl', url);
  }
}

// Functional guard (Angular 17+ recommended)
export const authGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot,
  state: RouterStateSnapshot
) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  if (authService.checkAuthentication()) {
    return true;
  }
  
  // Store intended destination for redirect after login
  authService.setRedirectUrl(state.url);
  return router.createUrlTree(['/login']);
};
```

### 5.2 Role-Based Authorization Guard

```typescript
import { inject } from '@angular/core';
import { Router, CanActivateFn, ActivatedRouteSnapshot } from '@angular/router';

export const roleGuard: CanActivateFn = (route: ActivatedRouteSnapshot) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  // Get required roles from route data
  const requiredRoles = route.data['roles'] as string[];
  
  if (!requiredRoles || requiredRoles.length === 0) {
    return true; // No roles required
  }
  
  if (!authService.checkAuthentication()) {
    return router.createUrlTree(['/login']);
  }
  
  if (authService.hasRole(requiredRoles)) {
    return true;
  }
  
  // User authenticated but lacks required role
  return router.createUrlTree(['/access-denied']);
};

// Route configuration with guards
export const routes: Routes = [
  {
    path: 'dashboard',
    component: DashboardComponent,
    canActivate: [authGuard]
  },
  {
    path: 'admin',
    component: AdminComponent,
    canActivate: [authGuard, roleGuard],
    data: { roles: ['ADMIN', 'SUPER_ADMIN'] }
  },
  {
    path: 'reports',
    component: ReportsComponent,
    canActivate: [authGuard, roleGuard],
    data: { roles: ['ADMIN', 'ANALYST'] }
  },
  {
    path: 'login',
    component: LoginComponent
  },
  {
    path: 'access-denied',
    component: AccessDeniedComponent
  }
];
```

### 5.3 Feature Flag Guard

```typescript
@Injectable({ providedIn: 'root' })
export class FeatureFlagService {
  private features: Map<string, boolean> = new Map();
  
  async loadFeatures(): Promise<void> {
    // Load from secure API
  }
  
  isEnabled(featureName: string): boolean {
    return this.features.get(featureName) ?? false;
  }
}

export const featureGuard: CanActivateFn = (route: ActivatedRouteSnapshot) => {
  const featureService = inject(FeatureFlagService);
  const router = inject(Router);
  
  const requiredFeature = route.data['feature'] as string;
  
  if (!requiredFeature || featureService.isEnabled(requiredFeature)) {
    return true;
  }
  
  return router.createUrlTree(['/feature-unavailable']);
};
```

### 5.4 CanDeactivate Guard for Unsaved Changes

```typescript
export interface CanComponentDeactivate {
  canDeactivate: () => boolean | Observable<boolean>;
}

export const unsavedChangesGuard: CanDeactivateFn<CanComponentDeactivate> = (
  component: CanComponentDeactivate
) => {
  if (component.canDeactivate && !component.canDeactivate()) {
    return confirm('You have unsaved changes. Are you sure you want to leave?');
  }
  return true;
};
```

### 5.5 Guard Summary Table

| Guard Type | Interface | Purpose |
|------------|-----------|---------|
| `canActivate` | `CanActivateFn` | Protect route access |
| `canActivateChild` | `CanActivateChildFn` | Protect child routes |
| `canDeactivate` | `CanDeactivateFn` | Prevent leaving with unsaved data |
| `canMatch` | `CanMatchFn` | Conditional route matching |
| `resolve` | `ResolveFn` | Pre-fetch data before activation |

---

## 6. Strict Mode and AOT Compilation Security Benefits

### 6.1 TypeScript Strict Mode

```json
// tsconfig.json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "strictNullChecks": true,
    "strictPropertyInitialization": true,
    "forceConsistentCasingInFileNames": true
  },
"angularCompilerOptions": {
    "strictInjectionParameters": true,
    "strictInputAccessModifiers": true,
    "strictTemplates": true
  }
}
```

### 6.2 Security Benefits of Strict Mode

| Strict Option | Security Benefit |
|--------------|------------------|
| `strictNullChecks` | Prevents null/undefined injection attacks |
| `noImplicitAny` | Forces type safety, reduces type confusion |
| `strictTemplates` | Catches template binding errors at compile time |
| `strictPropertyInitialization` | Prevents uninitialized property access |

### 6.3 AOT Compilation Security Benefits

**Ahead-of-Time (AOT) compilation** provides significant security advantages:

```typescript
// angular.json - Ensure AOT is enabled
{
  "projects": {
    "your-app": {
      "architect": {
        "build": {
          "configurations": {
            "production": {
              "aot": true,
              "buildOptimizer": true,
              "optimization": true,
              "outputHashing": "all",
              "sourceMap": false,
              "namedChunks": false,
              "extractLicenses": true
            }
          }
        }
      }
    }
  }
}
```

**AOT Security Advantages:**

| Feature | Security Benefit |
|---------|------------------|
| **Compile-time template validation** | Eliminates template injection vulnerabilities |
| **No runtime compiler** | Reduces attack surface (smaller bundle) |
| **Early error detection** | Catches security issues before deployment |
| **Template type checking** | Prevents type-related vulnerabilities |
| **Tree shaking** | Removes unused code, reducing exposure |

### 6.4 Angular Compiler Security Options

```json
// tsconfig.json - Angular compiler security options
{
  "angularCompilerOptions": {
    "fullTemplateTypeCheck": true,
    "strictInjectionParameters": true,
    "strictInputAccessModifiers": true,
    "strictTemplates": true,
    "disableTypeScriptVersionCheck": false
  }
}
```

---

## 7. Content Security Policy with Angular

### 7.1 Recommended CSP Configuration

```html
<!-- index.html - CSP meta tag (development) -->
<meta http-equiv="Content-Security-Policy" content="
  default-src 'self';
  script-src 'self' 'nonce-RANDOM_NONCE_VALUE';
  style-src 'self' 'nonce-RANDOM_NONCE_VALUE';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' https://api.yourdomain.com;
  frame-ancestors 'none';
  form-action 'self';
  base-uri 'self';
  object-src 'none';
">
```

**Production CSP (HTTP Header - Recommended):**

```
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM}';
  style-src 'self' 'nonce-{RANDOM}';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' https://api.yourdomain.com;
  frame-ancestors 'none';
  form-action 'self';
  base-uri 'self';
  object-src 'none';
  upgrade-insecure-requests;
```

### 7.2 Setting Nonces in Angular

**Method 1: Angular Configuration (autoCsp)**

```json
// angular.json
{
  "projects": {
    "your-app": {
      "architect": {
        "build": {
          "options": {
            "security": {
              "autoCsp": true
            }
          }
        }
      }
    }
  }
}
```

**Method 2: ngCspNonce Attribute**

```html
<!-- index.html -->
<app-root ngCspNonce="randomNonceGoesHere"></app-root>
```

**Method 3: CSP_NONCE Injection Token**

```typescript
// main.ts
import { bootstrapApplication, CSP_NONCE } from '@angular/core';
import { AppComponent } from './app/app.component';

// Get nonce from server-rendered page
const nonce = document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content');

bootstrapApplication(AppComponent, {
  providers: [
    {
      provide: CSP_NONCE,
      useValue: nonce
    }
  ]
});
```

### 7.3 CSP Directive Reference

| Directive | Purpose | Recommended Value |
|-----------|---------|-------------------|
| `default-src` | Fallback for other directives | `'self'` |
| `script-src` | JavaScript sources | `'self' 'nonce-{random}'` |
| `style-src` | CSS sources | `'self' 'nonce-{random}'` |
| `img-src` | Image sources | `'self' data: https:` |
| `connect-src` | XHR, WebSocket, etc. | `'self' https://api.domain.com` |
| `font-src` | Font sources | `'self'` |
| `object-src` | Plugins (Flash, etc.) | `'none'` |
| `frame-ancestors` | Embedding prevention | `'none'` |
| `base-uri` | Base URL restriction | `'self'` |
| `form-action` | Form submission targets | `'self'` |

### 7.4 Trusted Types Integration

```typescript
// Configure Trusted Types with Angular
Content-Security-Policy: 
  trusted-types angular angular#bundler angular#unsafe-bypass;
  require-trusted-types-for 'script';
```

---

## 8. NIST SP 800-53 Compliance Mapping

### 8.1 Relevant Control Families for Angular Applications

| Control Family | ID | Control Name | Angular Implementation |
|---------------|-----|--------------|----------------------|
| **Access Control** | AC-3 | Access Enforcement | Route guards, role-based authorization |
| **Access Control** | AC-4 | Information Flow Enforcement | HTTP interceptors, CORS configuration |
| **Access Control** | AC-6 | Least Privilege | Component-level permissions, lazy loading |
| **Audit & Accountability** | AU-2 | Audit Events | Security logging interceptor |
| **Audit & Accountability** | AU-3 | Content of Audit Records | Structured security event logging |
| **Identification & Auth** | IA-2 | Identification & Authentication | Auth guards, JWT validation |
| **Identification & Auth** | IA-5 | Authenticator Management | Secure token storage, session management |
| **System & Comms Protection** | SC-8 | Transmission Confidentiality | HTTPS enforcement, TLS |
| **System & Comms Protection** | SC-13 | Cryptographic Protection | FIPS-compliant cryptography |
| **System & Comms Protection** | SC-28 | Protection of Information at Rest | Secure storage practices |
| **System Integrity** | SI-3 | Malicious Code Protection | XSS prevention, CSP |
| **System Integrity** | SI-10 | Information Input Validation | Angular sanitization, input validation |

### 8.2 NIST Control Implementation Examples

#### AC-3: Access Enforcement

```typescript
// Implement least privilege access
export const routes: Routes = [
  {
    path: 'sensitive-data',
    component: SensitiveDataComponent,
    canActivate: [authGuard, roleGuard],
    data: { 
      roles: ['DATA_ANALYST'],
      minSecurityClearance: 'CONFIDENTIAL'
    }
  }
];
```

#### SI-10: Information Input Validation

```typescript
import { AbstractControl, ValidationErrors, ValidatorFn } from '@angular/forms';

// Custom validators for input validation
export class SecurityValidators {
  static noScriptTags(): ValidatorFn {
    return (control: AbstractControl): ValidationErrors | null => {
      const forbidden = /<script[\s\S]*?>[\s\S]*?<\/script>/gi.test(control.value);
      return forbidden ? { scriptTagsDetected: true } : null;
    };
  }
  
  static sanitizedInput(): ValidatorFn {
    return (control: AbstractControl): ValidationErrors | null => {
      const dangerousPatterns = [
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe/gi,
        /data:/gi
      ];
      
      for (const pattern of dangerousPatterns) {
        if (pattern.test(control.value)) {
          return { dangerousInput: true };
        }
      }
      return null;
    };
  }
}

// Usage in form
this.form = this.fb.group({
  userInput: ['', [
    Validators.required,
    SecurityValidators.noScriptTags(),
    SecurityValidators.sanitizedInput()
  ]]
});
```

---

## 9. OWASP Top 10 and Angular Mitigations

### 9.1 OWASP Top 10 (2025) Reference Table

| Rank | Vulnerability | Angular Mitigation |
|------|--------------|-------------------|
| **A01** | Broken Access Control | Route guards, role-based guards, server-side validation |
| **A02** | Security Misconfiguration | AOT compilation, strict mode, CSP headers |
| **A03** | Software Supply Chain Failures | npm audit, lockfile, dependency scanning |
| **A04** | Cryptographic Failures | HTTPS enforcement, secure token storage |
| **A05** | Injection | Built-in XSS protection, DomSanitizer, parameterized APIs |
| **A06** | Insecure Design | Security-first architecture, threat modeling |
| **A07** | Authentication Failures | Secure auth patterns, JWT best practices |
| **A08** | Software/Data Integrity Failures | SRI hashes, signed commits, verified builds |
| **A09** | Security Logging Failures | Interceptor-based logging, audit trails |
| **A10** | Mishandling Exceptions | Proper error handling, no sensitive data in errors |

### 9.2 Detailed Mitigations

#### A01: Broken Access Control

```typescript
// Server-side validation must accompany client-side guards
@Injectable({ providedIn: 'root' })
export class SecureApiService {
  constructor(private http: HttpClient) {}
  
  // Never trust client-side role checks alone
  getRestrictedResource(resourceId: string): Observable<Resource> {
    // Server validates user permissions
    return this.http.get<Resource>(`/api/resources/${resourceId}`, {
      // Include credentials for server-side validation
      withCredentials: true
    });
  }
}
```

#### A03: Software Supply Chain Failures

```json
// package.json - Use exact versions
{
  "dependencies": {
    "@angular/core": "18.2.0",
    "@angular/common": "18.2.0"
  }
}
```

```bash
# Regular security audits
npm audit
npm audit fix

# Use lockfile
npm ci  # Use in CI/CD instead of npm install
```

#### A05: Injection (XSS Prevention)

```typescript
// Template-based protection
@Component({
  template: `
    <!-- SAFE: Angular escapes by default -->
    <p>{{ userInput }}</p>
    
    <!-- SAFE: Property binding -->
    <input [value]="userInput">
    
    <!-- SANITIZED: innerHTML is sanitized -->
    <div [innerHTML]="htmlContent"></div>
  `
})
export class SafeComponent {
  userInput = '<script>alert("xss")</script>';
  htmlContent = '<b>Bold</b><script>evil()</script>'; // Script removed
}
```

#### A07: Authentication Failures

```typescript
// Secure authentication implementation
@Injectable({ providedIn: 'root' })
export class SecureAuthService {
  private readonly TOKEN_KEY = 'auth_token';
  
  login(credentials: Credentials): Observable<AuthResponse> {
    return this.http.post<AuthResponse>('/api/auth/login', credentials).pipe(
      tap(response => {
        // Store token securely
        this.storeToken(response.token);
        
        // Set secure session timeout
        this.scheduleTokenRefresh(response.expiresIn);
      })
    );
  }
  
  private storeToken(token: string): void {
    // Use sessionStorage (cleared on tab close) for sensitive apps
    // Never store in localStorage for high-security applications
    sessionStorage.setItem(this.TOKEN_KEY, token);
  }
  
  logout(): void {
    sessionStorage.removeItem(this.TOKEN_KEY);
    // Invalidate token server-side
    this.http.post('/api/auth/logout', {}).subscribe();
  }
}
```

### 9.3 OWASP Compliance Checklist

| Category | Requirement | Implementation | Status |
|----------|-------------|----------------|--------|
| A01 | Implement access controls | Route guards + server validation | [ ] |
| A01 | Deny by default | Guard all routes, whitelist public | [ ] |
| A02 | Remove debug features | AOT, sourceMap: false | [ ] |
| A02 | Configure CSP | CSP headers with nonces | [ ] |
| A03 | Audit dependencies | npm audit in CI/CD | [ ] |
| A04 | Use HTTPS | TLS 1.2+ enforced | [ ] |
| A05 | Sanitize inputs | Angular sanitization + validation | [ ] |
| A05 | Encode outputs | Use Angular bindings | [ ] |
| A07 | Secure session management | HttpOnly cookies, secure storage | [ ] |
| A09 | Log security events | Interceptor-based logging | [ ] |

---

## 10. DISA STIG Web Application Requirements

### 10.1 Applicable STIG Requirements

| STIG ID | Requirement | Angular Implementation |
|---------|-------------|----------------------|
| **APSC-DV-000460** | Access control enforcement | Route guards, authorization |
| **APSC-DV-000500** | Session management | Secure token handling |
| **APSC-DV-000580** | Failed logon attempts | Lock after 3 failed attempts |
| **APSC-DV-001290** | Input validation | Form validators, sanitization |
| **APSC-DV-001460** | Injection prevention | Angular XSS protection |
| **APSC-DV-001620** | Cryptographic protection | HTTPS, TLS 1.2+ |
| **APSC-DV-001750** | Error handling | Safe error messages |
| **APSC-DV-002010** | Audit logging | Security event logging |
| **APSC-DV-002400** | Session timeout | Automatic logout |

### 10.2 STIG Implementation Examples

#### APSC-DV-000580: Failed Logon Attempts

```typescript
@Injectable({ providedIn: 'root' })
export class LoginAttemptService {
  private readonly MAX_ATTEMPTS = 3;
  private readonly LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
  private attempts: Map<string, { count: number; lockedUntil?: Date }> = new Map();
  
  recordFailedAttempt(username: string): { locked: boolean; remainingAttempts: number } {
    const record = this.attempts.get(username) || { count: 0 };
    
    // Check if currently locked
    if (record.lockedUntil && new Date() < record.lockedUntil) {
      return { locked: true, remainingAttempts: 0 };
    }
    
    record.count++;
    
    if (record.count >= this.MAX_ATTEMPTS) {
      record.lockedUntil = new Date(Date.now() + this.LOCKOUT_DURATION);
      this.attempts.set(username, record);
      
      // Log security event
      this.logSecurityEvent('ACCOUNT_LOCKED', username);
      
      return { locked: true, remainingAttempts: 0 };
    }
    
    this.attempts.set(username, record);
    return { locked: false, remainingAttempts: this.MAX_ATTEMPTS - record.count };
  }
  
  resetAttempts(username: string): void {
    this.attempts.delete(username);
  }
  
  private logSecurityEvent(event: string, username: string): void {
    // Send to security logging service
    console.warn(`[SECURITY] ${event}: ${username} at ${new Date().toISOString()}`);
  }
}
```

#### APSC-DV-002400: Session Timeout

```typescript
@Injectable({ providedIn: 'root' })
export class SessionTimeoutService {
  private readonly TIMEOUT_DURATION = 15 * 60 * 1000; // 15 minutes
  private readonly WARNING_BEFORE = 2 * 60 * 1000; // 2 minutes warning
  private timeoutId?: ReturnType<typeof setTimeout>;
  private warningId?: ReturnType<typeof setTimeout>;
  
  constructor(
    private router: Router,
    private dialog: MatDialog
  ) {
    this.setupActivityListeners();
  }
  
  private setupActivityListeners(): void {
    const events = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach(event => {
      document.addEventListener(event, () => this.resetTimeout(), { passive: true });
    });
  }
  
  startSession(): void {
    this.resetTimeout();
  }
  
  private resetTimeout(): void {
    this.clearTimers();
    
    // Set warning timer
    this.warningId = setTimeout(() => {
      this.showTimeoutWarning();
    }, this.TIMEOUT_DURATION - this.WARNING_BEFORE);
    
    // Set logout timer
    this.timeoutId = setTimeout(() => {
      this.logout();
    }, this.TIMEOUT_DURATION);
  }
  
  private clearTimers(): void {
    if (this.timeoutId) clearTimeout(this.timeoutId);
    if (this.warningId) clearTimeout(this.warningId);
  }
  
  private showTimeoutWarning(): void {
    // Show warning dialog
  }
  
  private logout(): void {
    this.clearTimers();
    sessionStorage.clear();
    this.router.navigate(['/login'], {
      queryParams: { reason: 'timeout' }
    });
  }
}
```

---

## 11. CIS Benchmark Level 2 Controls

### 11.1 Applicable CIS Controls

| CIS Control | Sub-Control | Angular Implementation |
|-------------|-------------|----------------------|
| **1** | Inventory of Assets | Document all Angular dependencies |
| **2** | Software Inventory | package-lock.json, npm audit |
| **4** | Secure Configuration | Strict mode, AOT, CSP |
| **7** | Email/Browser Protections | CSP, X-Frame-Options |
| **8** | Malware Defenses | XSS protection, input validation |
| **9** | Port/Protocol Security | HTTPS only, secure WebSocket |
| **13** | Data Protection | Secure storage, encryption |
| **14** | Access Control | Route guards, RBAC |
| **16** | Account Monitoring | Login attempt tracking |

### 11.2 CIS Control Implementation

#### Control 4: Secure Configuration

```typescript
// environment.prod.ts - Secure production configuration
export const environment = {
  production: true,
  apiUrl: 'https://api.yourdomain.com',
  
  // Security settings
  security: {
    enforceHttps: true,
    sessionTimeout: 900000, // 15 minutes
    maxLoginAttempts: 3,
    csrfEnabled: true,
    cspEnabled: true
  },
  
  // Disable debugging in production
  enableDebugTools: false,
  logLevel: 'error'
};
```

#### Control 13: Data Protection

```typescript
// Secure data handling service
@Injectable({ providedIn: 'root' })
export class SecureDataService {
  // Never log sensitive data
  private sanitizeForLogging(data: any): any {
    const sensitiveFields = ['password', 'ssn', 'creditCard', 'token'];
    const sanitized = { ...data };
    
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }
  
  // Clear sensitive data on logout
  clearSensitiveData(): void {
    sessionStorage.clear();
    
    // Clear any in-memory sensitive data
    this.sensitiveDataCache.clear();
  }
}
```

### 11.3 CIS Level 2 Checklist

| Control | Requirement | Implemented | Notes |
|---------|-------------|-------------|-------|
| 1.1 | Maintain asset inventory | [ ] | Document all dependencies |
| 2.1 | Maintain software inventory | [ ] | package-lock.json |
| 4.1 | Establish secure configurations | [ ] | Angular strict mode |
| 4.3 | Implement application whitelisting | [ ] | CSP script-src |
| 7.7 | Use DNS filtering | [ ] | Block malicious domains |
| 8.1 | Use centrally managed anti-malware | [ ] | CI/CD security scanning |
| 13.1 | Maintain data inventory | [ ] | Document sensitive data |
| 14.6 | Protect information through access control | [ ] | RBAC implementation |
| 16.4 | Encrypt sensitive information | [ ] | TLS, secure storage |

---

## 12. FIPS 140-3 Cryptographic Requirements

### 12.1 Overview

FIPS 140-3 defines security requirements for cryptographic modules. For Angular applications, this primarily affects:

- TLS/HTTPS implementation
- Token encryption
- Data-at-rest encryption
- Cryptographic operations in the browser

### 12.2 FIPS-Compliant Cryptography in Angular

```typescript
// Use Web Crypto API for FIPS-compliant operations
@Injectable({ providedIn: 'root' })
export class FipsCryptoService {
  private crypto = window.crypto;
  
  // Generate cryptographically secure random values
  generateSecureToken(length: number = 32): string {
    const array = new Uint8Array(length);
    this.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  
  // SHA-256 hashing (FIPS approved)
  async hashData(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await this.crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  
  // AES-GCM encryption (FIPS approved)
  async encryptData(data: string, key: CryptoKey): Promise<{ iv: string; ciphertext: string }> {
    const encoder = new TextEncoder();
    const iv = this.crypto.getRandomValues(new Uint8Array(12));
    
    const ciphertext = await this.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(data)
    );
    
    return {
      iv: this.bufferToHex(iv),
      ciphertext: this.bufferToHex(new Uint8Array(ciphertext))
    };
  }
  
  // Generate AES key
  async generateAesKey(): Promise<CryptoKey> {
    return await this.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }
  
  private bufferToHex(buffer: Uint8Array): string {
    return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
  }
}
```

### 12.3 FIPS 140-3 Compliance Requirements

| Requirement | Level 1 | Angular Implementation |
|-------------|---------|----------------------|
| **Approved Algorithms** | Required | AES, SHA-256/384/512, RSA, ECDSA |
| **Key Management** | Required | Secure key storage, rotation |
| **Self-Tests** | Required | Verify crypto operations |
| **Physical Security** | N/A | Not applicable to software |
| **Design Assurance** | Required | Documented security design |

### 12.4 FIPS-Approved Algorithms

| Category | Approved Algorithms | Angular/Browser Support |
|----------|-------------------|------------------------|
| **Symmetric Encryption** | AES (128, 192, 256) | Web Crypto API |
| **Hashing** | SHA-256, SHA-384, SHA-512 | Web Crypto API |
| **Digital Signatures** | RSA, ECDSA | Web Crypto API |
| **Key Exchange** | ECDH | Web Crypto API |
| **Random Number Generation** | CTR_DRBG | crypto.getRandomValues() |

---

## 13. Compliance Checklists

### 13.1 Pre-Deployment Security Checklist

| Category | Item | Status |
|----------|------|--------|
| **Build Configuration** | | |
| | AOT compilation enabled | [ ] |
| | Production mode enabled | [ ] |
| | Source maps disabled | [ ] |
| | Strict mode enabled | [ ] |
| **Authentication** | | |
| | Secure token storage (sessionStorage) | [ ] |
| | Token expiration implemented | [ ] |
| | Refresh token rotation | [ ] |
| | Logout clears all session data | [ ] |
| **Authorization** | | |
| | Route guards on all protected routes | [ ] |
| | Role-based access control | [ ] |
| | Server-side authorization validation | [ ] |
| **XSS Prevention** | | |
| | Using Angular bindings (not innerHTML) | [ ] |
| | DomSanitizer used when necessary | [ ] |
| | No direct DOM manipulation | [ ] |
| | CSP headers configured | [ ] |
| **HTTP Security** | | |
| | HTTPS enforced | [ ] |
| | CSRF protection enabled | [ ] |
| | Security headers configured | [ ] |
| | HTTP interceptors implemented | [ ] |
| **Input Validation** | | |
| | Form validators on all inputs | [ ] |
| | Server-side validation | [ ] |
| | File upload restrictions | [ ] |
| **Dependencies** | | |
| | npm audit passes | [ ] |
| | No known vulnerabilities | [ ] |
| | Lock file committed | [ ] |
| **Logging** | | |
| | Security events logged | [ ] |
| | No sensitive data in logs | [ ] |
| | Error messages sanitized | [ ] |

### 13.2 Compliance Framework Summary

| Framework | Key Requirements | Angular Features |
|-----------|-----------------|------------------|
| **NIST 800-53** | Access control, audit logging, input validation | Route guards, interceptors, validators |
| **OWASP Top 10** | XSS, injection, broken auth, CSRF | Sanitization, HttpClient, guards |
| **DISA STIG** | Session management, failed logins, encryption | Timeout service, attempt tracking |
| **CIS Benchmark** | Secure config, malware defense, access control | Strict mode, CSP, RBAC |
| **FIPS 140-3** | Approved cryptography, key management | Web Crypto API, HTTPS |

### 13.3 Security Review Checklist

```markdown
## Angular Security Review Checklist

### Code Review Items
- [ ] No use of `eval()` or `Function()` constructor
- [ ] No use of `document.write()`
- [ ] No direct DOM manipulation with user input
- [ ] `bypassSecurityTrust*` methods justified and documented
- [ ] All routes have appropriate guards
- [ ] No sensitive data in URL parameters
- [ ] No hardcoded credentials or API keys

### Configuration Review
- [ ] angular.json has production optimizations
- [ ] tsconfig.json has strict mode enabled
- [ ] Environment files don't contain secrets
- [ ] CSP configured appropriately
- [ ] CORS configured on backend

### Dependency Review
- [ ] `npm audit` shows no high/critical vulnerabilities
- [ ] Dependencies are from trusted sources
- [ ] Package-lock.json is committed
- [ ] No deprecated packages in use

### Testing Requirements
- [ ] Security test cases exist
- [ ] XSS test cases pass
- [ ] Authentication flow tested
- [ ] Authorization boundaries tested
```

---

## 14. References

### Official Documentation

1. [Angular Security Guide](https://angular.dev/best-practices/security) - Official Angular security documentation
2. [Angular HTTP Client](https://angular.dev/guide/http) - HTTP security features
3. [Angular Router Guards](https://angular.dev/api/router/CanActivate) - Route protection documentation

### Security Standards

4. [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) - Security and Privacy Controls
5. [OWASP Top 10 2025](https://owasp.org/Top10/) - Web Application Security Risks
6. [DISA STIGs](https://www.cyber.mil/stigs) - Security Technical Implementation Guides
7. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Security Configuration Guidelines
8. [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) - Cryptographic Module Security

### Additional Resources

9. [Angular Security Best Practices - Security Compass](https://www.securitycompass.com/blog/angular-security-best-practices/)
10. [OWASP Angular Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Angular_Security_Cheat_Sheet.html)
11. [Web Crypto API MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
12. [Content Security Policy MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

## Appendix A: Quick Reference Cards

### A.1 Security Context Quick Reference

```
SecurityContext.NONE     → No sanitization
SecurityContext.HTML     → Strips scripts, dangerous tags
SecurityContext.STYLE    → Removes dangerous CSS
SecurityContext.URL      → Blocks javascript:, data: protocols
SecurityContext.RESOURCE_URL → Cannot be sanitized (must trust)
```

### A.2 Route Guard Quick Reference

```typescript
// Functional guards (Angular 17+)
canActivate: CanActivateFn       // Protect route access
canActivateChild: CanActivateChildFn  // Protect child routes
canDeactivate: CanDeactivateFn   // Prevent leaving
canMatch: CanMatchFn             // Conditional matching
```

### A.3 HTTP Interceptor Quick Reference

```typescript
// Interceptor order matters!
withInterceptors([
  authInterceptor,           // 1. Add auth token
  securityHeadersInterceptor, // 2. Add security headers
  csrfInterceptor,           // 3. Add CSRF token
  loggingInterceptor,        // 4. Log requests
  errorHandlerInterceptor    // 5. Handle errors (last)
])
```

---

**Document Version:** 1.0  
**Last Updated:** March 2026  
**Classification:** UNCLASSIFIED  
**Distribution:** Unlimited
