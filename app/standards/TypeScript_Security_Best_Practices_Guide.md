# TypeScript Security Best Practices Guide

**Version:** 1.0  
**Last Updated:** March 2026  
**Author:** Matrix Agent

---

## Executive Summary

This comprehensive guide provides TypeScript developers with security best practices aligned to industry standards including OWASP Top 10, NIST Cybersecurity Framework, DISA STIG, CIS Benchmarks Level 2, and FIPS 140-3. TypeScript's static type system offers powerful security advantages when properly configured, but types alone do not guarantee runtime safety. This document covers TypeScript 5.x features, strict mode configurations, branded types, runtime validation, XSS prevention, and secure API design patterns.

---

## Table of Contents

1. [TypeScript Coding Best Practices](#1-typescript-coding-best-practices)
   - [TypeScript 5.x Security Features](#11-typescript-5x-security-features)
   - [Type Safety for Security](#12-type-safety-for-security)
   - [Branded Types for Validation](#13-branded-types-for-validation)
   - [Runtime Validation Libraries](#14-runtime-validation-libraries)
   - [XSS Prevention](#15-xss-prevention)
   - [Secure API Typing](#16-secure-api-typing)
   - [tsconfig Security Settings](#17-tsconfig-security-settings)
2. [Security Standards Cross-Reference](#2-security-standards-cross-reference)
   - [NIST Cybersecurity Framework](#21-nist-cybersecurity-framework)
   - [OWASP Top 10](#22-owasp-top-10)
   - [DISA STIG](#23-disa-stig)
   - [CIS Benchmark Level 2](#24-cis-benchmark-level-2)
   - [FIPS 140-3](#25-fips-140-3)
3. [Compliance Checklists](#3-compliance-checklists)
4. [References](#4-references)

---

## 1. TypeScript Coding Best Practices

### 1.1 TypeScript 5.x Security Features

TypeScript 5.x introduces several features that enhance security when properly utilized:

#### Key TypeScript 5.x Features for Security

| Feature | Version | Security Benefit |
|---------|---------|------------------|
| `const` Type Parameters | 5.0 | Prevents mutation of inferred literal types |
| `satisfies` Operator | 4.9+ | Type validation without widening |
| Decorators (Stage 3) | 5.0 | Standardized metadata for validation |
| `--verbatimModuleSyntax` | 5.0 | Explicit import/export type safety |
| `--moduleResolution bundler` | 5.0 | Modern bundler compatibility |
| `using` and `await using` | 5.2 | Explicit resource disposal (prevents leaks) |
| `NoInfer<T>` | 5.4 | Controls type inference boundaries |

#### Const Type Parameters (TypeScript 5.0+)

```typescript
// Prevents accidental mutation of configuration objects
function createConfig<const T extends readonly string[]>(permissions: T): T {
  return permissions;
}

// Type is readonly ["read", "write"] - not string[]
const userPermissions = createConfig(["read", "write"] as const);
```

#### Explicit Resource Management (TypeScript 5.2+)

```typescript
// Ensures cryptographic resources are properly disposed
class SecureKeyManager implements Disposable {
  private key: CryptoKey;
  
  [Symbol.dispose](): void {
    // Securely clear key from memory
    this.key = null as unknown as CryptoKey;
    console.log("Key securely disposed");
  }
}

async function processSecureData() {
  using keyManager = new SecureKeyManager();
  // Key automatically disposed when scope exits
}
```

### 1.2 Type Safety for Security

#### Strict Mode: The Foundation

**Always enable strict mode in production applications.** This single setting enables multiple type-checking behaviors that prevent common security vulnerabilities.

```json
{
  "compilerOptions": {
    "strict": true
  }
}
```

#### `unknown` vs `any`: Critical Security Distinction

| Type | Type Checking | Security Risk | Use Case |
|------|---------------|---------------|----------|
| `any` | Disabled | **HIGH** - Bypasses all checks | Never use in production |
| `unknown` | Required before use | **LOW** - Forces validation | External data, user input |

```typescript
// DANGEROUS: Using 'any' bypasses type safety
function processUnsafe(data: any) {
  return data.sensitiveField; // No type error - potential runtime crash
}

// SECURE: Using 'unknown' forces validation
function processSecure(data: unknown): string {
  if (typeof data === 'object' && data !== null && 'sensitiveField' in data) {
    const field = (data as { sensitiveField: unknown }).sensitiveField;
    if (typeof field === 'string') {
      return field;
    }
  }
  throw new Error('Invalid data structure');
}
```

#### Type Guards for Input Validation

```typescript
// User-defined type guard for secure validation
interface UserInput {
  username: string;
  email: string;
  age: number;
}

function isValidUserInput(input: unknown): input is UserInput {
  if (typeof input !== 'object' || input === null) {
    return false;
  }
  
  const obj = input as Record<string, unknown>;
  
  return (
    typeof obj.username === 'string' &&
    obj.username.length >= 3 &&
    obj.username.length <= 50 &&
    typeof obj.email === 'string' &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(obj.email) &&
    typeof obj.age === 'number' &&
    obj.age >= 0 &&
    obj.age <= 150
  );
}

// Usage
function createUser(input: unknown): UserInput {
  if (!isValidUserInput(input)) {
    throw new Error('Invalid user input');
  }
  return input; // Type narrowed to UserInput
}
```

### 1.3 Branded Types for Validation

Branded types (also called "opaque types" or "nominal types") add compile-time safety by preventing accidental mixing of structurally identical but semantically different types.

#### Basic Branded Type Pattern

```typescript
// Define brand symbols
declare const __brand: unique symbol;
type Brand<T, B> = T & { [__brand]: B };

// Create branded types
type UserId = Brand<string, 'UserId'>;
type SessionId = Brand<string, 'SessionId'>;
type SanitizedHTML = Brand<string, 'SanitizedHTML'>;
type PositiveInteger = Brand<number, 'PositiveInteger'>;

// Type-safe functions
function getUserById(id: UserId): Promise<User> {
  // Implementation
}

function validateSession(id: SessionId): boolean {
  // Implementation
}

// This will cause a compile-time error:
const sessionId = "sess_123" as SessionId;
// getUserById(sessionId); // Error: SessionId not assignable to UserId
```

#### Branded Types with Runtime Validation

```typescript
type Email = Brand<string, 'Email'>;
type Password = Brand<string, 'Password'>;

// Assertion function for runtime + compile-time safety
function assertEmail(value: string): asserts value is Email {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(value)) {
    throw new Error(`Invalid email format: ${value}`);
  }
}

function assertPassword(value: string): asserts value is Password {
  if (value.length < 12) {
    throw new Error('Password must be at least 12 characters');
  }
  if (!/[A-Z]/.test(value)) {
    throw new Error('Password must contain uppercase letter');
  }
  if (!/[a-z]/.test(value)) {
    throw new Error('Password must contain lowercase letter');
  }
  if (!/[0-9]/.test(value)) {
    throw new Error('Password must contain number');
  }
  if (!/[!@#$%^&*]/.test(value)) {
    throw new Error('Password must contain special character');
  }
}

// Usage
function registerUser(emailInput: string, passwordInput: string) {
  assertEmail(emailInput);
  assertPassword(passwordInput);
  
  // After assertions, types are branded
  const email: Email = emailInput;
  const password: Password = passwordInput;
  
  return { email, password };
}
```

#### XSS Prevention with Branded Types

```typescript
type SafeHTML = Brand<string, 'SafeHTML'>;
type UnsafeHTML = string;

// DOMPurify integration
import DOMPurify from 'dompurify';

function sanitizeHTML(dirty: UnsafeHTML): SafeHTML {
  return DOMPurify.sanitize(dirty) as SafeHTML;
}

// Safe rendering function
function renderToDOM(html: SafeHTML, container: HTMLElement): void {
  container.innerHTML = html;
}

// Usage - compile-time protection
const userInput = '<script>alert("XSS")</script>';
// renderToDOM(userInput, document.body); // Compile error!
renderToDOM(sanitizeHTML(userInput), document.body); // OK
```

### 1.4 Runtime Validation Libraries

TypeScript types are erased at runtime. Use validation libraries to ensure runtime safety.

#### Zod (Recommended)

```typescript
import { z } from 'zod';

// Define schema with validation rules
const UserSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  password: z.string()
    .min(12, 'Password must be at least 12 characters')
    .regex(/[A-Z]/, 'Must contain uppercase')
    .regex(/[a-z]/, 'Must contain lowercase')
    .regex(/[0-9]/, 'Must contain number')
    .regex(/[!@#$%^&*]/, 'Must contain special character'),
  role: z.enum(['admin', 'user', 'guest']),
  createdAt: z.date(),
  metadata: z.record(z.string()).optional(),
});

// Infer TypeScript type from schema
type User = z.infer<typeof UserSchema>;

// Validation with error handling
function validateUser(input: unknown): User {
  const result = UserSchema.safeParse(input);
  
  if (!result.success) {
    const errors = result.error.errors
      .map(e => `${e.path.join('.')}: ${e.message}`)
      .join('; ');
    throw new Error(`Validation failed: ${errors}`);
  }
  
  return result.data;
}

// API endpoint example
async function handleUserRegistration(req: Request): Promise<Response> {
  try {
    const body = await req.json();
    const validatedUser = validateUser(body);
    // Process validated data...
    return new Response(JSON.stringify({ success: true }));
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 400 }
    );
  }
}
```

#### Zod Security Schemas

```typescript
import { z } from 'zod';

// SQL Injection prevention schema
const SafeStringSchema = z.string()
  .max(1000)
  .refine(
    (val) => !/['";--]|\/\*|\*\/|xp_/i.test(val),
    'String contains potentially dangerous characters'
  );

// Path traversal prevention
const SafeFilenameSchema = z.string()
  .max(255)
  .refine(
    (val) => !/[<>:"|?*\x00-\x1f]/.test(val),
    'Invalid filename characters'
  )
  .refine(
    (val) => !val.includes('..'),
    'Path traversal not allowed'
  )
  .refine(
    (val) => !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(val),
    'Reserved filename not allowed'
  );

// URL validation
const SafeURLSchema = z.string()
  .url()
  .refine(
    (val) => {
      const url = new URL(val);
      return ['https:'].includes(url.protocol);
    },
    'Only HTTPS URLs allowed'
  )
  .refine(
    (val) => {
      const url = new URL(val);
      return !['localhost', '127.0.0.1', '0.0.0.0'].includes(url.hostname);
    },
    'Local URLs not allowed'
  );
```

#### io-ts (Functional Approach)

```typescript
import * as t from 'io-ts';
import { isRight } from 'fp-ts/Either';
import { PathReporter } from 'io-ts/PathReporter';

// Define codec
const UserCodec = t.type({
  id: t.string,
  email: t.string,
  age: t.number,
  roles: t.array(t.union([
    t.literal('admin'),
    t.literal('user'),
    t.literal('guest')
  ])),
});

type User = t.TypeOf<typeof UserCodec>;

// Validation with detailed errors
function decodeUser(input: unknown): User {
  const result = UserCodec.decode(input);
  
  if (isRight(result)) {
    return result.right;
  }
  
  const errors = PathReporter.report(result).join('\n');
  throw new Error(`Validation failed:\n${errors}`);
}
```

#### Comparison Table

| Feature | Zod | io-ts | TypeBox | Yup |
|---------|-----|-------|---------|-----|
| TypeScript-first | Yes | Yes | Yes | No |
| Bundle size | ~12KB | ~5KB | ~30KB | ~20KB |
| Syntax | Fluent | Functional | JSON Schema | Fluent |
| Custom validators | Yes | Yes | Yes | Yes |
| Async validation | Yes | Yes | No | Yes |
| Error messages | Excellent | Good | Good | Excellent |
| Performance | Good | Good | Excellent | Fair |

### 1.5 XSS Prevention

#### Content Security Policy (CSP)

```typescript
// Express middleware for CSP
import { Request, Response, NextFunction } from 'express';

const cspMiddleware = (req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'strict-dynamic'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ].join('; '));
  next();
};
```

#### DOMPurify Integration

```typescript
import DOMPurify from 'dompurify';

// Strict sanitization configuration
const DOMPURIFY_CONFIG: DOMPurify.Config = {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
  ALLOWED_ATTR: ['href', 'title'],
  ALLOW_DATA_ATTR: false,
  FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'input'],
  FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
};

// Type-safe sanitizer
type SanitizedString = string & { __sanitized: true };

function sanitize(dirty: string): SanitizedString {
  return DOMPurify.sanitize(dirty, DOMPURIFY_CONFIG) as SanitizedString;
}

// React component example
interface SafeHTMLProps {
  content: SanitizedString;
  className?: string;
}

function SafeHTML({ content, className }: SafeHTMLProps) {
  return (
    <div 
      className={className}
      dangerouslySetInnerHTML={{ __html: content }}
    />
  );
}
```

#### Template Literal Type Safety

```typescript
// Prevent injection via template types
type SQLSafeString = string & { __sqlSafe: true };

function escapeSql(value: string): SQLSafeString {
  // Escape single quotes and other SQL metacharacters
  return value
    .replace(/'/g, "''")
    .replace(/\\/g, '\\\\') as SQLSafeString;
}

// Parameterized queries (preferred approach)
interface QueryParams {
  [key: string]: string | number | boolean | null;
}

function safeQuery(
  template: TemplateStringsArray,
  ...values: (SQLSafeString | number | boolean | null)[]
): { sql: string; params: unknown[] } {
  const params: unknown[] = [];
  const sql = template.reduce((acc, str, i) => {
    if (i < values.length) {
      params.push(values[i]);
      return acc + str + `$${i + 1}`;
    }
    return acc + str;
  }, '');
  
  return { sql, params };
}
```

### 1.6 Secure API Typing

#### Type-Safe API Client

```typescript
import { z } from 'zod';

// Response schema definitions
const ApiErrorSchema = z.object({
  code: z.string(),
  message: z.string(),
  details: z.record(z.unknown()).optional(),
});

const ApiResponseSchema = <T extends z.ZodTypeAny>(dataSchema: T) =>
  z.object({
    success: z.literal(true),
    data: dataSchema,
    timestamp: z.string().datetime(),
  });

// Type-safe fetch wrapper
async function secureApiFetch<T extends z.ZodTypeAny>(
  url: string,
  schema: T,
  options?: RequestInit
): Promise<z.infer<T>> {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json();
    const parsedError = ApiErrorSchema.safeParse(error);
    throw new Error(
      parsedError.success 
        ? parsedError.data.message 
        : 'Unknown API error'
    );
  }

  const json = await response.json();
  const result = schema.safeParse(json);

  if (!result.success) {
    throw new Error(`API response validation failed: ${result.error.message}`);
  }

  return result.data;
}

// Usage example
const UserResponseSchema = ApiResponseSchema(
  z.object({
    id: z.string().uuid(),
    email: z.string().email(),
    name: z.string(),
  })
);

async function getUser(id: string) {
  return secureApiFetch(
    `/api/users/${encodeURIComponent(id)}`,
    UserResponseSchema
  );
}
```

#### Express Route Type Safety

```typescript
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';

// Generic validated request handler
function validatedHandler<
  TParams extends z.ZodTypeAny,
  TBody extends z.ZodTypeAny,
  TQuery extends z.ZodTypeAny
>(
  schemas: {
    params?: TParams;
    body?: TBody;
    query?: TQuery;
  },
  handler: (
    req: Request & {
      validatedParams: z.infer<TParams>;
      validatedBody: z.infer<TBody>;
      validatedQuery: z.infer<TQuery>;
    },
    res: Response,
    next: NextFunction
  ) => Promise<void>
) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const validatedReq = req as Request & {
        validatedParams: z.infer<TParams>;
        validatedBody: z.infer<TBody>;
        validatedQuery: z.infer<TQuery>;
      };

      if (schemas.params) {
        validatedReq.validatedParams = schemas.params.parse(req.params);
      }
      if (schemas.body) {
        validatedReq.validatedBody = schemas.body.parse(req.body);
      }
      if (schemas.query) {
        validatedReq.validatedQuery = schemas.query.parse(req.query);
      }

      await handler(validatedReq, res, next);
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          error: 'Validation failed',
          details: error.errors,
        });
        return;
      }
      next(error);
    }
  };
}

// Usage
const UpdateUserSchema = {
  params: z.object({ id: z.string().uuid() }),
  body: z.object({
    name: z.string().min(1).max(100),
    email: z.string().email(),
  }),
};

app.put('/users/:id', validatedHandler(UpdateUserSchema, async (req, res) => {
  const { id } = req.validatedParams;
  const { name, email } = req.validatedBody;
  // Handle validated request...
  res.json({ success: true });
}));
```

### 1.7 tsconfig Security Settings

#### Recommended Security Configuration

```json
{
  "compilerOptions": {
    // Strict Type Checking (REQUIRED)
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "strictBindCallApply": true,
    "strictPropertyInitialization": true,
    "noImplicitThis": true,
    "useUnknownInCatchVariables": true,
    "alwaysStrict": true,

    // Additional Safety Checks (RECOMMENDED)
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noPropertyAccessFromIndexSignature": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "exactOptionalPropertyTypes": true,

    // Module Safety
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,

    // Build Safety
    "declaration": true,
    "declarationMap": true,
    "sourceMap": false,
    "inlineSourceMap": false,
    "inlineSources": false,
    
    // Output Configuration
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    
    // Skip Lib Check for Performance
    "skipLibCheck": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "**/*.test.ts"]
}
```

#### tsconfig Option Security Reference

| Option | Default | Recommended | Security Impact |
|--------|---------|-------------|-----------------|
| `strict` | `false` | `true` | Enables all strict checks |
| `noImplicitAny` | `false` | `true` | Prevents untyped code paths |
| `strictNullChecks` | `false` | `true` | Prevents null/undefined errors |
| `noUncheckedIndexedAccess` | `false` | `true` | Adds undefined to index access |
| `useUnknownInCatchVariables` | `false` | `true` | Forces error type checking |
| `exactOptionalPropertyTypes` | `false` | `true` | Distinguishes undefined vs missing |
| `sourceMap` | `true` | `false` (prod) | Prevents code exposure |
| `inlineSourceMap` | `false` | `false` | Prevents code exposure |

#### Environment-Specific Configurations

```json
// tsconfig.prod.json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "sourceMap": false,
    "inlineSourceMap": false,
    "inlineSources": false,
    "removeComments": true,
    "declaration": false,
    "declarationMap": false
  },
  "exclude": [
    "**/*.test.ts",
    "**/*.spec.ts",
    "**/__tests__/**"
  ]
}
```

---

## 2. Security Standards Cross-Reference

### 2.1 NIST Cybersecurity Framework

The NIST CSF 2.0 provides a comprehensive framework with six core functions. Below is the mapping to TypeScript security practices:

| NIST CSF Function | Category | TypeScript Implementation |
|-------------------|----------|---------------------------|
| **GOVERN (GV)** | GV.OC: Organizational Context | Document security requirements in code comments and types |
| **IDENTIFY (ID)** | ID.AM: Asset Management | Use typed configurations for sensitive assets |
| | ID.RA: Risk Assessment | Type-safe logging of security-relevant data |
| **PROTECT (PR)** | PR.AA: Identity Management | Branded types for authentication tokens |
| | PR.DS: Data Security | Type-safe encryption wrappers |
| | PR.PS: Platform Security | Strict tsconfig settings |
| **DETECT (DE)** | DE.CM: Continuous Monitoring | Type-safe audit logging |
| | DE.AE: Adverse Event Analysis | Structured error types |
| **RESPOND (RS)** | RS.AN: Incident Analysis | Type-safe incident reporting |
| | RS.MI: Incident Mitigation | Feature flags with type safety |
| **RECOVER (RC)** | RC.RP: Recovery Planning | Type-safe backup configurations |

#### NIST SP 800-53 Control Mapping

| Control | Description | TypeScript Practice |
|---------|-------------|---------------------|
| AC-3 | Access Enforcement | Role-based type guards |
| AC-6 | Least Privilege | Minimal type exports |
| AU-2 | Audit Events | Type-safe logging interface |
| CM-7 | Least Functionality | Tree-shaking, minimal deps |
| IA-5 | Authenticator Management | Branded credential types |
| SC-8 | Transmission Confidentiality | Type-safe HTTPS clients |
| SC-13 | Cryptographic Protection | Typed crypto wrappers |
| SI-10 | Information Input Validation | Zod/io-ts schemas |

### 2.2 OWASP Top 10

#### OWASP Top 10:2025 Mapping

| Rank | Vulnerability | TypeScript Mitigation |
|------|---------------|----------------------|
| **A01** | Broken Access Control | Role-based branded types, type-safe RBAC |
| **A02** | Security Misconfiguration | Strict tsconfig, typed configs |
| **A03** | Software Supply Chain Failures | Lockfile validation, typed dependencies |
| **A04** | Cryptographic Failures | Type-safe crypto APIs, FIPS wrappers |
| **A05** | Injection | Parameterized queries, branded SQL types |
| **A06** | Insecure Design | Type-driven security patterns |
| **A07** | Authentication Failures | Strong credential types, session typing |
| **A08** | Software/Data Integrity Failures | Signed type definitions, checksum types |
| **A09** | Security Logging & Alerting | Structured log types, audit schemas |
| **A10** | Mishandling Exceptional Conditions | Result types, typed error handling |

#### Detailed Mitigation Examples

**A01: Broken Access Control**

```typescript
// Role-based access control with branded types
type Role = 'admin' | 'editor' | 'viewer';
type Permission = 'read' | 'write' | 'delete' | 'admin';

type AuthorizedUser<R extends Role> = {
  id: string;
  role: R;
  __authorized: true;
};

const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  admin: ['read', 'write', 'delete', 'admin'],
  editor: ['read', 'write'],
  viewer: ['read'],
};

function requirePermission<P extends Permission>(
  permission: P,
  handler: (user: AuthorizedUser<Role>) => void
) {
  return (user: AuthorizedUser<Role>) => {
    if (!ROLE_PERMISSIONS[user.role].includes(permission)) {
      throw new Error(`Permission denied: ${permission}`);
    }
    handler(user);
  };
}

// Type-safe admin-only function
const deleteResource = requirePermission('delete', (user) => {
  console.log(`User ${user.id} deleting resource`);
});
```

**A05: Injection Prevention**

```typescript
import { z } from 'zod';

// SQL Injection Prevention
const SafeSearchSchema = z.object({
  query: z.string()
    .max(100)
    .regex(/^[\w\s-]+$/, 'Only alphanumeric characters allowed'),
  limit: z.number().int().min(1).max(100),
  offset: z.number().int().min(0),
});

async function searchUsers(params: unknown) {
  const { query, limit, offset } = SafeSearchSchema.parse(params);
  
  // Use parameterized query - NEVER concatenate
  return db.query(
    'SELECT id, name, email FROM users WHERE name ILIKE $1 LIMIT $2 OFFSET $3',
    [`%${query}%`, limit, offset]
  );
}

// Command Injection Prevention
const SafeFilenameSchema = z.string()
  .max(255)
  .regex(/^[\w.-]+$/, 'Invalid filename')
  .refine(s => !s.includes('..'), 'Path traversal not allowed');

function processFile(filename: unknown) {
  const safeName = SafeFilenameSchema.parse(filename);
  // Safe to use in file operations
}
```

**A10: Error Handling**

```typescript
// Result type for safe error handling
type Result<T, E = Error> = 
  | { success: true; data: T }
  | { success: false; error: E };

// Typed error classes
class ValidationError extends Error {
  constructor(
    message: string,
    public readonly field: string,
    public readonly code: string
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

class AuthorizationError extends Error {
  constructor(
    message: string,
    public readonly requiredPermission: string
  ) {
    super(message);
    this.name = 'AuthorizationError';
  }
}

// Safe async operation wrapper
async function safeAsync<T>(
  operation: () => Promise<T>
): Promise<Result<T>> {
  try {
    const data = await operation();
    return { success: true, data };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
}
```

### 2.3 DISA STIG

Security Technical Implementation Guides (STIGs) provide DoD security requirements.

#### Web Application STIG Mapping

| STIG ID | Requirement | TypeScript Implementation |
|---------|-------------|---------------------------|
| APSC-DV-000460 | Input validation | Zod schemas for all inputs |
| APSC-DV-000500 | Error handling | Typed error responses |
| APSC-DV-000580 | Login attempt limits | Rate limiting types |
| APSC-DV-001290 | Session management | Branded session types |
| APSC-DV-001460 | Cryptographic modules | FIPS-validated crypto |
| APSC-DV-002010 | Data-in-transit | Type-safe TLS config |
| APSC-DV-002400 | Audit logging | Structured log types |
| APSC-DV-002560 | XSS prevention | DOMPurify + branded types |

#### STIG-Compliant Session Management

```typescript
import { z } from 'zod';
import crypto from 'crypto';

// STIG-compliant session configuration
const SessionConfigSchema = z.object({
  maxAge: z.number().max(900000), // 15 minutes max (STIG requirement)
  secure: z.literal(true),
  httpOnly: z.literal(true),
  sameSite: z.enum(['strict', 'lax']),
  domain: z.string().optional(),
});

type BrandedSessionId = string & { __sessionId: true };
type BrandedCSRFToken = string & { __csrfToken: true };

interface SecureSession {
  id: BrandedSessionId;
  csrfToken: BrandedCSRFToken;
  userId: string;
  createdAt: Date;
  lastActivity: Date;
  ipAddress: string;
}

function generateSessionId(): BrandedSessionId {
  // FIPS-compliant random generation
  return crypto.randomBytes(32).toString('hex') as BrandedSessionId;
}

function generateCSRFToken(): BrandedCSRFToken {
  return crypto.randomBytes(32).toString('hex') as BrandedCSRFToken;
}

// Session timeout enforcement (APSC-DV-001290)
function isSessionValid(session: SecureSession, maxInactiveMs: number): boolean {
  const now = Date.now();
  const lastActivity = session.lastActivity.getTime();
  return (now - lastActivity) < maxInactiveMs;
}
```

### 2.4 CIS Benchmark Level 2

CIS Level 2 provides defense-in-depth configurations for high-security environments.

#### CIS Controls Mapping

| CIS Control | Description | TypeScript Practice |
|-------------|-------------|---------------------|
| 2.5 | Allowlist authorized software | Strict dependency typing |
| 3.4 | Encrypt data on end-user devices | Type-safe encryption |
| 4.1 | Secure configuration process | Typed config schemas |
| 5.2 | Use unique passwords | Password strength types |
| 7.1 | Secure email gateway | Type-safe email validation |
| 8.2 | Collect audit logs | Structured log schemas |
| 10.1 | Deploy malware defenses | Input validation types |
| 14.2 | Train workforce on auth | Type documentation |
| 16.1 | Secure app development | Strict TypeScript configs |
| 16.7 | Use standard configs | Shared tsconfig bases |

#### CIS Level 2 Compliant Configuration

```typescript
// Environment configuration with CIS compliance
import { z } from 'zod';

const CISCompliantConfigSchema = z.object({
  // Control 4.1: Secure Configuration
  server: z.object({
    port: z.number().int().min(1024).max(65535),
    host: z.string().ip(),
    tlsMinVersion: z.enum(['TLSv1.2', 'TLSv1.3']),
  }),
  
  // Control 5.2: Password Policy
  passwordPolicy: z.object({
    minLength: z.number().min(14), // CIS requires 14+
    requireUppercase: z.literal(true),
    requireLowercase: z.literal(true),
    requireNumbers: z.literal(true),
    requireSpecialChars: z.literal(true),
    maxAge: z.number().max(90), // Days
    historyCount: z.number().min(24), // Remember last 24
  }),
  
  // Control 8.2: Audit Logging
  logging: z.object({
    level: z.enum(['error', 'warn', 'info', 'debug']),
    auditEnabled: z.literal(true),
    retentionDays: z.number().min(90), // CIS requires 90+ days
    sensitiveFields: z.array(z.string()),
  }),
  
  // Control 16.1: Secure Development
  security: z.object({
    csrfEnabled: z.literal(true),
    corsOrigins: z.array(z.string().url()),
    rateLimitPerMinute: z.number().max(100),
    sessionTimeoutMinutes: z.number().max(15),
  }),
});

type CISCompliantConfig = z.infer<typeof CISCompliantConfigSchema>;

// Load and validate configuration
function loadConfig(): CISCompliantConfig {
  const config = {
    // ... load from environment
  };
  return CISCompliantConfigSchema.parse(config);
}
```

### 2.5 FIPS 140-3

FIPS 140-3 specifies cryptographic module requirements for federal systems.

#### FIPS 140-3 Compliance in TypeScript

| FIPS Requirement | TypeScript Implementation |
|------------------|---------------------------|
| Approved algorithms | Type-restricted crypto functions |
| Key management | Branded key types |
| Self-tests | Typed test interfaces |
| Physical security | N/A (software) |

#### FIPS-Compliant Crypto Wrapper

```typescript
import crypto from 'crypto';

// FIPS 140-3 approved algorithms only
type FIPSApprovedHashAlgorithm = 'sha256' | 'sha384' | 'sha512' | 'sha3-256' | 'sha3-384' | 'sha3-512';
type FIPSApprovedCipherAlgorithm = 'aes-128-gcm' | 'aes-256-gcm';
type FIPSApprovedKeyLength = 128 | 192 | 256;

// Branded key types
type EncryptionKey = Buffer & { __encryptionKey: true };
type InitializationVector = Buffer & { __iv: true };
type AuthTag = Buffer & { __authTag: true };

interface EncryptedData {
  ciphertext: Buffer;
  iv: InitializationVector;
  authTag: AuthTag;
  algorithm: FIPSApprovedCipherAlgorithm;
}

// FIPS-compliant key derivation
function deriveKey(
  password: string,
  salt: Buffer,
  keyLength: FIPSApprovedKeyLength = 256
): EncryptionKey {
  // PBKDF2 with SHA-256 (FIPS approved)
  const key = crypto.pbkdf2Sync(
    password,
    salt,
    310000, // OWASP recommended iterations
    keyLength / 8,
    'sha256'
  );
  return key as EncryptionKey;
}

// FIPS-compliant encryption
function encrypt(
  plaintext: Buffer,
  key: EncryptionKey,
  algorithm: FIPSApprovedCipherAlgorithm = 'aes-256-gcm'
): EncryptedData {
  const iv = crypto.randomBytes(12) as InitializationVector;
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  
  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);
  
  const authTag = cipher.getAuthTag() as AuthTag;
  
  return { ciphertext, iv, authTag, algorithm };
}

// FIPS-compliant decryption
function decrypt(
  encryptedData: EncryptedData,
  key: EncryptionKey
): Buffer {
  const decipher = crypto.createDecipheriv(
    encryptedData.algorithm,
    key,
    encryptedData.iv
  );
  
  decipher.setAuthTag(encryptedData.authTag);
  
  return Buffer.concat([
    decipher.update(encryptedData.ciphertext),
    decipher.final()
  ]);
}

// FIPS-compliant hashing
function hash(
  data: Buffer | string,
  algorithm: FIPSApprovedHashAlgorithm = 'sha256'
): Buffer {
  return crypto.createHash(algorithm).update(data).digest();
}

// FIPS-compliant HMAC
function hmac(
  data: Buffer | string,
  key: Buffer,
  algorithm: FIPSApprovedHashAlgorithm = 'sha256'
): Buffer {
  return crypto.createHmac(algorithm, key).update(data).digest();
}
```

---

## 3. Compliance Checklists

### 3.1 TypeScript Security Configuration Checklist

| Item | Status | Priority | Notes |
|------|--------|----------|-------|
| [ ] Enable `strict: true` in tsconfig | | Critical | Foundation for type safety |
| [ ] Enable `noImplicitAny` | | Critical | Prevents untyped code |
| [ ] Enable `strictNullChecks` | | Critical | Prevents null errors |
| [ ] Enable `noUncheckedIndexedAccess` | | High | Safer array/object access |
| [ ] Enable `useUnknownInCatchVariables` | | High | Safe error handling |
| [ ] Disable source maps in production | | High | Prevents code exposure |
| [ ] Enable `exactOptionalPropertyTypes` | | Medium | Stricter optional handling |
| [ ] Configure ESLint security rules | | High | Additional static analysis |
| [ ] Set up pre-commit hooks | | Medium | Enforce checks locally |

### 3.2 Runtime Validation Checklist

| Item | Status | Priority | Standard |
|------|--------|----------|----------|
| [ ] All API inputs validated with Zod/io-ts | | Critical | OWASP A03 |
| [ ] User input sanitized before rendering | | Critical | OWASP A03 |
| [ ] SQL queries use parameterization | | Critical | OWASP A03 |
| [ ] File paths validated for traversal | | High | OWASP A01 |
| [ ] URLs validated for SSRF | | High | OWASP A10 |
| [ ] JSON parsing wrapped in try-catch | | Medium | OWASP A10 |
| [ ] Schema validation on config files | | Medium | CIS 4.1 |

### 3.3 Authentication & Session Checklist

| Item | Status | Priority | Standard |
|------|--------|----------|----------|
| [ ] Sessions expire after 15 min inactivity | | Critical | DISA STIG |
| [ ] Passwords require 14+ characters | | Critical | CIS 5.2 |
| [ ] CSRF tokens implemented | | Critical | OWASP A01 |
| [ ] Session IDs are cryptographically random | | Critical | FIPS 140-3 |
| [ ] Failed login attempts are limited | | High | DISA STIG |
| [ ] Session binding to IP/User-Agent | | Medium | Defense-in-depth |
| [ ] Secure cookie flags set | | High | OWASP A07 |

### 3.4 Cryptography Checklist

| Item | Status | Priority | Standard |
|------|--------|----------|----------|
| [ ] TLS 1.2+ required for all connections | | Critical | FIPS 140-3 |
| [ ] FIPS-approved algorithms only | | Critical | FIPS 140-3 |
| [ ] Keys derived with PBKDF2/Argon2 | | Critical | OWASP A02 |
| [ ] AES-GCM for symmetric encryption | | High | FIPS 140-3 |
| [ ] SHA-256+ for hashing | | High | FIPS 140-3 |
| [ ] Secure random number generation | | Critical | FIPS 140-3 |
| [ ] Key rotation implemented | | Medium | NIST PR.DS |

### 3.5 Logging & Monitoring Checklist

| Item | Status | Priority | Standard |
|------|--------|----------|----------|
| [ ] Structured logging implemented | | High | CIS 8.2 |
| [ ] Security events logged | | Critical | NIST DE.CM |
| [ ] Sensitive data masked in logs | | Critical | Privacy |
| [ ] Log retention >= 90 days | | High | CIS 8.2 |
| [ ] Failed auth attempts logged | | High | DISA STIG |
| [ ] Audit trail for admin actions | | High | NIST AU-2 |

---

## 4. References

### Official Documentation

1. [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/) - Official TypeScript documentation
2. [TypeScript tsconfig Reference](https://www.typescriptlang.org/tsconfig) - Complete tsconfig options
3. [Zod Documentation](https://zod.dev/) - Runtime validation library
4. [io-ts Documentation](https://github.com/gcanti/io-ts) - Functional validation library
5. [DOMPurify](https://github.com/cure53/DOMPurify) - XSS sanitization library

### Security Standards

6. [OWASP Top 10:2025](https://owasp.org/Top10/) - Web application security risks
7. [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) - Security implementation guides
8. [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) - Cybersecurity guidelines
9. [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Security and privacy controls
10. [DISA STIGs](https://public.cyber.mil/stigs/) - DoD security implementation guides
11. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Security configuration guides
12. [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final) - Cryptographic module standards

### TypeScript Security Resources

13. [Aptori - Secure Coding in TypeScript](https://www.aptori.com/blog/secure-coding-in-typescript-best-practices-to-build-secure-applications) - Security best practices
14. [Learning TypeScript - Branded Types](https://www.learningtypescript.com/articles/branded-types) - Nominal type patterns
15. [Total TypeScript](https://www.totaltypescript.com/) - Advanced TypeScript patterns
16. [Snyk - React TypeScript Security](https://snyk.io/blog/best-practices-react-typescript-security/) - React security practices

### Tools

17. [ESLint](https://eslint.org/) - Static code analysis
18. [eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) - Security linting rules
19. [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) - Dependency vulnerability scanning
20. [Snyk](https://snyk.io/) - Security vulnerability detection

---

## Appendix A: Quick Reference Cards

### Type Safety Quick Reference

```typescript
// DO: Use unknown for external data
function parseJSON(input: string): unknown {
  return JSON.parse(input);
}

// DO: Use branded types for sensitive data
type UserId = string & { __brand: 'UserId' };
type Password = string & { __brand: 'Password' };

// DO: Use Zod for runtime validation
const schema = z.object({
  email: z.string().email(),
  password: z.string().min(14),
});

// DON'T: Use any
function bad(input: any) { /* ... */ }

// DON'T: Trust user input
const username = req.body.username; // Unsafe!

// DON'T: Use eval or dynamic code execution
eval(userInput); // Never!
```

### Security Headers Quick Reference

```typescript
const securityHeaders = {
  'Content-Security-Policy': "default-src 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=()',
};
```

---

*Document generated using security standards effective as of March 2026. Review and update according to the latest security advisories and standard revisions.*
