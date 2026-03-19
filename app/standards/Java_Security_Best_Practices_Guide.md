# Java Security Best Practices Guide

**Version:** 1.0  
**Last Updated:** March 2026  
**Author:** Matrix Agent  
**Applicable Standards:** NIST SP 800-53, OWASP Top Ten 2025, DISA STIG, CIS Benchmark Level 2, FIPS 140-3

---

## Executive Summary

This comprehensive guide provides Java developers and security professionals with actionable best practices for building secure Java applications. It covers modern Java security features (Java 21 LTS and Java 22+), Spring Security implementation patterns, secure coding practices, and compliance mappings to major security frameworks including NIST, OWASP, DISA STIG, CIS Benchmarks, and FIPS 140-3.

Key areas addressed include:
- Modern Java security features and Security Manager alternatives
- Spring Security 6 authentication and authorization best practices
- Input validation and bean validation patterns
- SQL injection prevention with JDBC and JPA
- Java Cryptography Architecture (JCA) and FIPS compliance
- Secure deserialization techniques
- Comprehensive compliance checklists and reference tables

---

## Table of Contents

1. [Java 21/22 Security Features](#1-java-2122-security-features)
2. [Spring Security Best Practices](#2-spring-security-best-practices)
3. [Input Validation and Bean Validation](#3-input-validation-and-bean-validation)
4. [JDBC/JPA Security - SQL Injection Prevention](#4-jdbcjpa-security---sql-injection-prevention)
5. [Java Cryptography Architecture (JCA)](#5-java-cryptography-architecture-jca)
6. [Secure Deserialization](#6-secure-deserialization)
7. [Security Manager Alternatives](#7-security-manager-alternatives)
8. [OWASP Top Ten Compliance](#8-owasp-top-ten-compliance)
9. [NIST SP 800-53 Control Mapping](#9-nist-sp-800-53-control-mapping)
10. [DISA STIG Requirements](#10-disa-stig-requirements)
11. [CIS Benchmark Level 2 Controls](#11-cis-benchmark-level-2-controls)
12. [FIPS 140-3 Cryptographic Compliance](#12-fips-140-3-cryptographic-compliance)
13. [Compliance Checklists](#13-compliance-checklists)
14. [References](#14-references)

---

## 1. Java 21/22 Security Features

### 1.1 Overview of Security Enhancements

Java 21 (LTS) and Java 22+ introduce significant security improvements that enhance application security by default. These features provide stronger defaults, improved cryptographic support, and better isolation mechanisms.

### 1.2 Key Security Features in Java 21 LTS

#### Virtual Threads and Security Context Propagation

Virtual threads (JEP 444) require careful handling of security contexts:

```java
// Secure context propagation with virtual threads
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SecureVirtualThreadExample {
    
    // Use structured concurrency for secure context propagation
    public void executeWithSecurityContext() {
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            // Security context is automatically inherited
            executor.submit(() -> {
                // SecurityContext is available in virtual thread
                performSecureOperation();
            });
        }
    }
    
    private void performSecureOperation() {
        // Security-sensitive operation
    }
}
```

#### Record Patterns for Secure Data Handling

Records provide immutable data structures ideal for security-sensitive data:

```java
// Secure record pattern for authentication data
public record AuthenticationResult(
    String userId,
    boolean authenticated,
    long timestamp,
    String tokenHash  // Never store raw tokens
) {
    // Compact constructor for validation
    public AuthenticationResult {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("User ID cannot be null or blank");
        }
        if (timestamp <= 0) {
            throw new IllegalArgumentException("Invalid timestamp");
        }
    }
    
    // Override toString to prevent sensitive data leakage
    @Override
    public String toString() {
        return "AuthenticationResult[userId=*****, authenticated=" + 
               authenticated + ", timestamp=" + timestamp + "]";
    }
}
```

#### Sequenced Collections for Predictable Iteration

```java
// Secure iteration order prevents timing attacks
import java.util.SequencedMap;
import java.util.LinkedHashMap;

public class SecurePermissionCheck {
    
    private final SequencedMap<String, Permission> permissions = new LinkedHashMap<>();
    
    public boolean checkPermissions(String user, String resource) {
        // Predictable iteration order prevents timing-based enumeration
        return permissions.sequencedValues().stream()
            .anyMatch(p -> p.allows(user, resource));
    }
}
```

### 1.3 Java 22+ Security Enhancements

#### Foreign Function & Memory API Security

The Foreign Function & Memory API (JEP 454) requires explicit security considerations:

```java
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

public class SecureNativeAccess {
    
    // Restricted operation - requires explicit enable
    public void secureNativeCall() {
        // Validate inputs before native call
        try (Arena arena = Arena.ofConfined()) {
            // Memory is automatically cleaned up
            MemorySegment segment = arena.allocate(1024);
            
            // Perform secure native operation
            // Memory bounds are automatically checked
        }
        // Memory is deallocated here - prevents memory leaks
    }
}
```

#### String Templates Security (Preview)

```java
// Secure string template usage (Preview Feature)
public class SecureLogging {
    
    public void logSecureEvent(String userId, String action) {
        // String templates with automatic escaping
        String sanitizedUserId = sanitize(userId);
        String sanitizedAction = sanitize(action);
        
        // Use structured logging instead of string concatenation
        logger.info("User {} performed action {}", 
                    sanitizedUserId, sanitizedAction);
    }
    
    private String sanitize(String input) {
        if (input == null) return "[null]";
        return input.replaceAll("[^a-zA-Z0-9_-]", "_");
    }
}
```

### 1.4 Security-Related JVM Options

```bash
# Recommended JVM security options for Java 21+
java \
  -Djava.security.manager=disallow \
  -Djdk.serialFilter=maxdepth=5;maxrefs=500;maxbytes=500000 \
  -Djavax.net.ssl.trustStore=/path/to/truststore.jks \
  -Djavax.net.ssl.keyStore=/path/to/keystore.jks \
  -Dhttps.protocols=TLSv1.3,TLSv1.2 \
  -Djdk.tls.client.protocols=TLSv1.3,TLSv1.2 \
  -Djdk.tls.ephemeralDHKeySize=2048 \
  -Dcom.sun.jndi.ldap.object.trustURLCodebase=false \
  -Dcom.sun.jndi.rmi.object.trustURLCodebase=false \
  -jar application.jar
```

---

## 2. Spring Security Best Practices

### 2.1 Spring Security 6 Configuration

Spring Security 6 introduces a component-based security configuration using the new `SecurityFilterChain` approach:

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            // Authorization rules
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**", "/health", "/info").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().denyAll()
            )
            
            // Session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true)
            )
            
            // CSRF protection
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/api/webhook/**")
            )
            
            // Security headers
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; " +
                        "script-src 'self'; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:; " +
                        "frame-ancestors 'none';"))
                .frameOptions(frame -> frame.deny())
                .xssProtection(xss -> xss
                    .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
                .permissionsPolicy(permissions -> permissions
                    .policy("geolocation=(), microphone=(), camera=()"))
            )
            
            // OAuth2 Resource Server
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Argon2 is recommended for password hashing (OWASP recommendation)
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }
}
```

### 2.2 JWT Authentication Implementation

```java
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

@Component
public class JwtTokenProvider {
    
    // Use at least 256-bit key for HS256, 384-bit for HS384, 512-bit for HS512
    private final SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    
    private static final long TOKEN_VALIDITY_MS = 3600000; // 1 hour
    private static final long REFRESH_TOKEN_VALIDITY_MS = 604800000; // 7 days
    
    public String generateToken(String userId, Map<String, Object> claims) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + TOKEN_VALIDITY_MS);
        
        return Jwts.builder()
            .setSubject(userId)
            .setIssuedAt(now)
            .setExpiration(validity)
            .setIssuer("secure-app")
            .setAudience("secure-app-users")
            .addClaims(claims)
            .signWith(secretKey, SignatureAlgorithm.HS512)
            .compact();
    }
    
    public Claims validateAndExtractClaims(String token) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .requireIssuer("secure-app")
                .requireAudience("secure-app-users")
                .build()
                .parseClaimsJws(token)
                .getBody();
        } catch (ExpiredJwtException e) {
            throw new SecurityException("Token has expired", e);
        } catch (JwtException e) {
            throw new SecurityException("Invalid token", e);
        }
    }
}
```

### 2.3 Role-Based Access Control (RBAC)

```java
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.stereotype.Service;

@Service
public class SecureResourceService {
    
    // Method-level security with SpEL expressions
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_READ')")
    public Resource getResource(Long id) {
        return resourceRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException(id));
    }
    
    // Owner-based access control
    @PreAuthorize("hasRole('ADMIN') or @securityService.isOwner(#id, authentication.name)")
    public void deleteResource(Long id) {
        resourceRepository.deleteById(id);
    }
    
    // Post-authorization for filtering results
    @PostAuthorize("returnObject.owner == authentication.name or hasRole('ADMIN')")
    public Resource getResourceWithOwnerCheck(Long id) {
        return resourceRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException(id));
    }
    
    // Collection filtering
    @PostFilter("filterObject.accessLevel <= principal.clearanceLevel")
    public List<Resource> getAllResources() {
        return resourceRepository.findAll();
    }
}
```

### 2.4 OAuth2 and OIDC Configuration

```java
@Configuration
public class OAuth2SecurityConfig {
    
    @Bean
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        return http
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(auth -> auth
                    .authorizationRequestRepository(
                        new HttpSessionOAuth2AuthorizationRequestRepository()))
                .tokenEndpoint(token -> token
                    .accessTokenResponseClient(accessTokenResponseClient()))
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(oauth2UserService()))
            )
            .oauth2Client(client -> client
                .authorizationCodeGrant(code -> code
                    .authorizationRequestResolver(authorizationRequestResolver()))
            )
            .build();
    }
    
    @Bean
    public JwtDecoder jwtDecoder() {
        // Validate issuer, audience, and signature
        NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuerUri);
        
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(audience);
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> combinedValidator = 
            new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);
        
        decoder.setJwtValidator(combinedValidator);
        return decoder;
    }
}
```

---

## 3. Input Validation and Bean Validation

### 3.1 Jakarta Bean Validation (JSR 380)

```java
import jakarta.validation.constraints.*;
import jakarta.validation.Valid;
import org.hibernate.validator.constraints.SafeHtml;

public class UserRegistrationRequest {
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", 
             message = "Username can only contain letters, numbers, and underscores")
    private String username;
    
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;
    
    @NotBlank(message = "Password is required")
    @Size(min = 12, max = 128, message = "Password must be between 12 and 128 characters")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$",
        message = "Password must contain uppercase, lowercase, number, and special character"
    )
    private String password;
    
    @NotNull(message = "Age is required")
    @Min(value = 18, message = "Must be at least 18 years old")
    @Max(value = 120, message = "Invalid age")
    private Integer age;
    
    @Valid  // Cascade validation to nested objects
    @NotNull(message = "Address is required")
    private AddressDTO address;
    
    // Getters and setters
}

public class AddressDTO {
    
    @NotBlank(message = "Street is required")
    @Size(max = 200, message = "Street must not exceed 200 characters")
    private String street;
    
    @NotBlank(message = "City is required")
    @Pattern(regexp = "^[a-zA-Z\\s-]+$", message = "Invalid city name")
    private String city;
    
    @NotBlank(message = "Postal code is required")
    @Pattern(regexp = "^[0-9]{5}(-[0-9]{4})?$", message = "Invalid postal code format")
    private String postalCode;
}
```

### 3.2 Custom Validators

```java
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import java.lang.annotation.*;

// Custom annotation for SQL injection prevention
@Documented
@Constraint(validatedBy = NoSqlInjectionValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface NoSqlInjection {
    String message() default "Potential SQL injection detected";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}

public class NoSqlInjectionValidator implements ConstraintValidator<NoSqlInjection, String> {
    
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "(?i)(--|;|'|\"|\\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\\b)",
        Pattern.CASE_INSENSITIVE
    );
    
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isEmpty()) {
            return true; // Let @NotNull/@NotBlank handle null checks
        }
        return !SQL_INJECTION_PATTERN.matcher(value).find();
    }
}

// Custom annotation for XSS prevention
@Documented
@Constraint(validatedBy = NoXssValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface NoXss {
    String message() default "Potential XSS attack detected";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}

public class NoXssValidator implements ConstraintValidator<NoXss, String> {
    
    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(?i)(<script|javascript:|on\\w+=|<iframe|<object|<embed)",
        Pattern.CASE_INSENSITIVE
    );
    
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isEmpty()) {
            return true;
        }
        return !XSS_PATTERN.matcher(value).find();
    }
}
```

### 3.3 Controller-Level Validation

```java
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

@RestController
@RequestMapping("/api/users")
@Validated
public class UserController {
    
    private final UserService userService;
    
    @PostMapping
    public ResponseEntity<UserResponse> createUser(
            @Valid @RequestBody UserRegistrationRequest request) {
        return ResponseEntity.ok(userService.createUser(request));
    }
    
    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> getUser(
            @PathVariable 
            @Min(value = 1, message = "ID must be positive")
            @Max(value = Long.MAX_VALUE, message = "Invalid ID") 
            Long id) {
        return ResponseEntity.ok(userService.getUser(id));
    }
    
    @GetMapping("/search")
    public ResponseEntity<List<UserResponse>> searchUsers(
            @RequestParam 
            @NotBlank(message = "Query cannot be blank")
            @Size(min = 2, max = 100, message = "Query must be 2-100 characters")
            @NoSqlInjection
            @NoXss
            String query,
            
            @RequestParam(defaultValue = "0")
            @Min(value = 0, message = "Page must be non-negative")
            int page,
            
            @RequestParam(defaultValue = "20")
            @Min(value = 1, message = "Size must be at least 1")
            @Max(value = 100, message = "Size must not exceed 100")
            int size) {
        return ResponseEntity.ok(userService.searchUsers(query, page, size));
    }
}
```

### 3.4 Global Exception Handler for Validation Errors

```java
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.ConstraintViolationException;
import java.util.Map;
import java.util.HashMap;

@ControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "Validation Failed");
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
            errors.put(error.getField(), error.getDefaultMessage())
        );
        response.put("errors", errors);
        
        // Log for security monitoring (do not include user input)
        logger.warn("Validation failed: {} errors detected", errors.size());
        
        return ResponseEntity.badRequest().body(response);
    }
    
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolation(
            ConstraintViolationException ex) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "Constraint Violation");
        
        Map<String, String> errors = new HashMap<>();
        ex.getConstraintViolations().forEach(violation ->
            errors.put(violation.getPropertyPath().toString(), violation.getMessage())
        );
        response.put("errors", errors);
        
        return ResponseEntity.badRequest().body(response);
    }
}
```

---

## 4. JDBC/JPA Security - SQL Injection Prevention

### 4.1 Secure JDBC with PreparedStatement

```java
import java.sql.*;
import javax.sql.DataSource;

public class SecureJdbcRepository {
    
    private final DataSource dataSource;
    
    // SECURE: Using PreparedStatement with parameterized queries
    public User findUserByUsername(String username) {
        String sql = "SELECT id, username, email, created_at FROM users WHERE username = ?";
        
        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            // Parameters are automatically escaped
            stmt.setString(1, username);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return mapToUser(rs);
                }
            }
        } catch (SQLException e) {
            throw new DataAccessException("Failed to find user", e);
        }
        return null;
    }
    
    // SECURE: Batch operations with PreparedStatement
    public void insertUsers(List<User> users) {
        String sql = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";
        
        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            conn.setAutoCommit(false);
            
            for (User user : users) {
                stmt.setString(1, user.getUsername());
                stmt.setString(2, user.getEmail());
                stmt.setString(3, user.getPasswordHash());
                stmt.addBatch();
            }
            
            stmt.executeBatch();
            conn.commit();
            
        } catch (SQLException e) {
            throw new DataAccessException("Failed to insert users", e);
        }
    }
    
    // VULNERABLE: Never do this!
    // public User findUserUnsafe(String username) {
    //     String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    //     // This is vulnerable to SQL injection!
    // }
}
```

### 4.2 Secure JPA/Hibernate Queries

```java
import jakarta.persistence.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;

// Secure JPA Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // SECURE: Spring Data JPA method naming (parameters are automatically bound)
    Optional<User> findByUsername(String username);
    
    List<User> findByEmailContainingIgnoreCase(String email);
    
    // SECURE: Named parameters with @Query
    @Query("SELECT u FROM User u WHERE u.department = :dept AND u.active = true")
    List<User> findActiveUsersByDepartment(@Param("dept") String department);
    
    // SECURE: Native query with named parameters
    @Query(value = "SELECT * FROM users WHERE created_at > :date AND status = :status",
           nativeQuery = true)
    List<User> findRecentUsersByStatus(@Param("date") LocalDateTime date,
                                       @Param("status") String status);
    
    // SECURE: Positional parameters
    @Query("SELECT u FROM User u WHERE u.role = ?1 AND u.lastLogin > ?2")
    List<User> findByRoleAndRecentLogin(String role, LocalDateTime since);
}

// Secure Criteria API usage
@Repository
public class UserCriteriaRepository {
    
    @PersistenceContext
    private EntityManager entityManager;
    
    // SECURE: Criteria API with type-safe queries
    public List<User> searchUsers(UserSearchCriteria criteria) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> query = cb.createQuery(User.class);
        Root<User> user = query.from(User.class);
        
        List<Predicate> predicates = new ArrayList<>();
        
        if (criteria.getUsername() != null) {
            // Parameters are safely bound
            predicates.add(cb.like(
                cb.lower(user.get("username")),
                "%" + criteria.getUsername().toLowerCase() + "%"
            ));
        }
        
        if (criteria.getRole() != null) {
            predicates.add(cb.equal(user.get("role"), criteria.getRole()));
        }
        
        query.where(predicates.toArray(new Predicate[0]));
        
        return entityManager.createQuery(query)
            .setMaxResults(criteria.getLimit())
            .getResultList();
    }
}
```

### 4.3 Dynamic Query Building (Safe Patterns)

```java
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

@Repository
public class DynamicQueryRepository {
    
    private final NamedParameterJdbcTemplate jdbcTemplate;
    
    // SECURE: Dynamic query with whitelist validation
    public List<User> findUsersWithSorting(String sortColumn, String sortDirection) {
        // Whitelist allowed columns
        Set<String> allowedColumns = Set.of("username", "email", "created_at", "last_login");
        Set<String> allowedDirections = Set.of("ASC", "DESC");
        
        // Validate sort column against whitelist
        if (!allowedColumns.contains(sortColumn.toLowerCase())) {
            throw new IllegalArgumentException("Invalid sort column: " + sortColumn);
        }
        
        // Validate sort direction
        String direction = sortDirection.toUpperCase();
        if (!allowedDirections.contains(direction)) {
            direction = "ASC";
        }
        
        // Safe to use validated column name directly
        String sql = String.format(
            "SELECT id, username, email, created_at FROM users ORDER BY %s %s",
            sortColumn, direction
        );
        
        return jdbcTemplate.query(sql, new MapSqlParameterSource(), userRowMapper);
    }
    
    // SECURE: Dynamic WHERE clause with parameters
    public List<User> searchUsers(Map<String, Object> filters) {
        StringBuilder sql = new StringBuilder("SELECT * FROM users WHERE 1=1");
        MapSqlParameterSource params = new MapSqlParameterSource();
        
        // Whitelist of allowed filter fields
        Map<String, String> allowedFilters = Map.of(
            "username", "username LIKE :username",
            "email", "email = :email",
            "status", "status = :status",
            "role", "role = :role"
        );
        
        for (Map.Entry<String, Object> filter : filters.entrySet()) {
            String key = filter.getKey();
            if (allowedFilters.containsKey(key)) {
                sql.append(" AND ").append(allowedFilters.get(key));
                Object value = filter.getValue();
                if ("username".equals(key)) {
                    value = "%" + value + "%";  // Wildcard for LIKE
                }
                params.addValue(key, value);
            }
        }
        
        return jdbcTemplate.query(sql.toString(), params, userRowMapper);
    }
}
```

---

## 5. Java Cryptography Architecture (JCA)

### 5.1 Secure Encryption Implementation

```java
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Base64;

public class SecureEncryptionService {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;  // 96 bits recommended for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128 bits authentication tag
    private static final int KEY_SIZE = 256;       // 256-bit key
    
    private final SecretKey secretKey;
    private final SecureRandom secureRandom;
    
    public SecureEncryptionService() throws NoSuchAlgorithmException {
        this.secureRandom = SecureRandom.getInstanceStrong();
        this.secretKey = generateKey();
    }
    
    public SecureEncryptionService(byte[] keyBytes) {
        this.secureRandom = new SecureRandom();
        this.secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
    }
    
    // Generate a cryptographically secure key
    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE, secureRandom);
        return keyGen.generateKey();
    }
    
    // Encrypt with AES-GCM (authenticated encryption)
    public EncryptedData encrypt(byte[] plaintext, byte[] associatedData) 
            throws GeneralSecurityException {
        
        // Generate random IV for each encryption
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        
        // Add associated data for additional authentication
        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }
        
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        return new EncryptedData(iv, ciphertext);
    }
    
    // Decrypt with AES-GCM
    public byte[] decrypt(EncryptedData encryptedData, byte[] associatedData) 
            throws GeneralSecurityException {
        
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, encryptedData.iv());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        
        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }
        
        return cipher.doFinal(encryptedData.ciphertext());
    }
    
    // Record for encrypted data
    public record EncryptedData(byte[] iv, byte[] ciphertext) {
        
        public String toBase64() {
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(combined);
        }
        
        public static EncryptedData fromBase64(String base64, int ivLength) {
            byte[] combined = Base64.getDecoder().decode(base64);
            byte[] iv = new byte[ivLength];
            byte[] ciphertext = new byte[combined.length - ivLength];
            System.arraycopy(combined, 0, iv, 0, ivLength);
            System.arraycopy(combined, ivLength, ciphertext, 0, ciphertext.length);
            return new EncryptedData(iv, ciphertext);
        }
    }
}
```

### 5.2 Secure Password Hashing

```java
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class SecurePasswordHasher {
    
    // PBKDF2 parameters (OWASP recommended)
    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 310000;  // OWASP 2023 recommendation
    private static final int SALT_LENGTH = 16;     // 128 bits
    private static final int KEY_LENGTH = 512;     // 512 bits for SHA-512
    
    private final SecureRandom secureRandom = new SecureRandom();
    
    public String hashPassword(char[] password) {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        
        byte[] hash = pbkdf2(password, salt, ITERATIONS, KEY_LENGTH);
        
        // Format: iterations$salt$hash
        return ITERATIONS + "$" + 
               Base64.getEncoder().encodeToString(salt) + "$" + 
               Base64.getEncoder().encodeToString(hash);
    }
    
    public boolean verifyPassword(char[] password, String storedHash) {
        String[] parts = storedHash.split("\\$");
        if (parts.length != 3) {
            return false;
        }
        
        try {
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[2]);
            
            byte[] actualHash = pbkdf2(password, salt, iterations, KEY_LENGTH);
            
            // Constant-time comparison to prevent timing attacks
            return constantTimeEquals(expectedHash, actualHash);
        } catch (Exception e) {
            return false;
        }
    }
    
    private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLength) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
    
    // Constant-time comparison to prevent timing attacks
    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
```

### 5.3 Digital Signatures

```java
import java.security.*;
import java.security.spec.*;

public class SecureDigitalSignature {
    
    private static final String ALGORITHM = "EC";
    private static final String SIGNATURE_ALGORITHM = "SHA512withECDSA";
    private static final String CURVE = "secp384r1";  // NIST P-384
    
    private final KeyPair keyPair;
    
    public SecureDigitalSignature() throws GeneralSecurityException {
        this.keyPair = generateKeyPair();
    }
    
    private KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE);
        keyGen.initialize(ecSpec, SecureRandom.getInstanceStrong());
        return keyGen.generateKeyPair();
    }
    
    public byte[] sign(byte[] data) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }
    
    public boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) 
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
    
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
}
```

### 5.4 Secure Random Number Generation

```java
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class SecureRandomGenerator {
    
    private final SecureRandom secureRandom;
    
    public SecureRandomGenerator() throws NoSuchAlgorithmException {
        // Use the strongest available PRNG
        this.secureRandom = SecureRandom.getInstanceStrong();
    }
    
    // Generate cryptographically secure random bytes
    public byte[] generateBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
    
    // Generate secure token (URL-safe Base64)
    public String generateToken(int byteLength) {
        byte[] bytes = generateBytes(byteLength);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    // Generate cryptographically secure UUID (Type 4)
    public UUID generateSecureUUID() {
        byte[] randomBytes = generateBytes(16);
        
        // Set version to 4 (random)
        randomBytes[6] &= 0x0f;
        randomBytes[6] |= 0x40;
        
        // Set variant to IETF
        randomBytes[8] &= 0x3f;
        randomBytes[8] |= 0x80;
        
        long msb = 0;
        long lsb = 0;
        for (int i = 0; i < 8; i++) {
            msb = (msb << 8) | (randomBytes[i] & 0xff);
        }
        for (int i = 8; i < 16; i++) {
            lsb = (lsb << 8) | (randomBytes[i] & 0xff);
        }
        
        return new UUID(msb, lsb);
    }
    
    // Generate secure session ID
    public String generateSessionId() {
        return generateToken(32);  // 256 bits
    }
    
    // Generate CSRF token
    public String generateCsrfToken() {
        return generateToken(32);  // 256 bits
    }
}
```

---

## 6. Secure Deserialization

### 6.1 Understanding Deserialization Vulnerabilities

Java object deserialization is a significant attack vector. When untrusted data is deserialized, attackers can execute arbitrary code through gadget chains.

### 6.2 JEP 290: Serialization Filtering

```java
import java.io.*;

public class SecureObjectInputStream extends ObjectInputStream {
    
    // Whitelist of allowed classes for deserialization
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.dto.UserDTO",
        "com.example.dto.ProductDTO",
        "com.example.dto.OrderDTO",
        "java.lang.String",
        "java.lang.Integer",
        "java.lang.Long",
        "java.util.ArrayList",
        "java.util.HashMap",
        "java.time.Instant",
        "java.time.LocalDateTime"
    );
    
    private static final Set<String> BLOCKED_PACKAGES = Set.of(
        "org.apache.commons.collections",
        "org.apache.commons.beanutils",
        "com.sun.org.apache.xalan",
        "javax.management",
        "java.rmi"
    );
    
    public SecureObjectInputStream(InputStream in) throws IOException {
        super(in);
    }
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) 
            throws IOException, ClassNotFoundException {
        
        String className = desc.getName();
        
        // Check against blocked packages
        for (String blockedPackage : BLOCKED_PACKAGES) {
            if (className.startsWith(blockedPackage)) {
                throw new InvalidClassException("Blocked class: " + className);
            }
        }
        
        // Only allow whitelisted classes
        if (!ALLOWED_CLASSES.contains(className) && !className.startsWith("[")) {
            throw new InvalidClassException("Class not in whitelist: " + className);
        }
        
        return super.resolveClass(desc);
    }
}
```

### 6.3 JVM-Level Serialization Filters

Configure serialization filters at JVM level:

```bash
# JVM argument for global serialization filter
java -Djdk.serialFilter=\
maxdepth=5;\
maxrefs=500;\
maxbytes=500000;\
maxarray=100000;\
!org.apache.commons.collections.*;\
!org.apache.commons.beanutils.*;\
!com.sun.org.apache.xalan.*;\
!javax.management.*;\
com.example.dto.*;java.util.*;java.lang.*;java.time.* \
-jar application.jar
```

Programmatic filter configuration:

```java
import java.io.*;

public class SerializationFilterConfig {
    
    public static void configureGlobalFilter() {
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
            "maxdepth=5;" +
            "maxrefs=500;" +
            "maxbytes=500000;" +
            "maxarray=100000;" +
            "!org.apache.commons.collections.**;" +
            "!org.apache.commons.beanutils.**;" +
            "!com.sun.org.apache.xalan.**;" +
            "!javax.management.**;" +
            "!java.rmi.**;" +
            "com.example.dto.**;" +
            "java.base/*;" +
            "!*"  // Reject everything else
        );
        
        ObjectInputFilter.Config.setSerialFilter(filter);
    }
    
    // Stream-specific filter
    public static <T> T deserializeSecurely(byte[] data, Class<T> expectedClass) 
            throws IOException, ClassNotFoundException {
        
        ObjectInputFilter filter = createClassFilter(expectedClass);
        
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            
            ois.setObjectInputFilter(filter);
            Object obj = ois.readObject();
            
            if (!expectedClass.isInstance(obj)) {
                throw new ClassCastException("Unexpected class: " + obj.getClass());
            }
            
            return expectedClass.cast(obj);
        }
    }
    
    private static ObjectInputFilter createClassFilter(Class<?> allowedClass) {
        return filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz == null) {
                return ObjectInputFilter.Status.UNDECIDED;
            }
            
            // Check depth limit
            if (filterInfo.depth() > 5) {
                return ObjectInputFilter.Status.REJECTED;
            }
            
            // Check reference limit
            if (filterInfo.references() > 500) {
                return ObjectInputFilter.Status.REJECTED;
            }
            
            // Allow the expected class and its dependencies
            if (clazz.equals(allowedClass) || 
                clazz.isPrimitive() ||
                clazz.getName().startsWith("java.lang.") ||
                clazz.getName().startsWith("java.util.")) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            
            return ObjectInputFilter.Status.REJECTED;
        };
    }
}
```

### 6.4 Alternative Serialization Formats

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class SecureJsonSerializer {
    
    private final ObjectMapper objectMapper;
    
    public SecureJsonSerializer() {
        this.objectMapper = new ObjectMapper();
        
        // Security configurations
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        objectMapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true);
        objectMapper.configure(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS, true);
        
        // Disable dangerous features
        objectMapper.deactivateDefaultTyping();  // Prevent polymorphic deserialization attacks
        
        // Enable strict type handling
        objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        
        // Register time module
        objectMapper.registerModule(new JavaTimeModule());
    }
    
    public String serialize(Object obj) throws JsonProcessingException {
        return objectMapper.writeValueAsString(obj);
    }
    
    public <T> T deserialize(String json, Class<T> clazz) throws JsonProcessingException {
        return objectMapper.readValue(json, clazz);
    }
    
    // Deserialize with type reference for generic types
    public <T> T deserialize(String json, TypeReference<T> typeRef) 
            throws JsonProcessingException {
        return objectMapper.readValue(json, typeRef);
    }
}
```

---

## 7. Security Manager Alternatives

### 7.1 Security Manager Deprecation

The Java Security Manager was deprecated in Java 17 (JEP 411) and removed in Java 24 (JEP 486). Modern applications must use alternative security mechanisms.

### 7.2 Recommended Alternatives

#### Container-Based Isolation

```yaml
# Docker security configuration
# docker-compose.yml
services:
  java-app:
    image: eclipse-temurin:21-jre
    security_opt:
      - no-new-privileges:true
      - seccomp:seccomp-profile.json
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,nodev
    user: "1000:1000"
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

#### Process Sandboxing with Java Agent

```java
import java.lang.instrument.Instrumentation;
import java.security.Permission;

public class SecurityAgent {
    
    public static void premain(String args, Instrumentation inst) {
        // Register class transformer for security checks
        inst.addTransformer(new SecurityTransformer());
        
        // Add shutdown hook for cleanup
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Security agent shutting down...");
        }));
    }
    
    // Custom security transformer
    static class SecurityTransformer implements ClassFileTransformer {
        
        private static final Set<String> RESTRICTED_CLASSES = Set.of(
            "java/lang/Runtime",
            "java/lang/ProcessBuilder",
            "java/io/FileOutputStream",
            "java/net/Socket"
        );
        
        @Override
        public byte[] transform(ClassLoader loader, String className,
                               Class<?> classBeingRedefined,
                               ProtectionDomain protectionDomain,
                               byte[] classfileBuffer) {
            
            // Log access to restricted classes
            if (RESTRICTED_CLASSES.contains(className)) {
                System.err.println("WARNING: Access to restricted class: " + className);
            }
            
            return classfileBuffer;  // Return unchanged
        }
    }
}
```

#### Module System Access Control

```java
// module-info.java
module com.example.secureapp {
    // Minimal required modules
    requires java.base;
    requires java.logging;
    requires java.sql;
    
    // Explicitly export only necessary packages
    exports com.example.api;
    exports com.example.dto;
    
    // Internal packages are not exported
    // com.example.internal is encapsulated
    
    // Open for reflection only where necessary
    opens com.example.dto to com.fasterxml.jackson.databind;
    
    // Provide services
    provides com.example.api.SecurityService 
        with com.example.internal.SecurityServiceImpl;
}
```

#### File System Permissions

```java
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.io.IOException;

public class SecureFileOperations {
    
    // Create file with restrictive permissions
    public Path createSecureFile(String filename) throws IOException {
        Path path = Paths.get("/secure/data", filename);
        
        // Create with owner-only permissions (Unix)
        Set<PosixFilePermission> perms = EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE
        );
        FileAttribute<Set<PosixFilePermission>> attr = 
            PosixFilePermissions.asFileAttribute(perms);
        
        return Files.createFile(path, attr);
    }
    
    // Securely create temporary file
    public Path createSecureTempFile(String prefix, String suffix) throws IOException {
        Path tempDir = Paths.get(System.getProperty("java.io.tmpdir"));
        
        // Verify temp directory permissions
        if (!Files.isWritable(tempDir)) {
            throw new SecurityException("Temp directory not writable");
        }
        
        Path tempFile = Files.createTempFile(tempDir, prefix, suffix);
        
        // Set restrictive permissions
        if (tempFile.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Set<PosixFilePermission> perms = EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE
            );
            Files.setPosixFilePermissions(tempFile, perms);
        }
        
        return tempFile;
    }
}
```

---

## 8. OWASP Top Ten Compliance

### 8.1 OWASP Top Ten 2025 Overview and Java Mitigations

| Rank | Vulnerability | Java Mitigation | Code Example Section |
|------|--------------|-----------------|---------------------|
| A01 | Broken Access Control | Spring Security RBAC, Method Security | Section 2.3 |
| A02 | Cryptographic Failures | JCA with strong algorithms | Section 5.1-5.4 |
| A03 | Injection | PreparedStatement, JPA parameters | Section 4.1-4.3 |
| A04 | Insecure Design | Threat modeling, secure defaults | Section 7.2 |
| A05 | Security Misconfiguration | Spring Security hardening | Section 2.1 |
| A06 | Vulnerable Components | Dependency scanning, updates | Section 13.3 |
| A07 | Authentication Failures | JWT best practices, MFA | Section 2.2 |
| A08 | Software/Data Integrity | Serialization filters, signing | Section 6.3 |
| A09 | Security Logging Failures | Structured logging | Section 8.2 |
| A10 | Server-Side Request Forgery | URL validation, allowlists | Section 8.3 |

### 8.2 Secure Logging Implementation

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

public class SecureLogger {
    
    private final Logger logger;
    
    public SecureLogger(Class<?> clazz) {
        this.logger = LoggerFactory.getLogger(clazz);
    }
    
    // Log security events with context
    public void logSecurityEvent(String eventType, String userId, String action, 
                                  boolean success, String details) {
        MDC.put("eventType", eventType);
        MDC.put("userId", sanitize(userId));
        MDC.put("action", sanitize(action));
        MDC.put("success", String.valueOf(success));
        MDC.put("timestamp", Instant.now().toString());
        MDC.put("requestId", getCurrentRequestId());
        
        if (success) {
            logger.info("Security event: {} - {}", eventType, sanitize(details));
        } else {
            logger.warn("Security event FAILED: {} - {}", eventType, sanitize(details));
        }
        
        MDC.clear();
    }
    
    // Log authentication events
    public void logAuthentication(String userId, String method, boolean success, 
                                   String sourceIp) {
        logSecurityEvent(
            "AUTHENTICATION",
            userId,
            method,
            success,
            String.format("IP: %s", sanitize(sourceIp))
        );
    }
    
    // Log authorization events
    public void logAuthorization(String userId, String resource, String permission,
                                  boolean granted) {
        logSecurityEvent(
            "AUTHORIZATION",
            userId,
            "ACCESS_" + permission,
            granted,
            String.format("Resource: %s", sanitize(resource))
        );
    }
    
    // Sanitize log messages to prevent log injection
    private String sanitize(String input) {
        if (input == null) {
            return "[null]";
        }
        return input
            .replaceAll("[\r\n]", "_")  // Remove newlines
            .replaceAll("[\\x00-\\x1F\\x7F]", "")  // Remove control characters
            .substring(0, Math.min(input.length(), 500));  // Limit length
    }
    
    private String getCurrentRequestId() {
        return MDC.get("requestId") != null ? MDC.get("requestId") : UUID.randomUUID().toString();
    }
}
```

### 8.3 SSRF Prevention

```java
import java.net.*;
import java.util.Set;
import java.util.regex.Pattern;

public class SsrfProtection {
    
    // Allowed external domains (whitelist)
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "api.trusted-partner.com",
        "cdn.example.com",
        "storage.googleapis.com"
    );
    
    // Blocked IP ranges (RFC 1918, localhost, link-local)
    private static final List<IpRange> BLOCKED_RANGES = List.of(
        new IpRange("10.0.0.0", "10.255.255.255"),
        new IpRange("172.16.0.0", "172.31.255.255"),
        new IpRange("192.168.0.0", "192.168.255.255"),
        new IpRange("127.0.0.0", "127.255.255.255"),
        new IpRange("169.254.0.0", "169.254.255.255"),
        new IpRange("0.0.0.0", "0.255.255.255")
    );
    
    public URL validateAndSanitizeUrl(String urlString) throws SecurityException {
        try {
            URL url = new URL(urlString);
            
            // Only allow HTTPS
            if (!"https".equalsIgnoreCase(url.getProtocol())) {
                throw new SecurityException("Only HTTPS URLs are allowed");
            }
            
            String host = url.getHost().toLowerCase();
            
            // Check against whitelist
            if (!ALLOWED_DOMAINS.contains(host)) {
                throw new SecurityException("Domain not in whitelist: " + host);
            }
            
            // Resolve and check IP address
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                if (isBlockedIp(addr)) {
                    throw new SecurityException("Blocked IP address: " + addr.getHostAddress());
                }
            }
            
            // Validate port
            int port = url.getPort();
            if (port != -1 && port != 443) {
                throw new SecurityException("Only port 443 is allowed");
            }
            
            return url;
            
        } catch (MalformedURLException | UnknownHostException e) {
            throw new SecurityException("Invalid URL", e);
        }
    }
    
    private boolean isBlockedIp(InetAddress address) {
        if (address.isLoopbackAddress() || 
            address.isSiteLocalAddress() ||
            address.isLinkLocalAddress() ||
            address.isAnyLocalAddress()) {
            return true;
        }
        
        byte[] addrBytes = address.getAddress();
        for (IpRange range : BLOCKED_RANGES) {
            if (range.contains(addrBytes)) {
                return true;
            }
        }
        
        return false;
    }
    
    record IpRange(String start, String end) {
        boolean contains(byte[] address) {
            // Implementation of IP range check
            // ...
            return false;
        }
    }
}
```

---

## 9. NIST SP 800-53 Control Mapping

### 9.1 Relevant Security Controls for Java Applications

| Control ID | Control Name | Java Implementation |
|------------|--------------|---------------------|
| **AC-2** | Account Management | Spring Security UserDetailsService, account lifecycle management |
| **AC-3** | Access Enforcement | @PreAuthorize, @Secured annotations, RBAC |
| **AC-6** | Least Privilege | Method-level security, minimal permissions |
| **AU-2** | Audit Events | SecureLogger implementation, audit trail |
| **AU-3** | Content of Audit Records | MDC context, structured logging |
| **AU-6** | Audit Review, Analysis | Log aggregation, SIEM integration |
| **CA-8** | Penetration Testing | SAST/DAST integration, security testing |
| **CM-7** | Least Functionality | Minimal dependencies, disable unused features |
| **IA-2** | Identification and Authentication | JWT, OAuth2, MFA implementation |
| **IA-5** | Authenticator Management | Password policies, credential rotation |
| **SC-8** | Transmission Confidentiality | TLS 1.3 configuration, certificate pinning |
| **SC-12** | Cryptographic Key Establishment | JCA key management, secure key storage |
| **SC-13** | Cryptographic Protection | AES-GCM, RSA-OAEP, ECDSA |
| **SC-28** | Protection of Information at Rest | Database encryption, secure file storage |
| **SI-2** | Flaw Remediation | Dependency updates, vulnerability scanning |
| **SI-10** | Information Input Validation | Bean Validation, input sanitization |
| **SI-11** | Error Handling | Global exception handlers, secure error messages |

### 9.2 Implementation Example: AC-3 Access Enforcement

```java
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class NistAc3CompliantService {
    
    private final SecureLogger auditLogger;
    private final UserService userService;
    
    // AC-3: Access Enforcement - Role-based access
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('DOCUMENT_READ')")
    public Document getDocument(Long documentId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        Document doc = documentRepository.findById(documentId)
            .orElseThrow(() -> new ResourceNotFoundException("Document not found"));
        
        // AU-2: Log access attempt
        auditLogger.logAuthorization(
            auth.getName(),
            "document:" + documentId,
            "READ",
            true
        );
        
        return doc;
    }
    
    // AC-6: Least Privilege - Attribute-based access
    @PreAuthorize("@documentSecurityService.canAccess(#documentId, authentication)")
    public Document getDocumentWithAbac(Long documentId) {
        return documentRepository.findById(documentId)
            .orElseThrow(() -> new ResourceNotFoundException("Document not found"));
    }
}

@Component
public class DocumentSecurityService {
    
    public boolean canAccess(Long documentId, Authentication authentication) {
        // Implement attribute-based access control logic
        User user = getUserFromAuthentication(authentication);
        Document doc = documentRepository.findById(documentId).orElse(null);
        
        if (doc == null) {
            return false;
        }
        
        // Check classification level
        if (doc.getClassificationLevel() > user.getClearanceLevel()) {
            return false;
        }
        
        // Check department access
        if (doc.isRestrictedToDepartment() && 
            !doc.getDepartment().equals(user.getDepartment())) {
            return false;
        }
        
        return true;
    }
}
```

---

## 10. DISA STIG Requirements

### 10.1 Application Security and Development STIG

| STIG ID | Requirement | Java Implementation |
|---------|-------------|---------------------|
| **V-222400** | Input validation | Bean Validation framework |
| **V-222425** | SQL injection prevention | PreparedStatement, JPA |
| **V-222430** | XSS prevention | Output encoding, CSP headers |
| **V-222432** | CSRF protection | Spring Security CSRF tokens |
| **V-222542** | Session management | Secure session configuration |
| **V-222543** | Session timeout | configureSession timeout |
| **V-222577** | Encryption in transit | TLS 1.2+ enforcement |
| **V-222578** | Encryption at rest | JCA encryption |
| **V-222596** | Audit logging | Structured security logging |
| **V-222599** | Error handling | Custom error handlers |
| **V-222602** | Access control | RBAC implementation |
| **V-222609** | Authentication | Strong authentication mechanisms |

### 10.2 STIG-Compliant Session Configuration

```java
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StigSessionConfig {
    
    // V-222542, V-222543: Secure session management
    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        
        // Secure cookie settings
        serializer.setCookieName("JSESSIONID");
        serializer.setUseSecureCookie(true);          // V-222577: HTTPS only
        serializer.setUseHttpOnlyCookie(true);        // Prevent XSS access
        serializer.setSameSite("Strict");             // V-222432: CSRF protection
        serializer.setCookiePath("/");
        serializer.setCookieMaxAge(1800);             // 30 minutes (V-222543)
        
        return serializer;
    }
    
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
    
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}

@Configuration
public class StigSecurityConfig {
    
    @Bean
    public SecurityFilterChain stigCompliantFilterChain(HttpSecurity http) throws Exception {
        return http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/login?invalid")
                .maximumSessions(1)                   // Single session per user
                .maxSessionsPreventsLogin(true)
                .expiredUrl("/login?expired")
                .sessionRegistry(sessionRegistry())
            )
            
            // V-222432: CSRF protection
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            
            // V-222430: Security headers for XSS prevention
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self'; " +
                        "style-src 'self'; " +
                        "img-src 'self' data:; " +
                        "font-src 'self'; " +
                        "object-src 'none'; " +
                        "frame-ancestors 'none'; " +
                        "base-uri 'self'; " +
                        "form-action 'self';"
                    ))
                .xssProtection(xss -> xss.block(true))
                .frameOptions(frame -> frame.deny())
                .contentTypeOptions(content -> {})
            )
            
            .build();
    }
}
```

---

## 11. CIS Benchmark Level 2 Controls

### 11.1 CIS Controls Applicable to Java Applications

| CIS Control | Description | Java Implementation |
|-------------|-------------|---------------------|
| **1.1** | Inventory of Software Assets | Dependency management (Maven/Gradle) |
| **2.5** | Allowlist Authorized Software | Module system, dependency verification |
| **3.4** | Encrypt Data in Transit | TLS configuration |
| **3.6** | Encrypt Data at Rest | JCA encryption services |
| **4.1** | Secure Configuration Process | Spring profiles, config management |
| **4.7** | Manage Default Accounts | Remove default credentials |
| **6.3** | Enable Detailed Logging | Comprehensive audit logging |
| **7.1** | Vulnerability Scanning | SAST/DAST integration |
| **7.4** | Software Updates | Dependency update automation |
| **8.2** | Access Control Lists | Spring Security ACL |
| **11.3** | Backup Recovery Data | Data backup strategies |
| **16.1** | Software Development Lifecycle | Secure SDLC practices |
| **16.4** | Threat Modeling | Security architecture review |

### 11.2 CIS Level 2 JVM Hardening

```bash
#!/bin/bash
# CIS Level 2 JVM Hardening Script

# Secure JVM startup options
JAVA_OPTS=""

# Disable deprecated security features
JAVA_OPTS="$JAVA_OPTS -Djava.security.manager=disallow"

# TLS hardening
JAVA_OPTS="$JAVA_OPTS -Dhttps.protocols=TLSv1.3,TLSv1.2"
JAVA_OPTS="$JAVA_OPTS -Djdk.tls.client.protocols=TLSv1.3,TLSv1.2"
JAVA_OPTS="$JAVA_OPTS -Djdk.tls.ephemeralDHKeySize=2048"

# Disable dangerous JNDI lookups
JAVA_OPTS="$JAVA_OPTS -Dcom.sun.jndi.ldap.object.trustURLCodebase=false"
JAVA_OPTS="$JAVA_OPTS -Dcom.sun.jndi.rmi.object.trustURLCodebase=false"
JAVA_OPTS="$JAVA_OPTS -Dcom.sun.jndi.cosnaming.object.trustURLCodebase=false"

# Serialization filter
JAVA_OPTS="$JAVA_OPTS -Djdk.serialFilter=maxdepth=5;maxrefs=500;maxbytes=500000"

# Disable remote debugging in production
# JAVA_OPTS="$JAVA_OPTS -agentlib:jdwp=..."  # DO NOT USE IN PRODUCTION

# Memory protection
JAVA_OPTS="$JAVA_OPTS -XX:+UseG1GC"
JAVA_OPTS="$JAVA_OPTS -XX:MaxRAMPercentage=75.0"

# GC logging for monitoring
JAVA_OPTS="$JAVA_OPTS -Xlog:gc*:file=/var/log/java/gc.log:time,uptime:filecount=5,filesize=10M"

export JAVA_OPTS
java $JAVA_OPTS -jar application.jar
```

### 11.3 CIS Level 2 Dependency Verification

```xml
<!-- pom.xml - Maven dependency verification -->
<project>
    <build>
        <plugins>
            <!-- OWASP Dependency Check -->
            <plugin>
                <groupId>org.owasp</groupId>
                <artifactId>dependency-check-maven</artifactId>
                <version>9.0.9</version>
                <configuration>
                    <failBuildOnCVSS>7</failBuildOnCVSS>
                    <suppressionFiles>
                        <suppressionFile>dependency-check-suppressions.xml</suppressionFile>
                    </suppressionFiles>
                </configuration>
                <executions>
                    <execution>
                        <goals>
                            <goal>check</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
            
            <!-- Checksum verification -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-dependency-plugin</artifactId>
                <version>3.6.1</version>
                <executions>
                    <execution>
                        <id>verify</id>
                        <phase>verify</phase>
                        <goals>
                            <goal>analyze</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

---

## 12. FIPS 140-3 Cryptographic Compliance

### 12.1 FIPS 140-3 Overview

FIPS 140-3 specifies cryptographic module requirements. Java applications requiring FIPS compliance must use FIPS-validated cryptographic providers.

### 12.2 FIPS-Compliant Providers

| Provider | FIPS 140-3 Status | Usage |
|----------|-------------------|-------|
| Bouncy Castle FIPS | Validated (Certificate #4743) | General cryptography |
| IBM JCEFIPS | Validated | IBM JDK environments |
| Oracle Jipher | Validated | Oracle Cloud Infrastructure |
| SafeLogic CryptoComply | Validated | Enterprise applications |

### 12.3 FIPS Mode Configuration

```java
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import java.security.Security;

public class FipsConfiguration {
    
    public static void enableFipsMode() {
        // Remove non-FIPS providers
        for (Provider provider : Security.getProviders()) {
            if (!provider.getName().contains("FIPS") && 
                !provider.getName().equals("SUN")) {
                Security.removeProvider(provider.getName());
            }
        }
        
        // Add FIPS provider as highest priority
        Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
        
        // Verify FIPS mode
        if (!FipsStatus.isReady()) {
            throw new SecurityException("FIPS mode not ready");
        }
        
        System.out.println("FIPS 140-3 mode enabled");
    }
}
```

### 12.4 FIPS-Compliant Algorithm Selection

```java
public class FipsCompliantCrypto {
    
    // FIPS 140-3 Approved Algorithms
    
    // Symmetric Encryption
    public static final String AES_GCM = "AES/GCM/NoPadding";  // Approved
    public static final String AES_CBC = "AES/CBC/PKCS5Padding";  // Approved
    
    // Hash Functions
    public static final String SHA256 = "SHA-256";  // Approved
    public static final String SHA384 = "SHA-384";  // Approved
    public static final String SHA512 = "SHA-512";  // Approved
    public static final String SHA3_256 = "SHA3-256";  // Approved
    
    // Key Derivation
    public static final String PBKDF2 = "PBKDF2WithHmacSHA256";  // Approved
    
    // Digital Signatures
    public static final String ECDSA = "SHA384withECDSA";  // Approved (P-384)
    public static final String RSA_PSS = "SHA256withRSA/PSS";  // Approved
    
    // Key Agreement
    public static final String ECDH = "ECDH";  // Approved with P-256, P-384, P-521
    
    // Random Number Generation
    public static final String DRBG = "SHA256DRBG";  // Approved
    
    // Minimum Key Sizes (FIPS 140-3)
    public static final int AES_KEY_SIZE = 256;  // bits
    public static final int RSA_KEY_SIZE = 2048;  // minimum
    public static final int EC_KEY_SIZE = 256;   // P-256 minimum
}
```

### 12.5 FIPS-Compliant TLS Configuration

```java
import javax.net.ssl.*;
import java.security.*;

public class FipsTlsConfiguration {
    
    // FIPS-approved cipher suites for TLS 1.2+
    private static final String[] FIPS_CIPHER_SUITES = {
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    };
    
    // TLS 1.3 cipher suites (inherently FIPS-compliant)
    private static final String[] TLS13_CIPHER_SUITES = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256"
    };
    
    private static final String[] FIPS_PROTOCOLS = {
        "TLSv1.3",
        "TLSv1.2"
    };
    
    public SSLContext createFipsSSLContext() throws GeneralSecurityException {
        // Use FIPS provider
        SSLContext sslContext = SSLContext.getInstance("TLS", "BCFIPS");
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", "BCFIPS");
        kmf.init(loadKeyStore(), getKeyStorePassword());
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "BCFIPS");
        tmf.init(loadTrustStore());
        
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), 
                        SecureRandom.getInstance("SHA256DRBG", "BCFIPS"));
        
        return sslContext;
    }
    
    public void configureFipsSSLSocket(SSLSocket socket) {
        socket.setEnabledProtocols(FIPS_PROTOCOLS);
        socket.setEnabledCipherSuites(FIPS_CIPHER_SUITES);
    }
}
```

---

## 13. Compliance Checklists

### 13.1 Pre-Deployment Security Checklist

| Category | Item | Status | Notes |
|----------|------|--------|-------|
| **Authentication** | | | |
| | Strong password policy implemented | [ ] | Min 12 chars, complexity requirements |
| | Password hashing uses Argon2/PBKDF2 | [ ] | OWASP recommended iterations |
| | Multi-factor authentication available | [ ] | TOTP, WebAuthn support |
| | Session tokens are cryptographically secure | [ ] | 256-bit minimum |
| | JWT tokens properly validated | [ ] | Signature, expiration, issuer |
| **Authorization** | | | |
| | Role-based access control implemented | [ ] | Spring Security @PreAuthorize |
| | Principle of least privilege followed | [ ] | Minimal permissions |
| | Resource-level authorization checks | [ ] | Owner/attribute-based checks |
| **Input Validation** | | | |
| | All inputs validated server-side | [ ] | Bean Validation framework |
| | SQL injection prevention | [ ] | PreparedStatement/JPA |
| | XSS prevention | [ ] | Output encoding, CSP |
| | Path traversal prevention | [ ] | Canonicalization, whitelist |
| **Cryptography** | | | |
| | TLS 1.2+ enforced | [ ] | TLS 1.3 preferred |
| | Strong cipher suites only | [ ] | AES-GCM, ChaCha20 |
| | Keys properly managed | [ ] | Secure storage, rotation |
| | FIPS mode (if required) | [ ] | Validated provider |
| **Data Protection** | | | |
| | Sensitive data encrypted at rest | [ ] | AES-256-GCM |
| | PII properly handled | [ ] | Minimization, masking |
| | Secure deletion implemented | [ ] | Overwrite before delete |
| **Logging & Monitoring** | | | |
| | Security events logged | [ ] | Auth, authz, errors |
| | No sensitive data in logs | [ ] | Sanitization applied |
| | Audit trail maintained | [ ] | Immutable, timestamped |
| **Dependencies** | | | |
| | Vulnerability scan passed | [ ] | OWASP Dependency Check |
| | All dependencies current | [ ] | No known vulnerabilities |
| | License compliance verified | [ ] | Compatible licenses |

### 13.2 OWASP Top Ten Compliance Checklist

| # | Vulnerability | Mitigated | Implementation |
|---|--------------|-----------|----------------|
| A01 | Broken Access Control | [ ] | RBAC, @PreAuthorize, resource checks |
| A02 | Cryptographic Failures | [ ] | TLS 1.3, AES-GCM, secure key management |
| A03 | Injection | [ ] | PreparedStatement, parameterized queries |
| A04 | Insecure Design | [ ] | Threat modeling, secure architecture |
| A05 | Security Misconfiguration | [ ] | Hardened defaults, security headers |
| A06 | Vulnerable Components | [ ] | Dependency scanning, updates |
| A07 | Authentication Failures | [ ] | Strong auth, secure sessions |
| A08 | Software/Data Integrity | [ ] | Signature verification, SBOM |
| A09 | Security Logging Failures | [ ] | Comprehensive audit logging |
| A10 | SSRF | [ ] | URL validation, allowlists |

### 13.3 Dependency Security Checklist

```xml
<!-- Maven configuration for security scanning -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.9</version>
    <configuration>
        <!-- Fail build on HIGH/CRITICAL vulnerabilities -->
        <failBuildOnCVSS>7</failBuildOnCVSS>
        
        <!-- Enable all analyzers -->
        <enableExperimental>true</enableExperimental>
        <assemblyAnalyzerEnabled>false</assemblyAnalyzerEnabled>
        
        <!-- Output formats -->
        <formats>
            <format>HTML</format>
            <format>JSON</format>
        </formats>
        
        <!-- Suppress known false positives -->
        <suppressionFiles>
            <suppressionFile>suppressions.xml</suppressionFile>
        </suppressionFiles>
    </configuration>
</plugin>
```

---

## 14. References

### 14.1 Official Documentation

1. **Oracle Java Security Documentation**
   - [Java Security Overview](https://docs.oracle.com/en/java/javase/21/security/)
   - [JDK 21 Release Notes](https://www.oracle.com/java/technologies/javase/21all-relnotes.html)
   - [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/21/security/java-cryptography-architecture-jca-reference-guide.html)

2. **Spring Security**
   - [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
   - [Spring Security 6 Migration Guide](https://docs.spring.io/spring-security/reference/migration/index.html)

3. **NIST Publications**
   - [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
   - [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final)
   - [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)

4. **OWASP Resources**
   - [OWASP Top Ten 2025](https://owasp.org/Top10/2025/en/)
   - [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
   - [OWASP Java Security](https://owasp.org/www-project-java-html-sanitizer/)

5. **DISA STIG**
   - [Application Security STIG](https://www.stigviewer.com/stigs/application_security_and_development)
   - [DoD Cyber Exchange](https://public.cyber.mil/stigs/)

6. **CIS Benchmarks**
   - [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
   - [CIS Controls](https://www.cisecurity.org/controls)

### 14.2 Additional Resources

7. **Bouncy Castle FIPS**
   - [Bouncy Castle FIPS Certification](https://www.bouncycastle.org/fips-java/)

8. **JEP References**
   - [JEP 411: Deprecate Security Manager](https://openjdk.org/jeps/411)
   - [JEP 486: Permanently Disable Security Manager](https://openjdk.org/jeps/486)
   - [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290)
   - [JEP 444: Virtual Threads](https://openjdk.org/jeps/444)

9. **Security Tools**
   - [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
   - [Snyk](https://snyk.io/)
   - [SonarQube](https://www.sonarqube.org/)

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | March 2026 | Matrix Agent | Initial release |

---

**Disclaimer:** This guide provides security best practices and should be adapted to specific organizational requirements. Security implementations should be reviewed by qualified security professionals before deployment to production environments. Compliance with specific standards (FIPS, DISA STIG, etc.) may require additional certification processes.
