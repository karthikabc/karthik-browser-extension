# Security Warning Quick Reference

## 🔴 CRITICAL - Immediate Action Required

### Untrusted Client-Supplied Identity ⚠️ NEW
**What it means**: Email, userId, or username in request body when JWT token is present  
**Risk**: Account takeover, privilege escalation, unauthorized access to other users' data  
**Why it's critical**: An attacker can send `{"email": "victim@example.com"}` to access/modify another user's account  
**Action**:
1. Extract user identity from JWT claims server-side (e.g., `req.user.email` from decoded token)
2. NEVER trust email/userId from request body for authenticated requests
3. Only use JWT-derived identity for authorization decisions
4. Example fix:
   ```javascript
   // ❌ VULNERABLE
   const email = req.body.email; // Attacker controls this!
   
   // ✅ SECURE
   const email = req.user.email; // From verified JWT
   ```

### Hardcoded Secrets in Request
**What it means**: API keys, tokens, or credentials are hardcoded in the application  
**Risk**: Complete account compromise, unauthorized access  
**Action**: 
1. Rotate all exposed credentials immediately
2. Move secrets to environment variables or secret manager
3. Scan codebase for other hardcoded secrets

### Weak Authentication
**What it means**: Using Basic Auth over HTTP, API keys in query strings, or plaintext passwords  
**Risk**: Credential interception, account takeover  
**Action**:
1. Switch to OAuth 2.0 or JWT tokens
2. Always use HTTPS
3. Move API keys to headers

### Insecure HTTP Protocol
**What it means**: API calls using HTTP instead of HTTPS  
**Risk**: Man-in-the-middle attacks, data interception  
**Action**: Upgrade all endpoints to HTTPS

### SQL Injection Risk
**What it means**: User input may allow SQL command injection  
**Risk**: Database breach, data exfiltration, data destruction  
**Action**: Use parameterized queries, ORM frameworks, or prepared statements

### Missing Authentication
**What it means**: Sensitive endpoint accessed without authentication  
**Risk**: Unauthorized access to data and functionality  
**Action**: Implement authentication (OAuth, JWT, API keys in headers)

### Unencrypted Sensitive Data
**What it means**: Passwords, secrets, or keys sent over HTTP  
**Risk**: Credential theft, system compromise  
**Action**: Always use HTTPS for sensitive data transmission

### Sensitive Data in Response Body
**What it means**: SSN, full credit card numbers, or private keys in API responses  
**Risk**: Data breach, regulatory violation (GDPR, PCI-DSS)  
**Action**: Mask sensitive data, use tokenization, implement data minimization

---

## 🟠 HIGH - Fix Within 24-48 Hours

### Sensitive Data in URL
**What it means**: PII (emails, SSN, credit cards) in URL path or query parameters  
**Risk**: Data leakage via logs, browser history, referrer headers  
**Action**: Move sensitive data to request body with POST/PUT

### XSS Risk
**What it means**: Potential script injection via user input  
**Risk**: Session hijacking, malware distribution  
**Action**: Sanitize all user input, use CSP headers, encode output

### Path Traversal Risk
**What it means**: File path manipulation attempts (../, %2e%2e)  
**Risk**: Unauthorized file access, server compromise  
**Action**: Validate file paths, use allowlists, chroot environments

### CORS Misconfiguration
**What it means**: Access-Control-Allow-Origin: * with credentials enabled  
**Risk**: Cross-origin attacks, credential theft  
**Action**: Specify exact origins, never use wildcard with credentials

### Mass Assignment
**What it means**: Privileged fields (isAdmin, role) in request body  
**Risk**: Privilege escalation, unauthorized access  
**Action**: Use input whitelists, validate field permissions

### Insecure Cookies
**What it means**: Cookies missing Secure, HttpOnly, or SameSite attributes  
**Risk**: Session hijacking, CSRF attacks  
**Action**: Set all three attributes on all cookies

### Open Redirect Risk
**What it means**: Unvalidated redirect URLs in parameters  
**Risk**: Phishing attacks, credential theft  
**Action**: Validate redirect URLs against allowlist

### SSRF Risk
**What it means**: User-controlled URLs in API parameters  
**Risk**: Internal network scanning, cloud metadata access, RCE  
**Action**: Validate URLs, use allowlists, disable internal network access

### Missing Input Validation
**What it means**: Dangerous user input without sanitization  
**Risk**: Injection attacks, data corruption  
**Action**: Validate and sanitize all user input server-side

---

## 🟡 MEDIUM - Fix Within 1 Week

### Missing Response Security Headers
**What it means**: Recommended security headers not present  
**Headers to add**:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'`
- `Referrer-Policy: strict-origin-when-cross-origin`

**Action**: Add these headers to all API responses

### Weak Password Policy
**What it means**: Password requirements too lenient (< 8 characters)  
**Risk**: Brute force attacks, account compromise  
**Action**: Enforce minimum 8 characters, complexity requirements

### Error Information Leakage
**What it means**: Stack traces or framework details in error responses  
**Risk**: Information disclosure aids attackers  
**Action**: Return generic error messages, log details server-side only

### Debug/Admin Endpoints
**What it means**: Access to debug/admin endpoints detected  
**Risk**: Information disclosure, unauthorized access  
**Action**: Disable in production or add strong authentication

---

## ℹ️ Understanding Location Tags

- **url**: Issue in URL path or query parameters
- **headers**: Issue in request headers
- **body**: Issue in request body
- **query**: Issue in query string parameters
- **response-headers**: Issue in response headers
- **response-body**: Issue in response body
- **protocol**: Issue with HTTP/HTTPS
- **path**: Issue in URL path structure
- **parameters**: Issue in any parameter (query or body)
- **general**: General security concern

---

## 🛠️ Developer Workflow

1. **New Alert Appears**: Review in Security panel
2. **Check Severity**: Critical/High = stop and fix now
3. **Read Details**: Click to see full vulnerability information
4. **Fix Root Cause**: Follow action items above
5. **Verify Fix**: Test endpoint again, alert should clear
6. **If False Positive**: Document and request exclusion

---

## 📊 Priority Matrix

| Severity | Response Time | Risk Level |
|----------|--------------|------------|
| Critical | Immediate | System compromise possible |
| High | 24-48 hours | Significant security risk |
| Medium | 1 week | Security best practice violation |
| Low | Next sprint | Informational/optimization |

---

## 🔍 Common False Positives

### "Missing Authentication" on public endpoints
- **Why**: Login, registration, health checks don't need auth
- **Fix**: Already excluded: /login, /register, /health, /status, /public

### "Sensitive Data in URL" for email in /users/user@example.com
- **Why**: Email as identifier, not as sensitive query param
- **Note**: Still a concern for logs/analytics - consider using user IDs

### "Debug Endpoints" on /swagger or /api-docs
- **Why**: API documentation endpoints
- **Note**: Should still be protected in production or disabled

---

**Last Updated**: October 18, 2025  
**For questions**: Contact Security Team
