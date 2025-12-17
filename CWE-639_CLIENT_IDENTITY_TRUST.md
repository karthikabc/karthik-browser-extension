# CWE-639: Authorization Bypass Through User-Controlled Key

## Vulnerability Overview

**Severity**: 🔴 **CRITICAL**  
**CWE ID**: CWE-639  
**OWASP**: A01:2021 - Broken Access Control  
**CVSS Score**: 9.1 (Critical)

## Description

This vulnerability occurs when an application trusts client-supplied identity information (email, userId, username) in the request body instead of extracting it from a verified authentication token (JWT, session cookie).

An attacker can simply change the identity field in the request to impersonate any user in the system.

---

## Real-World Example from Your Application

### Vulnerable Request Detected ❌

```http
POST /api/user/update HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "email": "gamtest.23@mockinbox.com",
  "pwd": "g2pBDB5nhPOJ|482eLUNRUGiPBLGncD0L2w==",
  "requestType": "registration"
}
```

### The Problem

1. **JWT is present** in the Authorization header (user is authenticated)
2. **Email is in request body** (client-supplied, not trusted)
3. **Server likely uses** `req.body.email` instead of `jwt.claims.email`

### Attack Scenario

```http
POST /api/user/update HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "email": "admin@company.com",  ← Attacker changes this
  "newPassword": "hacked123"
}
```

**Result**: Attacker's JWT authenticates the request, but the email in the body identifies the victim. The server changes the admin's password instead of the attacker's.

---

## Impact

| Impact Area | Severity | Description |
|-------------|----------|-------------|
| **Account Takeover** | Critical | Attacker can modify/access any user's account |
| **Privilege Escalation** | Critical | Change regular user to admin by modifying role |
| **Data Breach** | Critical | Access sensitive data of other users |
| **Regulatory Violation** | High | GDPR, HIPAA violations from unauthorized access |
| **Financial Loss** | High | Unauthorized transactions, fraudulent activities |

---

## Technical Details

### How Authentication Should Work

```
Client Request → Server
                  ↓
             Verify JWT
                  ↓
          Extract Claims (email, userId, role)
                  ↓
          Use JWT claims for authorization
                  ↓
          IGNORE client-supplied identity fields
```

### Vulnerable Code Pattern

```javascript
// ❌ VULNERABLE - Trusts client-supplied email
app.post('/api/update-profile', authenticateJWT, async (req, res) => {
  const { email, name, phone } = req.body;  // ← DANGER!
  
  // Attacker can change email to victim's email
  await User.update({ name, phone }, { 
    where: { email }  // ← Uses untrusted email from body
  });
});
```

### Secure Code Pattern

```javascript
// ✅ SECURE - Uses JWT-verified identity
app.post('/api/update-profile', authenticateJWT, async (req, res) => {
  const userEmail = req.user.email;  // ← From verified JWT
  const { name, phone } = req.body;  // Only non-identity fields
  
  // User can only update their own profile
  await User.update({ name, phone }, { 
    where: { email: userEmail }  // ← Uses JWT-derived email
  });
});
```

---

## Detection Logic

The security analyzer detects this vulnerability when:

1. ✅ JWT/Bearer token is present in Authorization header
2. ✅ Identity field (email, userId, username, etc.) found in request body
3. ✅ Endpoint is NOT in exclusion list (login, register, etc.)

### Excluded Endpoints (False Positives)

These endpoints legitimately need identity in request body:
- `/login` - User provides email/username to authenticate
- `/register` - New user provides email
- `/forgot-password` - User provides email to reset
- `/verify-email` - Email verification flows

---

## Remediation Steps

### Step 1: Identify All Vulnerable Endpoints

Search your codebase for patterns like:
```javascript
req.body.email
req.body.userId
req.body.username
req.body.accountId
```

### Step 2: Extract Identity from JWT

```javascript
// Middleware that decodes JWT and adds to req.user
function authenticateJWT(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;  // ← Contains email, userId, role, etc.
    next();
  });
}
```

### Step 3: Use JWT Claims for Authorization

```javascript
// BEFORE (vulnerable)
const email = req.body.email;
const user = await User.findOne({ where: { email } });

// AFTER (secure)
const email = req.user.email;  // From JWT
const user = await User.findOne({ where: { email } });
```

### Step 4: Validate Resource Ownership

```javascript
// Check that user owns the resource they're trying to access
app.put('/api/orders/:orderId', authenticateJWT, async (req, res) => {
  const orderId = req.params.orderId;
  const userId = req.user.id;  // From JWT
  
  const order = await Order.findOne({ 
    where: { id: orderId, userId }  // ← Ensures user owns this order
  });
  
  if (!order) {
    return res.status(403).json({ error: 'Not authorized' });
  }
  
  // Proceed with update...
});
```

---

## Testing for This Vulnerability

### Manual Testing

1. **Authenticate** as User A (get JWT token)
2. **Send request** with User A's JWT but User B's email in body
3. **Check** if the operation affects User B's account

Example with curl:
```bash
# Get token as user A
TOKEN=$(curl -X POST https://api.example.com/login \
  -H "Content-Type: application/json" \
  -d '{"email":"usera@example.com","password":"pass123"}' \
  | jq -r '.token')

# Try to modify user B's account using user A's token
curl -X POST https://api.example.com/update-profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"userb@example.com","phone":"555-0000"}'

# If User B's phone changes, you have the vulnerability
```

### Automated Testing

```javascript
describe('Authorization Tests', () => {
  it('should prevent user from modifying another user account', async () => {
    const userAToken = await authenticate('usera@example.com', 'pass123');
    
    const response = await request(app)
      .post('/api/update-profile')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        email: 'userb@example.com',  // Try to access user B
        phone: '555-0000'
      });
    
    expect(response.status).toBe(403);  // Should be forbidden
  });
});
```

---

## Related CWEs and OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **CWE-566**: Authorization Bypass Through User-Controlled SQL Primary Key
- **CWE-285**: Improper Authorization
- **OWASP A01:2021**: Broken Access Control
- **OWASP API1:2023**: Broken Object Level Authorization (BOLA)

---

## Real-World Incidents

### Peloton (2021)
- Users could access other users' private account information
- Changed user ID in API request to view others' data
- **Impact**: Exposed data of millions of users

### Venmo (2018)
- Transaction privacy settings could be changed for other users
- Modified userId in request to change others' privacy settings
- **Impact**: Privacy breach, regulatory fine

### Facebook (2019)
- Instagram bug allowed viewing private profiles
- Changed user ID in API request
- **Impact**: Privacy violation affecting millions

---

## Prevention Checklist

- [ ] All authenticated endpoints extract identity from JWT/session
- [ ] Identity fields (email, userId) removed from request body schemas
- [ ] Resource ownership validated before any operation
- [ ] Unit tests verify users cannot access others' resources
- [ ] API gateway enforces identity extraction from tokens
- [ ] Code review checklist includes this vulnerability
- [ ] Security training covers this issue for all developers

---

## Additional Resources

- [OWASP Top 10 - A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639 Details](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP API Security - BOLA](https://owasp.org/www-project-api-security/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

**Document Version**: 1.0  
**Last Updated**: October 18, 2025  
**Severity**: CRITICAL - Fix Immediately
