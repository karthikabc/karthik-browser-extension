# Encrypted Credentials Detection

## Overview
The security analyzer now intelligently detects encrypted and hashed credentials, preventing false positives when credentials are properly encrypted before transmission.

## What Changed

### Before
The analyzer would flag **any** field named "password", "username", "credential", etc. in the request body, even if the values were encrypted.

**Example False Positive:**
```json
{
  "username": "BMhAHGf1lQkmcabqwSpTnH+5M9vBQA==|+NmQc31J3kCJQWa0RtXBng==",
  "password": "IdZMA2rdzVBi|Qhk9eJunvTlOVP/ZnwNZPw==",
  "client_id": "ciampublicclient_gamx_qbZ6I5YMsC18vZlkL4Bg"
}
```
❌ **Would be flagged:** "Weak Authentication - Credentials in request body without proper encryption"

### After
The analyzer now checks if the credential values are encrypted before flagging them.

**Same Example - Now Properly Handled:**
```json
{
  "username": "BMhAHGf1lQkmcabqwSpTnH+5M9vBQA==|+NmQc31J3kCJQWa0RtXBng==",
  "password": "IdZMA2rdzVBi|Qhk9eJunvTlOVP/ZnwNZPw==",
  "client_id": "ciampublicclient_gamx_qbZ6I5YMsC18vZlkL4Bg"
}
```
✅ **Not flagged:** Values detected as encrypted (base64 with separator pattern)

## Encryption Detection Patterns

The analyzer recognizes these common encryption/hashing patterns:

### 1. **Encrypted Data with Separator** ✅
Pattern: `encrypted_data|initialization_vector` or `data==|salt==`
```
"BMhAHGf1lQkmcabqwSpTnH+5M9vBQA==|+NmQc31J3kCJQWa0RtXBng=="
"IdZMA2rdzVBi|Qhk9eJunvTlOVP/ZnwNZPw=="
```

### 2. **Base64 Encoded Strings** (32+ characters) ✅
```
"U2FsdGVkX1/R7p8pK5YqZ0X8pK5YqZ0="
"QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVz"
```

### 3. **Hexadecimal Hashes** (64+ characters) ✅
SHA-256 and similar:
```
"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
```

### 4. **JWT Tokens** ✅
```
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
```

### 5. **BCrypt Hashes** ✅
```
"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
"$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
```

### 6. **Salted Password Hashes** ✅
```
"$pbkdf2-sha256$29000$3RkDAKBQYgxBiDGGMOYc4w$B12IKTA5RA0Xz.nN3lfNvz1c"
"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj"
```

### 7. **Long Alphanumeric Strings** (40+ characters) ✅
AES encrypted, custom encryption:
```
"7d8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f"
```

## When Credentials ARE Flagged

The analyzer will still flag credentials that appear to be **plaintext**:

### ❌ Plaintext Password
```json
{
  "username": "john.doe@example.com",
  "password": "MyPassword123!"
}
```
**Flagged as:** Weak Authentication

### ❌ Short or Simple Values
```json
{
  "username": "admin",
  "password": "12345"
}
```
**Flagged as:** Weak Authentication

### ❌ Readable Text
```json
{
  "username": "testuser",
  "password": "password"
}
```
**Flagged as:** Weak Authentication

## Best Practices

### ✅ DO: Encrypt Credentials Client-Side
```javascript
// Encrypt password before sending
const encryptedPassword = await encryptPassword(plainPassword);

fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({
    username: encryptedUsername,
    password: encryptedPassword
  })
});
```

### ✅ DO: Use HTTPS
Always use HTTPS to encrypt the entire transmission:
```
https://api.example.com/login  ✅
http://api.example.com/login   ❌
```

### ✅ DO: Use Token-Based Auth
After initial login, use tokens:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "7d8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b..."
}
```

### ❌ DON'T: Send Plaintext Credentials
```json
{
  "username": "john@example.com",  // ❌ Plaintext
  "password": "MySecretPass123"     // ❌ Plaintext
}
```

### ❌ DON'T: Use Weak Encoding
Base64 alone is NOT encryption:
```json
{
  "password": "TXlQYXNzd29yZDEyMw=="  // ❌ Just base64, not encrypted
}
```

## Technical Details

### Detection Algorithm
```javascript
isEncryptedOrHashed(value) {
  // 1. Check for encryption separator pattern
  if (/^[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$/.test(value)) return true;
  
  // 2. Check for long base64 strings (32+ chars)
  if (value.length >= 32 && /^[A-Za-z0-9+/=]+$/.test(value)) return true;
  
  // 3. Check for hex hashes (64+ chars)
  if (value.length >= 64 && /^[a-fA-F0-9]+$/.test(value)) return true;
  
  // 4. Check for JWT tokens
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) return true;
  
  // 5. Check for bcrypt/password hashes
  if (/^\$\w+\$/.test(value)) return true;
  
  // 6. Check for very long alphanumeric (40+ chars)
  if (value.length >= 40 && /^[A-Za-z0-9+/=_-]+$/.test(value)) return true;
  
  return false;
}
```

### Integration
The check is automatically applied in the `checkWeakAuthentication` function:

```javascript
// Get credential fields with their values
const foundFieldsWithValues = this.findFieldsInObject(requestBody, check.fields, true);

// Filter out encrypted fields
const unencryptedFields = foundFieldsWithValues.filter(item => {
  return !this.isEncryptedOrHashed(item.value);
});

// Only report unencrypted credentials
if (unencryptedFields.length > 0) {
  issues.push({
    message: check.message,
    details: { fields: unencryptedFields.map(item => item.path) }
  });
}
```

## Testing

### Test Case 1: Encrypted Credentials (Should NOT Flag)
```json
POST /api/login
{
  "username": "BMhAHGf1lQkmcabqwSpTnH+5M9vBQA==|+NmQc31J3kCJQWa0RtXBng==",
  "password": "IdZMA2rdzVBi|Qhk9eJunvTlOVP/ZnwNZPw=="
}
```
✅ Result: No vulnerability reported

### Test Case 2: Plaintext Credentials (Should Flag)
```json
POST /api/login
{
  "username": "john.doe@example.com",
  "password": "MyPassword123"
}
```
❌ Result: Weak Authentication vulnerability reported

### Test Case 3: JWT Token (Should NOT Flag)
```json
POST /api/refresh
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}
```
✅ Result: No vulnerability reported

### Test Case 4: Hash in Password Field (Should NOT Flag)
```json
POST /api/register
{
  "email": "user@example.com",
  "password": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
}
```
✅ Result: No vulnerability reported

## Changelog

### Version 2.0.1 - Encrypted Credentials Detection
- ✅ Added `isEncryptedOrHashed()` helper function
- ✅ Updated `findFieldsInObject()` to optionally return values
- ✅ Modified `checkWeakAuthentication()` to verify encryption
- ✅ Reduced false positives for properly encrypted credentials
- ✅ Support for 7+ common encryption/hashing patterns

## Support

If you're still seeing false positives with your encryption format:
1. Check the console for detection details
2. Verify your encryption produces patterns matching the detection rules
3. File an issue with an example of your encryption format
4. Consider adding a custom pattern to the `isEncryptedOrHashed()` function

---

**Secure by Default, Smart by Design! 🔒**
