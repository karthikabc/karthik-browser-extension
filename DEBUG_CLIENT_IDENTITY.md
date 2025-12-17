# Debugging: Untrusted Client Identity Warning Not Appearing

## Quick Checklist

If the warning is not showing up, check these in order:

### 1. ✅ Extension Reload
```
Click the "Reload Extension" button in the API Mapper panel
OR
Go to chrome://extensions → Find API Mapper → Click reload icon
```

### 2. ✅ Open Browser Console
Press `F12` → Console tab

Look for these debug messages:
```
[untrusted-client-identity] Auth header: Present
[untrusted-client-identity] Has JWT: true
[untrusted-client-identity] Request body keys: ["email", "pwd", "requestType"]
[untrusted-client-identity] Found identity fields: ["email"]
[untrusted-client-identity] ⚠️ CRITICAL ISSUE DETECTED!
```

### 3. ✅ Check Request Details

The warning requires ALL of these:
- ✅ Method is POST, PUT, or PATCH (not GET)
- ✅ Authorization header contains JWT token (starts with `eyJ` or `Bearer eyJ`)
- ✅ Request body contains identity field: `email`, `userId`, `user_id`, `username`, etc.
- ✅ Endpoint is NOT in exclusion list: `/login`, `/register`, `/signup`, `/auth`, `/forgot-password`, `/reset-password`, `/verify-email`

### 4. ✅ Your Specific Payload

```json
POST /api/some-endpoint
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "email": "gamtest.23@mockinbox.com",
  "pwd": "g2pBDB5nhPOJ|482eLUNRUGiPBLGncD0L2w==",
  "requestType": "registration"
}
```

**Should trigger because:**
- ✅ POST method
- ✅ Has Authorization header with JWT
- ✅ Has `email` field in body
- ⚠️ **UNLESS** the endpoint path contains `/register` (which would exclude it)

## Troubleshooting Steps

### Step 1: Check if endpoint is excluded

If your endpoint URL is like:
- `/api/register` → **EXCLUDED** (won't warn)
- `/api/user/registration` → **EXCLUDED** (contains "register")
- `/api/user/update` → **NOT EXCLUDED** (will warn)

**Solution:** If this is a registration endpoint, the exclusion is correct! This is expected behavior.

### Step 2: Verify JWT is in the right header

The analyzer checks these header names (case-insensitive):
- `Authorization`
- `authorization` 
- `AUTHORIZATION`
- `Auth`
- `auth`

**Debug:** Open DevTools Console, look for:
```
[untrusted-client-identity] Auth header: Missing
```

If you see "Missing", your JWT might be in a different header like `X-Auth-Token`.

**Solution:** Add your custom header to the check in `security-analyzer.js`:
```javascript
const authHeader = headers['Authorization'] || headers['authorization'] || 
                   headers['X-Auth-Token'] || headers['x-auth-token'];
```

### Step 3: Check if request body is parsed

**Debug:** Look for:
```
[untrusted-client-identity] No request body or not an object
```

This means the request body wasn't captured or parsed as JSON.

**Common causes:**
- Body is FormData (not JSON)
- Body is URL-encoded (not JSON)
- Request body capture failed

**Solution:** Ensure `Content-Type: application/json` header is set.

### Step 4: Verify the rule is enabled

Open `security-rules.json` and find:
```json
"untrusted-client-identity": {
  "enabled": true,  ← Must be true
  "severity": "critical",
  ...
}
```

### Step 5: Check console for errors

Look for errors like:
```
Error checking rule untrusted-client-identity: ...
```

This means the checker function crashed.

## Testing

### Option 1: Use the Test Page

1. Open `test-security-warnings.html` in Chrome
2. Open DevTools → API Mapper panel
3. Click "Run Test 1" or "Run Test 5"
4. Check for security warning in the panel

### Option 2: Manual cURL Test

```bash
# This should trigger the warning
curl -X POST https://jsonplaceholder.typicode.com/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test" \
  -d '{"email":"test@example.com","name":"Test"}'
```

Then check the API Mapper panel.

## Expected Console Output

When the check works correctly, you should see:

```
[untrusted-client-identity] Auth header: Present
[untrusted-client-identity] Has JWT: true
[untrusted-client-identity] Request body keys: ["email", "pwd", "requestType"]
[untrusted-client-identity] Found identity fields: ["email"]
[untrusted-client-identity] ⚠️ CRITICAL ISSUE DETECTED! [{
  message: "Identity field in request body when JWT present - extract from token instead",
  details: {
    fields: ["email"],
    recommendation: "Extract user identity (email, userId) from JWT claims on server-side...",
    impact: "Account takeover, privilege escalation, unauthorized access",
    cwe: "CWE-639: Authorization Bypass Through User-Controlled Key"
  },
  location: "body"
}]
```

## If Still Not Working

### Collect Debug Info

1. Open DevTools Console
2. Run your request
3. Copy all `[untrusted-client-identity]` log messages
4. Share the output along with:
   - Full request URL
   - Authorization header value (first 20 chars)
   - Request body
   - Request method (POST/PUT/etc)

### Temporary Enhanced Logging

Add this to the top of `checkUntrustedClientIdentity` function:

```javascript
console.log('=== UNTRUSTED CLIENT IDENTITY CHECK ===');
console.log('URL:', context.url);
console.log('Method:', context.method);
console.log('Headers:', Object.keys(context.headers));
console.log('Body:', context.requestBody);
console.log('Rule enabled:', rule?.enabled);
```

## Quick Fix: Force Enable Debug Mode

Edit `security-analyzer.js`, find the `checkUntrustedClientIdentity` function and uncomment all `console.log` lines. Reload extension and retry.

---

**Last Updated**: October 18, 2025  
**Status**: Enhanced with debug logging
