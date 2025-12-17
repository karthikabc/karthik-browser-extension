# Testing Encrypted Credentials Detection

## Quick Test

### Your Specific Case ✅

**Request Body:**
```json
{
  "username": "BMhAHGf1lQkmcabqwSpTnH+5M9vBQA==|+NmQc31J3kCJQWa0RtXBng==",
  "password": "IdZMA2rdzVBi|Qhk9eJunvTlOVP/ZnwNZPw==",
  "client_id": "ciampublicclient_gamx_qbZ6I5YMsC18vZlkL4Bg"
}
```

**Expected Result:**
- ✅ Should **NOT** show "Weak Authentication" warning
- ✅ Values detected as encrypted (base64 with `|` separator pattern)
- ✅ Only `client_id` might be flagged if it contains sensitive data (separate check)

## How to Test

### 1. Reload the Extension
```
1. Go to chrome://extensions
2. Find "API Mapper - Security Edition"
3. Click reload button
4. Version should show "2.0.1"
```

### 2. Clear Old Data
```
1. Open DevTools (F12)
2. Go to API Mapper tab
3. Click "Clear All Data"
```

### 3. Make API Call
```
1. Navigate to your site with the login endpoint
2. Perform login with encrypted credentials
3. Check the endpoint in API Mapper
```

### 4. Verify Results
```
1. Click on the login endpoint
2. Scroll to "Security Issues" section
3. Should NOT see "Weak Authentication" for encrypted credentials
4. If it still appears, check details to see which fields are flagged
```

## Test Cases

### ✅ Should NOT Flag (Encrypted)

#### Case 1: Your Format (Encrypted | IV)
```json
{
  "password": "IdZMA2rdzVBi|Qhk9eJunvTlOVP/ZnwNZPw=="
}
```
Pattern: `base64|base64` ✅ Detected as encrypted

#### Case 2: Long Base64
```json
{
  "password": "U2FsdGVkX1/R7p8pK5YqZ0X8pK5YqZ0X8pK5YqZ0="
}
```
32+ chars, base64 ✅ Detected as encrypted

#### Case 3: Hex Hash
```json
{
  "password": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
}
```
64+ chars, hex ✅ Detected as hash

#### Case 4: JWT
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
}
```
JWT format ✅ Detected as token

#### Case 5: BCrypt
```json
{
  "password": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
}
```
BCrypt format ✅ Detected as hash

### ❌ Should Flag (Plaintext)

#### Case 1: Plaintext Password
```json
{
  "password": "MyPassword123"
}
```
❌ Should be flagged

#### Case 2: Short String
```json
{
  "password": "12345"
}
```
❌ Should be flagged

#### Case 3: Email as Password
```json
{
  "username": "john.doe@example.com",
  "password": "john.doe@example.com"
}
```
❌ Should be flagged

## Debugging

### Check Detection in Console

Open browser console and test the detection function:

```javascript
// Test your specific values
const analyzer = new SecurityAnalyzer();

// Test encrypted password (should return true)
console.log(analyzer.isEncryptedOrHashed("IdZMA2rdzVBi|Qhk9eJunvTlOVP/ZnwNZPw=="));
// Expected: true

// Test plaintext (should return false)
console.log(analyzer.isEncryptedOrHashed("MyPassword123"));
// Expected: false

// Test long base64 (should return true)
console.log(analyzer.isEncryptedOrHashed("U2FsdGVkX1/R7p8pK5YqZ0X8pK5YqZ0X8pK5YqZ0="));
// Expected: true
```

### Check Rule Status

```javascript
// Check if weak-authentication rule is enabled
chrome.storage.local.get('securityRules', (result) => {
  console.log('Weak Auth Rule:', result.securityRules?.['weak-authentication']);
});
```

## Troubleshooting

### Still Seeing False Positive?

1. **Check Extension Version**
   - Should be 2.0.1
   - Reload extension if not

2. **Verify Pattern**
   - Your password format: `base64==|base64==`
   - Regex: `/^[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$/`
   - Test in console

3. **Check Console Errors**
   - Open browser console
   - Look for any JavaScript errors
   - Check if SecurityAnalyzer loaded

4. **Clear Cache**
   - Clear all data
   - Hard refresh (Ctrl+Shift+R)
   - Make new API call

### Custom Encryption Format?

If your encryption uses a different format:

1. Open `security-analyzer.js`
2. Find `isEncryptedOrHashed()` function
3. Add your custom pattern:

```javascript
// 8. Your custom encryption format
if (/your-regex-pattern/.test(value)) {
  return true;
}
```

## Success Criteria

✅ **Fix is working if:**
1. Encrypted passwords NOT flagged
2. Plaintext passwords STILL flagged
3. Other security checks still work
4. No console errors
5. Version shows 2.0.1

## Example Output

### Before Fix (2.0.0)
```
Endpoint: POST /api/login
❌ Security Issues (1)
   ├── Weak Authentication
   │   Message: Credentials in request body without proper encryption
   │   Location: body
   │   Fields: password, username
```

### After Fix (2.0.1)
```
Endpoint: POST /api/login
✅ No security issues detected
```

Or if truly plaintext:
```
Endpoint: POST /api/login
❌ Security Issues (1)
   ├── Weak Authentication
   │   Message: Credentials in request body without proper encryption
   │   Location: body
   │   Fields: password (plaintext detected)
```

## Report Issues

If the fix doesn't work:
1. Note the exact password format
2. Check browser console for errors
3. Take screenshot of the security issue
4. Provide example encrypted value (if safe)
5. Report with details

---

**Your credentials should now be properly recognized as encrypted! 🔒✅**
