# Request & Response Viewer - Quick Start

## What's New? 🎉

Your API Mapper extension can now show you **complete request and response details** for every API call!

## Quick Visual Guide

### Before
```
Recent Calls
└── Call 1
    ├── Time: 10:30:45 AM
    ├── Status: 200
    └── [Copy cURL button]
```

### After (NEW!)
```
Recent Calls
└── Call 1
    ├── Time: 10:30:45 AM
    ├── Status: 200
    │
    ├── 📤 Request Details (click to expand)
    │   ├── Query Parameters
    │   │   {
    │   │     "userId": "12345",
    │   │     "format": "json"
    │   │   }
    │   │
    │   ├── Request Headers
    │   │   {
    │   │     "Content-Type": "application/json",
    │   │     "Authorization": "Bearer ***REDACTED***",
    │   │     "X-API-Key": "***REDACTED***"
    │   │   }
    │   │
    │   └── Request Body
    │       {
    │         "email": "***REDACTED***",
    │         "name": "John Doe"
    │       }
    │
    ├── 📥 Response Details (click to expand)
    │   ├── Status: 200 OK
    │   │
    │   └── Response Headers
    │       {
    │         "content-type": "application/json",
    │         "x-rate-limit-remaining": "98",
    │         "cache-control": "no-cache"
    │       }
    │
    └── 📋 Copy cURL
```

## How to Use (3 Easy Steps)

### Step 1: Click an Endpoint
In the left panel, click any API endpoint (e.g., "GET /api/users")

### Step 2: Scroll to "Recent Calls"
Scroll down in the right panel to the "Recent Calls" section

### Step 3: Expand Details
- Click **"📤 Request Details"** to see what was sent
- Click **"📥 Response Details"** to see what was received

## What You Can See

### 📤 Request Details

| Section | What It Shows | Example |
|---------|---------------|---------|
| **Query Parameters** | URL query string params | `?userId=123&format=json` |
| **Request Headers** | All HTTP headers sent | Authorization, Content-Type, etc. |
| **Request Body** | JSON payload sent | User data, form data, etc. |

### 📥 Response Details

| Section | What It Shows | Example |
|---------|---------------|---------|
| **Status** | HTTP status code | 200 OK, 404 Not Found, etc. |
| **Response Headers** | All HTTP headers received | Cache-Control, Content-Type, etc. |
| **Response Body** | ⚠️ Not available* | See note below |

*Response bodies cannot be captured by Chrome extensions due to security restrictions. Use Chrome DevTools Network tab instead.

## Real-World Examples

### Example 1: Debugging Authentication
**Problem**: Login API not working

**Solution**: Expand Request Details → Check Authorization header
```json
"Authorization": "Bearer ***REDACTED***"  ✅ Present
```
or
```json
// No Authorization header found  ❌ Missing!
```

### Example 2: API Rate Limiting
**Problem**: Getting rate limit errors

**Solution**: Expand Response Details → Check rate limit headers
```json
"x-rate-limit-remaining": "0",  ⚠️ Rate limit hit!
"x-rate-limit-reset": "1634567890"
```

### Example 3: Content Type Issues
**Problem**: API returning HTML instead of JSON

**Solution**: Expand Response Details → Check Content-Type
```json
"content-type": "text/html"  ❌ Should be "application/json"
```

## Security Features 🔒

All sensitive data is automatically hidden:
- ✅ Passwords → `***REDACTED***`
- ✅ Tokens → `***REDACTED***`
- ✅ API Keys → `***REDACTED***`
- ✅ Credit Cards → `***REDACTED***`
- ✅ SSN → `***REDACTED***`

## Pro Tips 💡

### Tip 1: Copy as cURL
Click "📋 Copy cURL" to get a complete cURL command with all headers and body data. Perfect for:
- Testing in terminal
- Sharing with teammates
- Reproducing issues

### Tip 2: Compare Calls
Open multiple recent calls to compare:
- Header differences
- Payload changes
- Status code variations

### Tip 3: Security Scanning
Combined with the security scanner, you can:
1. See which endpoints have issues (red badges)
2. Expand details to see the vulnerable data
3. Check request/response to understand the flow

## Troubleshooting

### Q: I don't see Request Body
**A**: Request body only appears if:
- The request had a body (POST, PUT, PATCH)
- The body was JSON format
- The body was successfully parsed

### Q: Response Headers are empty
**A**: Make sure you've reloaded the extension after updating to version 2.0.0

### Q: Details won't expand
**A**: Try:
1. Reload the page
2. Clear all data and capture new calls
3. Check browser console for errors

## Next Steps

1. ✅ **Reload your extension** in `chrome://extensions`
2. ✅ **Open DevTools** on a website with API calls
3. ✅ **Navigate to the API Mapper tab**
4. ✅ **Click an endpoint** and scroll to "Recent Calls"
5. ✅ **Expand Request/Response details** and explore!

---

## Summary: What Changed?

| Feature | Before | After |
|---------|--------|-------|
| Request visibility | Only method & URL | Full headers, body, params |
| Response visibility | Status code only | Status + all headers |
| Data format | Plain text | Formatted JSON |
| UI | Flat list | Expandable sections with emojis |
| cURL export | Basic | Complete with all headers |

**Enjoy your enhanced API debugging experience! 🚀**
