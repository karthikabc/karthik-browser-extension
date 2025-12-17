# Raw HTTP Request/Response Viewer

## Overview
The API Mapper now displays complete raw HTTP requests and responses in a side-by-side view, making it easy to see exactly what's being sent and received.

## Features

### 📄 View Raw HTTP Data
Click the **"📄 View Raw"** button on any API call to see:
- Complete HTTP request (request line, headers, body)
- Complete HTTP response (status line, headers, limitation note)
- Side-by-side comparison layout
- Properly formatted raw HTTP protocol text

### 📋 Copy Raw Data
Each column has its own copy button:
- **Copy Request** - Copy the complete raw HTTP request to clipboard
- **Copy Response** - Copy the complete raw HTTP response to clipboard

### 🎨 Space-Efficient Layout
- **Side-by-side view** - Request on left, response on right
- **Scrollable** - Long requests/responses are scrollable within their column
- **Collapsible** - Click "🔼 Hide Raw" to collapse and save space
- **Color-coded** - Request (yellow), Response (blue) for easy identification

## What You See

### Request Column (📤 LEFT - Yellow)
```
GET /api/users?page=1&limit=10 HTTP/1.1
Host: api.example.com
Accept: application/json
Authorization: Bearer ***REDACTED***
Content-Type: application/json
User-Agent: Mozilla/5.0...
X-API-Key: ***REDACTED***

{
  "filter": "active",
  "sort": "name"
}
```

### Response Column (📥 RIGHT - Blue)
```
HTTP/1.1 200 OK
content-type: application/json
cache-control: no-cache, no-store
x-rate-limit-remaining: 99
x-ratelimit-reset: 1634567890
content-length: 1234

⚠️ Response body cannot be captured by Chrome extensions.
Use Chrome DevTools Network tab to view response bodies.

Reason: Browser security policy prevents extensions from
accessing response body content to protect user privacy.
```

## How to Use

### Step 1: Find an API Call
Navigate to any endpoint in the left panel and scroll to "Recent Calls"

### Step 2: Click "View Raw"
Click the **"📄 View Raw"** button on the call you want to inspect

### Step 3: View Both Sides
- **Left side** shows the complete HTTP request
- **Right side** shows HTTP response headers and status

### Step 4: Copy What You Need
- Click **"📋 Copy Request"** to copy the full request
- Click **"📋 Copy Response"** to copy the response headers
- Perfect for documentation, debugging, or sharing with team

### Step 5: Hide When Done
Click **"🔼 Hide Raw"** to collapse and see other calls

## Use Cases

### 1. **Debugging API Issues**
See exactly what headers and body are sent:
```
POST /api/login HTTP/1.1
Host: auth.example.com
Content-Type: application/json

{
  "username": "***REDACTED***",
  "password": "***REDACTED***"
}
```

### 2. **Testing API Calls**
Copy the raw request and modify it for testing:
```bash
# Copy from extension, paste into terminal, modify as needed
curl -X POST https://api.example.com/users \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe"}'
```

### 3. **Documentation**
Copy raw HTTP for API documentation:
```
Example Request:
GET /api/products?category=electronics&sort=price HTTP/1.1
Host: api.shop.com
Authorization: Bearer token123
```

### 4. **Security Analysis**
Review what sensitive data is being sent:
```
Request Headers:
Authorization: Bearer ***REDACTED***
X-API-Key: ***REDACTED***
Cookie: session=***REDACTED***
```

### 5. **Performance Investigation**
Check response headers for caching and optimization:
```
Response Headers:
cache-control: max-age=3600, public
etag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
x-response-time: 45ms
```

## Layout Details

### Side-by-Side View
```
┌─────────────────────────────────────────────────────────────┐
│ Time: 10:30:45 AM  Status: 200    [📄 View Raw] [📋 cURL]  │
├─────────────────────────────────────────────────────────────┤
│  📤 REQUEST                │  📥 RESPONSE                    │
├────────────────────────────┼────────────────────────────────┤
│                            │                                 │
│ GET /api/users HTTP/1.1    │ HTTP/1.1 200 OK                │
│ Host: api.example.com      │ content-type: application/json │
│ Accept: application/json   │ cache-control: no-cache        │
│ Authorization: Bearer ...  │ x-rate-limit-remaining: 99     │
│                            │                                 │
│ {                          │ ⚠️ Response body cannot be     │
│   "filter": "active"       │ captured by extensions.        │
│ }                          │                                 │
│                            │                                 │
│ [📋 Copy Request]          │ [📋 Copy Response]             │
└────────────────────────────┴────────────────────────────────┘
```

### Responsive Design
On narrow screens, columns stack vertically:
```
┌─────────────────────────────┐
│  📤 REQUEST                 │
│  GET /api/users HTTP/1.1    │
│  ...                        │
│  [📋 Copy Request]          │
├─────────────────────────────┤
│  📥 RESPONSE                │
│  HTTP/1.1 200 OK            │
│  ...                        │
│  [📋 Copy Response]         │
└─────────────────────────────┘
```

## Technical Details

### Request Format
```
{METHOD} {PATH}{QUERY_STRING} HTTP/1.1
Host: {hostname}
{Header-Name}: {header-value}
...

{request-body-json}
```

### Response Format
```
HTTP/1.1 {STATUS_CODE} {STATUS_TEXT}
{header-name}: {header-value}
...

⚠️ Response body limitation note
```

### Headers Included
**Request Headers:**
- All standard headers (Accept, User-Agent, etc.)
- Authorization headers (redacted values)
- Custom X-* headers
- Content-Type and Content-Length
- Cookies (redacted values)

**Response Headers:**
- All headers returned by server
- Cache-Control directives
- Rate limiting headers
- Custom headers
- Content-Type and Length

### Security Redaction
Sensitive values are automatically hidden:
- `Authorization: Bearer ***REDACTED***`
- `X-API-Key: ***REDACTED***`
- `Cookie: session=***REDACTED***`
- `password: "***REDACTED***"`

## Advantages Over DevTools

### ✅ Persistent Across Pages
- DevTools Network tab clears on navigation
- API Mapper keeps history

### ✅ Grouped by Endpoint
- See all calls to same endpoint together
- Compare different requests easily

### ✅ Security Analysis
- Integrated vulnerability detection
- Highlights security issues

### ✅ Easy Export
- One-click copy to clipboard
- Generate cURL commands
- Export to OpenAPI spec

## Limitations

### ⚠️ Response Body Not Available
Chrome extensions **cannot** capture response bodies due to browser security policies.

**Why?**
- Protects user privacy
- Prevents malicious extensions from stealing data
- Browser-level security restriction

**Workaround:**
Use Chrome DevTools Network tab to view response bodies:
1. Press F12 to open DevTools
2. Go to Network tab
3. Click on the request
4. View Response tab

### ⚠️ Binary Data Not Supported
Only text-based requests/responses are displayed properly. Binary data (images, files) may not display correctly.

## Keyboard Shortcuts

- **Ctrl+F** (in raw view) - Search within request/response
- **Ctrl+A** (in raw view) - Select all text
- **Ctrl+C** - Copy selected text

## Tips & Tricks

### Tip 1: Compare Multiple Calls
Open multiple "View Raw" sections to compare:
- Different request parameters
- Header changes
- Status code variations

### Tip 2: Quick Copy-Paste Testing
1. Copy raw request
2. Paste into Postman or curl
3. Modify and test
4. Compare results

### Tip 3: Documentation Screenshots
- Expand raw view
- Take screenshot
- Perfect for documentation

### Tip 4: Security Review
- Review all headers sent
- Check for sensitive data leaks
- Verify authentication headers

## Troubleshooting

### Q: Raw view is empty
**A:** Make sure:
- Extension is loaded (version 2.0.1+)
- You've captured new calls after update
- Headers were captured (check browser console)

### Q: Request body not showing
**A:** Body only shows for:
- POST, PUT, PATCH requests
- JSON content-type
- Successfully parsed body

### Q: Can't see full request
**A:** The raw view is scrollable:
- Scroll horizontally for long lines
- Scroll vertically for many lines
- Max height is 600px per column

### Q: Copy button not working
**A:** Check:
- Browser clipboard permissions
- Try clicking directly on the button
- Check browser console for errors

## Changelog

### Version 2.0.1 - Raw HTTP Viewer
- ✅ Added side-by-side raw HTTP view
- ✅ Complete request display (line, headers, body)
- ✅ Response headers display with status
- ✅ Individual copy buttons for request/response
- ✅ Collapsible view to save space
- ✅ Color-coded columns (yellow/blue)
- ✅ Responsive layout for narrow screens
- ✅ Scrollable content for long requests
- ✅ Space-efficient design

---

**See your API calls exactly as they are sent! 🚀**
