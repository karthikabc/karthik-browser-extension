# API Request & Response Viewer

## Overview
The API Mapper extension now captures and displays complete request and response details for each API call, allowing you to inspect all aspects of HTTP communication.

## Features Added

### 📤 Request Details
For each API call, you can now view:

1. **Query Parameters** - Full query string parameters with values
2. **Request Headers** - Complete list of all headers sent with the request
3. **Request Body** - Full JSON request payload (when available)

### 📥 Response Details
For each API call, you can now view:

1. **Response Status** - HTTP status code and status line
2. **Response Headers** - Complete list of all headers returned by the server
3. **Response Body** - ⚠️ *Not available due to Chrome extension security restrictions*

## How to Use

### Viewing Request/Response Data

1. **Navigate to an endpoint** - Click on any endpoint in the left panel
2. **Scroll to "Recent Calls"** section at the bottom of the details panel
3. **Expand Request Details** - Click on "📤 Request Details" to see:
   - Query parameters in formatted JSON
   - All request headers (including custom headers)
   - Complete request body
4. **Expand Response Details** - Click on "📥 Response Details" to see:
   - HTTP status code
   - All response headers
   - Information about response body limitations

### Example Use Cases

#### 1. **Debugging Authentication Issues**
```
📤 Request Details
  → Request Headers
    - Authorization: Bearer ***REDACTED***
    - X-API-Key: ***REDACTED***
    - Content-Type: application/json
```

#### 2. **Analyzing Query Parameters**
```
📤 Request Details
  → Query Parameters
    {
      "userId": "12345",
      "includeDetails": "true",
      "format": "json"
    }
```

#### 3. **Inspecting Request Payloads**
```
📤 Request Details
  → Request Body
    {
      "email": "***REDACTED***",
      "password": "***REDACTED***",
      "rememberMe": true
    }
```

#### 4. **Checking Response Headers**
```
📥 Response Details
  → Status: 200 OK
  → Response Headers
    {
      "content-type": "application/json",
      "x-rate-limit-remaining": "98",
      "cache-control": "no-cache"
    }
```

## Security Features

### 🔒 Automatic Data Sanitization
Sensitive data is automatically redacted:
- **Passwords** - Replaced with `***REDACTED***`
- **Tokens** - Replaced with `***REDACTED***`
- **API Keys** - Replaced with `***REDACTED***`
- **Credit Cards** - Replaced with `***REDACTED***`
- **Social Security Numbers** - Replaced with `***REDACTED***`
- **Email Addresses** (in some contexts) - Partially masked

### 🛡️ Privacy Protection
- All data stays local in your browser
- No data is sent to external servers
- Data is cleared when you close DevTools or click "Clear All Data"

## Enhanced cURL Command Generation

The **Copy cURL** button now generates complete cURL commands including:
- All request headers
- Request body
- Query parameters
- HTTP method

Example generated cURL:
```bash
curl -X POST 'https://api.example.com/users?format=json' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ***REDACTED***' \
  -d '{
    "name": "John Doe",
    "email": "***REDACTED***"
  }'
```

## UI Improvements

### Expandable Sections
- Request and response details are collapsible
- Clean, organized layout with emoji indicators (📤/📥)
- Syntax-highlighted JSON with proper formatting

### Call Header
Each call now shows:
- **Timestamp** - Exact time the call was made
- **Status Code** - HTTP response status

### Organized Sub-sections
- Query Parameters
- Request Headers
- Request Body
- Response Status
- Response Headers

## Limitations

### Response Body Not Available
Due to Chrome extension security policies, extensions cannot access response body content. This is a browser-level restriction for security reasons.

**Workaround**: Use Chrome DevTools Network tab to view response bodies:
1. Open Chrome DevTools (F12)
2. Go to Network tab
3. Click on the request
4. View "Response" tab

### Response Headers Permission
The extension now requests `webRequest` and `webRequestBlocking` permissions to capture response headers. You may see a warning when updating the extension.

## Technical Details

### Permissions Required
```json
{
  "permissions": [
    "webRequest",
    "webRequestBlocking",
    "storage"
  ],
  "host_permissions": [
    "<all_urls>"
  ]
}
```

### Data Flow
1. **Request Captured** - `chrome.webRequest.onBeforeRequest`
2. **Headers Captured** - `chrome.webRequest.onBeforeSendHeaders`
3. **Response Captured** - `chrome.webRequest.onCompleted`
4. **Data Stored** - In-memory Map with security analysis
5. **UI Updated** - Real-time display in DevTools panel

## Best Practices

### 1. **Use for Development Only**
This extension captures all API calls, which may impact performance on production sites.

### 2. **Clear Data Regularly**
Click "Clear All Data" to free up memory when working with high-traffic sites.

### 3. **Export Important Data**
Use "Export JSON" to save important API call data before clearing.

### 4. **Review Security Issues**
Always check the Security Issues section for potential vulnerabilities in your API design.

## Changelog

### Version 2.0.0 - Request/Response Viewer
- ✅ Added complete request header display
- ✅ Added response header capture and display
- ✅ Improved request body formatting
- ✅ Enhanced UI with expandable sections
- ✅ Added emoji indicators for better UX
- ✅ Improved cURL command generation
- ✅ Added security note about response body limitations

## Support

For issues or feature requests, please check the GitHub repository or contact the development team.

---

**Happy API Debugging! 🚀**
