# Response Body Capture Feature

## Overview
The API Mapper can now capture actual HTTP response bodies using Chrome's Debugger API! This allows you to see the complete response data, not just headers.

## ⚠️ Important Notice

### Debugger Permission Required
- This feature uses Chrome's `debugger` permission
- Chrome will display a warning banner: **"DevTools is debugging this browser"**
- This is normal and safe - it's how extensions capture response data
- The warning disappears when you disable the feature or close DevTools

### Privacy & Security
- ✅ All data stays local in your browser
- ✅ No data is sent to external servers  
- ✅ You control when it's enabled/disabled
- ✅ Only captures data from the tab you're inspecting

## How to Use

### Step 1: Enable Response Body Capture
1. Open Chrome DevTools (F12)
2. Go to the **API Mapper** tab
3. Find the checkbox labeled **"Response Bodies"** in the header
4. Click to enable it

### Step 2: Accept the Warning
Chrome will show a banner at the top of the browser:
```
"DevTools is debugging this browser"
```
- This is normal and expected
- Click anywhere to dismiss the banner
- It indicates response capture is active

### Step 3: Make API Calls
- Navigate the website or perform actions
- API calls will be captured as usual
- Response bodies will now be included

### Step 4: View Response Bodies
1. Click any endpoint in the left panel
2. Scroll to "Recent Calls"
3. Click **"📄 View Raw"**
4. The response column will now show the actual response body!

### Step 5: Disable When Done
- Uncheck the **"Response Bodies"** checkbox
- The warning banner will disappear
- Response bodies will no longer be captured (but existing data remains)

## What You'll See

### With Response Bodies Enabled ✅

```
📥 RESPONSE

HTTP/1.1 200 OK
content-type: application/json
cache-control: no-cache

{
  "id": 12345,
  "name": "John Doe",
  "email": "john@example.com",
  "role": "admin",
  "created_at": "2025-10-16T10:30:45Z"
}
```

### Without Response Bodies (Default) ⚠️

```
📥 RESPONSE

HTTP/1.1 200 OK
content-type: application/json
cache-control: no-cache

⚠️ Response body capture is disabled.

Enable "Response Bodies" checkbox in the header to capture response bodies.
Note: This requires debugger permission and will show a warning banner.
```

## Use Cases

### 1. **Debugging API Responses**
See exactly what data the API returns:
```json
{
  "error": "Invalid authentication token",
  "code": "AUTH_FAILED",
  "details": {...}
}
```

### 2. **Security Analysis**
Check for sensitive data in responses:
```json
{
  "user": {
    "ssn": "123-45-6789",  // ⚠️ PII leak!
    "password_hash": "..."
  }
}
```

### 3. **API Documentation**
Capture real response examples for documentation:
```json
{
  "products": [
    {"id": 1, "name": "Widget", "price": 9.99},
    {"id": 2, "name": "Gadget", "price": 19.99}
  ],
  "total": 2,
  "page": 1
}
```

### 4. **Performance Analysis**
Check response payload sizes:
```json
{
  "data": [...1000 items...],  // Large response!
  "metadata": {...}
}
```

### 5. **Error Investigation**
See detailed error messages:
```json
{
  "error": {
    "message": "Database connection timeout",
    "stack_trace": "...",
    "timestamp": "2025-10-16T10:30:45Z"
  }
}
```

## Technical Details

### How It Works
1. **Attaches Chrome Debugger** to the inspected tab
2. **Enables Network Domain** to intercept HTTP traffic
3. **Captures Response Bodies** using `Network.getResponseBody`
4. **Matches with Requests** by URL and timestamp
5. **Stores in Memory** with existing API call data

### What's Captured
- ✅ **JSON responses** - Formatted and pretty-printed
- ✅ **Text responses** - Plain text content
- ✅ **HTML responses** - Full HTML source
- ✅ **XML responses** - Complete XML documents
- ⚠️ **Binary responses** - May not display correctly (images, PDFs)

### Limitations
1. **Binary Data** - Images, files may not display properly
2. **Large Responses** - Very large responses (>1MB) may be slow
3. **One Tab at a Time** - Can only debug one tab at once
4. **Warning Banner** - Chrome shows persistent warning when enabled

### Performance Impact
- **Minimal** - Only captures data you're already receiving
- **Memory** - Response bodies stored in memory (cleared with "Clear All Data")
- **Speed** - No noticeable impact on page load times

## Comparison with DevTools

| Feature | API Mapper | DevTools Network Tab |
|---------|------------|---------------------|
| Persist across navigation | ✅ Yes | ❌ No |
| Group by endpoint | ✅ Yes | ❌ No |
| Security analysis | ✅ Yes | ❌ No |
| Response bodies | ✅ Yes (with debugger) | ✅ Yes |
| Export to OpenAPI | ✅ Yes | ❌ No |
| cURL generation | ✅ Yes | ✅ Yes |
| Side-by-side view | ✅ Yes | ❌ No |

## Troubleshooting

### Q: Checkbox is disabled/grayed out
**A:** Make sure you're on a page with an active tab. Refresh the page and try again.

### Q: Warning banner won't go away
**A:** The banner persists as long as the feature is enabled. Uncheck "Response Bodies" to remove it.

### Q: Response body still shows "not available"
**A:** Possible reasons:
- Feature was enabled after the request was made (won't capture old requests)
- Response has no body (204 No Content, 304 Not Modified)
- Binary content that can't be displayed as text
- Very large response that was truncated

### Q: Extension crashed or became slow
**A:** 
1. Disable "Response Bodies" checkbox
2. Click "Clear All Data"
3. Reload the extension at `chrome://extensions`
4. Try again with fewer API calls

### Q: Can I use this on any website?
**A:** Yes, but some websites may detect the debugger and behave differently. Banking sites, for example, may block access.

### Q: Is this safe?
**A:** Yes! The debugger permission is the same one used by Chrome DevTools. Your data stays local and is never sent anywhere.

## Best Practices

### ✅ DO:
- Enable only when you need response bodies
- Disable when done to remove the warning banner
- Clear data regularly to free memory
- Use for development/testing only

### ❌ DON'T:
- Leave it enabled on production sites
- Capture sensitive data on shared computers
- Use on websites that explicitly block debugging
- Keep it enabled 24/7 (impacts memory)

## Privacy Considerations

### What's Collected
- HTTP response bodies from the inspected tab
- Only while DevTools is open and feature is enabled
- Stored locally in browser memory

### What's NOT Collected
- Data from other tabs or windows
- Data when feature is disabled
- Data when DevTools is closed
- Nothing is sent to external servers

### Data Retention
- Cleared when you click "Clear All Data"
- Cleared when DevTools is closed
- Not saved to disk (session only)
- Not shared with anyone

## Alternatives

If you don't want to use the debugger permission:

### Option 1: Chrome DevTools Network Tab
- No permissions needed
- Same response body data
- Doesn't persist across navigation

### Option 2: Network Proxy Tools
- Burp Suite, Fiddler, Charles Proxy
- More powerful but more complex
- Works outside the browser

### Option 3: Browser Extensions API
- Limited to headers only (default behavior)
- No warning banner
- No response bodies

## Changelog

### Version 2.0.2 - Response Body Capture
- ✅ Added debugger permission
- ✅ Created ResponseBodyCapture module
- ✅ Integrated with existing API call data
- ✅ Added "Response Bodies" checkbox toggle
- ✅ Enhanced raw HTTP view to show bodies
- ✅ Added comprehensive error handling
- ✅ Automatic matching with requests
- ✅ JSON pretty-printing for responses

## Support

### Still have questions?
- Check browser console for errors
- Try disabling/re-enabling the feature
- Clear all data and start fresh
- Report issues with examples

---

**Capture complete API responses with confidence! 🎉📥**
