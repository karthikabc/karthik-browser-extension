# Testing the Request & Response Viewer

## Quick Test Checklist ✅

### 1. Reload the Extension
- [ ] Go to `chrome://extensions`
- [ ] Find "API Mapper - Security Edition"
- [ ] Click the reload button (circular arrow)

### 2. Open DevTools
- [ ] Navigate to any website with API calls (e.g., GitHub, Twitter, Gmail)
- [ ] Press F12 to open DevTools
- [ ] Click the "API Mapper" tab

### 3. Capture Some API Calls
- [ ] Refresh the page or interact with the site
- [ ] Watch API calls appear in the left panel

### 4. Test Request Details
- [ ] Click on any endpoint in the left panel
- [ ] Scroll down to "Recent Calls" section
- [ ] Find the "📤 Request Details" section
- [ ] Click to expand it
- [ ] Verify you can see:
  - [ ] Query Parameters (if any)
  - [ ] Request Headers (should see many headers)
  - [ ] Request Body (for POST/PUT requests)

### 5. Test Response Details
- [ ] In the same call, find "📥 Response Details"
- [ ] Click to expand it
- [ ] Verify you can see:
  - [ ] Status code (e.g., "200 OK")
  - [ ] Response Headers (should see content-type, cache-control, etc.)
  - [ ] Info note about response body limitations

### 6. Test cURL Copy
- [ ] Click the "📋 Copy cURL" button
- [ ] Paste into a text editor
- [ ] Verify the cURL command includes:
  - [ ] HTTP method (GET, POST, etc.)
  - [ ] Full URL
  - [ ] All headers (-H flags)
  - [ ] Request body (-d flag for POST/PUT)

### 7. Test Multiple Calls
- [ ] Make several API calls by interacting with the site
- [ ] Each call should have its own expandable sections
- [ ] Verify you can expand multiple calls at once

### 8. Test Collapsible Behavior
- [ ] Expand a Request Details section
- [ ] Click elsewhere on the page
- [ ] The section should stay open
- [ ] Click the summary again to collapse it

## Expected Results

### Request Details Section Should Show:
```
📤 Request Details
  ├── Query Parameters
  │   {
  │     "param1": "value1",
  │     "param2": "value2"
  │   }
  │
  ├── Request Headers
  │   {
  │     "accept": "application/json",
  │     "authorization": "Bearer ***REDACTED***",
  │     "content-type": "application/json",
  │     "user-agent": "Mozilla/5.0...",
  │     ...
  │   }
  │
  └── Request Body
      {
        "field1": "value1",
        "sensitive": "***REDACTED***"
      }
```

### Response Details Section Should Show:
```
📥 Response Details
  ├── Status
  │   200 OK
  │
  └── Response Headers
      {
        "content-type": "application/json",
        "cache-control": "no-cache",
        "x-rate-limit-remaining": "99",
        ...
      }
```

## Common Issues & Solutions

### Issue: No Request Headers Showing
**Cause**: Extension not fully reloaded
**Solution**: 
1. Close DevTools
2. Go to chrome://extensions
3. Click reload on API Mapper
4. Open DevTools again

### Issue: Response Headers Empty
**Cause**: Permission not granted or old cached data
**Solution**:
1. Clear all data in API Mapper
2. Refresh the page
3. Make new API calls

### Issue: Request Body Not Showing
**This is normal if**:
- The request was GET (no body)
- The body wasn't JSON format
- The body was binary data

### Issue: Sections Won't Expand
**Cause**: JavaScript error or cached old version
**Solution**:
1. Open browser console (F12 → Console tab)
2. Check for errors (red text)
3. Hard refresh: Ctrl+Shift+R (Windows) or Cmd+Shift+R (Mac)

### Issue: cURL Missing Headers
**Cause**: Old data captured before update
**Solution**:
1. Click "Clear All Data"
2. Refresh the page
3. Capture new API calls
4. Try Copy cURL again

## Test Websites

### Good Sites for Testing:
1. **GitHub.com** - Many API calls, good headers
2. **Twitter/X.com** - Complex API structure
3. **JSONPlaceholder** (jsonplaceholder.typicode.com) - Test API
4. **Any site you're developing** - Best for real testing

### What to Look For:
- ✅ Authorization headers (often redacted)
- ✅ Custom X-* headers
- ✅ Content-Type headers
- ✅ Rate limiting headers in responses
- ✅ Cache-Control in responses
- ✅ Request bodies for POST/PUT operations

## Verification Checklist

Before considering the feature complete, verify:

- [ ] **Visual Design**: Sections look clean and organized
- [ ] **Functionality**: All expandable sections work
- [ ] **Data Accuracy**: Headers match what's in Network tab
- [ ] **Sanitization**: Sensitive data is redacted
- [ ] **Performance**: No lag when expanding sections
- [ ] **cURL Export**: Generated commands are valid
- [ ] **Multiple Calls**: Can view multiple calls independently
- [ ] **Responsive**: UI adapts to DevTools size

## Screenshot Locations

Take screenshots of:
1. Expanded Request Details showing all headers
2. Expanded Response Details showing status and headers
3. Formatted JSON in request body
4. Generated cURL command
5. Multiple calls with some expanded, some collapsed

Save for documentation or bug reports if needed.

## Debugging Tips

### Check Browser Console
```javascript
// In browser console, check if security analyzer loaded:
console.log(window.SecurityAnalyzer);

// Check if data is being captured:
// (In API Mapper panel console)
port.postMessage({ type: "GET_API_CALLS" });
```

### Verify Permissions
Go to chrome://extensions → API Mapper → Details
Should show:
- ✅ "Read and change all your data on all websites"
- ✅ "webRequest"
- ✅ "storage"

### Check Network Tab
Compare API Mapper data with Chrome DevTools Network tab:
1. Open Network tab alongside API Mapper
2. Click same request in both
3. Verify headers match

## Success Criteria

✅ **Feature is working if**:
1. Request details expand and show JSON
2. All request headers are visible
3. Response headers are captured
4. Sensitive data is redacted
5. cURL commands include all headers
6. UI is clean and responsive
7. No errors in console

❌ **Feature needs fixes if**:
1. Sections don't expand
2. Headers are empty or missing
3. JSON is not formatted
4. Errors appear in console
5. Performance is sluggish
6. Data is not redacted

## Next Steps After Testing

1. ✅ Mark all checklist items
2. 📸 Take screenshots of working features
3. 📝 Note any issues or bugs
4. 🎉 Celebrate if everything works!
5. 📤 Share feedback or bug reports

---

**Happy Testing! 🧪🚀**
