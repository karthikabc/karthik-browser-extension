# API Mapper Security Edition - Testing Checklist

## Pre-Installation Testing

### Environment Check
- [ ] Chrome browser version 88 or higher
- [ ] Developer mode enabled in chrome://extensions/
- [ ] Sufficient disk space for extension
- [ ] No conflicting extensions installed

## Installation Testing

### Load Extension
- [ ] Navigate to chrome://extensions/
- [ ] Enable "Developer mode"
- [ ] Click "Load unpacked"
- [ ] Select api-mapper directory
- [ ] Extension loads without errors
- [ ] Extension icon appears in Chrome
- [ ] Version shows as 2.0.0

### Initial State
- [ ] Open DevTools (F12)
- [ ] "API Mapper" tab is visible
- [ ] Click on API Mapper tab
- [ ] Panel opens without errors
- [ ] Security summary shows 0/0/0/0
- [ ] "🛡️ Rules" button is visible
- [ ] No console errors

## Core Functionality Testing

### Basic API Capture
- [ ] Navigate to a website with API calls (e.g., jsonplaceholder.typicode.com)
- [ ] API calls appear in endpoint list
- [ ] Endpoint count increments
- [ ] Click endpoint to view details
- [ ] Details panel populates correctly
- [ ] Recording checkbox works (on/off)

### Security Analysis
- [ ] Security summary badges update with numbers
- [ ] Endpoints show shield icons (🛡️) if issues detected
- [ ] Shield icons have correct severity colors
- [ ] Click endpoint with shield icon
- [ ] Security Analysis section appears
- [ ] Issues are grouped by severity
- [ ] Severity sections color-coded correctly
- [ ] Issue names and descriptions are clear
- [ ] "Details" button expands/collapses info

## Security Rules Testing

### Rules Configuration UI
- [ ] Click "🛡️ Rules" button
- [ ] Modal opens smoothly
- [ ] All rules are listed
- [ ] Each rule shows:
  - [ ] Checkbox (checked/unchecked)
  - [ ] Severity badge (colored)
  - [ ] Rule name
  - [ ] Rule description
- [ ] Click "X" closes modal
- [ ] Click outside modal closes it

### Enable/Disable Rules
- [ ] Uncheck a rule (e.g., "Insecure HTTP")
- [ ] Click "Save Rules"
- [ ] Success message appears
- [ ] Modal closes
- [ ] Browse to trigger that rule
- [ ] Verify rule no longer detects issues
- [ ] Re-enable the rule
- [ ] Save again
- [ ] Verify rule detects issues again

### Reset to Defaults
- [ ] Disable several rules
- [ ] Click "Reset to Defaults"
- [ ] Confirm dialog appears
- [ ] Confirm reset
- [ ] All rules re-enabled
- [ ] Success message appears

### Rule Persistence
- [ ] Configure rules (disable some)
- [ ] Save configuration
- [ ] Close DevTools completely
- [ ] Reopen DevTools
- [ ] Open "🛡️ Rules"
- [ ] Verify configuration persisted

## Individual Rule Testing

### Critical Severity Rules

#### 1. Insecure HTTP Protocol
- [ ] Visit http://example.com (non-HTTPS)
- [ ] Make API call over HTTP
- [ ] Critical severity issue detected
- [ ] Message: "API calls should use HTTPS"
- [ ] Shield icon is red

#### 2. SQL Injection Risk
- [ ] Make API call with: `/api/users?query=SELECT * FROM users`
- [ ] High severity issue detected
- [ ] Pattern identified in query parameters
- [ ] Details show the suspicious pattern

#### 3. Missing Authentication
- [ ] Make API call without Authorization header
- [ ] To non-excluded path (not /login, /public, etc.)
- [ ] Critical severity issue detected
- [ ] Message about missing authentication

### High Severity Rules

#### 4. Sensitive Data in URL
Test each pattern:
- [ ] Email: `/api/user?email=test@example.com`
- [ ] Phone: `/api/user?phone=555-123-4567`
- [ ] SSN: `/api/user?ssn=123-45-6789`
- [ ] JWT: `/api/auth?token=eyJhbGc...`
- [ ] Each triggers high severity issue

#### 5. Sensitive Headers
- [ ] Add header: `X-Email: test@example.com`
- [ ] High severity issue detected
- [ ] Message about PII in headers

#### 6. PII in Request Body
- [ ] POST request with body:
  ```json
  {
    "email": "test@example.com",
    "ssn": "123-45-6789",
    "phone": "555-123-4567"
  }
  ```
- [ ] High severity issue detected
- [ ] All PII fields identified

### Medium Severity Rules

#### 7. Missing Pagination
- [ ] GET request without limit/page params
- [ ] Medium severity issue detected
- [ ] Recommendation to add pagination

#### 8. Predictable IDs
- [ ] Access `/api/user/123`
- [ ] Medium severity issue detected
- [ ] Recommendation to use UUIDs

### Low Severity Rules

#### 9. Verbose Error Messages
- [ ] Trigger 400, 404, or 500 error
- [ ] Low severity issue detected
- [ ] Warning about error details

## UI/UX Testing

### Visual Elements
- [ ] Severity badges visible and distinct
- [ ] Colors match severity levels:
  - [ ] Critical: Red (#dc2626)
  - [ ] High: Orange (#ea580c)
  - [ ] Medium: Yellow (#f59e0b)
  - [ ] Low: Blue (#3b82f6)
- [ ] Shield icons visible in endpoint list
- [ ] Modal styling is clean and professional
- [ ] No layout breaking or overflow

### Responsiveness
- [ ] Resize DevTools window
- [ ] UI adapts appropriately
- [ ] No horizontal scrolling in modal
- [ ] Security section fits in details panel
- [ ] Long issue descriptions wrap properly

### Performance
- [ ] Capture 50+ API calls
- [ ] UI remains responsive
- [ ] No noticeable lag
- [ ] Security summary updates quickly
- [ ] Scrolling is smooth
- [ ] Memory usage acceptable (check Task Manager)

## Integration Testing

### With Existing Features

#### Tagging System
- [ ] Add tags to endpoints with security issues
- [ ] Tags appear correctly
- [ ] Security section remains visible
- [ ] Tag filtering works
- [ ] Security issues persist with tags

#### Filtering
- [ ] Filter by method while security issues present
- [ ] Filter by host
- [ ] Filter by tags
- [ ] Security summary updates correctly
- [ ] Shield icons update with filters

#### Selection & Export
- [ ] Select endpoints with security issues
- [ ] Click "Export"
- [ ] OpenAPI spec generates
- [ ] Contains endpoint data
- [ ] Click "Open in Swagger"
- [ ] Swagger opens correctly

#### Clear Data
- [ ] Click "Clear" button
- [ ] All endpoints cleared
- [ ] Security summary resets to 0/0/0/0
- [ ] No errors in console

## Edge Cases & Error Handling

### Error Scenarios
- [ ] Make API call with malformed JSON
- [ ] Extension handles gracefully
- [ ] No console errors break functionality
- [ ] Make extremely large request body
- [ ] Analyzer handles without crashing
- [ ] Disable all rules and save
- [ ] No issues detected (expected)
- [ ] UI shows "No issues detected"

### Boundary Testing
- [ ] 0 API calls captured
- [ ] 1 API call captured
- [ ] 100+ API calls captured
- [ ] Very long endpoint paths (200+ chars)
- [ ] Unicode in parameters
- [ ] Special characters in URLs
- [ ] Null/undefined values handled

## Browser Compatibility

### Chrome Versions
- [ ] Test on Chrome Stable
- [ ] Test on Chrome Beta (if available)
- [ ] Test on Chrome Canary (if available)
- [ ] Test on Chromium
- [ ] Test on Edge (Chromium-based)

## Documentation Testing

### README.md
- [ ] Installation instructions are clear
- [ ] Security features section is accurate
- [ ] Examples work as described
- [ ] Links to other docs work
- [ ] Images display correctly (if any)

### SECURITY_README.md
- [ ] All rules documented
- [ ] Configuration examples work
- [ ] Code samples are correct
- [ ] Troubleshooting helps resolve issues

### SECURITY_QUICKSTART.md
- [ ] Quick start steps are accurate
- [ ] Badge meanings are correct
- [ ] Examples demonstrate issues properly
- [ ] Configuration examples work

## Regression Testing

### Original Features Still Work
- [ ] API call capture
- [ ] Endpoint grouping
- [ ] Method badges (GET, POST, etc.)
- [ ] Host filtering
- [ ] Query parameter detection
- [ ] Request body analysis
- [ ] Recent calls display
- [ ] cURL generation
- [ ] Complete cURL with headers
- [ ] Tag management
- [ ] Multi-select filtering
- [ ] Selection controls
- [ ] OpenAPI export
- [ ] Swagger integration
- [ ] Recording toggle
- [ ] Clear functionality

## Security & Privacy Testing

### Data Handling
- [ ] No data sent to external servers
- [ ] Verify in Network tab (DevTools)
- [ ] All processing is local
- [ ] Rules stored in chrome.storage.local
- [ ] No cookies created
- [ ] No tracking scripts loaded

### Sensitive Data Redaction
- [ ] Sensitive headers still redacted
- [ ] "***REDACTED***" appears for:
  - [ ] Authorization headers
  - [ ] Cookie headers
  - [ ] API keys in headers
- [ ] Sensitive query params redacted
- [ ] Security analysis uses redacted values

## Final Checklist

### Functionality
- [ ] All security rules work correctly
- [ ] UI is intuitive and clear
- [ ] Performance is acceptable
- [ ] No breaking bugs found
- [ ] Error handling is robust

### Documentation
- [ ] All docs are accurate
- [ ] Examples are working
- [ ] Installation guide is complete
- [ ] Troubleshooting covers common issues

### Quality
- [ ] No console errors
- [ ] No memory leaks
- [ ] Code is clean and commented
- [ ] Files properly organized

### User Experience
- [ ] Easy to install
- [ ] Easy to use
- [ ] Clear feedback on actions
- [ ] Helpful error messages
- [ ] Professional appearance

## Sign-Off

Tester Name: _________________
Date: _________________
Version Tested: 2.0.0
Test Environment: _________________

- [ ] All critical tests passed
- [ ] All high priority tests passed
- [ ] All medium priority tests passed
- [ ] Known issues documented
- [ ] Ready for deployment

## Known Issues / Notes

List any issues found during testing:

1. _________________________________________________
2. _________________________________________________
3. _________________________________________________

## Recommendations

_________________________________________________________________
_________________________________________________________________
_________________________________________________________________

---

**Testing Status**: ⬜ Not Started | 🟡 In Progress | ✅ Complete | ❌ Failed
