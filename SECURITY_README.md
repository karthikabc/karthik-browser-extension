# API Mapper - Security Edition

**Version 2.0.0 - Security Analysis Features**

## 🛡️ New Security Features

API Mapper now includes comprehensive security vulnerability detection capabilities! This Chrome extension not only maps and documents your APIs but also identifies potential security issues in real-time.

### Security Vulnerability Detection

The extension automatically analyzes all API calls for 18+ security vulnerabilities:

#### Critical Severity Issues
- **Insecure HTTP Protocol**: Detects unencrypted HTTP connections
- **Weak Authentication**: Identifies Basic Auth and insecure authentication patterns
- **SQL Injection Risks**: Detects potential SQL injection patterns in parameters
- **Missing Authentication**: Flags endpoints without proper authentication headers
- **Unencrypted Sensitive Data**: Identifies sensitive data transmitted over HTTP

#### High Severity Issues
- **Sensitive Data in URLs**: Detects emails, SSNs, credit cards, phone numbers, etc. in URLs
- **Sensitive Headers**: Identifies PII in custom headers
- **PII in Request Body**: Detects personally identifiable information in payloads
- **XSS Risks**: Identifies potential cross-site scripting patterns
- **Path Traversal**: Detects directory traversal attack patterns
- **Mass Assignment**: Flags sensitive fields that could allow privilege escalation

#### Medium Severity Issues
- **Missing Security Headers**: Checks for recommended security headers (CSRF tokens, etc.)
- **Excessive Data Exposure**: Identifies endpoints without pagination
- **Insufficient Rate Limiting**: Detects rapid calls without rate limit headers
- **Weak Password Policy**: Validates password requirements
- **Predictable Resource IDs**: Identifies sequential numeric IDs that could be enumerated

#### Low Severity Issues
- **Verbose Error Messages**: Flags error responses that may leak implementation details
- **CORS Misconfiguration**: Detects potential CORS policy issues

### Customizable Security Rules

All security rules are **fully customizable** via a JSON configuration file:

```json
{
  "rules": {
    "sensitive-data-in-url": {
      "enabled": true,
      "severity": "high",
      "name": "Sensitive Data in URL",
      "description": "Detects sensitive information exposed in URL",
      "patterns": {
        "email": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
        "ssn": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
        ...
      }
    },
    ...
  }
}
```

### Visual Security Dashboard

**Real-time Security Summary** in the header shows:
- 🔴 Critical issues count
- 🟠 High severity issues count
- 🟡 Medium severity issues count
- 🔵 Low severity issues count

**Endpoint Security Indicators** show:
- Shield icon with color coding for each endpoint
- Highest severity level at a glance
- Total issue count on hover

**Detailed Security Analysis** for each endpoint includes:
- Grouped by severity level
- Specific issue names and descriptions
- Detailed context and remediation recommendations
- Expandable details with affected fields/parameters

### Security Rules Configuration UI

Click the "🛡️ Rules" button to:
- Enable/disable individual security rules
- View rule descriptions and severity levels
- Save custom configurations
- Reset to default rules
- Changes persist across sessions

## Installation

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked"
5. Select the `api-mapper` directory

## Usage

### Monitoring APIs with Security Analysis

1. Open Chrome DevTools (F12 or right-click → Inspect)
2. Click on the "API Mapper" tab
3. Navigate to any website - API calls are automatically captured
4. View the security summary in the header
5. Click any endpoint to see detailed security analysis

### Customizing Security Rules

1. Click the "🛡️ Rules" button in the header
2. Browse through all available security rules
3. Toggle rules on/off based on your requirements
4. Click "Save Rules" to apply changes
5. Click "Reset to Defaults" to restore original configuration

### Editing Rules Manually

For advanced customization, edit `security-rules.json`:

```json
{
  "rules": {
    "your-custom-rule": {
      "enabled": true,
      "severity": "high",
      "name": "Your Custom Rule",
      "description": "Description of what this rule checks",
      "patterns": ["regex-pattern-1", "regex-pattern-2"],
      "message": "Message shown when vulnerability is detected"
    }
  }
}
```

**Rule Properties:**
- `enabled`: Boolean - Whether the rule is active
- `severity`: String - "critical", "high", "medium", or "low"
- `name`: String - Display name of the rule
- `description`: String - Detailed explanation
- `patterns`/`checks`: Array - Detection patterns (varies by rule type)
- `message`: String - Alert message when issue is found

### Exporting Security Reports

The OpenAPI export now includes security findings:
1. Select endpoints to export (including security issues)
2. Click "Export" or "Open in Swagger"
3. Security issues are documented in the API description

## Security Rules Reference

### Configurable Parameters

Each rule type has specific configuration options:

#### Pattern-Based Rules
- `patterns`: Array of regex patterns
- Example: SQL injection, XSS, path traversal

#### Header-Based Rules
- `headers`: Array of header names to check
- Example: Sensitive headers, missing security headers

#### Field-Based Rules
- `fields`: Array of field names to detect
- Example: PII in request body, mass assignment

#### Rate Limiting Rules
- `threshold`: Number of calls
- `timeWindow`: Time window in milliseconds
- Example: Insufficient rate limiting

#### Authentication Rules
- `excludePaths`: Array of paths to skip checking
- Example: Missing authentication

## File Structure

```
api-mapper/
├── manifest.json                # Extension manifest (v2.0.0)
├── background.js                # Network interception + security analysis
├── security-analyzer.js         # Security vulnerability detection engine
├── security-rules.json          # Customizable security rules configuration
├── config.js                    # Extension configuration
├── devtools.html                # DevTools page
├── devtools.js                  # Creates custom panel
├── panel.html                   # Panel UI with security dashboard
├── panel.js                     # Panel functionality + security UI
├── panel.css                    # Styling with security components
└── favicon/                     # Extension icons
```

## Technical Details

### Security Analysis Flow

1. **Capture**: Background script intercepts all XHR/Fetch requests
2. **Analyze**: Security analyzer evaluates each request against enabled rules
3. **Store**: Vulnerabilities are stored with each API call
4. **Display**: Panel UI shows security summary and detailed issues
5. **Configure**: Users can enable/disable rules via UI or JSON

### Performance Considerations

- Analysis runs asynchronously to avoid blocking
- Results are cached to prevent redundant checks
- Rules can be disabled to reduce overhead
- Memory limits prevent excessive data storage

### Privacy & Data Handling

- All analysis happens locally in the browser
- No data is sent to external servers
- Security configuration stored in browser local storage
- Data cleared when DevTools is closed or manually cleared

## Security Rule Examples

### Detecting Email in Headers

```json
{
  "sensitive-headers": {
    "enabled": true,
    "severity": "high",
    "headers": ["x-email", "user-email", "email"]
  }
}
```

### Custom Password Policy

```json
{
  "weak-password-policy": {
    "enabled": true,
    "checks": [
      {
        "field": "password",
        "min_length": 12,
        "message": "Password should be at least 12 characters"
      }
    ]
  }
}
```

### Detecting API Keys in Query Parameters

```json
{
  "weak-authentication": {
    "enabled": true,
    "checks": [
      {
        "type": "api_key_in_query",
        "params": ["api_key", "apikey", "key", "token"],
        "message": "API keys should be in headers, not query parameters"
      }
    ]
  }
}
```

## Common Use Cases

### Security Auditing
Monitor your application's API calls to identify security issues before they reach production.

### Penetration Testing
Track API security during security assessments and penetration tests.

### Compliance Checking
Ensure APIs comply with security standards (OWASP, PCI-DSS, etc.).

### Developer Training
Help developers understand common API security vulnerabilities.

### Third-Party API Assessment
Evaluate the security posture of third-party APIs your application uses.

## Limitations

- Browser-level analysis (cannot detect server-side vulnerabilities)
- Response bodies not captured (only status codes)
- Pattern-based detection (may have false positives/negatives)
- Cannot verify actual exploitation, only potential risks
- TLS version detection limited by browser capabilities

## Best Practices

1. **Enable All Rules Initially**: Start with all rules enabled, then adjust based on your needs
2. **Regular Reviews**: Periodically review security findings and update your APIs
3. **False Positive Management**: Disable rules that generate too many false positives for your specific case
4. **Custom Rules**: Add custom rules for organization-specific security requirements
5. **Team Collaboration**: Share security-rules.json configurations across your team
6. **Documentation**: Document why certain rules are disabled in your project

## Troubleshooting

### No Security Issues Detected
- Ensure recording is enabled (checkbox in header)
- Check that DevTools is open while making API calls
- Verify rules are enabled in Security Rules modal

### Too Many False Positives
- Adjust rule patterns in security-rules.json
- Disable overly sensitive rules for your use case
- Add exclusion patterns for known safe endpoints

### Performance Issues
- Disable unused security rules
- Reduce MAX_CALLS_PER_ENDPOINT in config.js
- Clear data regularly

## Contributing

Feel free to contribute additional security rules or improvements:

1. Add new rules to `security-rules.json`
2. Implement detection logic in `security-analyzer.js`
3. Update UI to display new issue types
4. Test thoroughly with real-world APIs
5. Submit pull request with documentation

## License

MIT License

## Changelog

### Version 2.0.0 (2025-10-15)
- ✨ Added comprehensive security vulnerability detection
- ✨ Added 18+ customizable security rules
- ✨ Added visual security dashboard
- ✨ Added security rules configuration UI
- ✨ Added security indicators in endpoint list
- ✨ Added detailed security analysis for each endpoint
- ✨ Added JSON-based rule customization
- 🔧 Updated manifest to v2.0.0
- 📚 Added comprehensive security documentation

### Version 1.0.0
- Initial release with API mapping and OpenAPI export

## Credits

Developed as a senior security architect's tool for identifying API security vulnerabilities during development and testing.
