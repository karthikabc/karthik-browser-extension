# API Mapper Security Features - Quick Start Guide

## 🚀 Getting Started with Security Analysis

### Step 1: Install the Extension
1. Load the extension in Chrome (`chrome://extensions/`)
2. Enable "Developer mode" and click "Load unpacked"
3. Select the `api-mapper` folder

### Step 2: Open DevTools
1. Press F12 or right-click → Inspect
2. Click the "API Mapper" tab
3. The extension is now active with all security rules enabled

### Step 3: Browse and Analyze
1. Navigate to any website with APIs
2. Watch the security summary badges update in real-time
3. Endpoints with issues show a colored 🛡️ shield icon

### Step 4: Review Security Issues
1. Click any endpoint with a shield icon
2. Scroll to the "🛡️ Security Analysis" section
3. Review issues grouped by severity
4. Click "Details ▼" to see technical information

### Step 5: Customize Rules
1. Click "🛡️ Rules" in the header
2. Enable/disable rules based on your needs
3. Click "Save Rules" to persist changes

## 📊 Understanding Security Badges

| Badge | Severity | Color | Meaning |
|-------|----------|-------|---------|
| 🔴 | Critical | Red | Immediate security risk - fix ASAP |
| 🟠 | High | Orange | Serious vulnerability - high priority |
| 🟡 | Medium | Yellow | Important issue - should fix |
| 🔵 | Low | Blue | Best practice recommendation |

## 🔍 Common Security Issues Detected

### Critical Issues (Fix Immediately)

**1. Insecure HTTP Protocol**
```
❌ Problem: http://api.example.com/users
✅ Solution: https://api.example.com/users
```

**2. Missing Authentication**
```
❌ Problem: No Authorization header on protected endpoint
✅ Solution: Add Authorization: Bearer <token>
```

**3. SQL Injection Risk**
```
❌ Problem: /users?query=SELECT * FROM users
✅ Solution: Use parameterized queries, validate input
```

### High Severity Issues

**4. Sensitive Data in URL**
```
❌ Problem: /api/user?email=john@example.com
✅ Solution: Move email to POST body or use user ID
```

**5. Email in Custom Headers**
```
❌ Problem: X-User-Email: john@example.com
✅ Solution: Use standard Authorization header
```

**6. Weak Authentication**
```
❌ Problem: /api/data?api_key=12345
✅ Solution: Move API key to Authorization header
```

### Medium Severity Issues

**7. Missing Pagination**
```
❌ Problem: GET /api/users (returns all users)
✅ Solution: GET /api/users?limit=50&page=1
```

**8. Predictable IDs**
```
❌ Problem: /api/user/123
✅ Solution: /api/user/550e8400-e29b-41d4-a716-446655440000
```

## ⚙️ Rule Configuration Examples

### Example 1: Custom Email Pattern

```json
{
  "sensitive-data-in-url": {
    "enabled": true,
    "severity": "high",
    "patterns": {
      "email": "\\b[A-Za-z0-9._%+-]+@yourcompany\\.com\\b",
      "internal_ip": "\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b"
    }
  }
}
```

### Example 2: Stricter Password Policy

```json
{
  "weak-password-policy": {
    "enabled": true,
    "severity": "medium",
    "checks": [
      {
        "field": "password",
        "min_length": 12,
        "message": "Password must be at least 12 characters"
      }
    ]
  }
}
```

### Example 3: Disable False Positives

```json
{
  "predictable-resource-ids": {
    "enabled": false,
    "severity": "medium",
    "message": "Disabled due to many false positives"
  }
}
```

## 🎯 Use Case Scenarios

### Scenario 1: Security Audit
**Goal**: Identify all security issues in your application

1. Enable ALL security rules
2. Navigate through your entire application
3. Review all endpoints with security issues
4. Export findings to share with team
5. Fix issues and re-test

### Scenario 2: API Development
**Goal**: Ensure new APIs are secure

1. Enable relevant rules for your stack
2. Test your API endpoints
3. Fix issues as they appear
4. Verify no critical/high issues remain
5. Document security measures

### Scenario 3: Third-Party API Assessment
**Goal**: Evaluate external API security

1. Enable all detection rules
2. Use the third-party API normally
3. Review captured security issues
4. Contact vendor about critical issues
5. Implement additional client-side protections

### Scenario 4: Compliance Checking
**Goal**: Ensure OWASP/PCI-DSS compliance

1. Enable all rules
2. Focus on Critical and High severity
3. Document all findings
4. Create remediation plan
5. Re-audit after fixes

## 💡 Tips and Best Practices

### For Developers
- ✅ Run security analysis during development
- ✅ Fix critical issues before committing
- ✅ Review high/medium issues in code review
- ✅ Add security tests based on findings
- ✅ Share rules configuration with team

### For Security Teams
- ✅ Create custom rules for organization-specific threats
- ✅ Regularly update security rules
- ✅ Train developers on common vulnerabilities
- ✅ Include in penetration testing toolkit
- ✅ Document exceptions and justifications

### For QA Teams
- ✅ Include security checks in test plans
- ✅ Verify fixes for reported issues
- ✅ Test edge cases for each rule
- ✅ Report new patterns to security team
- ✅ Maintain baseline of acceptable issues

## 🚫 Handling False Positives

### Strategy 1: Disable Specific Rules
If a rule generates too many false positives:
```json
{
  "rule-name": {
    "enabled": false
  }
}
```

### Strategy 2: Adjust Patterns
Modify regex patterns to be more specific:
```json
{
  "sensitive-data-in-url": {
    "patterns": {
      "email": "\\b[a-z]+@internal\\.com\\b"  // More specific
    }
  }
}
```

### Strategy 3: Use Exclusions
Add paths to exclude from checking:
```json
{
  "missing-authentication": {
    "excludePaths": ["/public", "/health", "/docs"]
  }
}
```

## 📚 Additional Resources

- **Full Documentation**: See `SECURITY_README.md`
- **Rule Reference**: See `security-rules.json`
- **Configuration Guide**: Edit rules in UI or JSON
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **API Security**: https://apisecurity.io/

## 🆘 Troubleshooting

### Issue: No security issues detected
**Solution**: 
- Verify recording is enabled (checkbox)
- Check that DevTools is open
- Try navigating to a page with API calls
- Ensure rules are enabled in settings

### Issue: Too many false positives
**Solution**:
- Review and adjust patterns in rules
- Disable overly sensitive rules
- Add exclusion patterns
- Customize for your specific environment

### Issue: Performance degradation
**Solution**:
- Disable unused rules
- Reduce MAX_CALLS_PER_ENDPOINT in config.js
- Clear data regularly
- Use specific filters to reduce data volume

### Issue: Rules not saving
**Solution**:
- Check browser console for errors
- Verify chrome.storage permission
- Try resetting to defaults first
- Clear browser cache and reload extension

## 🤝 Contributing Security Rules

Want to add a new security rule?

1. **Define the rule** in `security-rules.json`:
```json
{
  "your-rule-id": {
    "enabled": true,
    "severity": "high",
    "name": "Your Rule Name",
    "description": "What this rule detects",
    "patterns": ["pattern1", "pattern2"]
  }
}
```

2. **Implement detection** in `security-analyzer.js`:
```javascript
checkYourRule(context) {
  const issues = [];
  // Your detection logic here
  return issues;
}
```

3. **Add to rule checker map**:
```javascript
const checkers = {
  'your-rule-id': this.checkYourRule,
  // ...
};
```

4. **Test thoroughly** with real-world APIs

5. **Submit PR** with documentation

## 📞 Support

For issues, questions, or contributions:
- GitHub Issues: [Report a bug or request a feature]
- Documentation: Check SECURITY_README.md
- Examples: See security-rules.json for rule templates

---

**Happy Secure API Development! 🛡️**
