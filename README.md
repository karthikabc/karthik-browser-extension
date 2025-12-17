# GAMX Chrome & Edge Extension

**Comprehensive API monitoring, documentation, and security analysis tool for Chrome and Edge browsers**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-green.svg)](https://developer.chrome.com/docs/extensions/)
[![Edge Add-on](https://img.shields.io/badge/Edge-Add--on-blue.svg)](https://microsoftedge.microsoft.com/addons/)

---

## 📖 Table of Contents

- [Overview](#-overview)
- [What's New](#-whats-new-in-version-20)
- [Key Features](#-key-features)
- [Security Features](#-security-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Documentation](#-documentation)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

GAMX Chrome & Edge Extension is a powerful developer tool that automatically captures, documents, and analyzes API calls made by websites. It integrates directly into browser DevTools and provides:

- 📊 **Real-time API monitoring** - See all API calls as they happen
- 🛡️ **Security analysis** - Detect 22+ vulnerability types
- 📝 **OpenAPI documentation** - Auto-generate API specifications
- 🔍 **Complete request/response inspection** - View headers, bodies, and more
- 🎨 **Raw HTTP viewer** - Side-by-side request/response display
- 📋 **Export capabilities** - JSON, cURL, OpenAPI 3.0

Perfect for developers, testers, security professionals, and anyone working with APIs.

---

## ✨ What's New in Version 2.0

### 📥 Response Body Capture (LATEST!)
**Now captures actual HTTP response bodies!**
- 🎯 **Real Response Data**: See actual JSON, HTML, text responses
- 🔬 **Debugger API**: Uses Chrome's debugger to capture bodies
- ⚡ **One-Click Enable**: Toggle "Response Bodies" checkbox
- 📊 **Pretty-Printed**: JSON responses formatted automatically
- 🎨 **Integrated View**: Shows in side-by-side raw HTTP viewer
- ⚠️ **Note**: Shows debugger warning banner when enabled (normal & safe)

[📖 Response Body Capture Guide →](RESPONSE_BODY_CAPTURE.md)

### 📄 Raw HTTP Viewer
**Complete raw HTTP request and response viewer**
- 📝 See exact HTTP requests and responses
- 🔄 Side-by-side comparison view
- 📋 One-click copy to clipboard
- 🎯 Shows status codes, headers, bodies

[📖 Raw HTTP Viewer Guide →](RAW_HTTP_VIEWER.md)

### 🛡️ Security Analysis (Enhanced!)
**Comprehensive security vulnerability detection**
- 22 built-in security rules (6 critical, 10 high priority)
- Real-time vulnerability detection
- CWE mappings and remediation guidance
- Customizable rule configuration
- Severity-based filtering

[📖 Security Features Guide →](SECURITY_README.md)

---

## ⚡ Key Features

### API Documentation & Monitoring
- **Auto-Discovery**: Captures all API calls automatically
- **Smart Grouping**: Organizes by endpoint
- **Request History**: See all calls for each endpoint
- **Query Parameters**: Track all parameter variations
- **Headers & Bodies**: Full request/response details
- **OpenAPI Export**: Generate OpenAPI 3.0 specs

### Developer Tools
- **DevTools Integration**: Seamless Chrome/Edge DevTools panel
- **cURL Generation**: Export any request as cURL command
- **Complete/Simple cURL**: Toggle browser headers on/off
- **Swagger Integration**: Open in Swagger Editor directly
- **JSON Export**: Download complete capture data
- **Clear & Filter**: Organize captured data efficiently

### Security Features
- **22+ Security Rules**: Detect critical vulnerabilities
- **Real-time Analysis**: Issues flagged as they occur
- **Severity Indicators**: Critical/High/Medium/Low badges
- **Detailed Reports**: CWE mappings, impacts, remediation steps
- **Customizable Rules**: Enable/disable/configure checks
- **Security Summary**: Overview of all detected issues

---

## 🛡️ Security Features

### Critical Vulnerabilities Detected
1. **Untrusted Client-Supplied Identity** (CWE-639)
2. **Weak Authentication** (Basic auth, API keys in query)
3. **Insecure HTTP Protocol** (Unencrypted transmission)
4. **SQL Injection Risk** (Malicious SQL patterns)
5. **Missing Authentication** (Unauthenticated endpoints)
6. **Unencrypted Sensitive Data** (Plaintext passwords/secrets)
7. **Hardcoded Secrets** (Exposed API keys, tokens)
8. **Sensitive Data in Response Body** (SSN, credit cards)

### High-Priority Issues
- Sensitive Data in URLs
- XSS Risk (Script injection)
- Path Traversal Risk
- CORS Misconfiguration
- Mass Assignment Vulnerabilities
- Insecure Cookies
- Open Redirect Risk
- SSRF Risk
- Missing Input Validation
- And more...

[📖 Complete Security Rules List →](SECURITY_README.md)

---

## 📦 Installation

### For Chrome

1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. **Enable Developer Mode** (toggle in top-right corner)
4. Click **"Load unpacked"**
5. Select the `api-mapper` directory
6. The extension icon should appear in your browser toolbar

### For Edge

1. Open Edge and navigate to `edge://extensions/`
2. Enable **"Developer mode"** (toggle in left sidebar)
3. Click **"Load unpacked"**
4. Select the `api-mapper` directory
5. The extension icon should appear in your browser toolbar

---

## 🚀 Quick Start

### Opening GAMX Extension

1. **Open DevTools** (Press `F12` or right-click → Inspect)
2. Look for the **"GAMX Extension"** tab in the DevTools panel
3. Click to open the extension

### Capturing API Calls

1. With GAMX Extension open, navigate to any website
2. Interact with the site (submit forms, click buttons, navigate pages)
3. Watch as API calls appear in real-time in the extension panel
4. Click on any endpoint to see detailed information

### Enabling Response Body Capture

1. Check the **"Response Bodies"** checkbox in the control bar
2. Accept the debugger permission prompt
3. Response bodies will now be captured and displayed
4. Uncheck to stop capturing and remove debugger

### Viewing Security Issues

1. Look at the security summary badges in the header (Critical/High/Medium/Low counts)
2. Click on any endpoint with a security badge 🛡️
3. Expand the "Security Issues" section to see details
4. Click "Rules" button to configure security rules

---

## 📚 Usage Guide

### Endpoint Details

Click on any endpoint in the sidebar to view:
- **Request Details**: Method, URL, headers, query parameters
- **Request Body**: JSON/Form data sent (if applicable)
- **Response Details**: Status, headers, body (if enabled)
- **Raw HTTP**: Side-by-side request/response view
- **Security Issues**: Detected vulnerabilities with details
- **cURL Command**: Ready-to-use command line equivalent

### Filtering Endpoints

Use the filter bar at the top to search for specific endpoints:

**Basic search:**
```
/api/users
```

**Advanced filters:**
```
method:GET host:api.example.com
status:2xx -tag:internal
/(aac|mga)/
```

**Quick filters:**
- Check **DC** for `/(aac|mga)/` pattern
- Check **GAMX** for `/(sys-gam-digital)/` pattern

### Export Options

**OpenAPI 3.0 Specification:**
1. Click the **"Export"** button
2. Your browser downloads a `.json` file
3. Use with Swagger, Postman, or other API tools

**Individual cURL:**
1. View any endpoint details
2. Scroll to the cURL section
3. Click "Copy" to copy to clipboard
4. Toggle "Complete cURL" for all browser headers

**Open in Swagger:**
1. Click **"Open in Swagger"** button
2. Swagger Editor opens in new tab
3. Paste (`Ctrl+V`) - the spec is already in your clipboard!

**JSON Data Export:**
1. Right-click on endpoint
2. Select "Export as JSON"
3. Download complete capture data

---

## 📖 Documentation

### Comprehensive Guides
- [Security Features & Rules](SECURITY_README.md)
- [Response Body Capture](RESPONSE_BODY_CAPTURE.md)
- [Raw HTTP Viewer](RAW_HTTP_VIEWER.md)
- [Security Quick Start](SECURITY_QUICKSTART.md)
- [Testing Checklist](TESTING_CHECKLIST.md)

### Security Resources
- [CWE-639: Untrusted Client Identity](CWE-639_CLIENT_IDENTITY_TRUST.md)
- [Security Warning Guide](SECURITY_WARNING_GUIDE.md)
- [Security Audit Report](SECURITY_AUDIT_2025-10-18.md)

### Developer Docs
- [Implementation Summary](IMPLEMENTATION_SUMMARY.md)
- [Feature Overview](FEATURE_OVERVIEW.md)
- [Changelog](CHANGELOG.md)

---

## 🐛 Troubleshooting

### Extension not capturing API calls
- Make sure DevTools is open and the GAMX Extension tab is selected
- Verify the "Recording" checkbox is checked (it should be by default)
- Try reloading the extension: Click "Reload Extension" button

### Response bodies not showing
- Enable "Response Bodies" checkbox
- Accept the debugger permission prompt
- Note: Some requests may complete before debugger attaches
- Large response bodies may take a moment to display

### Security warnings not appearing
- Check that security rules are enabled (click "Rules" button)
- View browser console for debug logs (Press F12 → Console tab)
- See [Debugging Guide](DEBUG_CLIENT_IDENTITY.md) for detailed troubleshooting

### Extension not visible in DevTools
- Make sure the extension is installed and enabled
- Restart Chrome/Edge
- Reload the extension from `chrome://extensions/` or `edge://extensions/`

### Performance issues
- Click "Clear" to remove old data
- Disable "Response Bodies" when not needed
- Use filters to focus on specific endpoints

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Bugs**: Open an issue with detailed information
2. **Suggest Features**: Share your ideas for improvements
3. **Submit Pull Requests**: Fix bugs or add features
4. **Improve Documentation**: Help make the docs clearer
5. **Security Rules**: Suggest new vulnerability checks

---

## 📁 Project Structure

```
api-mapper/
├── manifest.json          # Extension configuration
├── background.js          # Service worker / background script
├── devtools.js           # DevTools page registration
├── panel.html            # Extension UI structure
├── panel.js              # Main UI logic and functionality
├── panel.css             # Styling
├── config.js             # Configuration constants
├── security-analyzer.js  # Security vulnerability detection
├── security-rules.json   # Security rule definitions
├── response-capture.js   # Response body capture logic
├── favicon/              # Extension icons
└── docs/                 # Documentation files
    ├── SECURITY_README.md
    ├── RESPONSE_BODY_CAPTURE.md
    ├── RAW_HTTP_VIEWER.md
    └── ...
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with Chrome Extension Manifest V3
- Compatible with both Chrome and Edge browsers
- Security rules based on OWASP Top 10 and CWE standards
- Inspired by the need for better API documentation and security testing tools

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/mikkelkrogsholm/api-mapper/issues)
- **Documentation**: See the `docs/` folder for detailed guides
- **Security**: Report security vulnerabilities responsibly

---

**Made with ❤️ for developers, by developers**

