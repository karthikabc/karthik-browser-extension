# Changelog

All notable changes to GAMX Chrome & Edge Extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2025-10-19

### Changed
- **BREAKING**: Renamed extension from "API Mapper - Security Edition" to "GAMX Chrome & Edge Extension"
- Updated all user-facing text and documentation
- Updated DevTools panel name to "GAMX Extension"
- Updated panel header to "GAMX Security Monitor"

## [2.0.2] - 2025-10-18

### Added
- **Untrusted Client-Supplied Identity Detection** (CWE-639) - Critical security check
- Detects when email/userId is trusted from request body instead of JWT
- Enhanced debug logging for security checks
- Test page for security warning validation
- Comprehensive documentation for CWE-639 vulnerability

### Changed
- Security audit completed: Disabled 4 noisy rules, added 6 critical checks
- Enhanced JWT detection to be more flexible
- Improved verbose error detection with response body pattern matching
- Updated security rules to focus on actionable vulnerabilities

### Security
- Added detection for hardcoded secrets (AWS keys, GitHub tokens, etc.)
- Added open redirect risk detection
- Added SSRF (Server-Side Request Forgery) risk detection
- Added debug/admin endpoint exposure detection
- Enhanced CORS misconfiguration detection
- Improved error information leakage detection

## [2.0.1] - 2025-10-15

### Added
- Response body capture using Chrome Debugger API
- Side-by-side raw HTTP request/response viewer
- "Response Bodies" toggle checkbox
- "View Raw" expandable section for each endpoint
- Copy buttons for raw HTTP content
- Support for JSON, text, and other content types

### Changed
- Enhanced security analysis to include response-based checks
- Security analyzer now runs at both request and response phases
- Improved error handling for disconnected ports

## [2.0.0] - 2025-10-10

### Added
- **Security Analysis System**: 22 built-in security vulnerability checks
- Real-time security issue detection with severity indicators
- Security rules configuration modal
- CWE mappings and remediation guidance
- Security summary badges in header
- Filter by security severity
- Detailed security reports for each endpoint

### Security Rules
- Sensitive data in URLs and headers
- Weak authentication detection
- Insecure HTTP protocol usage
- Missing authentication
- SQL injection, XSS, and path traversal risks
- CORS misconfiguration
- Mass assignment vulnerabilities
- Weak password policies
- Insecure cookies
- PII in request/response bodies
- Missing security headers
- Error information leakage

### Changed
- Upgraded to Manifest V3
- Improved UI with security indicators
- Enhanced endpoint details view
- Better error handling and resilience

## [1.5.0] - 2024-08-15

### Added
- Complete cURL generation with all browser headers
- Toggle for "Complete cURL" vs simple cURL
- Request headers section in details view
- Copy button for cURL commands

### Changed
- Improved curl command formatting
- Better header sanitization
- Enhanced UI for request details

## [1.4.0] - 2024-06-20

### Added
- Advanced filter syntax with tokens (method:, host:, path:, status:)
- Regex literal support in filters `/(pattern)/`
- Field-scoped regex for url/host/path
- DC and GAMX quick filter checkboxes
- Full URL matching in filters

### Changed
- Filter behavior aligned with Chrome DevTools Network tab
- Improved filter performance
- Better filter feedback and UX

## [1.3.0] - 2024-04-10

### Added
- Clear button with immediate UI feedback
- Data versioning to prevent stale updates
- Reload Extension button
- Enhanced error handling for extension context

### Fixed
- Clear button not working properly
- Race conditions with data updates
- "Disconnected port" errors

## [1.2.0] - 2024-02-15

### Added
- Request body capture and display
- Query parameter tracking
- Multiple calls per endpoint history
- Call details view

### Changed
- Improved endpoint grouping
- Better request details organization

## [1.1.0] - 2023-12-01

### Added
- OpenAPI 3.0 export functionality
- Swagger Editor integration
- JSON export
- Export button in UI

### Changed
- Improved documentation generation
- Better schema inference

## [1.0.0] - 2023-10-01

### Added
- Initial release
- Basic API call capture
- Endpoint listing
- DevTools panel integration
- Request headers display
- Basic UI

---

## Legend

- `Added` for new features
- `Changed` for changes in existing functionality
- `Deprecated` for soon-to-be removed features
- `Removed` for now removed features
- `Fixed` for any bug fixes
- `Security` for vulnerability fixes and security improvements
