/**
 * Security Analyzer Module
 * Analyzes API calls for security vulnerabilities based on customizable rules
 */

class SecurityAnalyzer {
  constructor() {
    this.rules = null;
    this.initialized = false;
    this.callFrequency = new Map(); // Track call frequency for rate limiting detection
  }

  /**
   * Initialize the analyzer by loading security rules
   */
  async init() {
    try {
      const response = await fetch(chrome.runtime.getURL('security-rules.json'));
      const config = await response.json();
      this.rules = config.rules;
      this.initialized = true;
      console.log('Security Analyzer initialized with', Object.keys(this.rules).length, 'rules');
    } catch (error) {
      console.error('Failed to load security rules:', error);
      this.initialized = false;
    }
  }

  /**
   * Analyze an API call for security vulnerabilities
   * @param {Object} callDetails - The API call details
   * @returns {Array} Array of detected vulnerabilities
   */
  analyzeCall(callDetails) {
    if (!this.initialized || !this.rules) {
      return [];
    }

    const vulnerabilities = [];
    const url = callDetails.url;
    const method = callDetails.method || 'GET';
    const headers = callDetails.allHeaders || {};
    const queryParams = callDetails.queryParams || {};
    const requestBody = callDetails.requestBody || {};

    // Check each rule
    for (const [ruleId, rule] of Object.entries(this.rules)) {
      if (!rule.enabled) continue;

      try {
        const ruleChecks = this.getRuleChecker(ruleId);
        if (ruleChecks) {
          const issues = ruleChecks.call(this, {
            url,
            method,
            headers,
            queryParams,
            requestBody,
            callDetails
          });
          
          if (issues && issues.length > 0) {
            issues.forEach(issue => {
              vulnerabilities.push({
                ruleId,
                severity: rule.severity,
                name: rule.name,
                description: rule.description,
                message: issue.message || rule.message,
                details: issue.details || {},
                location: issue.location || 'general',
                requestId: callDetails.requestId,
                url: url,
                timestamp: new Date().toISOString()
              });
            });
          }
        }
      } catch (error) {
        console.error(`Error checking rule ${ruleId}:`, error);
      }
    }

    return vulnerabilities;
  }

  /**
   * Get the appropriate checker function for a rule
   */
  getRuleChecker(ruleId) {
    const checkers = {
      'sensitive-data-in-url': this.checkSensitiveDataInUrl,
      'sensitive-headers': this.checkSensitiveHeaders,
      'weak-authentication': this.checkWeakAuthentication,
      'insecure-http': this.checkInsecureHttp,
      'missing-response-security-headers': this.checkMissingResponseSecurityHeaders,
      'cors-misconfiguration': this.checkCorsMisconfiguration,
      'pii-in-request-body': this.checkPiiInRequestBody,
      'pii-in-response-body': this.checkPiiInResponseBody,
      'excessive-data-exposure': this.checkExcessiveDataExposure,
      'sql-injection-risk': this.checkSqlInjectionRisk,
      'xss-risk': this.checkXssRisk,
      'path-traversal-risk': this.checkPathTraversalRisk,
      'insufficient-rate-limiting': this.checkRateLimiting,
      'weak-password-policy': this.checkWeakPasswordPolicy,
      'verbose-error-messages': this.checkVerboseErrors,
      'predictable-resource-ids': this.checkPredictableIds,
      'missing-authentication': this.checkMissingAuthentication,
      'mass-assignment': this.checkMassAssignment,
      'unencrypted-sensitive-data': this.checkUnencryptedSensitiveData,
      'insecure-cookies': this.checkInsecureCookies,
      'missing-input-validation': this.checkMissingInputValidation,
      'hardcoded-secrets': this.checkHardcodedSecrets,
      'open-redirect': this.checkOpenRedirect,
      'ssrf-risk': this.checkSsrfRisk,
      'debug-endpoints': this.checkDebugEndpoints,
      'untrusted-client-identity': this.checkUntrustedClientIdentity,
      'idor-in-path': this.checkIdorInPath,
      'jwt-security': this.checkJwtSecurity,
      'http-method-override': this.checkHttpMethodOverride,
      'server-version-disclosure': this.checkServerVersionDisclosure,
      'command-injection-risk': this.checkCommandInjectionRisk,
      'xxe-risk': this.checkXxeRisk,
      'broken-access-control': this.checkBrokenAccessControl,
      'crlf-injection': this.checkCrlfInjection,
      'sensitive-file-exposure': this.checkSensitiveFileExposure,
      'authorization-header-exposure': this.checkAuthorizationHeaderExposure,
      'ssti-risk': this.checkSstiRisk,
      'insecure-deserialization': this.checkInsecureDeserialization,
      'host-header-injection': this.checkHostHeaderInjection,
      'graphql-introspection': this.checkGraphqlIntrospection,
      'api-version-bypass': this.checkApiVersionBypass,
      'race-condition-risk': this.checkRaceConditionRisk,
      'ldap-injection-risk': this.checkLdapInjectionRisk,
      'nosql-injection-risk': this.checkNoSqlInjectionRisk,
      'sensitive-param-names': this.checkSensitiveParamNames,
      'prototype-pollution': this.checkPrototypePollution,
      'unsafe-csp': this.checkUnsafeCsp,
      'cache-poisoning-risk': this.checkCachePoisoningRisk,
      'business-logic-bypass': this.checkBusinessLogicBypass,
      'missing-rate-limit-headers': this.checkMissingRateLimitHeaders,
      'file-upload-risk': this.checkFileUploadRisk,
      'subdomain-takeover-risk': this.checkSubdomainTakeoverRisk,
      'email-header-injection': this.checkEmailHeaderInjection,
      'xpath-injection-risk': this.checkXPathInjectionRisk
    };

    return checkers[ruleId];
  }

  /**
   * Check for sensitive data in URL
   */
  checkSensitiveDataInUrl(context) {
    const issues = [];
    const rule = this.rules['sensitive-data-in-url'];
    const fullUrl = context.url;

    for (const [patternName, pattern] of Object.entries(rule.patterns)) {
      const regex = new RegExp(pattern, 'gi');
      const matches = fullUrl.match(regex);
      
      if (matches) {
        issues.push({
          message: `Sensitive data detected in URL: ${patternName}`,
          details: {
            type: patternName,
            matchCount: matches.length,
            example: matches[0].substring(0, 20) + '...',
            fixType: 'Server-side/Client-side',
            remediation: 'Do not pass sensitive data in URL parameters. Use POST body instead.'
          },
          location: 'url'
        });
      }
    }

    return issues;
  }

  /**
   * Check for sensitive data in headers
   */
  checkSensitiveHeaders(context) {
    const issues = [];
    const rule = this.rules['sensitive-headers'];
    const headers = context.headers;

    for (const [headerName, headerValue] of Object.entries(headers)) {
      const lowerHeaderName = headerName.toLowerCase();
      
      if (rule.headers.some(h => lowerHeaderName.includes(h))) {
        issues.push({
          message: `Sensitive data in header: ${headerName}`,
          details: {
            header: headerName,
            reason: 'PII should not be transmitted in headers',
            fixType: 'Server-side/Client-side',
            remediation: 'Do not use custom headers to transmit sensitive information.'
          },
          location: 'headers'
        });
      }
    }

    return issues;
  }

  /**
   * Check for weak authentication - only flag basic auth over HTTP
   */
  checkWeakAuthentication(context) {
    const issues = [];
    const rule = this.rules['weak-authentication'];
    const headers = context.headers;
    const queryParams = context.queryParams;
    const isHttp = context.url.startsWith('http://');

    rule.checks.forEach(check => {
      if (check.type === 'basic_auth_over_http') {
        const authHeader = headers['Authorization'] || headers['authorization'];
        if (isHttp && authHeader && new RegExp(check.pattern).test(authHeader)) {
          issues.push({
            message: check.message,
            details: { 
                type: 'basic_auth_over_http', 
                protocol: 'HTTP',
                fixType: 'Server-side',
                remediation: 'Use HTTPS for Basic Authentication.'
            },
            location: 'headers'
          });
        }
      }
      
      if (check.type === 'api_key_in_query') {
        const foundParams = check.params.filter(param => 
          Object.keys(queryParams).some(qp => qp.toLowerCase() === param.toLowerCase())
        );
        if (foundParams.length > 0) {
          issues.push({
            message: check.message,
            details: { 
                params: foundParams,
                fixType: 'Server-side/Client-side',
                remediation: 'Do not pass API keys in query parameters. Use Authorization header instead.'
            },
            location: 'query'
          });
        }
      }
    });

    return issues;
  }

  /**
   * Check for insecure HTTP
   */
  checkInsecureHttp(context) {
    const issues = [];
    const rule = this.rules['insecure-http'];
    
    if (context.url.startsWith('http://')) {
      issues.push({
        message: rule.message,
        details: { 
            protocol: 'http',
            fixType: 'Server-side',
            remediation: 'Enable HTTPS and redirect HTTP traffic to HTTPS.'
        },
        location: 'protocol'
      });
    }

    return issues;
  }

  /**
   * Check for missing security headers with enhanced HSTS and scope awareness
   */
  checkMissingResponseSecurityHeaders(context) {
    const issues = [];
    const rule = this.rules['missing-response-security-headers'];
    if (!rule || !rule.headers) return [];

    const call = context.callDetails || {};
    
    // CRITICAL: Only evaluate response headers after the response has been received.
    // This check runs twice: once during onBeforeSendHeaders (request phase) and
    // once during onCompleted (response phase). We must skip the request phase
    // to avoid false positives when responseHeaders haven't been populated yet.
    // We detect response phase by checking if status code is set (only set in onCompleted).
    if (!call.status) {
      // Request phase - response headers not available yet, skip this check
      return [];
    }
    
    const responseHeaders = call.responseHeaders || {};
    // Normalize header names to lowercase for case-insensitive lookup
    const headersMap = new Map();
    Object.keys(responseHeaders).forEach(h => headersMap.set(h.toLowerCase(), responseHeaders[h]));

    const url = context.url || '';
    const isHttps = url.toLowerCase().startsWith('https://');
    const status = call.status || 0;
    const isRedirect = status >= 300 && status < 400;
    const method = (context.method || '').toUpperCase();
    const isOptions = method === 'OPTIONS';

    // Enhanced logic definitions
    const headerLogic = {
      'strict-transport-security': {
        check: (value) => {
            // HSTS Requirements:
            // 1. HTTPS-only rule: Only require HSTS when the final request URL scheme is HTTPS.
            if (!isHttps) return { status: 'not-applicable', reason: 'Non-HTTPS scheme' };
            
            // 2. Final-response evaluation: Do not evaluate on Redirects (3xx)
            if (isRedirect) return { status: 'not-applicable', reason: 'Redirect response' };
            
            // 3. Final-response evaluation: Do not evaluate on OPTIONS
            if (isOptions) return { status: 'not-applicable', reason: 'OPTIONS method' };
            
            // 4. Header presence logic: If missing on final HTTPS response
            if (!value) return { status: 'missing' };
            
            // 5. Normalize the header value for robust parsing:
            //    - Trim leading/trailing whitespace
            //    - Normalize whitespace around semicolons and equals signs
            //    This handles HTTP/2 and HTTP/3 header variations
            const normalizedValue = value
              .trim()
              .replace(/\s*;\s*/g, ';')  // Remove whitespace around semicolons
              .replace(/\s*=\s*/g, '='); // Remove whitespace around equals signs
            
            // 6. Compliance thresholds - use case-insensitive matching
            //    Match max-age directive with optional whitespace already normalized
            const maxAgeMatch = normalizedValue.match(/max-age=(\d+)/i);
            
            // Validate that max-age directive exists and has a valid numeric value
            if (!maxAgeMatch) {
              return {
                status: 'weak',
                message: 'HSTS header present but missing valid max-age directive',
                details: { rawValue: value, normalizedValue }
              };
            }
            
            const maxAge = parseInt(maxAgeMatch[1], 10);
            const includeSubDomains = /includeSubDomains/i.test(normalizedValue);
            const preload = /preload/i.test(normalizedValue);

            // Treat as compliant if max-age >= 31536000 (1 year)
            if (maxAge < 31536000) {
                return { 
                    status: 'weak', 
                    message: 'HSTS max-age is less than 1 year (31536000 seconds)',
                    details: { maxAge, includeSubDomains, preload }
                };
            }
            
            // 6. Reporting classification: PRESENT (Compliant)
            return { status: 'compliant', details: { maxAge, includeSubDomains, preload } };
        },
        description: 'Enforces secure (HTTP over SSL/TLS) connections to the server.',
        remediation: 'Configure on Server-side (Web Server, Load Balancer, or CDN). Ensure max-age >= 31536000.'
      },
      'content-security-policy': {
        check: (value) => !value ? { status: 'missing' } : { status: 'compliant' },
        description: 'Prevents cross-site scripting (XSS), clickjacking and other code injection attacks.',
        remediation: 'Configure on Server-side. Define allowed sources for content.'
      },
      'x-frame-options': {
        check: (value) => !value ? { status: 'missing' } : { status: 'compliant' },
        description: 'Protects against Clickjacking attacks.',
        remediation: 'Configure on Server-side.'
      },
      'x-content-type-options': {
        check: (value) => {
          // Skip evaluation for redirect responses - evaluate only final response
          if (isRedirect) return { status: 'not-applicable', reason: 'Redirect response' };
          
          // Header is missing
          if (!value) return { status: 'missing' };
          
          // Normalize the value: trim whitespace and compare case-insensitively
          // This handles HTTP/1.1, HTTP/2, HTTP/3 and gzip encoding variations
          const normalizedValue = value.trim().toLowerCase();
          
          // The only valid value for x-content-type-options is "nosniff"
          if (normalizedValue === 'nosniff') {
            return { status: 'compliant' };
          }
          
          // Header present but with invalid value
          return { 
            status: 'weak', 
            message: `Invalid value "${value}" - must be "nosniff"`,
            details: { currentValue: value, expectedValue: 'nosniff' }
          };
        },
        description: 'Prevents MIME type sniffing.',
        remediation: 'Configure on Server-side. Set header value to "nosniff".'
      },
      'referrer-policy': {
        check: (value) => !value ? { status: 'missing' } : { status: 'compliant' },
        description: 'Controls how much referrer information is included with requests.',
        remediation: 'Configure on Server-side.'
      },
      'permissions-policy': {
        check: (value) => !value ? { status: 'missing' } : { status: 'compliant' },
        description: 'Allows a site to allow or block the use of browser features.',
        remediation: 'Configure on Server-side.'
      }
    };

    rule.headers.forEach(headerName => {
        const lowerName = headerName.toLowerCase();
        const headerValue = headersMap.get(lowerName);
        const logic = headerLogic[lowerName];

        if (logic) {
            const result = logic.check(headerValue);
            
            // For HSTS specifically, handle all classification states
            if (lowerName === 'strict-transport-security') {
                if (result.status === 'not-applicable') {
                    // Do NOT create a finding for non-applicable cases
                    // (HTTP, redirects, OPTIONS) - this prevents false positives
                    return;
                } else if (result.status === 'compliant') {
                    // PRESENT - Header exists with valid max-age. No finding needed.
                    return;
                } else if (result.status === 'weak') {
                    // WEAK CONFIGURATION - Header present but max-age below threshold
                    issues.push({
                        message: `Weak configuration for ${headerName}: ${result.message}`,
                        details: {
                            header: headerName,
                            currentValue: headerValue,
                            classification: 'WEAK CONFIGURATION',
                            ...result.details,
                            remediation: logic.remediation,
                            fixType: 'Server-side',
                            findingStatus: 'Informational',
                            evaluationContext: 'Final HTTPS response evaluated'
                        },
                        location: 'response-headers'
                    });
                } else if (result.status === 'missing') {
                    // MISSING - Only if final HTTPS response lacks the header
                    issues.push({
                        message: `Missing security header: ${headerName}`,
                        details: {
                            header: headerName,
                            classification: 'MISSING',
                            description: logic.description,
                            remediation: logic.remediation,
                            fixType: 'Server-side',
                            findingStatus: 'Confirmed Issue',
                            evaluationContext: 'Final HTTPS response evaluated - header absent'
                        },
                        location: 'response-headers'
                    });
                }
            } else {
                // For other headers, use enhanced logic that handles all statuses
                if (result.status === 'not-applicable') {
                    // Do NOT create a finding for non-applicable cases
                    // (e.g., redirects for x-content-type-options)
                    return;
                } else if (result.status === 'compliant') {
                    // Header exists with valid value. No finding needed.
                    return;
                } else if (result.status === 'missing') {
                    issues.push({
                        message: `Missing security header: ${headerName}`,
                        details: {
                            header: headerName,
                            description: logic.description,
                            remediation: logic.remediation,
                            fixType: 'Server-side',
                            findingStatus: 'Confirmed Issue'
                        },
                        location: 'response-headers'
                    });
                } else if (result.status === 'weak') {
                    issues.push({
                        message: `Weak configuration for ${headerName}: ${result.message}`,
                        details: {
                            header: headerName,
                            currentValue: headerValue,
                            ...result.details,
                            remediation: logic.remediation,
                            fixType: 'Server-side',
                            findingStatus: 'Confirmed Issue'
                        },
                        location: 'response-headers'
                    });
                }
            }
        } else {
            // Fallback for other headers in the list
            if (!headerValue) {
                issues.push({
                    message: `Missing recommended security header: ${headerName}`,
                    details: { 
                        header: headerName, 
                        fixType: 'Server-side',
                        findingStatus: 'Confirmed Issue'
                    },
                    location: 'response-headers'
                });
            }
        }
    });

    return issues;
  }

  /**
   * Check for CORS misconfiguration - enhanced with multiple checks
   */
  checkCorsMisconfiguration(context) {
    const issues = [];
    const rule = this.rules['cors-misconfiguration'];
    const resp = context.callDetails || {};
    const responseHeaders = resp.responseHeaders || {};
    const requestHeaders = context.headers || {};
    
    const acao = responseHeaders['Access-Control-Allow-Origin'] || responseHeaders['access-control-allow-origin'];
    const acac = responseHeaders['Access-Control-Allow-Credentials'] || responseHeaders['access-control-allow-credentials'];
    const requestOrigin = requestHeaders['Origin'] || requestHeaders['origin'];

    // Check 1: Wildcard with credentials
    if (acao === '*' && acac && acac.toLowerCase() === 'true') {
      issues.push({
        message: rule.checks[0].message,
        details: { 
            acao, 
            acac, 
            type: 'wildcard_with_credentials',
            fixType: 'Server-side',
            remediation: 'Configure CORS on the server to not allow wildcard origins with credentials.'
        },
        location: 'response-headers'
      });
    }
    
    // Check 2: Null origin allowed
    if (acao === 'null' && acac && acac.toLowerCase() === 'true') {
      issues.push({
        message: rule.checks[1].message,
        details: { 
            acao, 
            acac, 
            type: 'null_origin',
            fixType: 'Server-side',
            remediation: 'Do not allow "null" origin in CORS configuration.'
        },
        location: 'response-headers'
      });
    }
    
    // Check 3: Origin reflection (ACAO matches request Origin exactly)
    if (requestOrigin && acao === requestOrigin && acac && acac.toLowerCase() === 'true') {
      // Only flag if it looks like reflection (not a legitimate allowlist match)
      issues.push({
        message: rule.checks[2].message,
        details: { 
            acao, 
            requestOrigin, 
            acac, 
            type: 'origin_reflection',
            fixType: 'Server-side',
            remediation: 'Validate the Origin header against a strict allowlist on the server.'
        },
        location: 'response-headers'
      });
    }

    return issues;
  }

  /**
   * Check for PII in request body
   */
  checkPiiInRequestBody(context) {
    const issues = [];
    const rule = this.rules['pii-in-request-body'];
    const requestBody = context.requestBody;

    if (requestBody && typeof requestBody === 'object') {
      const foundFields = this.findFieldsInObject(requestBody, rule.fields);
      
      if (foundFields.length > 0) {
        issues.push({
          message: `PII detected in request body: ${foundFields.join(', ')}`,
          details: { 
              fields: foundFields,
              fixType: 'Client-side',
              remediation: 'Ensure PII is not sent in the request body unless absolutely necessary and encrypted.'
          },
          location: 'body'
        });
      }
    }

    return issues;
  }

  /**
   * Check for excessive data exposure
   */
  checkExcessiveDataExposure(context) {
    const issues = [];
    const rule = this.rules['excessive-data-exposure'];
    
    if (context.method === 'GET') {
      const queryParams = context.queryParams;
      const hasLimit = Object.keys(queryParams).some(key => 
        ['limit', 'page', 'size', 'per_page', 'pageSize'].includes(key.toLowerCase())
      );
      
      if (!hasLimit) {
        issues.push({
          message: rule.checks[0].message,
          details: { 
              recommendation: 'Implement pagination with limit/page parameters',
              fixType: 'Server-side',
              remediation: 'Implement pagination for this endpoint to prevent excessive data exposure.'
          },
          location: 'query'
        });
      }
    }

    return issues;
  }

  /**
   * Check for SQL injection risk
   */
  checkSqlInjectionRisk(context) {
    const issues = [];
    const rule = this.rules['sql-injection-risk'];
    
    const valuesToCheck = [
      ...Object.values(context.queryParams),
      ...this.getDeepValues(context.requestBody)
    ];

    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(value)) {
            issues.push({
              message: 'Potential SQL injection pattern detected',
              details: { 
                pattern,
                sample: value.substring(0, 50) + (value.length > 50 ? '...' : '')
              },
              location: 'parameters'
            });
          }
        });
      }
    });

    return issues;
  }

  /**
   * Check for XSS risk
   */
  checkXssRisk(context) {
    const issues = [];
    const rule = this.rules['xss-risk'];
    
    const valuesToCheck = [
      ...Object.values(context.queryParams),
      ...this.getDeepValues(context.requestBody)
    ];

    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(value)) {
            issues.push({
              message: 'Potential XSS pattern detected',
              details: { 
                pattern,
                sample: value.substring(0, 50) + (value.length > 50 ? '...' : '')
              },
              location: 'parameters'
            });
          }
        });
      }
    });

    return issues;
  }

  /**
   * Check for path traversal risk
   */
  checkPathTraversalRisk(context) {
    const issues = [];
    const rule = this.rules['path-traversal-risk'];
    
    const valuesToCheck = [
      context.url,
      ...Object.values(context.queryParams),
      ...this.getDeepValues(context.requestBody)
    ];

    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(value)) {
            issues.push({
              message: 'Potential path traversal pattern detected',
              details: { 
                pattern,
                sample: value.substring(0, 50) + (value.length > 50 ? '...' : '')
              },
              location: 'parameters'
            });
          }
        });
      }
    });

    return issues;
  }

  /**
   * Check for insufficient rate limiting
   */
  checkRateLimiting(context) {
    const issues = [];
    const rule = this.rules['insufficient-rate-limiting'];
    const endpoint = `${context.method} ${new URL(context.url).pathname}`;
    const now = Date.now();

    if (!this.callFrequency.has(endpoint)) {
      this.callFrequency.set(endpoint, []);
    }

    const calls = this.callFrequency.get(endpoint);
    calls.push(now);

    // Keep only calls within the time window
    const recentCalls = calls.filter(time => now - time < rule.timeWindow);
    this.callFrequency.set(endpoint, recentCalls);

    if (recentCalls.length > rule.threshold) {
      const hasRateLimitHeaders = context.headers['X-RateLimit-Limit'] || 
                                  context.headers['x-ratelimit-limit'] ||
                                  context.headers['RateLimit-Limit'];
      
      if (!hasRateLimitHeaders) {
        issues.push({
          message: rule.message,
          details: { 
            callCount: recentCalls.length,
            threshold: rule.threshold,
            timeWindow: rule.timeWindow
          },
          location: 'general'
        });
      }
    }

    return issues;
  }

  /**
   * Check for weak password policy
   */
  checkWeakPasswordPolicy(context) {
    const issues = [];
    const rule = this.rules['weak-password-policy'];
    const requestBody = context.requestBody;

    if (requestBody && typeof requestBody === 'object') {
      rule.checks.forEach(check => {
        const passwordValue = this.findFieldValue(requestBody, check.field);
        if (passwordValue && typeof passwordValue === 'string') {
          if (passwordValue.length < check.min_length) {
            issues.push({
              message: check.message,
              details: { 
                actualLength: passwordValue.length,
                requiredLength: check.min_length
              },
              location: 'body'
            });
          }
        }
      });
    }

    return issues;
  }

  /**
   * Check for verbose error messages
   */
  checkVerboseErrors(context) {
    const issues = [];
    const rule = this.rules['verbose-error-messages'];
    const status = context.callDetails.status;
    const body = context.callDetails.responseBody || '';
    if (status && rule.status_codes.includes(status) && typeof body === 'string') {
      const patterns = (rule.patterns || []).map(p => new RegExp(p, 'i'));
      const matched = patterns.find(re => re.test(body));
      if (matched) {
        issues.push({
          message: `${rule.message} (Status: ${status})`,
          details: {
            status,
            sample: body.substring(0, 200)
          },
          location: 'response-body'
        });
      }
    }

    return issues;
  }

  /**
   * Check for predictable resource IDs
   */
  checkPredictableIds(context) {
    const issues = [];
    const rule = this.rules['predictable-resource-ids'];
    const urlPath = new URL(context.url).pathname;
    const regex = new RegExp(rule.pattern, 'g');
    const matches = urlPath.match(regex);

    if (matches && matches.length > 0) {
      // Check if it's a simple numeric ID (not a UUID or complex identifier)
      const simpleNumericIds = matches.filter(match => 
        /^\d{1,8}$/.test(match) && parseInt(match) < 1000000
      );

      if (simpleNumericIds.length > 0) {
        issues.push({
          message: rule.message,
          details: { 
            ids: simpleNumericIds,
            recommendation: 'Use UUIDs or non-sequential identifiers'
          },
          location: 'path'
        });
      }
    }

    return issues;
  }

  /**
   * Check for missing authentication - with method exclusions
   */
  checkMissingAuthentication(context) {
    const issues = [];
    const rule = this.rules['missing-authentication'];
    const headers = context.headers;
    const urlPath = new URL(context.url).pathname;
    const method = (context.method || 'GET').toUpperCase();

    // Check if method is excluded (OPTIONS, HEAD)
    if (rule.excludeMethods && rule.excludeMethods.includes(method)) {
      return issues;
    }

    // Check if path is excluded
    const isExcluded = rule.excludePaths.some(path => 
      urlPath.toLowerCase().includes(path.toLowerCase())
    );

    if (!isExcluded) {
      const hasAuth = headers['Authorization'] || headers['authorization'] ||
                     headers['X-API-Key'] || headers['x-api-key'] ||
                     headers['Cookie'] || headers['cookie'];

      if (!hasAuth) {
        issues.push({
          message: rule.message,
          details: { 
            path: urlPath,
            method: method,
            recommendation: 'Implement proper authentication mechanism'
          },
          location: 'headers'
        });
      }
    }

    return issues;
  }

  /**
   * Check for mass assignment vulnerabilities
   */
  checkMassAssignment(context) {
    const issues = [];
    const rule = this.rules['mass-assignment'];
    const requestBody = context.requestBody;

    if (requestBody && typeof requestBody === 'object') {
      const foundFields = this.findFieldsInObject(requestBody, rule.sensitiveFields);
      
      if (foundFields.length > 0) {
        issues.push({
          message: rule.message,
          details: { 
            fields: foundFields,
            recommendation: 'Whitelist allowed fields on server-side'
          },
          location: 'body'
        });
      }
    }

    return issues;
  }

  /**
   * Check for unencrypted sensitive data
   */
  checkUnencryptedSensitiveData(context) {
    const issues = [];
    const rule = this.rules['unencrypted-sensitive-data'];
    const requestBody = context.requestBody;

    if (context.url.startsWith('http://') && requestBody && typeof requestBody === 'object') {
      const foundFields = this.findFieldsInObject(requestBody, rule.fields);
      
      if (foundFields.length > 0) {
        issues.push({
          message: `${rule.message}: ${foundFields.join(', ')}`,
          details: { 
            fields: foundFields,
            protocol: 'HTTP'
          },
          location: 'body'
        });
      }
    }

    return issues;
  }

  /**
   * Check for insecure cookie attributes in response
   * Enhanced to reduce false positives by focusing on:
   * 1. Critical issues (SameSite=None without Secure, prefix violations)
   * 2. Authentication/session cookies (based on common naming patterns)
   */
  checkInsecureCookies(context) {
    const issues = [];
    const rule = this.rules['insecure-cookies'];
    if (!rule) return issues;
    
    const responseHeaders = (context.callDetails && context.callDetails.responseHeaders) || {};
    const setCookieHeader = responseHeaders['Set-Cookie'] || responseHeaders['set-cookie'];
    if (!setCookieHeader) return issues;

    // Auth cookie patterns to identify sensitive cookies
    const authPatterns = rule.authCookiePatterns || 
      ['session', 'sess', 'sid', 'auth', 'token', 'jwt', 'access', 'refresh', 'login', 'credential', 'jsessionid', 'phpsessid', 'asp.net_sessionid', 'connect.sid'];
    const authRegex = new RegExp(`^(${authPatterns.join('|')})`, 'i');

    const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    
    cookies.forEach((cookie) => {
      const cookieName = cookie.split('=')[0].trim();
      const cookiePreview = cookie.split(';')[0];
      
      // Parse cookie attributes
      const hasSecure = /;\s*Secure/i.test(cookie);
      const hasHttpOnly = /;\s*HttpOnly/i.test(cookie);
      const sameSiteMatch = cookie.match(/;\s*SameSite=(Strict|Lax|None)/i);
      const hasSameSite = !!sameSiteMatch;
      const sameSiteValue = sameSiteMatch ? sameSiteMatch[1].toLowerCase() : null;
      const hasDomain = /;\s*Domain=/i.test(cookie);
      const pathMatch = cookie.match(/;\s*Path=([^;]*)/i);
      const pathValue = pathMatch ? pathMatch[1].trim() : null;
      
      // Check if this looks like an auth/session cookie
      const isAuthCookie = authRegex.test(cookieName);
      
      // CRITICAL: SameSite=None without Secure (browsers will reject this)
      if (sameSiteValue === 'none' && !hasSecure) {
        issues.push({
          message: rule.checks?.sameSiteNoneWithoutSecure?.message || 'SameSite=None requires Secure flag',
          severity: 'high',
          details: {
            cookiePreview,
            issue: 'SameSite=None without Secure flag',
            impact: 'Cookie will be rejected by modern browsers',
            fixType: 'Server-side',
            remediation: 'Add Secure flag when using SameSite=None'
          },
          location: 'response-headers'
        });
      }
      
      // CRITICAL: __Secure- prefix violation
      if (cookieName.startsWith('__Secure-') && !hasSecure) {
        issues.push({
          message: rule.checks?.securePrefixViolation?.message || '__Secure- cookie missing Secure flag',
          severity: 'high',
          details: {
            cookiePreview,
            issue: '__Secure- prefix requires Secure flag',
            fixType: 'Server-side',
            remediation: 'Add Secure flag or remove __Secure- prefix'
          },
          location: 'response-headers'
        });
      }
      
      // CRITICAL: __Host- prefix violation
      if (cookieName.startsWith('__Host-')) {
        const violations = [];
        if (!hasSecure) violations.push('missing Secure flag');
        if (hasDomain) violations.push('must not have Domain attribute');
        if (pathValue !== '/') violations.push('Path must be "/"');
        
        if (violations.length > 0) {
          issues.push({
            message: rule.checks?.hostPrefixViolation?.message || '__Host- cookie prefix violation',
            severity: 'high',
            details: {
              cookiePreview,
              issue: '__Host- prefix requirements not met',
              violations,
              fixType: 'Server-side',
              remediation: '__Host- cookies must have Secure, no Domain, and Path=/'
            },
            location: 'response-headers'
          });
        }
      }
      
      // HIGH: Auth/session cookie without Secure flag
      if (isAuthCookie && !hasSecure) {
        issues.push({
          message: rule.checks?.missingSecureOnAuth?.message || 'Session cookie missing Secure flag',
          severity: 'high',
          details: {
            cookiePreview,
            issue: 'Authentication cookie transmitted over insecure connection',
            fixType: 'Server-side',
            remediation: 'Add Secure flag to prevent transmission over HTTP'
          },
          location: 'response-headers'
        });
      }
      
      // MEDIUM: Auth/session cookie without HttpOnly flag
      if (isAuthCookie && !hasHttpOnly) {
        issues.push({
          message: rule.checks?.missingHttpOnlyOnAuth?.message || 'Session cookie missing HttpOnly flag',
          severity: 'medium',
          details: {
            cookiePreview,
            issue: 'Authentication cookie accessible to JavaScript',
            fixType: 'Server-side',
            remediation: 'Add HttpOnly flag to prevent XSS cookie theft'
          },
          location: 'response-headers'
        });
      }
      
      // Note: We intentionally DO NOT flag:
      // - Non-auth cookies missing Secure/HttpOnly (too many false positives)
      // - Missing SameSite on non-auth cookies (defaults to Lax in modern browsers)
    });

    return issues;
  }

  /**
   * Check for PII patterns in response body
   */
  checkPiiInResponseBody(context) {
    const issues = [];
    const rule = this.rules['pii-in-response-body'];
    const body = context.callDetails && context.callDetails.responseBody;
    if (!body || typeof body !== 'string') return issues;
    Object.entries(rule.patterns || {}).forEach(([name, pattern]) => {
      const re = new RegExp(pattern, 'i');
      if (re.test(body)) {
        issues.push({
          message: `Sensitive data detected in response: ${name}`,
          details: { 
              pattern: name,
              fixType: 'Server-side',
              remediation: 'Ensure PII is not exposed in the response body unless absolutely necessary and encrypted.'
          },
          location: 'response-body'
        });
      }
    });
    return issues;
  }

  /**
   * Check for missing input validation indicators
   */
  checkMissingInputValidation(context) {
    const issues = [];
    const rule = this.rules['missing-input-validation'];
    
    // Check if user-controlled input is present without validation headers
    const valuesToCheck = [
      ...Object.values(context.queryParams),
      ...this.getDeepValues(context.requestBody)
    ];

    const hasDangerousInput = valuesToCheck.some(val => {
      if (typeof val !== 'string') return false;
      // Check for special chars that might indicate lack of sanitization
      return val.length > 100 || /[<>'"\\]/.test(val);
    });

    if (hasDangerousInput) {
      const responseHeaders = (context.callDetails && context.callDetails.responseHeaders) || {};
      const hasValidationHeaders = responseHeaders['X-Content-Type-Options'] || 
                                    responseHeaders['x-content-type-options'];
      
      if (!hasValidationHeaders && context.method !== 'GET') {
        issues.push({
          message: rule.message,
          details: { 
            recommendation: 'Ensure server validates and sanitizes all user input'
          },
          location: 'general'
        });
      }
    }

    return issues;
  }

  /**
   * Check for hardcoded secrets in requests
   */
  checkHardcodedSecrets(context) {
    const issues = [];
    const rule = this.rules['hardcoded-secrets'];
    const fullUrl = context.url;
    const requestBody = JSON.stringify(context.requestBody || {});
    const allHeaders = Object.values(context.headers).join(' ');
    
    const textToCheck = [fullUrl, requestBody, allHeaders].join(' ');

    Object.entries(rule.patterns || {}).forEach(([name, pattern]) => {
      const re = new RegExp(pattern, 'g');
      const matches = textToCheck.match(re);
      if (matches && matches.length > 0) {
        issues.push({
          message: `Potential hardcoded secret detected: ${name}`,
          details: { 
            type: name,
            recommendation: 'Use environment variables or secure vaults for secrets'
          },
          location: 'request'
        });
      }
    });

    return issues;
  }

  /**
   * Check for open redirect vulnerabilities
   */
  checkOpenRedirect(context) {
    const issues = [];
    const rule = this.rules['open-redirect'];
    const queryParams = context.queryParams || {};
    
    const foundParams = rule.params.filter(param => 
      Object.keys(queryParams).some(qp => qp.toLowerCase() === param.toLowerCase())
    );

    if (foundParams.length > 0) {
      foundParams.forEach(param => {
        const value = queryParams[param] || queryParams[param.toLowerCase()];
        // Check if value looks like a URL
        if (value && (value.startsWith('http://') || value.startsWith('https://') || value.startsWith('//'))) {
          issues.push({
            message: `Potential open redirect via parameter: ${param}`,
            details: { 
              param,
              recommendation: 'Validate redirect URLs against allowlist'
            },
            location: 'query'
          });
        }
      });
    }

    return issues;
  }

  /**
   * Check for SSRF risks
   */
  checkSsrfRisk(context) {
    const issues = [];
    const rule = this.rules['ssrf-risk'];
    const queryParams = context.queryParams || {};
    const requestBody = context.requestBody || {};
    
    const allParams = { ...queryParams };
    this.findFieldsInObject(requestBody, rule.params, true).forEach(item => {
      allParams[item.path] = item.value;
    });

    const foundParams = rule.params.filter(param => 
      Object.keys(allParams).some(p => p.toLowerCase().includes(param.toLowerCase()))
    );

    if (foundParams.length > 0) {
      foundParams.forEach(param => {
        const matchingKey = Object.keys(allParams).find(k => k.toLowerCase().includes(param.toLowerCase()));
        const value = allParams[matchingKey];
        // Check if value looks like a URL or endpoint
        if (value && typeof value === 'string' && (
          value.startsWith('http://') || 
          value.startsWith('https://') || 
          value.includes('://') ||
          /^[a-z0-9.-]+\.[a-z]{2,}/.test(value)
        )) {
          issues.push({
            message: `Potential SSRF risk via parameter: ${matchingKey}`,
            details: { 
              param: matchingKey,
              recommendation: 'Validate URLs against allowlist and use internal DNS resolution'
            },
            location: 'parameters'
          });
        }
      });
    }

    return issues;
  }

  /**
   * Check for debug/admin endpoints
   */
  checkDebugEndpoints(context) {
    const issues = [];
    const rule = this.rules['debug-endpoints'];
    const urlPath = new URL(context.url).pathname.toLowerCase();

    const matchedPattern = rule.patterns.find(pattern => 
      urlPath.includes(pattern.toLowerCase())
    );

    if (matchedPattern) {
      issues.push({
        message: `Potentially sensitive endpoint accessed: ${matchedPattern}`,
        details: { 
          pattern: matchedPattern,
          recommendation: 'Ensure debug/admin endpoints are properly secured'
        },
        location: 'path'
      });
    }

    return issues;
  }

  /**
   * Check for untrusted client-supplied identity
   * Critical: Identity should be extracted from JWT/session, not trusted from request body
   */
  checkUntrustedClientIdentity(context) {
    const issues = [];
    const rule = this.rules['untrusted-client-identity'];
    if (!rule) return issues;
    
    const headers = context.headers;
    const requestBody = context.requestBody;
    const urlPath = new URL(context.url).pathname.toLowerCase();
    const method = context.method || 'GET';

    // Only check POST, PUT, PATCH methods
    if (!['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
      return issues;
    }

    // Skip if this is an excluded endpoint (login, register, etc.)
    const isExcluded = rule.excludeEndpoints.some(endpoint => 
      urlPath.includes(endpoint.toLowerCase())
    );
    
    if (isExcluded) {
      console.log('[untrusted-client-identity] Excluded endpoint:', urlPath);
      return issues;
    }
    
    if (!requestBody || typeof requestBody !== 'object') {
      console.log('[untrusted-client-identity] No request body or not an object:', typeof requestBody);
      return issues;
    }

    // Check if JWT/bearer token is present - check multiple header variations
    const authHeader = headers['Authorization'] || headers['authorization'] || 
                       headers['AUTHORIZATION'] || headers['Auth'] || headers['auth'];
    
    // More flexible JWT detection
    const hasJWT = authHeader && (
      /^Bearer\s+eyJ/i.test(authHeader) ||  // Bearer eyJ...
      /^eyJ/.test(authHeader) ||             // eyJ... (direct JWT)
      authHeader.includes('eyJ')             // Contains JWT anywhere
    );

    console.log('[untrusted-client-identity] Auth header:', authHeader ? 'Present' : 'Missing');
    console.log('[untrusted-client-identity] Has JWT:', hasJWT);
    console.log('[untrusted-client-identity] Request body keys:', Object.keys(requestBody));

    // If JWT is present, check for identity fields in request body
    if (hasJWT) {
      const foundFields = this.findFieldsInObject(requestBody, rule.identityFields);
      
      console.log('[untrusted-client-identity] Found identity fields:', foundFields);
      
      if (foundFields.length > 0) {
        issues.push({
          message: rule.message,
          details: { 
            fields: foundFields,
            recommendation: 'Extract user identity (email, userId) from JWT claims on server-side. Never trust client-supplied identity when authenticated.',
            impact: 'Account takeover, privilege escalation, unauthorized access',
            cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key'
          },
          location: 'body'
        });
        console.log('[untrusted-client-identity] ⚠️ CRITICAL ISSUE DETECTED!', issues);
      }
    }

    return issues;
  }

  /**
   * Check for IDOR via sequential IDs in URL path
   */
  checkIdorInPath(context) {
    const issues = [];
    const rule = this.rules['idor-in-path'];
    if (!rule) return issues;
    
    const urlPath = new URL(context.url).pathname;
    
    rule.pathPatterns.forEach(pattern => {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(urlPath)) {
        // Extract the ID from the path
        const idMatch = urlPath.match(/\/(\d+)(?:\/|$)/);
        if (idMatch) {
          issues.push({
            message: rule.message,
            details: { 
              path: urlPath,
              id: idMatch[1],
              recommendation: 'Verify server-side authorization checks. Test with different user sessions.'
            },
            location: 'path'
          });
        }
      }
    });

    return issues;
  }

  /**
   * Check for JWT security issues
   */
  checkJwtSecurity(context) {
    const issues = [];
    const rule = this.rules['jwt-security'];
    if (!rule) return issues;
    
    const headers = context.headers;
    const authHeader = headers['Authorization'] || headers['authorization'];
    
    if (!authHeader) return issues;
    
    // Extract JWT token
    const jwtMatch = authHeader.match(/(?:Bearer\s+)?(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)/);
    if (!jwtMatch) return issues;
    
    const token = jwtMatch[1];
    
    try {
      // Decode header (first part)
      const headerPart = token.split('.')[0];
      const headerJson = atob(headerPart.replace(/-/g, '+').replace(/_/g, '/'));
      const header = JSON.parse(headerJson);
      
      // Check for 'none' algorithm
      if (header.alg && header.alg.toLowerCase() === 'none') {
        issues.push({
          message: rule.checks[0].message,
          details: { algorithm: header.alg, type: 'none_algorithm' },
          location: 'headers'
        });
      }
      
      // Decode payload (second part)
      const payloadPart = token.split('.')[1];
      const payloadJson = atob(payloadPart.replace(/-/g, '+').replace(/_/g, '/'));
      const payload = JSON.parse(payloadJson);
      
      // Check for missing expiry
      if (!payload.exp) {
        issues.push({
          message: rule.checks[2].message,
          details: { type: 'missing_expiry' },
          location: 'headers'
        });
      } else {
        // Check for long expiry
        const expDate = new Date(payload.exp * 1000);
        const now = new Date();
        const hoursUntilExpiry = (expDate - now) / (1000 * 60 * 60);
        
        if (hoursUntilExpiry > rule.checks[3].maxHours) {
          issues.push({
            message: rule.checks[3].message,
            details: { 
              type: 'long_expiry',
              expiresIn: `${Math.round(hoursUntilExpiry)} hours`,
              expDate: expDate.toISOString()
            },
            location: 'headers'
          });
        }
      }
    } catch (e) {
      // Invalid JWT format - not an issue to report
    }

    return issues;
  }

  /**
   * Check for HTTP method override headers
   */
  checkHttpMethodOverride(context) {
    const issues = [];
    const rule = this.rules['http-method-override'];
    if (!rule) return issues;
    
    const headers = context.headers;
    
    rule.headers.forEach(headerName => {
      const value = headers[headerName] || headers[headerName.toLowerCase()];
      if (value) {
        issues.push({
          message: rule.message,
          details: { 
            header: headerName,
            value: value,
            recommendation: 'Ensure server validates overridden method permissions'
          },
          location: 'headers'
        });
      }
    });

    return issues;
  }

  /**
   * Check for server version disclosure
   */
  checkServerVersionDisclosure(context) {
    const issues = [];
    const rule = this.rules['server-version-disclosure'];
    if (!rule) return issues;
    
    const responseHeaders = (context.callDetails && context.callDetails.responseHeaders) || {};
    const disclosedHeaders = [];
    
    rule.headers.forEach(headerName => {
      const value = responseHeaders[headerName] || responseHeaders[headerName.toLowerCase()];
      if (value) {
        disclosedHeaders.push({ header: headerName, value: value });
      }
    });

    if (disclosedHeaders.length > 0) {
      issues.push({
        message: rule.message,
        details: { 
          headers: disclosedHeaders,
          recommendation: 'Remove or obfuscate version headers in production'
        },
        location: 'response-headers'
      });
    }

    return issues;
  }

  /**
   * Check for command injection patterns
   */
  checkCommandInjectionRisk(context) {
    const issues = [];
    const rule = this.rules['command-injection-risk'];
    if (!rule) return issues;
    
    const valuesToCheck = [
      ...Object.values(context.queryParams || {}),
      ...this.getDeepValues(context.requestBody)
    ];

    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(value)) {
            issues.push({
              message: rule.message,
              details: { 
                pattern,
                sample: value.substring(0, 50) + (value.length > 50 ? '...' : '')
              },
              location: 'parameters'
            });
          }
        });
      }
    });

    return issues;
  }

  /**
   * Check for XXE risk in XML content
   */
  checkXxeRisk(context) {
    const issues = [];
    const rule = this.rules['xxe-risk'];
    if (!rule) return issues;
    
    const headers = context.headers;
    const contentType = headers['Content-Type'] || headers['content-type'] || '';
    const requestBody = context.requestBody;
    
    // Only check XML content
    const isXml = rule.contentTypes.some(ct => contentType.toLowerCase().includes(ct.toLowerCase()));
    
    if (isXml && requestBody) {
      const bodyStr = typeof requestBody === 'string' ? requestBody : JSON.stringify(requestBody);
      
      rule.patterns.forEach(pattern => {
        const regex = new RegExp(pattern, 'i');
        if (regex.test(bodyStr)) {
          issues.push({
            message: rule.message,
            details: { 
              contentType,
              pattern,
              recommendation: 'Disable external entity processing in XML parser'
            },
            location: 'body'
          });
        }
      });
    }

    return issues;
  }

  /**
   * Check for broken access control indicators
   */
  checkBrokenAccessControl(context) {
    const issues = [];
    const rule = this.rules['broken-access-control'];
    if (!rule) return issues;
    
    const fullUrl = context.url;
    
    Object.entries(rule.patterns).forEach(([name, pattern]) => {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(fullUrl)) {
        issues.push({
          message: rule.message,
          details: { 
            type: name,
            recommendation: 'Verify server enforces authorization regardless of client parameters'
          },
          location: 'request'
        });
      }
    });

    return issues;
  }

  /**
   * Check for CRLF injection
   */
  checkCrlfInjection(context) {
    const issues = [];
    const rule = this.rules['crlf-injection'];
    if (!rule) return issues;
    
    const valuesToCheck = [
      context.url,
      ...Object.values(context.queryParams || {}),
      ...Object.values(context.headers || {}),
      ...this.getDeepValues(context.requestBody)
    ];

    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          if (value.toLowerCase().includes(pattern.toLowerCase())) {
            issues.push({
              message: rule.message,
              details: { 
                pattern,
                recommendation: 'Sanitize CRLF sequences from user input'
              },
              location: 'parameters'
            });
          }
        });
      }
    });

    return issues;
  }

  /**
   * Check for sensitive file exposure
   */
  checkSensitiveFileExposure(context) {
    const issues = [];
    const rule = this.rules['sensitive-file-exposure'];
    if (!rule) return issues;
    
    const urlPath = new URL(context.url).pathname.toLowerCase();
    
    rule.patterns.forEach(pattern => {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(urlPath)) {
        issues.push({
          message: rule.message,
          details: { 
            path: urlPath,
            pattern,
            recommendation: 'Block access to sensitive files via web server configuration'
          },
          location: 'path'
        });
      }
    });

    return issues;
  }

  /**
   * Check for authorization header exposure (informational)
   */
  checkAuthorizationHeaderExposure(context) {
    const issues = [];
    const rule = this.rules['authorization-header-exposure'];
    if (!rule) return issues;
    
    const headers = context.headers;
    const authHeader = headers['Authorization'] || headers['authorization'];
    
    // Only flag on sensitive endpoints that shouldn't need logging
    if (authHeader) {
      const urlPath = new URL(context.url).pathname.toLowerCase();
      const sensitiveEndpoints = ['/payment', '/transfer', '/admin', '/internal'];
      
      if (sensitiveEndpoints.some(ep => urlPath.includes(ep))) {
        issues.push({
          message: rule.message,
          details: { 
            path: urlPath,
            recommendation: 'Ensure auth tokens are not logged server-side for this endpoint'
          },
          location: 'headers'
        });
      }
    }

    return issues;
  }

  /**
   * Check for Server-Side Template Injection (SSTI) risk
   */
  checkSstiRisk(context) {
    const issues = [];
    const rule = this.rules['ssti-risk'];
    if (!rule) return issues;
    
    const valuesToCheck = [
      ...Object.values(context.queryParams || {}),
      ...this.getDeepValues(context.requestBody)
    ];

    const foundPatterns = new Set();
    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          const regex = new RegExp(pattern);
          if (regex.test(value) && !foundPatterns.has(pattern)) {
            foundPatterns.add(pattern);
            issues.push({
              message: rule.message,
              details: { 
                pattern,
                sample: value.substring(0, 50) + (value.length > 50 ? '...' : ''),
                recommendation: 'Sanitize template expressions from user input; use logic-less templates'
              },
              location: 'parameters'
            });
          }
        });
      }
    });

    return issues;
  }

  /**
   * Check for insecure deserialization patterns
   */
  checkInsecureDeserialization(context) {
    const issues = [];
    const rule = this.rules['insecure-deserialization'];
    if (!rule) return issues;
    
    const requestBody = context.requestBody;
    const bodyStr = typeof requestBody === 'string' ? requestBody : JSON.stringify(requestBody || '');
    
    Object.entries(rule.patterns).forEach(([name, pattern]) => {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(bodyStr)) {
        issues.push({
          message: rule.message,
          details: { 
            type: name,
            recommendation: 'Avoid deserializing untrusted data; use safe formats like JSON'
          },
          location: 'body'
        });
      }
    });

    return issues;
  }

  /**
   * Check for Host Header Injection risk
   */
  checkHostHeaderInjection(context) {
    const issues = [];
    const rule = this.rules['host-header-injection'];
    if (!rule) return issues;
    
    const headers = context.headers;
    const hostHeader = headers['Host'] || headers['host'] || '';
    const xForwardedHost = headers['X-Forwarded-Host'] || headers['x-forwarded-host'] || '';
    
    const headersToCheck = [hostHeader, xForwardedHost].filter(h => h);
    
    headersToCheck.forEach(headerValue => {
      rule.suspiciousPatterns.forEach(pattern => {
        const regex = new RegExp(pattern, 'i');
        if (regex.test(headerValue)) {
          issues.push({
            message: rule.message,
            details: { 
              value: headerValue,
              pattern,
              recommendation: 'Validate Host header against expected values; do not trust for URL generation'
            },
            location: 'headers'
          });
        }
      });
    });

    return issues;
  }

  /**
   * Check for GraphQL introspection exposure
   */
  checkGraphqlIntrospection(context) {
    const issues = [];
    const rule = this.rules['graphql-introspection'];
    if (!rule) return issues;
    
    const urlPath = new URL(context.url).pathname.toLowerCase();
    const isGraphql = urlPath.includes('graphql');
    
    if (!isGraphql) return issues;
    
    const requestBody = context.requestBody;
    const bodyStr = typeof requestBody === 'string' ? requestBody : JSON.stringify(requestBody || '');
    
    rule.patterns.forEach(pattern => {
      if (bodyStr.includes(pattern)) {
        issues.push({
          message: rule.message,
          details: { 
            pattern,
            recommendation: 'Disable introspection in production to prevent schema disclosure'
          },
          location: 'body'
        });
      }
    });

    return issues;
  }

  /**
   * Check for API version bypass attempts
   */
  checkApiVersionBypass(context) {
    const issues = [];
    const rule = this.rules['api-version-bypass'];
    if (!rule) return issues;
    
    const urlPath = new URL(context.url).pathname.toLowerCase();
    
    rule.patterns.forEach(pattern => {
      if (urlPath.includes(pattern.toLowerCase())) {
        // Don't flag the current active version (likely v2 or higher)
        if (!urlPath.includes('/v2/') && !urlPath.includes('/v3/') && !urlPath.includes('/api/v2') && !urlPath.includes('/api/v3')) {
          issues.push({
            message: rule.message,
            details: { 
              pattern,
              path: urlPath,
              recommendation: 'Ensure deprecated API versions are disabled or have equal security controls'
            },
            location: 'path'
          });
        }
      }
    });

    return issues;
  }

  /**
   * Check for race condition risk on sensitive endpoints
   */
  checkRaceConditionRisk(context) {
    const issues = [];
    const rule = this.rules['race-condition-risk'];
    if (!rule) return issues;
    
    const method = (context.method || 'GET').toUpperCase();
    const urlPath = new URL(context.url).pathname.toLowerCase();
    
    // Only check specified methods (POST, PUT, PATCH)
    if (!rule.methods.includes(method)) return issues;
    
    const matchedEndpoint = rule.sensitiveEndpoints.find(endpoint => 
      urlPath.includes(endpoint.toLowerCase())
    );

    if (matchedEndpoint) {
      issues.push({
        message: rule.message,
        details: { 
          endpoint: matchedEndpoint,
          method,
          recommendation: 'Implement mutex/locking, use idempotency keys, or database-level constraints'
        },
        location: 'path'
      });
    }

    return issues;
  }

  /**
   * Check for LDAP injection risk
   */
  checkLdapInjectionRisk(context) {
    const issues = [];
    const rule = this.rules['ldap-injection-risk'];
    if (!rule) return issues;
    
    const valuesToCheck = [
      ...Object.values(context.queryParams || {}),
      ...this.getDeepValues(context.requestBody)
    ];

    const foundPatterns = new Set();
    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          const regex = new RegExp(pattern.replace(/\\/g, '\\\\'), 'i');
          if (regex.test(value) && !foundPatterns.has(pattern)) {
            foundPatterns.add(pattern);
            issues.push({
              message: rule.message,
              details: { 
                pattern,
                sample: value.substring(0, 50) + (value.length > 50 ? '...' : ''),
                recommendation: 'Escape LDAP special characters: *, (, ), \\, NUL'
              },
              location: 'parameters'
            });
          }
        });
      }
    });

    return issues;
  }

  /**
   * Check for NoSQL injection risk
   */
  checkNoSqlInjectionRisk(context) {
    const issues = [];
    const rule = this.rules['nosql-injection-risk'];
    if (!rule) return issues;
    
    const valuesToCheck = [
      ...Object.values(context.queryParams || {}),
      ...this.getDeepValues(context.requestBody)
    ];
    
    // Also check stringified body for operator patterns
    const bodyStr = JSON.stringify(context.requestBody || {});

    const foundPatterns = new Set();
    
    // Check individual values
    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(value) && !foundPatterns.has(pattern)) {
            foundPatterns.add(pattern);
            issues.push({
              message: rule.message,
              details: { 
                pattern,
                recommendation: 'Sanitize MongoDB operators; use parameterized queries'
              },
              location: 'parameters'
            });
          }
        });
      }
    });
    
    // Check body for MongoDB-style operators
    rule.patterns.forEach(pattern => {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(bodyStr) && !foundPatterns.has(pattern)) {
        foundPatterns.add(pattern);
        issues.push({
          message: rule.message,
          details: { 
            pattern,
            recommendation: 'Sanitize MongoDB operators; use parameterized queries'
          },
          location: 'body'
        });
      }
    });

    return issues;
  }

  /**
   * Check for sensitive parameter names
   */
  checkSensitiveParamNames(context) {
    const issues = [];
    const rule = this.rules['sensitive-param-names'];
    if (!rule) return issues;
    
    const queryParams = context.queryParams || {};
    
    const foundParams = [];
    Object.keys(queryParams).forEach(param => {
      const paramLower = param.toLowerCase();
      rule.params.forEach(sensitiveParam => {
        if (paramLower.includes(sensitiveParam.toLowerCase())) {
          foundParams.push(param);
        }
      });
    });

    if (foundParams.length > 0) {
      issues.push({
        message: rule.message,
        details: { 
          params: foundParams,
          recommendation: 'Move sensitive parameters to request body or headers; use HTTPS'
        },
        location: 'query'
      });
    }

    return issues;
  }

  /**
   * Helper: Find fields in nested object
   */
  findFieldsInObject(obj, fieldNames, includeValues = false) {
    const found = [];
    
    const search = (object, path = '') => {
      if (!object || typeof object !== 'object') return;
      
      for (const [key, value] of Object.entries(object)) {
        const currentPath = path ? `${path}.${key}` : key;
        
        if (fieldNames.some(field => key.toLowerCase().includes(field.toLowerCase()))) {
          if (includeValues) {
            found.push({ path: currentPath, value: value });
          } else {
            found.push(currentPath);
          }
        }
        
        if (typeof value === 'object' && value !== null) {
          search(value, currentPath);
        }
      }
    };
    
    search(obj);
    return found;
  }

  /**
   * Helper: Find field value in nested object
   */
  findFieldValue(obj, fieldName) {
    if (!obj || typeof obj !== 'object') return null;
    
    for (const [key, value] of Object.entries(obj)) {
      if (key.toLowerCase() === fieldName.toLowerCase()) {
        return value;
      }
      
      if (typeof value === 'object' && value !== null) {
        const found = this.findFieldValue(value, fieldName);
        if (found !== null) return found;
      }
    }
    
    return null;
  }

  /**
   * Helper: Check if a value appears to be encrypted/hashed
   */
  isEncryptedOrHashed(value) {
    if (typeof value !== 'string' || !value) return false;
    
    // Common patterns for encrypted/hashed data:
    
    // 1. Base64-like strings with encryption separators (e.g., "encrypted|iv" or "data==|salt==")
    if (/^[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$/.test(value)) {
      return true;
    }
    
    // 2. Long base64 strings (likely encrypted) - at least 32 chars with base64 chars
    if (value.length >= 32 && /^[A-Za-z0-9+/=]+$/.test(value) && (value.includes('=') || value.length % 4 === 0)) {
      return true;
    }
    
    // 3. Hex-encoded strings (64+ chars, common for SHA256)
    if (value.length >= 64 && /^[a-fA-F0-9]+$/.test(value)) {
      return true;
    }
    
    // 4. JWT tokens (three base64 parts separated by dots)
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
      return true;
    }
    
    // 5. bcrypt hashes ($2a$, $2b$, $2y$ prefix)
    if (/^\$2[aby]\$\d{2}\$/.test(value)) {
      return true;
    }
    
    // 6. Password hashes with salt (format: $algorithm$salt$hash)
    if (/^\$\w+\$/.test(value)) {
      return true;
    }
    
    // 7. Very long alphanumeric strings (likely encrypted)
    if (value.length >= 40 && /^[A-Za-z0-9+/=_-]+$/.test(value)) {
      return true;
    }
    
    return false;
  }

  /**
   * Helper: Get all values from nested object
   */
  getDeepValues(obj) {
    const values = [];
    
    const extract = (object) => {
      if (!object || typeof object !== 'object') return;
      
      for (const value of Object.values(object)) {
        if (typeof value === 'object' && value !== null) {
          extract(value);
        } else if (value !== null && value !== undefined) {
          values.push(value);
        }
      }
    };
    
    extract(obj);
    return values;
  }

  /**
   * Get summary statistics of vulnerabilities
   */
  getVulnerabilitySummary(vulnerabilities) {
    const summary = {
      total: vulnerabilities.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      byRule: {}
    };

    vulnerabilities.forEach(vuln => {
      summary[vuln.severity]++;
      
      if (!summary.byRule[vuln.ruleId]) {
        summary.byRule[vuln.ruleId] = {
          count: 0,
          name: vuln.name,
          severity: vuln.severity
        };
      }
      summary.byRule[vuln.ruleId].count++;
    });

    return summary;
  }

  /**
   * Check for prototype pollution attempts
   */
  checkPrototypePollution(context) {
    const issues = [];
    const rule = this.rules['prototype-pollution'];
    const requestBody = JSON.stringify(context.requestBody || {});
    const queryParams = JSON.stringify(context.queryParams || {});
    
    const textToCheck = requestBody + queryParams;

    rule.patterns.forEach(pattern => {
      if (textToCheck.includes(pattern)) {
        issues.push({
          message: rule.message,
          details: { 
            pattern,
            recommendation: 'Validate and sanitize input keys to prevent prototype pollution'
          },
          location: 'body/query'
        });
      }
    });

    return issues;
  }

  /**
   * Check for unsafe CSP
   */
  checkUnsafeCsp(context) {
    const issues = [];
    const rule = this.rules['unsafe-csp'];
    const responseHeaders = (context.callDetails && context.callDetails.responseHeaders) || {};
    
    // Find CSP header (case-insensitive)
    const cspHeaderName = Object.keys(responseHeaders).find(h => 
      h.toLowerCase() === 'content-security-policy' || 
      h.toLowerCase() === 'x-content-security-policy'
    );

    if (cspHeaderName) {
      const csp = responseHeaders[cspHeaderName];
      rule.patterns.forEach(pattern => {
        if (csp.includes(pattern)) {
          issues.push({
            message: `${rule.message}: ${pattern}`,
            details: { 
              directive: pattern,
              fullCsp: csp
            },
            location: 'response-headers'
          });
        }
      });
    }

    return issues;
  }

  /**
   * Check for cache poisoning risk headers
   */
  checkCachePoisoningRisk(context) {
    const issues = [];
    const rule = this.rules['cache-poisoning-risk'];
    if (!rule) return issues;
    
    const headers = context.headers;
    
    rule.headers.forEach(headerName => {
      const value = headers[headerName] || headers[headerName.toLowerCase()];
      if (value) {
        issues.push({
          message: rule.message,
          details: { 
            header: headerName,
            value: value,
            recommendation: 'Ensure cache keys include these headers or strip them'
          },
          location: 'headers'
        });
      }
    });

    return issues;
  }

  /**
   * Check for business logic bypass attempts
   */
  checkBusinessLogicBypass(context) {
    const issues = [];
    const rule = this.rules['business-logic-bypass'];
    if (!rule) return issues;
    
    const fullUrl = context.url;
    const requestBody = JSON.stringify(context.requestBody || {});
    const textToCheck = fullUrl + requestBody;

    rule.patterns.forEach(pattern => {
      if (textToCheck.toLowerCase().includes(pattern.toLowerCase())) {
        issues.push({
          message: rule.message,
          details: { 
            pattern,
            recommendation: 'Verify server-side validation for business logic'
          },
          location: 'request'
        });
      }
    });

    return issues;
  }

  /**
   * Check for missing rate limit headers on sensitive endpoints
   */
  checkMissingRateLimitHeaders(context) {
    const issues = [];
    const rule = this.rules['missing-rate-limit-headers'];
    if (!rule) return issues;
    
    const urlPath = new URL(context.url).pathname.toLowerCase();
    const responseHeaders = (context.callDetails && context.callDetails.responseHeaders) || {};
    
    const isSensitive = rule.sensitiveEndpoints.some(endpoint => 
      urlPath.includes(endpoint.toLowerCase())
    );

    if (isSensitive) {
      const hasRateLimitHeader = rule.headers.some(header => 
        responseHeaders[header] || responseHeaders[header.toLowerCase()]
      );

      if (!hasRateLimitHeader) {
        issues.push({
          message: rule.message,
          details: { 
            endpoint: urlPath,
            recommendation: 'Implement rate limiting with proper response headers'
          },
          location: 'response-headers'
        });
      }
    }

    return issues;
  }

  /**
   * Check for file upload risks
   */
  checkFileUploadRisk(context) {
    const issues = [];
    const rule = this.rules['file-upload-risk'];
    if (!rule) return issues;
    
    const urlPath = new URL(context.url).pathname.toLowerCase();
    const method = context.method || 'GET';
    
    if (method.toUpperCase() !== 'POST' && method.toUpperCase() !== 'PUT') {
      return issues;
    }

    const isUploadEndpoint = rule.pathPatterns.some(pattern => 
      urlPath.includes(pattern.toLowerCase())
    );

    if (isUploadEndpoint) {
      issues.push({
        message: rule.message,
        details: { 
          endpoint: urlPath,
          dangerousExtensions: rule.dangerousExtensions,
          recommendation: 'Validate file type, size, and content. Store outside web root.'
        },
        location: 'path'
      });
    }

    return issues;
  }

  /**
   * Check for subdomain takeover indicators
   */
  checkSubdomainTakeoverRisk(context) {
    const issues = [];
    const rule = this.rules['subdomain-takeover-risk'];
    if (!rule) return issues;
    
    const body = context.callDetails && context.callDetails.responseBody;
    if (!body || typeof body !== 'string') return issues;

    rule.patterns.forEach(pattern => {
      if (body.includes(pattern)) {
        issues.push({
          message: rule.message,
          details: { 
            indicator: pattern,
            recommendation: 'Check DNS configuration and cloud service setup'
          },
          location: 'response-body'
        });
      }
    });

    return issues;
  }

  /**
   * Check for email header injection
   */
  checkEmailHeaderInjection(context) {
    const issues = [];
    const rule = this.rules['email-header-injection'];
    if (!rule) return issues;
    
    const valuesToCheck = [
      ...Object.values(context.queryParams),
      ...this.getDeepValues(context.requestBody)
    ];

    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(value)) {
            issues.push({
              message: rule.message,
              details: { pattern },
              location: 'parameters'
            });
          }
        });
      }
    });

    return issues;
  }

  /**
   * Check for XPath injection
   */
  checkXPathInjectionRisk(context) {
    const issues = [];
    const rule = this.rules['xpath-injection-risk'];
    if (!rule) return issues;
    
    const valuesToCheck = [
      ...Object.values(context.queryParams),
      ...this.getDeepValues(context.requestBody)
    ];

    valuesToCheck.forEach(value => {
      if (typeof value === 'string') {
        rule.patterns.forEach(pattern => {
          if (value.toLowerCase().includes(pattern.toLowerCase())) {
            issues.push({
              message: rule.message,
              details: { 
                pattern,
                sample: value.substring(0, 50)
              },
              location: 'parameters'
            });
          }
        });
      }
    });

    return issues;
  }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecurityAnalyzer;
}
