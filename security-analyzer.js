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
      'untrusted-client-identity': this.checkUntrustedClientIdentity
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
            example: matches[0].substring(0, 20) + '...'
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
            reason: 'PII should not be transmitted in headers'
          },
          location: 'headers'
        });
      }
    }

    return issues;
  }

  /**
   * Check for weak authentication
   */
  checkWeakAuthentication(context) {
    const issues = [];
    const rule = this.rules['weak-authentication'];
    const headers = context.headers;
    const queryParams = context.queryParams;

    rule.checks.forEach(check => {
      if (check.type === 'basic_auth') {
        const authHeader = headers['Authorization'] || headers['authorization'];
        if (authHeader && new RegExp(check.pattern).test(authHeader)) {
          issues.push({
            message: check.message,
            details: { type: 'basic_auth' },
            location: 'headers'
          });
        }
      }
      
      if (check.type === 'api_key_in_query') {
        const foundParams = check.params.filter(param => 
          Object.keys(queryParams).some(qp => qp.toLowerCase().includes(param))
        );
        if (foundParams.length > 0) {
          issues.push({
            message: check.message,
            details: { params: foundParams },
            location: 'query'
          });
        }
      }
      
      if (check.type === 'credentials_in_body') {
        const requestBody = context.requestBody;
        if (requestBody && typeof requestBody === 'object') {
          // Get fields with their values to check if they're encrypted
          const foundFieldsWithValues = this.findFieldsInObject(requestBody, check.fields, true);
          
          // Filter out fields that contain encrypted/hashed values
          const unencryptedFields = foundFieldsWithValues.filter(item => {
            return !this.isEncryptedOrHashed(item.value);
          });
          
          // Only report if there are unencrypted credential fields
          if (unencryptedFields.length > 0) {
            issues.push({
              message: check.message,
              details: { fields: unencryptedFields.map(item => item.path) },
              location: 'body'
            });
          }
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
        details: { protocol: 'http' },
        location: 'protocol'
      });
    }

    return issues;
  }

  /**
   * Check for missing security headers
   */
  checkMissingResponseSecurityHeaders(context) {
    const issues = [];
    const rule = this.rules['missing-response-security-headers'];
    const responseHeaders = (context.callDetails && context.callDetails.responseHeaders) || {};
    const headerNames = Object.keys(responseHeaders).map(h => h.toLowerCase());

    const missingHeaders = rule.headers.filter(h => 
      !headerNames.includes(h.toLowerCase())
    );

    if (missingHeaders.length > 0) {
      issues.push({
        message: `Missing recommended security headers: ${missingHeaders.join(', ')}`,
        details: { missingHeaders },
        location: 'response-headers'
      });
    }

    return issues;
  }

  /**
   * Check for CORS misconfiguration
   */
  checkCorsMisconfiguration(context) {
    const issues = [];
    const resp = context.callDetails || {};
    const responseHeaders = resp.responseHeaders || {};
    const acao = responseHeaders['Access-Control-Allow-Origin'] || responseHeaders['access-control-allow-origin'];
    const acac = responseHeaders['Access-Control-Allow-Credentials'] || responseHeaders['access-control-allow-credentials'];

    if (acao === '*' && acac && acac.toLowerCase() === 'true') {
      issues.push({
        message: this.rules['cors-misconfiguration'].message,
        details: {
          acao,
          acac
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
          details: { fields: foundFields },
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
          details: { recommendation: 'Implement pagination with limit/page parameters' },
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
   * Check for missing authentication
   */
  checkMissingAuthentication(context) {
    const issues = [];
    const rule = this.rules['missing-authentication'];
    const headers = context.headers;
    const urlPath = new URL(context.url).pathname;

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
   */
  checkInsecureCookies(context) {
    const issues = [];
    const rule = this.rules['insecure-cookies'];
    const responseHeaders = (context.callDetails && context.callDetails.responseHeaders) || {};
    const setCookieHeader = responseHeaders['Set-Cookie'] || responseHeaders['set-cookie'];
    if (!setCookieHeader) return issues;

    const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    cookies.forEach((cookie) => {
      const hasSecure = /;\s*Secure/i.test(cookie);
      const hasHttpOnly = /;\s*HttpOnly/i.test(cookie);
      const hasSameSite = /;\s*SameSite=(Strict|Lax|None)/i.test(cookie);
      if (!hasSecure || !hasHttpOnly || !hasSameSite) {
        issues.push({
          message: rule.message,
          details: {
            cookiePreview: cookie.split(';')[0],
            missing: [!hasSecure && 'Secure', !hasHttpOnly && 'HttpOnly', !hasSameSite && 'SameSite'].filter(Boolean)
          },
          location: 'response-headers'
        });
      }
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
          details: { pattern: name },
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
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecurityAnalyzer;
}
