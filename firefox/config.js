const CONFIG = {
  // Memory management
  MAX_CALLS_PER_ENDPOINT: 100,
  MAX_TOTAL_ENDPOINTS: 500,
  
  // UI settings
  UPDATE_INTERVAL: 1000,
  DEBOUNCE_DELAY: 300,
  
  // AI Settings
  AI_MODEL: 'Claude Haiku 4.5',

  // Security
  SENSITIVE_HEADERS: [
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token',
    'x-access-token',
    'x-session-id',
    'x-session-token',
    'api-key',
    'bearer',
    'token',
    'x-csrf-token',
    'x-xsrf-token',
    'authentication',
    'x-request-token',
    'proxy-authorization'
  ],
  
  SENSITIVE_QUERY_PARAMS: [
    'api_key',
    'apikey',
    'token',
    'auth',
    'key',
    'secret',
    'password',
    'pwd'
  ],
  
  // Export formats
  EXPORT_FORMATS: {
    OPENAPI: 'openapi',
    POSTMAN: 'postman',
    HAR: 'har'
  },
  
  // HTTP status descriptions
  STATUS_DESCRIPTIONS: {
    200: 'OK',
    201: 'Created',
    204: 'No Content',
    301: 'Moved Permanently',
    302: 'Found',
    304: 'Not Modified',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    409: 'Conflict',
    422: 'Unprocessable Entity',
    429: 'Too Many Requests',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout'
  }
};

// Security utilities
const SecurityUtils = {
  sanitizeHeader: function(headerName, headerValue) {
    // No redaction as per user request
    return headerValue;
  },
  
  sanitizeQueryParam: function(paramName, paramValue) {
    // No redaction as per user request
    return paramValue;
  },
  
  sanitizeUrl: function(url) {
    // No redaction as per user request
    return url;
  },
  
  escapeHtml: function(unsafe) {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
};