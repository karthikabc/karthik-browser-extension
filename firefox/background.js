console.log('[GAMX Firefox] Background script starting...');

const apiCalls = new Map();
const pendingRequests = new Map(); // Store request details temporarily to match with headers
let recording = true;
let totalCallsCount = 0;
let responseBodiesEnabled = false;
let dataVersion = 0; // bump on CLEAR_DATA to invalidate in-flight updates

console.log('[GAMX Firefox] Initializing security analyzer...');
// Initialize security analyzer
const securityAnalyzer = new SecurityAnalyzer();
securityAnalyzer.init().then(() => {
  console.log('[GAMX Firefox] Security analyzer initialized');
}).catch(err => {
  console.error('[GAMX Firefox] Security analyzer init failed:', err);
});

// Initialize response body capture
const responseCapture = new ResponseBodyCapture();
responseCapture.initListeners((responseData) => {
  // Match with existing API call data
  for (const [endpoint, data] of apiCalls.entries()) {
    const matchingCall = data.calls.find(call => 
      call.url === responseData.url && 
      Math.abs(new Date(call.timestamp).getTime() - responseData.timestamp) < 5000
    );
    
    if (matchingCall) {
      matchingCall.responseBody = responseData.body;
      matchingCall.responseMimeType = responseData.mimeType;
      // Also keep in callDetails for analyzer
      matchingCall.responseBodyString = (typeof responseData.body === 'string') ? responseData.body : JSON.stringify(responseData.body);
      console.log('Response body captured for', endpoint);
      break;
    }
  }
});

// Memory management - clean up old data
function enforceMemoryLimits() {
  // Remove oldest endpoints if we exceed the limit
  if (apiCalls.size > CONFIG.MAX_TOTAL_ENDPOINTS) {
    const entriesToRemove = apiCalls.size - CONFIG.MAX_TOTAL_ENDPOINTS;
    const entries = Array.from(apiCalls.entries());
    for (let i = 0; i < entriesToRemove; i++) {
      apiCalls.delete(entries[i][0]);
    }
  }
  
  // Limit calls per endpoint
  apiCalls.forEach((data, endpoint) => {
    if (data.calls.length > CONFIG.MAX_CALLS_PER_ENDPOINT) {
      data.calls = data.calls.slice(-CONFIG.MAX_CALLS_PER_ENDPOINT);
    }
  });
}

console.log('[GAMX Firefox] Setting up runtime connection listener...');

browser.runtime.onConnect.addListener((port) => {
  console.log('[GAMX Firefox] Port connected:', port.name);
  if (port.name === "devtools-panel") {
    console.log('[GAMX Firefox] DevTools panel connected');
    
    // Send CONNECTION_READY immediately
    try {
      port.postMessage({ type: "CONNECTION_READY", version: dataVersion });
      console.log('[GAMX Firefox] CONNECTION_READY sent');
    } catch (e) {
      console.error('[GAMX Firefox] Failed to send CONNECTION_READY:', e);
    }
    
    port.onMessage.addListener(async (msg) => {
      console.log('[GAMX Firefox] Message received:', msg.type);
      try {
        if (msg.type === "GET_API_CALLS") {
          console.log('[GAMX Firefox] Sending API calls, count:', apiCalls.size);
          const data = Array.from(apiCalls.entries()).map(([key, value]) => ({
            endpoint: key,
            method: value.method,
            url: value.url,
            host: value.host,
            pathname: value.pathname,
            calls: value.calls,
            queryParams: Array.from(value.queryParams), // Convert Set to Array for serialization
            requestBodies: value.requestBodies,
            requestHeaders: value.requestHeaders ? Array.from(value.requestHeaders) : [],
            securityIssues: value.securityIssues || []
          }));
          port.postMessage({ type: "API_CALLS_DATA", version: dataVersion, data });
        } else if (msg.type === "CLEAR_DATA") {
          console.log('CLEAR_DATA message received in background');
          apiCalls.clear();
          totalCallsCount = 0;
          dataVersion += 1;
          // Also clear pending maps and any cached state
          try { pendingRequests.clear(); } catch (_) {}
          try { responseCapture.pendingRequests?.clear(); } catch (_) {}
          console.log('Data cleared, sending DATA_CLEARED response');
          port.postMessage({ type: "DATA_CLEARED", version: dataVersion });
        } else if (msg.type === "SET_RECORDING") {
          recording = msg.recording;
        } else if (msg.type === "ENABLE_RESPONSE_BODIES") {
          const tabId = msg.tabId;
          const success = await responseCapture.enableForTab(tabId);
          responseBodiesEnabled = success;
          port.postMessage({ 
            type: "RESPONSE_BODIES_STATUS", 
            enabled: success,
            message: success ? "Response body capture enabled" : "Response body capture is not available in Firefox"
          });
        } else if (msg.type === "DISABLE_RESPONSE_BODIES") {
          const tabId = msg.tabId;
          await responseCapture.disableForTab(tabId);
          responseBodiesEnabled = false;
          port.postMessage({ 
            type: "RESPONSE_BODIES_STATUS", 
            enabled: false,
            message: "Response body capture disabled"
          });
        } else if (msg.type === "GET_RESPONSE_BODIES_STATUS") {
          port.postMessage({ 
            type: "RESPONSE_BODIES_STATUS", 
            enabled: responseBodiesEnabled
          });
        }
      } catch (error) {
        console.error('Error handling message:', error);
        port.postMessage({ type: "ERROR", message: error.message });
      }
    });
  }
});

console.log('[GAMX Firefox] Setting up webRequest listeners...');

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!recording) return;
    
    console.log('[GAMX Firefox] onBeforeRequest:', details.type, details.url);
    
    if (details.type === "xmlhttprequest" || details.type === "fetch") {
      console.log('[GAMX Firefox] Captured API call:', details.method, details.url);
      const url = new URL(details.url);
      const endpoint = `${details.method} ${url.pathname}`;
      
      if (!apiCalls.has(endpoint)) {
        apiCalls.set(endpoint, {
          method: details.method,
          url: url.href,
          host: url.host,
          pathname: url.pathname,
          calls: [],
          queryParams: new Set(),
          requestBodies: [],
          requestHeaders: new Set()
        });
      }
      
      const apiCall = apiCalls.get(endpoint);
      
      const queryParams = Array.from(url.searchParams.entries());
      queryParams.forEach(([key, value]) => {
        apiCall.queryParams.add(key);
      });
      
      // Sanitize sensitive data
      const sanitizedQueryParams = {};
      queryParams.forEach(([key, value]) => {
        sanitizedQueryParams[key] = SecurityUtils.sanitizeQueryParam(key, value);
      });
      
      const callDetails = {
        timestamp: new Date().toISOString(),
        url: SecurityUtils.sanitizeUrl(details.url),
        queryParams: sanitizedQueryParams,
        requestId: details.requestId,
        tabId: details.tabId,
        method: details.method
      };
      
      if (details.requestBody && details.requestBody.raw) {
        try {
          const decoder = new TextDecoder();
          const body = details.requestBody.raw.map(data => decoder.decode(data.bytes)).join('');
          callDetails.requestBody = JSON.parse(body);
          apiCall.requestBodies.push(callDetails.requestBody);
        } catch (e) {
          console.log("Could not parse request body");
        }
      }
      
      // Store temporarily to match with headers
      pendingRequests.set(details.requestId, {
        endpoint,
        callDetails
      });
      
      apiCall.calls.push(callDetails);
      totalCallsCount++;
      
      // Enforce memory limits periodically
      if (totalCallsCount % 50 === 0) {
        enforceMemoryLimits();
      }
      
      // Send update to panel
      browser.runtime.sendMessage({
        type: "API_CALL_DETECTED",
        endpoint,
        data: {
          method: apiCall.method,
          url: apiCall.url,
          host: apiCall.host,
          pathname: apiCall.pathname,
          calls: apiCall.calls,
          queryParams: Array.from(apiCall.queryParams),
          requestBodies: apiCall.requestBodies,
          requestHeaders: apiCall.requestHeaders ? Array.from(apiCall.requestHeaders) : []
        }
      }).catch(() => {});
    }
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// Capture request headers
browser.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!recording) return;
    
    if (details.type === "xmlhttprequest" || details.type === "fetch") {
      const pending = pendingRequests.get(details.requestId);
      if (pending && details.requestHeaders) {
        const url = new URL(details.url);
        const endpoint = `${details.method} ${url.pathname}`;
        
        if (apiCalls.has(endpoint)) {
          const apiCall = apiCalls.get(endpoint);
          const call = apiCall.calls.find(c => c.requestId === details.requestId);
          
          if (call) {
            // Store ALL headers for complete curl generation
            call.allHeaders = {};
            call.requestHeaders = {};
            
            details.requestHeaders.forEach(header => {
              const sanitizedValue = SecurityUtils.sanitizeHeader(header.name, header.value);
              call.allHeaders[header.name] = sanitizedValue;
              
              // Also add to the Set for unique header tracking
              apiCall.requestHeaders.add(header.name);
              
              // Store custom headers separately (non-standard ones)
              const lowerName = header.name.toLowerCase();
              if (!['accept', 'accept-encoding', 'accept-language', 'cache-control', 
                   'connection', 'content-length', 'content-type', 'host', 'origin', 
                   'referer', 'user-agent', 'sec-', 'upgrade-insecure-requests'].some(std => lowerName.startsWith(std))) {
                call.requestHeaders[header.name] = sanitizedValue;
              }
            });

            // Perform security analysis on this call
            const vulnerabilities = securityAnalyzer.analyzeCall(call);
            if (vulnerabilities && vulnerabilities.length > 0) {
              call.securityIssues = vulnerabilities;
              
              // Add security issues to the endpoint data
              if (!apiCall.securityIssues) {
                apiCall.securityIssues = [];
              }
              apiCall.securityIssues.push(...vulnerabilities);
            }
          }
        }
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// Capture response headers
browser.webRequest.onCompleted.addListener(
  (details) => {
    if (!recording) return;
    
    if (details.type === "xmlhttprequest" || details.type === "fetch") {
      const url = new URL(details.url);
      const endpoint = `${details.method} ${url.pathname}`;
      
      if (apiCalls.has(endpoint)) {
        const apiCall = apiCalls.get(endpoint);
        const call = apiCall.calls.find(c => c.requestId === details.requestId);
        if (call) {
          call.status = details.statusCode;
          call.statusLine = details.statusLine;
          
          // Store response headers
          if (details.responseHeaders) {
            call.responseHeaders = {};
            details.responseHeaders.forEach(header => {
              call.responseHeaders[header.name] = header.value;
            });
          }

          // Perform response-based security analysis now that we have headers (and possibly body)
          const vulnerabilities = securityAnalyzer.analyzeCall(call);
          if (vulnerabilities && vulnerabilities.length > 0) {
            call.securityIssues = [...(call.securityIssues || []), ...vulnerabilities];
            if (!apiCall.securityIssues) apiCall.securityIssues = [];
            apiCall.securityIssues.push(...vulnerabilities);
          }
        }
      }
      
      // Clean up pending request
      pendingRequests.delete(details.requestId);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

console.log('[GAMX Firefox] Background script fully loaded and ready!');