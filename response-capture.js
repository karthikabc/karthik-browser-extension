/**
 * Response Body Capture Module
 * Uses Chrome Debugger API to capture HTTP response bodies
 * 
 * Note: This requires user consent due to debugger permission
 */

class ResponseBodyCapture {
  constructor() {
    this.attachedTabs = new Set();
    this.pendingRequests = new Map(); // requestId -> { url, method, timestamp }
    this.responseCallbacks = new Map(); // requestId -> callback
    this.enabled = false;
    this.currentTabId = null;
  }

  /**
   * Enable response body capture for a specific tab
   */
  async enableForTab(tabId) {
    if (this.attachedTabs.has(tabId)) {
      console.log('Already attached to tab', tabId);
      return true;
    }

    try {
      // Attach debugger to the tab
      await chrome.debugger.attach({ tabId }, "1.3");
      
      // Enable Network domain
      await chrome.debugger.sendCommand({ tabId }, "Network.enable");
      
      this.attachedTabs.add(tabId);
      this.currentTabId = tabId;
      this.enabled = true;
      
      console.log('Response body capture enabled for tab', tabId);
      return true;
    } catch (error) {
      console.error('Failed to enable response body capture:', error);
      return false;
    }
  }

  /**
   * Disable response body capture for a tab
   */
  async disableForTab(tabId) {
    if (!this.attachedTabs.has(tabId)) {
      return;
    }

    try {
      await chrome.debugger.detach({ tabId });
      this.attachedTabs.delete(tabId);
      
      if (this.currentTabId === tabId) {
        this.currentTabId = null;
        this.enabled = false;
      }
      
      console.log('Response body capture disabled for tab', tabId);
    } catch (error) {
      console.error('Failed to disable response body capture:', error);
    }
  }

  /**
   * Check if capture is enabled for a tab
   */
  isEnabledForTab(tabId) {
    return this.attachedTabs.has(tabId);
  }

  /**
   * Get response body for a request
   */
  async getResponseBody(tabId, requestId) {
    if (!this.attachedTabs.has(tabId)) {
      console.warn('Tab not attached for response body capture');
      return null;
    }

    try {
      const response = await chrome.debugger.sendCommand(
        { tabId },
        "Network.getResponseBody",
        { requestId }
      );
      
      if (response.base64Encoded) {
        // Decode base64 if needed
        return atob(response.body);
      }
      
      return response.body;
    } catch (error) {
      // Silently fail - not all requests have bodies
      return null;
    }
  }

  /**
   * Initialize debugger event listeners
   */
  initListeners(onResponseReceived) {
    // Listen for Network events
    chrome.debugger.onEvent.addListener((source, method, params) => {
      if (!this.attachedTabs.has(source.tabId)) {
        return;
      }

      // When response is received
      if (method === "Network.responseReceived") {
        const { requestId, response, type } = params;
        
        // Only capture XHR and Fetch requests
        if (type === "XHR" || type === "Fetch") {
          // Store for later retrieval
          this.pendingRequests.set(requestId, {
            tabId: source.tabId,
            url: response.url,
            status: response.status,
            mimeType: response.mimeType,
            timestamp: Date.now()
          });
        }
      }

      // When loading is finished
      if (method === "Network.loadingFinished") {
        const { requestId } = params;
        const requestInfo = this.pendingRequests.get(requestId);
        
        if (requestInfo && onResponseReceived) {
          // Get the response body
          this.getResponseBody(requestInfo.tabId, requestId)
            .then(body => {
              if (body) {
                onResponseReceived({
                  requestId,
                  url: requestInfo.url,
                  status: requestInfo.status,
                  mimeType: requestInfo.mimeType,
                  body: body,
                  timestamp: requestInfo.timestamp
                });
              }
              
              // Clean up
              this.pendingRequests.delete(requestId);
            });
        }
      }
    });

    // Clean up when debugger is detached
    chrome.debugger.onDetach.addListener((source, reason) => {
      console.log('Debugger detached from tab', source.tabId, 'reason:', reason);
      this.attachedTabs.delete(source.tabId);
      
      if (this.currentTabId === source.tabId) {
        this.currentTabId = null;
        this.enabled = false;
      }
    });
  }

  /**
   * Clean up old pending requests (memory management)
   */
  cleanupOldRequests() {
    const now = Date.now();
    const maxAge = 60000; // 1 minute
    
    for (const [requestId, info] of this.pendingRequests.entries()) {
      if (now - info.timestamp > maxAge) {
        this.pendingRequests.delete(requestId);
      }
    }
  }
}

// Export for use in background script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ResponseBodyCapture;
}
