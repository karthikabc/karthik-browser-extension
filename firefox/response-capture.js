/**
 * Response Body Capture Module for Firefox
 * 
 * NOTE: Firefox does not support the browser.debugger API that Chrome uses
 * for response body capture. This is a stub implementation that provides
 * the same interface but response body capture is not available in Firefox.
 * 
 * The extension will still work for all other features (request logging,
 * security analysis, etc.) - just without response body capture.
 */

class ResponseBodyCapture {
  constructor() {
    this.enabled = false;
    this.pendingRequests = new Map();
    console.log('[GAMX Firefox] ResponseBodyCapture initialized (stub - debugger API not available in Firefox)');
  }

  /**
   * Enable response body capture for a specific tab
   * In Firefox, this always returns false as the debugger API is not supported
   */
  async enableForTab(tabId) {
    console.warn('[GAMX Firefox] Response body capture is not available in Firefox (debugger API not supported)');
    return false;
  }

  /**
   * Disable response body capture for a tab
   */
  async disableForTab(tabId) {
    // No-op in Firefox
  }

  /**
   * Check if capture is enabled for a tab
   */
  isEnabledForTab(tabId) {
    return false;
  }

  /**
   * Get response body for a request
   */
  async getResponseBody(tabId, requestId) {
    return null;
  }

  /**
   * Initialize debugger event listeners
   * In Firefox, this is a no-op since debugger API is not available
   */
  initListeners(onResponseReceived) {
    console.log('[GAMX Firefox] Response body capture listeners not initialized (debugger API not available)');
    // No-op - Firefox doesn't support debugger API
  }

  /**
   * Clean up old pending requests (memory management)
   */
  cleanupOldRequests() {
    // No-op in Firefox
  }
}

// Export for use in background script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ResponseBodyCapture;
}
