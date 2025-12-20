let apiData = new Map();
let selectedEndpoint = null;
let selectedEndpoints = new Set(); // Track which endpoints are selected for export
let endpointTags = new Map(); // Track tags for each endpoint
let allTags = new Set(); // Track all unique tags
let filterText = '';
let filterMethods = new Set(); // Changed to Set for multiple selections
let filterHosts = new Set(); // Changed to Set for multiple host selections
let filterTags = new Set(); // Filter by tags
let filterSeverity = new Set(); // Filter by vulnerability severity
let groupByTags = false; // Toggle tag grouping
let hostsList = new Set();
let isConnected = false;
let updateTimer = null;
let currentDataVersion = 0; // to ignore stale updates after Clear
let securityAnalyzer = null; // Security analyzer instance
let securityRulesConfig = null; // Current security rules configuration

const port = chrome.runtime.connect({ name: "devtools-panel" });

// Local clear to reset UI/state immediately
function clearAllDataLocal() {
  try {
    apiData.clear();
    selectedEndpoint = null;
    selectedEndpoints.clear();
    endpointTags.clear();
    allTags.clear();
    filterTags.clear();
    filterHosts.clear();
    hostsList.clear();
    updateEndpointsList();
    updateSelectionInfo();
    if (typeof updateTagFilter === 'function') updateTagFilter();
    if (typeof updateHostFilter === 'function') updateHostFilter();
    if (typeof updateSecuritySummary === 'function') updateSecuritySummary();
    if (requestDetails) requestDetails.textContent = 'Select an endpoint to view details';
  } catch (e) {
    console.warn('Local clear failed:', e);
  }
}

// Check if extension context is valid
function isExtensionContextValid() {
  try {
    return !!chrome.runtime?.id;
  } catch (error) {
    return false;
  }
}

// Helper function to safely post messages through port
function safePostMessage(message) {
  try {
    if (!isExtensionContextValid()) {
      console.warn('Extension context invalidated, cannot send message:', message);
      return false;
    }
    if (port) {
      port.postMessage(message);
      return true;
    } else {
      console.warn('Port is disconnected, cannot send message:', message);
      return false;
    }
  } catch (error) {
    if (error.message?.includes('Extension context invalidated')) {
      console.warn('Extension was reloaded. Please close and reopen DevTools.');
      showStatus('Extension reloaded - please close and reopen DevTools', 'error');
    } else {
      console.error('Error posting message:', error);
    }
    return false;
  }
}

// Global error handler for extension context invalidation
window.addEventListener('error', (event) => {
  if (event.error?.message?.includes('Extension context invalidated')) {
    event.preventDefault();
    console.warn('Extension context invalidated - please reload DevTools');
    showStatus('Extension reloaded - please close and reopen DevTools', 'error');
  }
});
const reloadExtensionBtn = document.getElementById('reload-extension-btn');
// Reload extension button
if (reloadExtensionBtn) {
  reloadExtensionBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      showStatus('Reloading extension...', 'info');
      // Give the status a moment to render
      setTimeout(() => {
        // chrome.runtime.reload will invalidate context; the panel will disconnect
        chrome.runtime.reload();
      }, 250);
    } catch (err) {
      console.error('Failed to reload extension:', err);
      showStatus('Failed to reload extension', 'error');
    }
  });
}

// Initialize security analyzer
(async () => {
  securityAnalyzer = new SecurityAnalyzer();
  await securityAnalyzer.init();
  console.log('Security analyzer initialized in panel');
})();

// DOM elements
const endpointsList = document.getElementById('endpoints-list');
const requestDetails = document.getElementById('request-details');
const clearBtn = document.getElementById('clear-btn');
const exportBtn = document.getElementById('export-btn');
const recordCheckbox = document.getElementById('record-checkbox');
const selectAllBtn = document.getElementById('select-all-btn');
const selectNoneBtn = document.getElementById('select-none-btn');
const askAiAllBtn = document.getElementById('ask-ai-all-btn');
const excelReportBtn = document.getElementById('excel-report-btn');
const selectionInfo = document.getElementById('selection-info');
const securitySummary = document.getElementById('security-summary');
const securitySettingsBtn = document.getElementById('security-settings-btn');
const securityModal = document.getElementById('security-modal');
const modalCloseBtn = document.getElementById('modal-close-btn');
const saveRulesBtn = document.getElementById('save-rules-btn');
const resetRulesBtn = document.getElementById('reset-rules-btn');
const clearSeverityFilterBtn = document.getElementById('clear-severity-filter-btn');
const responseBodiesCheckbox = document.getElementById('response-bodies-checkbox');
const dcFilterCheckbox = document.getElementById('dc-filter-checkbox');
const gamxFilterCheckbox = document.getElementById('gamx-filter-checkbox');

// Response bodies state
let responseBodiesEnabled = false;

// Safe DOM creation helper
function createElement(tag, className, textContent, attributes = {}) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (textContent) element.textContent = textContent;
  Object.entries(attributes).forEach(([key, value]) => {
    element.setAttribute(key, value);
  });
  return element;
}

// Debounce function for performance
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Filter endpoints based on search text, method, and host
function getFilteredEndpoints() {
  let filtered = Array.from(apiData.entries());
  
  // Advanced query filtering similar to Chrome's Network filter bar
  if (filterText && filterText.trim().length > 0) {
    const qp = parseFilterQuery(filterText);
    filtered = filtered.filter(([endpoint, data]) => matchesAdvancedFilter(endpoint, data, qp));
  }
  
  if (filterMethods.size > 0) {
    filtered = filtered.filter(([endpoint, data]) => {
      return filterMethods.has(data.method.toUpperCase());
    });
  }
  
  if (filterHosts.size > 0) {
    filtered = filtered.filter(([endpoint, data]) => {
      return filterHosts.has(data.host);
    });
  }
  
  if (filterTags.size > 0) {
    filtered = filtered.filter(([endpoint, data]) => {
      const endpointTagsSet = endpointTags.get(endpoint) || new Set();
      // Check if endpoint has at least one of the selected tags
      for (const tag of filterTags) {
        if (endpointTagsSet.has(tag)) {
          return true;
        }
      }
      return false;
    });
  }
  
  // Filter by vulnerability severity
  if (filterSeverity.size > 0) {
    filtered = filtered.filter(([endpoint, data]) => {
      if (!data.securityIssues || data.securityIssues.length === 0) {
        return false; // Only show endpoints with issues
      }
      
      // Check if endpoint has at least one issue with the selected severity
      for (const issue of data.securityIssues) {
        if (filterSeverity.has(issue.severity)) {
          return true;
        }
      }
      return false;
    });
  }
  
  // Sort by tags if grouping is enabled
  if (groupByTags) {
    return filtered.sort((a, b) => {
      const tagsA = Array.from(endpointTags.get(a[0]) || new Set()).join(',');
      const tagsB = Array.from(endpointTags.get(b[0]) || new Set()).join(',');
      if (tagsA !== tagsB) {
        return tagsA.localeCompare(tagsB);
      }
      return a[0].localeCompare(b[0]);
    });
  }
  
  return filtered.sort((a, b) => a[0].localeCompare(b[0]));
}

// ---- Advanced Filter Helpers ----
function parseFilterQuery(q) {
  const tokens = [];
  const re = /\S+/g; // split by whitespace
  let m;
  while ((m = re.exec(q)) !== null) {
    const raw = m[0];
    const neg = raw.startsWith('-');
    const t = neg ? raw.slice(1) : raw;
    let type = 'text';
    let value = t;
    let flags = '';

    // Chrome-like regex literal: /(aac|mga)/ or /(aac|mga)/i
    if (t.startsWith('/') && t.length > 1) {
      const lastSlash = t.lastIndexOf('/');
      if (lastSlash > 0) {
        const pattern = t.slice(1, lastSlash);
        const maybeFlags = t.slice(lastSlash + 1);
        // Only treat as regex if flags are empty or valid letters
        if (/^[a-z]*$/.test(maybeFlags)) {
          type = 'regex-literal';
          value = pattern;
          flags = maybeFlags || 'i'; // default to case-insensitive like Chrome search
          tokens.push({ neg, type, value, flags });
          continue;
        }
      }
    }

    const colon = t.indexOf(':');
    if (colon > 0) {
      type = t.slice(0, colon).toLowerCase();
      value = t.slice(colon + 1);
    }
    tokens.push({ neg, type, value, flags });
  }
  return tokens;
}

function matchesAdvancedFilter(endpoint, data, tokens) {
  // precompute lowercase fields
  const method = (data.method || '').toLowerCase();
  const host = (data.host || '').toLowerCase();
  const path = (data.pathname || '').toLowerCase();
  const fullUrl = (data.url || '');
  const fullUrlLc = fullUrl.toLowerCase();
  const endpointLc = (endpoint || '').toLowerCase();
  const tags = Array.from((endpointTags.get(endpoint) || new Set()).values());
  const tagsLc = tags.map(t => (t || '').toLowerCase());
  const statusSet = new Set((data.calls || []).map(c => c.status).filter(Boolean));
  const hasMap = new Set();
  // mark presence helpers
  if (data.queryParams && data.queryParams.size ? data.queryParams.size > 0 : Array.isArray(data.queryParams) ? data.queryParams.length > 0 : false) {
    hasMap.add('query');
  }
  if (data.requestBodies && data.requestBodies.length > 0) {
    hasMap.add('request-body');
  }
  if (data.requestHeaders && (data.requestHeaders.size ? data.requestHeaders.size > 0 : Array.isArray(data.requestHeaders) ? data.requestHeaders.length > 0 : false)) {
    hasMap.add('request-headers');
    hasMap.add('headers');
  }
  if ((data.securityIssues || []).length > 0) {
    hasMap.add('security');
  }

  // evaluate each token; all tokens must be satisfied
  for (const tok of tokens) {
    let ok = false;
    const val = tok.value.toLowerCase();
    const rawVal = tok.value;
    switch (tok.type) {
      case 'regex-literal':
        try {
          const rx = new RegExp(tok.value, tok.flags || 'i');
          ok = rx.test(endpoint) || rx.test(data.pathname) || rx.test(data.host) || rx.test(fullUrl);
        } catch (_) { ok = false; }
        break;
      case 'method':
        ok = method === val;
        break;
      case 'host':
        // Support regex literal in value: host:/pattern/flags
        if (/^\/.+\/[a-z]*$/i.test(rawVal)) {
          const m = rawVal.match(/^\/(.+)\/([a-z]*)$/i);
          try { ok = new RegExp(m[1], m[2] || 'i').test(data.host || ''); } catch (_) { ok = false; }
        } else {
          ok = host.includes(val);
        }
        break;
      case 'path':
        if (/^\/.+\/[a-z]*$/i.test(rawVal)) {
          const m = rawVal.match(/^\/(.+)\/([a-z]*)$/i);
          try { ok = new RegExp(m[1], m[2] || 'i').test(data.pathname || ''); } catch (_) { ok = false; }
        } else {
          ok = path.includes(val);
        }
        break;
      case 'url':
        if (/^\/.+\/[a-z]*$/i.test(rawVal)) {
          const m = rawVal.match(/^\/(.+)\/([a-z]*)$/i);
          try { ok = new RegExp(m[1], m[2] || 'i').test(fullUrl); } catch (_) { ok = false; }
        } else {
          ok = fullUrlLc.includes(val) || path.includes(val) || endpointLc.includes(val);
        }
        break;
      case 'status':
        // supports prefix like 4xx, exact like 404
        if (/^\d{3}$/.test(val)) ok = statusSet.has(Number(val));
        else if (/^[1-5]xx$/.test(val)) {
          const prefix = Number(val[0]);
          ok = Array.from(statusSet).some(s => Math.floor(s / 100) === prefix);
        }
        break;
      case 'tag':
        ok = tagsLc.some(t => t.includes(val));
        break;
      case 'has':
        ok = hasMap.has(val);
        break;
      case 're':
      case 'regex':
        try {
          const rx = new RegExp(tok.value, 'i');
          ok = rx.test(endpoint) || rx.test(data.pathname) || rx.test(data.host);
        } catch (_) { ok = false; }
        break;
      case 'text':
      default:
        ok = endpointLc.includes(val) || host.includes(val) || path.includes(val) || fullUrlLc.includes(val) || method.includes(val) || tagsLc.some(t => t.includes(val));
        break;
    }
    if (tok.neg ? ok : !ok) return false; // negated token fails if matched
  }
  return true;
}

// Update endpoints list with safe DOM manipulation
const updateEndpointsList = debounce(() => {
  // Clear existing content
  while (endpointsList.firstChild) {
    endpointsList.removeChild(endpointsList.firstChild);
  }
  
  const filteredEndpoints = getFilteredEndpoints();
  
  if (filteredEndpoints.length === 0) {
    let message = 'No API calls captured yet';
    
    if (filterSeverity.size > 0) {
      const severityNames = Array.from(filterSeverity).join(', ');
      message = `No endpoints with ${severityNames} severity issues found`;
    } else if (filterText || filterMethods.size > 0 || filterHosts.size > 0 || filterTags.size > 0) {
      message = 'No endpoints match your filters';
    }
    
    const emptyMessage = createElement('div', 'empty-message', message);
    endpointsList.appendChild(emptyMessage);
    return;
  }
  
  filteredEndpoints.forEach(([endpoint, data]) => {
    const div = createElement('div', 'endpoint-item');
    if (endpoint === selectedEndpoint) {
      div.classList.add('selected');
    }
    
    // Add checkbox
    const checkbox = createElement('input', 'endpoint-checkbox', '', {
      type: 'checkbox',
      'data-endpoint': endpoint
    });
    checkbox.checked = selectedEndpoints.has(endpoint);
    checkbox.addEventListener('click', (e) => {
      e.stopPropagation(); // Prevent triggering the div click
      if (e.target.checked) {
        selectedEndpoints.add(endpoint);
      } else {
        selectedEndpoints.delete(endpoint);
      }
      updateSelectionInfo();
    });
    
    const methodSpan = createElement('span', `method ${data.method.toLowerCase()}`, data.method);
    const pathSpan = createElement('span', 'path', data.pathname);
    const hostSpan = createElement('span', 'host', data.host);
    const countSpan = createElement('span', 'count', `(${data.calls.length})`);
    
    // Add security indicator
    if (data.securityIssues && data.securityIssues.length > 0) {
      // Deduplicate issues for count
      const uniqueIssuesMap = new Map();
      data.securityIssues.forEach(issue => {
        const key = `${issue.severity}:${issue.rule}:${issue.message || ''}`;
        if (!uniqueIssuesMap.has(key)) {
          uniqueIssuesMap.set(key, issue);
        }
      });
      const uniqueCount = uniqueIssuesMap.size;
      
      const highestSeverity = getHighestSeverity(data.securityIssues);
      const securityIndicator = createElement('span', `security-indicator ${highestSeverity}`, '🛡️');
      securityIndicator.title = `${uniqueCount} security issue(s) detected`;
      div.appendChild(securityIndicator);
    }
    
    // Add tags display
    const tagsSpan = createElement('span', 'endpoint-tags');
    const endpointTagsSet = endpointTags.get(endpoint) || new Set();
    endpointTagsSet.forEach(tag => {
      const tagBadge = createElement('span', 'tag-badge', tag);
      tagsSpan.appendChild(tagBadge);
    });
    
    div.appendChild(checkbox);
    div.appendChild(methodSpan);
    div.appendChild(pathSpan);
    if (endpointTagsSet.size > 0) {
      div.appendChild(tagsSpan);
    }
    if (filterHosts.size === 0 || filterHosts.size > 1) {
      div.appendChild(hostSpan);
    }
    div.appendChild(countSpan);
    
    div.addEventListener('click', (e) => {
      if (e.target.type !== 'checkbox') {
        // If we're switching endpoints, update the list to show any tag changes
        if (selectedEndpoint !== endpoint) {
          updateEndpointsList();
        }
        selectedEndpoint = endpoint;
        showEndpointDetails(endpoint);
      }
    });
    
    endpointsList.appendChild(div);
  });
}, CONFIG.DEBOUNCE_DELAY);

// Show endpoint details safely
function showEndpointDetails(endpoint) {
  const data = apiData.get(endpoint);
  if (!data) {
    requestDetails.textContent = 'Endpoint not found';
    return;
  }
  
  // Don't rebuild if we're already showing this endpoint and just updating tags
  if (window.currentShowingEndpoint === endpoint && window.isEditingTags) {
    return;
  }
  window.currentShowingEndpoint = endpoint;
  
  // Clear existing content
  while (requestDetails.firstChild) {
    requestDetails.removeChild(requestDetails.firstChild);
  }
  
  // Create sections
  const title = createElement('h2', null, 'Endpoint Details');
  requestDetails.appendChild(title);
  
  // General Information section
  const generalSection = createElement('div', 'detail-section');
  generalSection.appendChild(createElement('h3', null, 'General Information'));
  
  const infoList = createElement('div', 'info-list');
  infoList.appendChild(createInfoItem('Method', data.method));
  infoList.appendChild(createInfoItem('Path', data.pathname));
  infoList.appendChild(createInfoItem('Host', data.host));
  infoList.appendChild(createInfoItem('Total Calls', data.calls.length));
  generalSection.appendChild(infoList);
  requestDetails.appendChild(generalSection);
  
  // Security Issues section - show first for visibility
  const securitySection = createSecurityIssuesSection(data);
  requestDetails.appendChild(securitySection);
  
  // User Notes section
  const tagsSection = createElement('div', 'detail-section');
  tagsSection.appendChild(createElement('h3', null, 'User Notes'));
  
  const tagsContainer = createElement('div', 'tags-container');
  const endpointTagsSet = endpointTags.get(endpoint) || new Set();
  
  // Display existing tags
  const tagsDisplay = createElement('div', 'tags-display');
  
  // Define updateTagsDisplay function first
  const updateTagsDisplay = () => {
    // Clear existing tags
    while (tagsDisplay.firstChild) {
      tagsDisplay.removeChild(tagsDisplay.firstChild);
    }
    
    // Re-render tags
    const currentTags = endpointTags.get(endpoint) || new Set();
    currentTags.forEach(tag => {
      const tagElement = createElement('span', 'tag');
      tagElement.textContent = tag;
      
      const removeBtn = createElement('button', 'tag-remove', '×');
      removeBtn.addEventListener('click', () => {
        removeTag(endpoint, tag);
        updateTagsDisplay(); // Update just the tags display
      });
      
      tagElement.appendChild(removeBtn);
      tagsDisplay.appendChild(tagElement);
    });
  };
  
  // Initial render of tags
  updateTagsDisplay();
  
  // Add tag input
  const addTagContainer = createElement('div', 'add-tag-container');
  const tagInput = createElement('input', 'tag-input', '', {
    type: 'text',
    placeholder: 'Add a note...',
    list: 'tag-suggestions'
  });
  
  // Prevent any event bubbling that might cause focus loss
  const preventFocusLoss = (e) => {
    e.stopPropagation();
    e.stopImmediatePropagation();
  };
  
  tagInput.addEventListener('focus', (e) => {
    window.isEditingTags = true;
    preventFocusLoss(e);
  });
  
  tagInput.addEventListener('blur', (e) => {
    window.isEditingTags = false;
  });
  
  tagInput.addEventListener('click', preventFocusLoss);
  tagInput.addEventListener('mousedown', preventFocusLoss);
  tagInput.addEventListener('mouseup', preventFocusLoss);
  
  
  // Create datalist for tag suggestions
  const datalist = createElement('datalist', null, '', { id: 'tag-suggestions' });
  allTags.forEach(tag => {
    const option = createElement('option', null, '', { value: tag });
    datalist.appendChild(option);
  });
  
  const addTagBtn = createElement('button', 'add-tag-btn', 'Add Note');
  
  // Update the container click handler to include the button reference
  addTagContainer.addEventListener('click', (e) => {
    if (e.target !== tagInput && e.target !== addTagBtn) {
      e.preventDefault();
      tagInput.focus();
    }
  });
  
  const addTag = () => {
    const tag = tagInput.value.trim();
    if (tag && tag.length > 0) {
      addTagToEndpoint(endpoint, tag);
      tagInput.value = '';
      // Don't refresh the whole details, just update the tags display
      updateTagsDisplay();
    }
  };
  
  addTagBtn.addEventListener('click', addTag);
  tagInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault(); // Prevent form submission
      addTag();
    }
  });
  
  addTagContainer.appendChild(tagInput);
  addTagContainer.appendChild(datalist);
  addTagContainer.appendChild(addTagBtn);
  
  tagsContainer.appendChild(tagsDisplay);
  tagsContainer.appendChild(addTagContainer);
  tagsSection.appendChild(tagsContainer);
  requestDetails.appendChild(tagsSection);
  
  // Query Parameters section
  if (data.queryParams.size > 0) {
    const querySection = createElement('div', 'detail-section');
    querySection.appendChild(createElement('h3', null, 'Query Parameters'));
    
    const paramList = createElement('ul');
    Array.from(data.queryParams).forEach(param => {
      const li = createElement('li', null, param);
      paramList.appendChild(li);
    });
    querySection.appendChild(paramList);
    requestDetails.appendChild(querySection);
  }
  
  // Request Headers section removed per requirements
  
  // Request Body Structure section
  if (data.requestBodies.length > 0) {
    const bodySection = createElement('div', 'detail-section');
    bodySection.appendChild(createElement('h3', null, 'Request Body Structure'));
    
    const pre = createElement('pre');
    pre.textContent = JSON.stringify(analyzeStructure(data.requestBodies[0]), null, 2);
    bodySection.appendChild(pre);
    requestDetails.appendChild(bodySection);
  }
  
  // Recent Calls section
  const callsSection = createElement('div', 'detail-section');
  callsSection.appendChild(createElement('h3', null, 'Recent Calls'));
  
  const callsList = createElement('div', 'calls-list');
  const recentCalls = data.calls.slice(-5).reverse();
  
  if (recentCalls.length === 0) {
    callsList.appendChild(createElement('p', null, 'No calls recorded'));
  } else {
    recentCalls.forEach((call, idx) => {
      const callItem = createElement('div', 'call-item');
      
      // Call header with timestamp, status, and actions
      const callHeader = createElement('div', 'call-header-bar');
      
      const callInfo = createElement('div', 'call-info');
      callInfo.appendChild(createInfoItem('Time', new Date(call.timestamp).toLocaleTimeString()));
      callInfo.appendChild(createInfoItem('Status', call.status || 'Pending'));
      
      const callActions = createElement('div', 'call-actions');
      
      // Copy cURL button
      const curlButton = createElement('button', 'copy-curl-btn', 'Copy cURL');
      curlButton.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        e.stopImmediatePropagation();
        copyCurlCommand(data, call);
      });
      
      callActions.appendChild(curlButton);
      
      callHeader.appendChild(callInfo);
      callHeader.appendChild(callActions);
      callItem.appendChild(callHeader);
      
  // Raw HTTP container (open by default)
  const rawContainer = createElement('div', 'raw-http-container');
      rawContainer.setAttribute('data-call-id', `call-${idx}`);
      
      // Side-by-side layout for request and response
      const httpGrid = createElement('div', 'http-grid');
      
      // === REQUEST COLUMN ===
      const requestColumn = createElement('div', 'http-column request-column');
      
      // Request Column Header with Copy Button
      const reqColHeader = createElement('div', 'column-header-row');
      
      reqColHeader.appendChild(createElement('h4', 'column-title-text', 'REQUEST'));
      
      const copyReqBtn = createElement('button', 'copy-icon-btn', '');
      copyReqBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-copy" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1z"/></svg>';
      copyReqBtn.title = 'Copy Entire Request';
      const fullReqText = buildRawHttpRequest(call, data);
      copyReqBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(fullReqText);
        const original = copyReqBtn.innerHTML;
        copyReqBtn.textContent = '✓';
        setTimeout(() => copyReqBtn.innerHTML = original, 1500);
      });
      reqColHeader.appendChild(copyReqBtn);
      
      requestColumn.appendChild(reqColHeader);
      
      // Request Headers Section with copy icon
      const reqHeadersTitle = createElement('div', 'section-title-row');
      reqHeadersTitle.appendChild(createElement('span', 'section-label', 'Headers'));
      const copyReqHeadersBtn = createElement('button', 'copy-icon-btn', '📋');
      copyReqHeadersBtn.title = 'Copy Request Headers';
      const reqHeadersText = buildRequestHeaders(call, data);
      copyReqHeadersBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(reqHeadersText);
        copyReqHeadersBtn.textContent = '✓';
        setTimeout(() => copyReqHeadersBtn.textContent = '📋', 1500);
      });
      reqHeadersTitle.appendChild(copyReqHeadersBtn);
      requestColumn.appendChild(reqHeadersTitle);
      
      const reqHeadersPre = createElement('pre', 'raw-http-text headers-section');
      reqHeadersPre.textContent = reqHeadersText;
      requestColumn.appendChild(reqHeadersPre);
      
      // Request Body Section with copy icon
      const reqBodyTitle = createElement('div', 'section-title-row');
      reqBodyTitle.appendChild(createElement('span', 'section-label', 'Body'));
      const copyReqBodyBtn = createElement('button', 'copy-icon-btn', '📋');
      copyReqBodyBtn.title = 'Copy Request Body';
      const reqBodyText = buildRequestBody(call);
      copyReqBodyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(reqBodyText);
        copyReqBodyBtn.textContent = '✓';
        setTimeout(() => copyReqBodyBtn.textContent = '📋', 1500);
      });
      reqBodyTitle.appendChild(copyReqBodyBtn);
      requestColumn.appendChild(reqBodyTitle);
      
      const reqBodyPre = createElement('pre', 'raw-http-text body-section');
      reqBodyPre.textContent = reqBodyText || '(No request body)';
      requestColumn.appendChild(reqBodyPre);
      
      httpGrid.appendChild(requestColumn);
      
      // === RESPONSE COLUMN ===
      const responseColumn = createElement('div', 'http-column response-column');
      
      // Response Column Header with Copy Button
      const resColHeader = createElement('div', 'column-header-row');
      
      resColHeader.appendChild(createElement('h4', 'column-title-text', 'RESPONSE'));
      
      const copyResBtn = createElement('button', 'copy-icon-btn', '');
      copyResBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-copy" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1z"/></svg>';
      copyResBtn.title = 'Copy Entire Response';
      const fullResText = buildRawHttpResponse(call);
      copyResBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(fullResText);
        const original = copyResBtn.innerHTML;
        copyResBtn.textContent = '✓';
        setTimeout(() => copyResBtn.innerHTML = original, 1500);
      });
      resColHeader.appendChild(copyResBtn);
      
      responseColumn.appendChild(resColHeader);
      
      // Response Headers Section with copy icon
      const resHeadersTitle = createElement('div', 'section-title-row');
      resHeadersTitle.appendChild(createElement('span', 'section-label', 'Headers'));
      const copyResHeadersBtn = createElement('button', 'copy-icon-btn', '📋');
      copyResHeadersBtn.title = 'Copy Response Headers';
      const resHeadersText = buildResponseHeaders(call);
      copyResHeadersBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(resHeadersText);
        copyResHeadersBtn.textContent = '✓';
        setTimeout(() => copyResHeadersBtn.textContent = '📋', 1500);
      });
      resHeadersTitle.appendChild(copyResHeadersBtn);
      responseColumn.appendChild(resHeadersTitle);
      
      const resHeadersPre = createElement('pre', 'raw-http-text headers-section');
      resHeadersPre.textContent = resHeadersText;
      responseColumn.appendChild(resHeadersPre);
      
      // Response Body Section with copy icon
      const resBodyTitle = createElement('div', 'section-title-row');
      resBodyTitle.appendChild(createElement('span', 'section-label', 'Body'));
      const copyResBodyBtn = createElement('button', 'copy-icon-btn', '📋');
      copyResBodyBtn.title = 'Copy Response Body';
      const resBodyText = buildResponseBody(call);
      copyResBodyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(resBodyText);
        copyResBodyBtn.textContent = '✓';
        setTimeout(() => copyResBodyBtn.textContent = '📋', 1500);
      });
      resBodyTitle.appendChild(copyResBodyBtn);
      responseColumn.appendChild(resBodyTitle);
      
      const resBodyPre = createElement('pre', 'raw-http-text body-section');
      resBodyPre.textContent = resBodyText;
      responseColumn.appendChild(resBodyPre);
      
      httpGrid.appendChild(responseColumn);
      
      rawContainer.appendChild(httpGrid);
      callItem.appendChild(rawContainer);
      
      callsList.appendChild(callItem);
    });
  }
  
  callsSection.appendChild(callsList);
  requestDetails.appendChild(callsSection);
}

// Helper to create info items
function createInfoItem(label, value) {
  const p = createElement('p');
  const strong = createElement('strong', null, `${label}: `);
  p.appendChild(strong);
  p.appendChild(document.createTextNode(String(value)));
  return p;
}

// Build raw HTTP request
function buildRawHttpRequest(call, data) {
  const lines = [];
  lines.push(buildRequestHeaders(call, data));
  lines.push('');
  const body = buildRequestBody(call);
  if (body) lines.push(body);
  return lines.join('\n');
}

// Build request headers only
function buildRequestHeaders(call, data) {
  const lines = [];
  
  // Request line
  const url = new URL(call.url);
  const pathAndQuery = url.search ? `${url.pathname}${url.search}` : url.pathname;
  lines.push(`${data.method} ${pathAndQuery} HTTP/1.1`);
  lines.push(`Host: ${url.host}`);
  
  // ALL Headers - no filtering
  if (call.allHeaders) {
    Object.entries(call.allHeaders).forEach(([name, value]) => {
      if (name.toLowerCase() !== 'host') { // Skip host, already added
        lines.push(`${name}: ${value}`);
      }
    });
  }
  
  return lines.join('\n');
}

// Build request body only
function buildRequestBody(call) {
  if (call.requestBody) {
    if (typeof call.requestBody === 'object') {
      return JSON.stringify(call.requestBody, null, 2);
    } else {
      return call.requestBody;
    }
  }
  return '';
}

// Build raw HTTP response
function buildRawHttpResponse(call) {
  const lines = [];
  lines.push(buildResponseHeaders(call));
  lines.push('');
  lines.push(buildResponseBody(call));
  return lines.join('\n');
}

// Build response headers only
function buildResponseHeaders(call) {
  const lines = [];
  
  // Status line
  lines.push(`HTTP/1.1 ${call.status || 'Pending'} ${call.statusLine || ''}`);
  
  // ALL Response headers - no filtering
  if (call.responseHeaders && Object.keys(call.responseHeaders).length > 0) {
    Object.entries(call.responseHeaders).forEach(([name, value]) => {
      lines.push(`${name}: ${value}`);
    });
  }
  
  return lines.join('\n');
}

// Build response body only
function buildResponseBody(call) {
  if (call.responseBody) {
    try {
      // Try to parse as JSON for pretty printing
      const parsed = JSON.parse(call.responseBody);
      return JSON.stringify(parsed, null, 2);
    } catch {
      // Not JSON, show as-is
      return call.responseBody;
    }
  } else {
    // Body note when not available
    if (!responseBodiesEnabled) {
      return 'Response body capture is disabled.\nEnable "Response Bodies" checkbox to capture.';
    } else {
      return '(Response body not available)';
    }
  }
}

// Toggle raw view
function toggleRawView(callItem, call, data) {
  const rawContainer = callItem.querySelector('.raw-http-container');
  const viewButton = callItem.querySelector('.view-raw-btn');
  
  if (rawContainer && viewButton) {
    if (rawContainer.classList.contains('hidden')) {
      rawContainer.classList.remove('hidden');
      viewButton.textContent = 'Hide Raw';
    } else {
      rawContainer.classList.add('hidden');
      viewButton.textContent = 'View Raw';
    }
  }
}

// Analyze structure with better type detection
function analyzeStructure(obj) {
  if (obj === null) return "null";
  if (obj === undefined) return "string"; // Default to string instead of "undefined"
  
  const type = Array.isArray(obj) ? "array" : typeof obj;
  
  // Map JavaScript types to valid JSON Schema types
  if (type === "function") return "string";
  if (type === "symbol") return "string";
  if (type === "bigint") return "number";
  
  if (type === "object" && obj !== null) {
    const structure = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const analyzed = analyzeStructure(obj[key]);
        // Ensure we don't propagate invalid types
        if (typeof analyzed === "string" && !["string", "number", "boolean", "null", "array", "object"].includes(analyzed)) {
          structure[key] = "string";
        } else {
          structure[key] = analyzed;
        }
      }
    }
    return structure;
  } else if (type === "array") {
    if (obj.length === 0) {
      return [];
    }
    // Analyze all items to find common structure
    const itemTypes = obj.map(item => analyzeStructure(item));
    // For now, use the first item's structure
    return [itemTypes[0]];
  } else if (type === "string" || type === "number" || type === "boolean") {
    return type;
  } else {
    // Default any unknown types to string
    return "string";
  }
}

// Port message handler with error handling
port.onMessage.addListener((msg) => {
  try {
    if (msg.type === "CONNECTION_READY") {
      if (typeof msg.version === 'number') currentDataVersion = msg.version;
      isConnected = true;
      showStatus('Connected to GAMX Extension', 'success');
      // Request initial data
      safePostMessage({ type: "GET_API_CALLS" });
      // Check response bodies status
      safePostMessage({ type: "GET_RESPONSE_BODIES_STATUS" });
    } else if (msg.type === "API_CALLS_DATA") {
      if (typeof msg.version === 'number' && msg.version < currentDataVersion) {
        // stale message after a clear; ignore
        return;
      }
      if (typeof msg.version === 'number') currentDataVersion = msg.version;
      apiData.clear();
      hostsList.clear();
      msg.data.forEach(item => {
        // Convert arrays back to Sets if needed
        const processedItem = {
          ...item,
          queryParams: Array.isArray(item.queryParams) ? 
            new Set(item.queryParams) : 
            item.queryParams,
          requestHeaders: Array.isArray(item.requestHeaders) ? 
            new Set(item.requestHeaders) : 
            (item.requestHeaders || new Set()),
          securityIssues: item.securityIssues || [] // Ensure security issues are included
        };
        apiData.set(item.endpoint, processedItem);
        if (item.host) {
          hostsList.add(item.host);
        }
      });
      updateHostFilter();
      updateEndpointsList();
      updateSecuritySummary();
      if (selectedEndpoint && apiData.has(selectedEndpoint)) {
        showEndpointDetails(selectedEndpoint);
      }
    } else if (msg.type === "DATA_CLEARED") {
      if (typeof msg.version === 'number') currentDataVersion = msg.version;
      console.log('DATA_CLEARED message received');
      clearAllDataLocal();
      showStatus('Data cleared', 'success');
    } else if (msg.type === "RESPONSE_BODIES_STATUS") {
      responseBodiesEnabled = msg.enabled;
      responseBodiesCheckbox.checked = msg.enabled;
      if (msg.message) {
        showStatus(msg.message, msg.enabled ? 'success' : 'info');
      }
      if (msg.enabled) {
        showStatus('WARNING: Response body capture enabled. You may see a debugger warning banner.', 'warning', 5000);
      }
    } else if (msg.type === "ERROR") {
      showStatus(`Error: ${msg.message}`, 'error');
    }
  } catch (error) {
    console.error('Error handling message:', error);
    showStatus('Error processing data', 'error');
  }
});

// Handle disconnection
port.onDisconnect.addListener(() => {
  try {
    isConnected = false;
    const error = chrome.runtime.lastError;
    if (error?.message?.includes('Extension context invalidated')) {
      showStatus('Extension reloaded - please close and reopen DevTools', 'error');
    } else {
      showStatus('Disconnected from background script', 'error');
    }
    clearInterval(updateTimer);
  } catch (e) {
    console.error('Error in disconnect handler:', e);
  }
});

// Chrome runtime message handler
chrome.runtime.onMessage.addListener((msg) => {
  try {
    if (msg.type === "API_CALL_DETECTED") {
      // If we've just cleared, ensure we're not showing stale items by requiring currentDataVersion to be stable
      // Since runtime messages have no version, we accept them but state was cleared already; nothing extra needed
      // Convert arrays back to Sets if needed
      const processedData = {
        ...msg.data,
        queryParams: Array.isArray(msg.data.queryParams) ? 
          new Set(msg.data.queryParams) : 
          msg.data.queryParams,
        requestHeaders: Array.isArray(msg.data.requestHeaders) ? 
          new Set(msg.data.requestHeaders) : 
          (msg.data.requestHeaders || new Set())
      };
      apiData.set(msg.endpoint, processedData);
      if (msg.data.host && !hostsList.has(msg.data.host)) {
        hostsList.add(msg.data.host);
        updateHostFilter();
      }
      updateEndpointsList();
      if (msg.endpoint === selectedEndpoint) {
        showEndpointDetails(selectedEndpoint);
      }
    }
  } catch (error) {
    console.error('Error handling API_CALL_DETECTED:', error);
  }
});

// Update selection info display
function updateSelectionInfo() {
  const count = selectedEndpoints.size;
  const total = apiData.size;
  selectionInfo.textContent = `${count} of ${total} selected`;
}

// Tag management functions
function addTagToEndpoint(endpoint, tag) {
  if (!endpointTags.has(endpoint)) {
    endpointTags.set(endpoint, new Set());
  }
  endpointTags.get(endpoint).add(tag);
  allTags.add(tag);
  updateTagFilter();
  // Don't update the endpoints list while editing tags - it will update when user navigates away
}

function removeTag(endpoint, tag) {
  if (endpointTags.has(endpoint)) {
    endpointTags.get(endpoint).delete(tag);
    if (endpointTags.get(endpoint).size === 0) {
      endpointTags.delete(endpoint);
    }
  }
  
  // Check if tag is still used by other endpoints
  let tagStillUsed = false;
  endpointTags.forEach(tags => {
    if (tags.has(tag)) {
      tagStillUsed = true;
    }
  });
  
  if (!tagStillUsed) {
    allTags.delete(tag);
    filterTags.delete(tag);
  }
  
  updateTagFilter();
  // Don't update the endpoints list while editing tags - it will update when user navigates away
}

// Show status messages
function showStatus(message, type = 'info', duration = 3000) {
  // Create or update status element
  let status = document.getElementById('status-message');
  if (!status) {
    status = createElement('div', 'status-message', '', { id: 'status-message' });
    document.body.appendChild(status);
  }
  
  status.textContent = message;
  status.className = `status-message ${type}`;
  
  setTimeout(() => {
    status.style.opacity = '0';
    setTimeout(() => {
      if (status.parentNode) {
        status.parentNode.removeChild(status);
      }
    }, 300);
  }, duration);
}

// Copy curl command to clipboard
function copyCurlCommand(data, call) {
  // Build curl command
  let curl = `curl -X ${data.method} \\\n  'https://${data.host}${data.pathname}`;
  
  // Add query parameters
  if (Object.keys(call.queryParams).length > 0) {
    const queryPairs = Object.entries(call.queryParams).map(([key, value]) => {
      if (value === '***REDACTED***') {
        return `${key}=YOUR_${key.toUpperCase()}_HERE`;
      }
      return `${key}=${encodeURIComponent(value)}`;
    });
    curl += `?${queryPairs.join('&')}`;
  }
  curl += "'";
  
  // Add custom headers only
  if (call.requestHeaders) {
    Object.entries(call.requestHeaders).forEach(([header, value]) => {
      if (!['Accept', 'Content-Type', 'User-Agent', 'Referer', 'Origin'].includes(header)) {
        if (value === '***REDACTED***') {
          curl += ` \\\n  -H '${header}: YOUR_${header.toUpperCase().replace(/-/g, '_')}_HERE'`;
        } else {
          const escapedValue = value.replace(/'/g, "'\\''");
          curl += ` \\\n  -H '${header}: ${escapedValue}'`;
        }
      }
    });
  }
  
  // Add request body
  if (call.requestBody) {
    curl += ` \\\n  -d '${JSON.stringify(call.requestBody)}'`;
  }
  
  // Copy to clipboard
  navigator.clipboard.writeText(curl).then(() => {
    showStatus('cURL command copied to clipboard', 'success');
  }).catch(() => {
    showStatus('Failed to copy to clipboard', 'error');
  });
}

// Event listeners
clearBtn.addEventListener('click', () => {
  console.log('Clear button clicked');
  if (confirm('Are you sure you want to clear all captured data?')) {
    console.log('User confirmed clear');
    // Clear UI immediately for responsiveness
    clearAllDataLocal();
    // Optimistically bump version to ignore stale responses until background confirms
    currentDataVersion += 1;
    showStatus('Clearing data...', 'info');
    const sent = safePostMessage({ type: "CLEAR_DATA" });
    if (!sent) {
      showStatus('Failed to notify background - connection lost. UI cleared locally.', 'warning');
    } else {
      console.log('Clear data message sent successfully');
    }
  } else {
    console.log('User cancelled clear');
  }
});

exportBtn.addEventListener('click', () => {
  try {
    if (selectedEndpoints.size === 0) {
      showStatus('Please select at least one endpoint to export', 'error');
      return;
    }
    
    const openApiSpec = generateOpenApiSpec(true); // Pass true to filter by selection
    
    const blob = new Blob([JSON.stringify(openApiSpec, null, 2)], 
      { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `openapi-spec-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    showStatus(`Exported ${selectedEndpoints.size} endpoints`, 'success');
  } catch (error) {
    console.error('Export error:', error);
    showStatus('Export failed', 'error');
  }
});

recordCheckbox.addEventListener('change', (e) => {
  safePostMessage({ type: "SET_RECORDING", recording: e.target.checked });
  showStatus(e.target.checked ? 'Recording enabled' : 'Recording paused', 'info');
});

// Response bodies checkbox
responseBodiesCheckbox.addEventListener('change', async (e) => {
  const enabled = e.target.checked;
  
  if (enabled) {
    // Get current tab ID
    const tabId = chrome.devtools.inspectedWindow.tabId;
    if (!safePostMessage({ type: "ENABLE_RESPONSE_BODIES", tabId })) {
      showStatus('Failed to enable response body capture - disconnected', 'error');
      e.target.checked = false;
      return;
    }
    showStatus('Enabling response body capture...', 'info');
  } else {
    const tabId = chrome.devtools.inspectedWindow.tabId;
    if (!safePostMessage({ type: "DISABLE_RESPONSE_BODIES", tabId })) {
      showStatus('Failed to disable response body capture - disconnected', 'error');
      return;
    }
    showStatus('Response body capture disabled', 'info');
  }
});

selectAllBtn.addEventListener('click', () => {
  const filteredEndpoints = getFilteredEndpoints();
  filteredEndpoints.forEach(([endpoint]) => {
    selectedEndpoints.add(endpoint);
  });
  updateEndpointsList();
  updateSelectionInfo();
  showStatus('All visible endpoints selected', 'info');
});

selectNoneBtn.addEventListener('click', () => {
  selectedEndpoints.clear();
  updateEndpointsList();
  updateSelectionInfo();
  showStatus('Selection cleared', 'info');
});

askAiAllBtn.addEventListener('click', () => {
  if (selectedEndpoints.size === 0) {
    showStatus('Please select at least one endpoint to analyze', 'error');
    return;
  }

  const prompt = generateCombinedAiPrompt();
  navigator.clipboard.writeText(prompt).then(() => {
    // Save original state
    const originalHTML = '<span class="ai-icon">✨</span> ASK AI';
    
    // Change to success state
    askAiAllBtn.textContent = 'Prompt Copied!';
    askAiAllBtn.style.background = '#10b981'; // Success green
    askAiAllBtn.style.animation = 'none'; // Stop animation temporarily
    
    // Revert after 2 seconds
    setTimeout(() => {
      askAiAllBtn.innerHTML = originalHTML;
      askAiAllBtn.style.background = ''; // Revert to CSS gradient
      askAiAllBtn.style.animation = ''; // Restore animation
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy text: ', err);
    showStatus('Failed to copy prompt to clipboard', 'error');
  });
});

excelReportBtn.addEventListener('click', () => {
  if (selectedEndpoints.size === 0) {
    showStatus('Please select at least one endpoint to export', 'error');
    return;
  }
  
  generateExcelReport();
});

/**
 * Generate and download Excel (CSV) report
 */
function generateExcelReport() {
  try {
    // Prepare CSV content
    const headers = [
      'Endpoint URL',
      'Method',
      'Host',
      'Severity',
      'Vulnerability Name',
      'Description',
      'Location',
      'Technical Details',
      'User Notes'
    ];
    
    let csvContent = headers.join(',') + '\n';
    let issueCount = 0;
    
    selectedEndpoints.forEach(endpoint => {
      const data = apiData.get(endpoint);
      if (data && data.securityIssues && data.securityIssues.length > 0) {
        // Get user notes (tags) for this endpoint
        const tags = endpointTags.get(endpoint);
        const userNotes = tags ? Array.from(tags).join('; ') : '';

        data.securityIssues.forEach(issue => {
          issueCount++;
          
          // Format details as a single string
          let detailsStr = '';
          if (issue.details) {
            detailsStr = JSON.stringify(issue.details).replace(/"/g, '""'); // Escape quotes
          }
          
          const row = [
            `"${(data.url || endpoint).replace(/"/g, '""')}"`,
            `"${(data.method || '').replace(/"/g, '""')}"`,
            `"${(data.host || '').replace(/"/g, '""')}"`,
            `"${(issue.severity || '').toUpperCase()}"`,
            `"${(issue.name || '').replace(/"/g, '""')}"`,
            `"${(issue.message || '').replace(/"/g, '""')}"`,
            `"${(issue.location || '').replace(/"/g, '""')}"`,
            `"${detailsStr}"`,
            `"${userNotes.replace(/"/g, '""')}"`
          ];
          
          csvContent += row.join(',') + '\n';
        });
      }
    });
    
    if (issueCount === 0) {
      showStatus('No security issues found in selected endpoints', 'warning');
      return;
    }
    
    // Create download
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `security_report_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    showStatus(`Exported ${issueCount} vulnerabilities to Excel/CSV`, 'success');
    
  } catch (error) {
    console.error('Export error:', error);
    showStatus('Failed to generate Excel report', 'error');
  }
}

// Add filter controls to header
function addFilterControls() {
  const controls = document.querySelector('.controls');
  
  // Search input
  const searchInput = createElement('input', 'search-input', '', {
    type: 'text',
  placeholder: 'Filter (e.g., method:GET host:api.example.com status:2xx -tag:internal /(aac|mga)/)',
    id: 'search-input'
  });
  
  searchInput.addEventListener('input', (e) => {
    filterText = e.target.value;
    updateEndpointsList();
    updateSecuritySummary();
    // Keep the DC/GAMX checkboxes in sync with the current filter text
    syncCheckboxesFromFilter();
  });

  // Helper to compute regex token based on checkboxes
  function computePartnerRegex() {
    const dc = dcFilterCheckbox?.checked;
    const gamx = gamxFilterCheckbox?.checked;
    if (dc && gamx) return '/(aac|mga|sys-gam-digital)/';
    if (dc) return '/(aac|mga)/';
    if (gamx) return '/(sys-gam-digital)/';
    return '';
  }

  // Inject or remove the partner regex token from the search input without clobbering other terms
  function applyPartnerFilterToken() {
    const token = computePartnerRegex();
    
    // If a token exists (checkbox is being checked), clear the search input first
    if (token) {
      searchInput.value = token;
      filterText = token;
      updateEndpointsList();
      updateSecuritySummary();
    } else {
      // If no token (all checkboxes unchecked), clear the search input
      searchInput.value = '';
      filterText = '';
      updateEndpointsList();
      updateSecuritySummary();
    }
  }

  dcFilterCheckbox?.addEventListener('change', applyPartnerFilterToken);
  gamxFilterCheckbox?.addEventListener('change', applyPartnerFilterToken);

  // Reflect the current filter text back into the DC/GAMX checkboxes
  function syncCheckboxesFromFilter() {
    const terms = (searchInput.value || '').trim().split(/\s+/).filter(Boolean);
    const combinedRe = /^\/\((?:aac\|mga\|sys-gam-digital)\)\/$/i;
    const dcOnlyRe = /^\/\((?:aac\|mga)\)\/$/i;
    const gamxOnlyRe = /^\/\((?:sys-gam-digital)\)\/$/i;

    const hasCombined = terms.some(t => combinedRe.test(t));
    if (hasCombined) {
      if (dcFilterCheckbox) dcFilterCheckbox.checked = true;
      if (gamxFilterCheckbox) gamxFilterCheckbox.checked = true;
      return;
    }
    const hasDC = terms.some(t => dcOnlyRe.test(t));
    const hasGAMX = terms.some(t => gamxOnlyRe.test(t));
    if (dcFilterCheckbox) dcFilterCheckbox.checked = !!hasDC;
    if (gamxFilterCheckbox) gamxFilterCheckbox.checked = !!hasGAMX;
  }

  // Initial sync on load
  syncCheckboxesFromFilter();
  
  // Host filter - Multi-select dropdown
  const hostDropdown = createElement('div', 'host-dropdown', '', {
    id: 'host-dropdown'
  });
  
  const hostButton = createElement('button', 'host-filter-btn', 'All hosts', {
    type: 'button',
    id: 'host-filter-btn'
  });
  
  const hostDropdownContent = createElement('div', 'host-dropdown-content', '', {
    id: 'host-dropdown-content'
  });
  
  // Function to update host filter dropdown
  window.updateHostFilterDropdown = function() {
    // Clear existing content
    while (hostDropdownContent.firstChild) {
      hostDropdownContent.removeChild(hostDropdownContent.firstChild);
    }
    
    // Count calls per host
    const hostCounts = new Map();
    apiData.forEach((data) => {
      const count = hostCounts.get(data.host) || 0;
      hostCounts.set(data.host, count + data.calls.length);
    });
    
    // Sort hosts by call count
    const sortedHosts = Array.from(hostsList).sort((a, b) => {
      const aCount = hostCounts.get(a) || 0;
      const bCount = hostCounts.get(b) || 0;
      if (aCount !== bCount) return bCount - aCount;
      return a.localeCompare(b);
    });
    
    sortedHosts.forEach(host => {
      const label = createElement('label', 'host-option');
      const checkbox = createElement('input', null, '', {
        type: 'checkbox',
        value: host,
        'data-host': host
      });
      checkbox.checked = filterHosts.has(host);
      
      const count = hostCounts.get(host) || 0;
      const endpointCount = Array.from(apiData.values()).filter(d => d.host === host).length;
      const span = createElement('span', 'host-filter-badge');
      span.textContent = `${host} (${endpointCount} endpoints)`;
      
      checkbox.addEventListener('change', (e) => {
        if (e.target.checked) {
          filterHosts.add(host);
        } else {
          filterHosts.delete(host);
        }
        updateHostButtonText();
        updateEndpointsList();
        updateSecuritySummary();
      });
      
      label.appendChild(checkbox);
      label.appendChild(span);
      hostDropdownContent.appendChild(label);
    });
  };
  
  hostDropdown.appendChild(hostButton);
  hostDropdown.appendChild(hostDropdownContent);
  
  // Toggle dropdown
  hostButton.addEventListener('click', (e) => {
    e.stopPropagation();
    updateHostFilterDropdown(); // Update content when opening
    hostDropdown.classList.toggle('open');
  });
  
  // Close dropdown when clicking outside
  document.addEventListener('click', () => {
    hostDropdown.classList.remove('open');
  });
  
  hostDropdownContent.addEventListener('click', (e) => {
    e.stopPropagation();
  });
  
  // Update button text based on selection
  function updateHostButtonText() {
    if (filterHosts.size === 0) {
      hostButton.textContent = 'All hosts';
    } else if (filterHosts.size === hostsList.size) {
      hostButton.textContent = 'All hosts';
    } else if (filterHosts.size === 1) {
      hostButton.textContent = Array.from(filterHosts)[0];
    } else {
      hostButton.textContent = `${filterHosts.size} hosts`;
    }
  }
  
  // Method filter - Multi-select dropdown
  const methodDropdown = createElement('div', 'method-dropdown', '', {
    id: 'method-dropdown'
  });
  
  const methodButton = createElement('button', 'method-filter-btn', 'All methods', {
    type: 'button',
    id: 'method-filter-btn'
  });
  
  const methodDropdownContent = createElement('div', 'method-dropdown-content', '', {
    id: 'method-dropdown-content'
  });
  
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
  methods.forEach(method => {
    const label = createElement('label', 'method-option');
    const checkbox = createElement('input', null, '', {
      type: 'checkbox',
      value: method,
      'data-method': method
    });
    const span = createElement('span', `method-badge ${method.toLowerCase()}`, method);
    
    checkbox.addEventListener('change', (e) => {
      if (e.target.checked) {
        filterMethods.add(method);
      } else {
        filterMethods.delete(method);
      }
      updateMethodButtonText();
      updateEndpointsList();
      updateSecuritySummary();
    });
    
    label.appendChild(checkbox);
    label.appendChild(span);
    methodDropdownContent.appendChild(label);
  });
  
  methodDropdown.appendChild(methodButton);
  methodDropdown.appendChild(methodDropdownContent);
  
  // Toggle dropdown
  methodButton.addEventListener('click', (e) => {
    e.stopPropagation();
    methodDropdown.classList.toggle('open');
  });
  
  // Close dropdown when clicking outside
  document.addEventListener('click', () => {
    methodDropdown.classList.remove('open');
  });
  
  methodDropdownContent.addEventListener('click', (e) => {
    e.stopPropagation();
  });
  
  // Update button text based on selection
  function updateMethodButtonText() {
    if (filterMethods.size === 0) {
      methodButton.textContent = 'All methods';
    } else if (filterMethods.size === methods.length) {
      methodButton.textContent = 'All methods';
    } else {
      methodButton.textContent = `${filterMethods.size} methods`;
    }
  }
  
  // Tag filter dropdown
  const tagDropdown = createElement('div', 'tag-dropdown', '', {
    id: 'tag-dropdown'
  });
  
  const tagButton = createElement('button', 'tag-filter-btn', 'All notes', {
    type: 'button',
    id: 'tag-filter-btn'
  });
  
  const tagDropdownContent = createElement('div', 'tag-dropdown-content', '', {
    id: 'tag-dropdown-content'
  });
  
  // Function to update tag filter dropdown
  window.updateTagFilter = function() {
    // Clear existing content
    while (tagDropdownContent.firstChild) {
      tagDropdownContent.removeChild(tagDropdownContent.firstChild);
    }
    
    if (allTags.size === 0) {
      const emptyMsg = createElement('div', 'tag-empty-msg', 'No notes yet');
      tagDropdownContent.appendChild(emptyMsg);
    } else {
      Array.from(allTags).sort().forEach(tag => {
        const label = createElement('label', 'tag-option');
        const checkbox = createElement('input', null, '', {
          type: 'checkbox',
          value: tag,
          'data-tag': tag
        });
        checkbox.checked = filterTags.has(tag);
        
        const span = createElement('span', 'tag-filter-badge', tag);
        
        checkbox.addEventListener('change', (e) => {
          if (e.target.checked) {
            filterTags.add(tag);
          } else {
            filterTags.delete(tag);
          }
          updateTagButtonText();
          updateEndpointsList();
          updateSecuritySummary();
        });
        
        label.appendChild(checkbox);
        label.appendChild(span);
        tagDropdownContent.appendChild(label);
      });
    }
  };
  
  // Group by tags toggle
  const groupToggle = createElement('label', 'group-toggle');
  const groupCheckbox = createElement('input', null, '', {
    type: 'checkbox',
    id: 'group-by-tags'
  });
  groupCheckbox.addEventListener('change', (e) => {
    groupByTags = e.target.checked;
    updateEndpointsList();
  });
  const groupLabel = createElement('span', null, 'Group by notes');
  groupToggle.appendChild(groupCheckbox);
  groupToggle.appendChild(groupLabel);
  tagDropdownContent.appendChild(createElement('hr', 'dropdown-divider'));
  tagDropdownContent.appendChild(groupToggle);
  
  tagDropdown.appendChild(tagButton);
  tagDropdown.appendChild(tagDropdownContent);
  
  // Toggle dropdown
  tagButton.addEventListener('click', (e) => {
    e.stopPropagation();
    updateTagFilter(); // Update content when opening
    tagDropdown.classList.toggle('open');
  });
  
  // Close dropdown when clicking outside
  document.addEventListener('click', () => {
    tagDropdown.classList.remove('open');
  });
  
  tagDropdownContent.addEventListener('click', (e) => {
    e.stopPropagation();
  });
  
  // Update button text based on selection
  function updateTagButtonText() {
    if (filterTags.size === 0) {
      tagButton.textContent = 'All notes';
    } else if (filterTags.size === allTags.size) {
      tagButton.textContent = 'All notes';
    } else {
      tagButton.textContent = `${filterTags.size} notes`;
    }
  }
  
  // Insert before existing controls
  controls.insertBefore(searchInput, controls.firstChild);
  searchInput.style.marginLeft = '15px'; // Add margin to separate from security summary
  controls.insertBefore(hostDropdown, searchInput.nextSibling);
  controls.insertBefore(methodDropdown, hostDropdown.nextSibling);
  controls.insertBefore(tagDropdown, methodDropdown.nextSibling);
}

// Update host filter dropdown
function updateHostFilter() {
  // This now just triggers an update when the hosts list changes
  if (window.updateHostFilterDropdown) {
    window.updateHostFilterDropdown();
  }
}

// Initialize
addFilterControls();
updateSelectionInfo();

// Update data periodically
updateTimer = setInterval(() => {
  if (isConnected && !window.isEditingTags) {
    safePostMessage({ type: "GET_API_CALLS" });
  }
}, CONFIG.UPDATE_INTERVAL);

// OpenAPI generation functions (keep existing implementations)
function generateOpenApiSpec(filterBySelection = false) {
  const paths = {};
  const schemas = {};
  const servers = new Set();
  
  // Filter endpoints based on selection if requested
  const endpointsToExport = filterBySelection 
    ? Array.from(apiData.entries()).filter(([endpoint]) => selectedEndpoints.has(endpoint))
    : Array.from(apiData.entries());
  
  endpointsToExport.forEach(([endpoint, data]) => {
    if (data.host) {
      servers.add(`https://${data.host}`);
    }
    
    // Collect all pathnames for this endpoint to detect variable segments
    const allPaths = data.calls.map(call => {
      const url = new URL(call.url);
      return url.pathname;
    });
    
    const pathParams = extractPathParams(data.pathname, allPaths);
    const path = pathParams.path;
    const method = data.method.toLowerCase();
    
    if (!paths[path]) {
      paths[path] = {};
    }
    
    const operation = {
      summary: `${data.method} ${data.pathname}`,
      operationId: `${method}${path.replace(/[^a-zA-Z0-9]/g, '')}`,
      description: generateOperationDescription(data),
      responses: {}
    };
    
    // Add tags to the operation
    const endpointTagsSet = endpointTags.get(endpoint) || new Set();
    if (endpointTagsSet.size > 0) {
      operation.tags = Array.from(endpointTagsSet);
    }
    
    if (pathParams.params.length > 0) {
      operation.parameters = pathParams.params.map(param => ({
        name: param,
        in: 'path',
        required: true,
        schema: { type: 'string' },
        example: pathParams.values[param]
      }));
    }
    
    if (data.queryParams.size > 0) {
      if (!operation.parameters) operation.parameters = [];
      
      // Collect all query parameter examples
      const paramExamples = new Map();
      data.calls.forEach(call => {
        Object.entries(call.queryParams).forEach(([key, value]) => {
          if (!paramExamples.has(key)) {
            paramExamples.set(key, []);
          }
          // Skip redacted values when collecting examples
          if (value !== '***REDACTED***' && !paramExamples.get(key).includes(value)) {
            paramExamples.get(key).push(value);
          }
        });
      });
      
      Array.from(data.queryParams).forEach(param => {
        const examples = paramExamples.get(param) || [];
        const paramDef = {
          name: param,
          in: 'query',
          required: false,
          schema: { type: 'string' }
        };
        
        // Only add examples if we have non-redacted values
        if (examples.length > 0) {
          if (examples.length === 1) {
            // Single example - use 'example'
            paramDef.example = examples[0];
          } else {
            // Multiple examples - use 'examples' (not both!)
            paramDef.examples = {};
            examples.slice(0, 5).forEach((ex, idx) => {
              paramDef.examples[`example${idx + 1}`] = {
                value: ex,
                summary: `Example value ${idx + 1}`
              };
            });
          }
        } else {
          // If all values were redacted, add a placeholder
          paramDef.example = "value";
          paramDef.description = "This parameter contains sensitive data that was redacted";
        }
        
        operation.parameters.push(paramDef);
      });
    }
    
    // Add request headers as parameters
    if (data.requestHeaders && data.requestHeaders.size > 0) {
      if (!operation.parameters) operation.parameters = [];
      
      // Collect header examples from calls
      const headerExamples = new Map();
      data.calls.forEach(call => {
        if (call.requestHeaders) {
          Object.entries(call.requestHeaders).forEach(([header, value]) => {
            if (!headerExamples.has(header)) {
              headerExamples.set(header, []);
            }
            if (value !== '***REDACTED***' && !headerExamples.get(header).includes(value)) {
              headerExamples.get(header).push(value);
            }
          });
        }
      });
      
      Array.from(data.requestHeaders).forEach(header => {
        // Skip common headers that are usually set automatically
        if (['Accept', 'Content-Type', 'User-Agent', 'Referer', 'Origin'].includes(header)) {
          return;
        }
        
        const examples = headerExamples.get(header) || [];
        const headerDef = {
          name: header,
          in: 'header',
          required: false,
          schema: { type: 'string' }
        };
        
        if (examples.length > 0) {
          if (examples.length === 1) {
            headerDef.example = examples[0];
          } else {
            headerDef.examples = {};
            examples.slice(0, 3).forEach((ex, idx) => {
              headerDef.examples[`example${idx + 1}`] = {
                value: ex,
                summary: `Example value ${idx + 1}`
              };
            });
          }
        } else {
          headerDef.description = "This header contains sensitive data that was redacted";
        }
        
        operation.parameters.push(headerDef);
      });
    }
    
    if (data.requestBodies.length > 0 && ['post', 'put', 'patch'].includes(method)) {
      const schemaName = `${method}${path.replace(/[^a-zA-Z0-9]/g, '')}Request`;
      schemas[schemaName] = convertToJsonSchema(analyzeStructure(data.requestBodies[0]));
      
      operation.requestBody = {
        content: {
          'application/json': {
            schema: { '$ref': `#/components/schemas/${schemaName}` }
          }
        }
      };
      
      // Add examples based on count
      if (data.requestBodies.length === 1) {
        // Single example - use 'example'
        operation.requestBody.content['application/json'].example = data.requestBodies[0];
      } else if (data.requestBodies.length > 1) {
        // Multiple examples - use 'examples' (not both!)
        operation.requestBody.content['application/json'].examples = {};
        data.requestBodies.slice(0, 3).forEach((body, idx) => {
          operation.requestBody.content['application/json'].examples[`example${idx + 1}`] = {
            value: body,
            summary: `Request example ${idx + 1}`
          };
        });
      }
    }
    
    const statusCodes = new Set();
    data.calls.forEach(call => {
      if (call.status) {
        statusCodes.add(call.status.toString());
      }
    });
    
    if (statusCodes.size === 0) {
      operation.responses['200'] = { description: 'Successful response' };
    } else {
      statusCodes.forEach(status => {
        operation.responses[status] = { 
          description: getStatusDescription(parseInt(status)) 
        };
      });
    }
    
    paths[path][method] = operation;
  });
  
  return {
    openapi: '3.0.0',
    info: {
      title: 'API Documentation',
      version: '1.0.0',
      description: 'Auto-generated API documentation from GAMX Chrome & Edge Extension'
    },
    servers: Array.from(servers).sort().map(url => ({ url })),
    paths: paths,
    components: {
      schemas: schemas
    }
  };
}

function extractPathParams(pathname, allPaths = []) {
  const segments = pathname.split('/');
  const params = [];
  const paramValues = {};
  
  const pathSegments = segments.map((segment, idx) => {
    // Check if this segment varies across different calls
    const segmentVaries = allPaths.some(p => {
      const otherSegments = p.split('/');
      return otherSegments[idx] && otherSegments[idx] !== segment;
    });
    
    if (segmentVaries || /^\d+$/.test(segment) || /^[a-f0-9-]{36}$/i.test(segment)) {
      const paramName = params.length === 0 ? 'id' : `id${params.length + 1}`;
      params.push(paramName);
      paramValues[paramName] = segment;
      return `{${paramName}}`;
    }
    return segment;
  });
  
  return {
    path: pathSegments.join('/'),
    params: params,
    values: paramValues
  };
}

function convertToJsonSchema(structure) {
  // Direct type mappings
  if (structure === 'string') return { type: 'string' };
  if (structure === 'number') return { type: 'number' };
  if (structure === 'boolean') return { type: 'boolean' };
  if (structure === 'null') return { type: 'string', nullable: true }; // Use string with nullable
  
  // Handle any other string values that might have slipped through
  if (typeof structure === 'string') {
    // Validate it's a proper type, otherwise default to string
    const validTypes = ['string', 'number', 'boolean', 'array', 'object'];
    if (!validTypes.includes(structure)) {
      return { type: 'string' };
    }
  }
  
  if (Array.isArray(structure)) {
    return {
      type: 'array',
      items: structure.length > 0 ? convertToJsonSchema(structure[0]) : { type: 'string' }
    };
  }
  
  if (typeof structure === 'object' && structure !== null) {
    const properties = {};
    const required = [];
    
    Object.keys(structure).forEach(key => {
      const value = structure[key];
      const propSchema = convertToJsonSchema(value);
      
      // Clean the key name (remove special characters that might cause issues)
      const cleanKey = key.replace(/[\$\-]/g, '_');
      properties[cleanKey] = propSchema;
      
      // Only add to required if it's not nullable/optional
      if (value !== 'null' && value !== null && value !== undefined) {
        required.push(cleanKey);
      }
    });
    
    const schema = {
      type: 'object',
      properties: properties
    };
    
    // Only add required array if it has items
    if (required.length > 0) {
      schema.required = required;
    }
    
    return schema;
  }
  
  return { type: 'string' }; // Default fallback
}

function getStatusDescription(status) {
  return CONFIG.STATUS_DESCRIPTIONS[status] || `HTTP ${status}`;
}

function generateOperationDescription(data) {
  let description = `Endpoint: ${data.method} ${data.pathname}\n`;
  description += `Total calls captured: ${data.calls.length}\n\n`;
  
  // Add curl examples
  if (data.calls.length > 0) {
    description += `## Example Requests\n\n`;
    
    // Get up to 3 unique examples
    const uniqueExamples = [];
    const seenExamples = new Set();
    
    for (const call of data.calls.slice().reverse()) {
      const exampleKey = JSON.stringify({
        query: call.queryParams,
        body: call.requestBody
      });
      
      if (!seenExamples.has(exampleKey)) {
        seenExamples.add(exampleKey);
        uniqueExamples.push(call);
        if (uniqueExamples.length >= 3) break;
      }
    }
    
    uniqueExamples.forEach((call, idx) => {
      description += `### Example ${idx + 1}\n\n`;
      
      // Build COMPLETE curl command with ALL headers
      let curl = `curl -X ${data.method} \\\n  'https://${data.host}${data.pathname}`;
      
      // Add query parameters
      if (Object.keys(call.queryParams).length > 0) {
        // Build query string, replacing redacted values with placeholders
        const queryPairs = Object.entries(call.queryParams).map(([key, value]) => {
          if (value === '***REDACTED***') {
            return `${key}=YOUR_${key.toUpperCase()}_HERE`;
          }
          return `${key}=${encodeURIComponent(value)}`;
        });
        curl += `?${queryPairs.join('&')}`;
      }
      curl += "'";
      
      // Add ALL headers if available (including User-Agent, etc)
      if (call.allHeaders) {
        // Sort headers for consistent output
        const sortedHeaders = Object.entries(call.allHeaders).sort((a, b) => a[0].localeCompare(b[0]));
        sortedHeaders.forEach(([header, value]) => {
          if (value === '***REDACTED***') {
            curl += ` \\\n  -H '${header}: YOUR_${header.toUpperCase().replace(/-/g, '_')}_HERE'`;
          } else {
            // Escape single quotes in header values
            const escapedValue = value.replace(/'/g, "'\\''");
            curl += ` \\\n  -H '${header}: ${escapedValue}'`;
          }
        });
      } else if (call.requestHeaders) {
        // Fallback to custom headers only
        Object.entries(call.requestHeaders).forEach(([header, value]) => {
          if (value === '***REDACTED***') {
            curl += ` \\\n  -H '${header}: YOUR_${header.toUpperCase().replace(/-/g, '_')}_HERE'`;
          } else {
            const escapedValue = value.replace(/'/g, "'\\''");
            curl += ` \\\n  -H '${header}: ${escapedValue}'`;
          }
        });
      }
      
      // Add request body
      if (call.requestBody) {
        curl += ` \\\n  -d '${JSON.stringify(call.requestBody)}'`;
      }
      
      description += `\`\`\`bash\n${curl}\n\`\`\`\n\n`;
      
      if (call.status) {
        description += `**Response Status:** ${call.status}\n\n`;
      }
    });
  }
  
  // Add observed query parameters
  if (data.queryParams.size > 0) {
    description += `## Query Parameters\n\n`;
    description += Array.from(data.queryParams).map(param => `- \`${param}\``).join('\n');
    description += '\n\n';
  }
  
  // Add observed headers
  if (data.requestHeaders && data.requestHeaders.size > 0) {
    const customHeaders = Array.from(data.requestHeaders).filter(h => 
      !['Accept', 'Content-Type', 'User-Agent', 'Referer', 'Origin'].includes(h)
    );
    if (customHeaders.length > 0) {
      description += `## Custom Headers\n\n`;
      description += customHeaders.map(header => `- \`${header}\``).join('\n');
      description += '\n\n';
    }
  }
  
  return description;
}

// ============================================================================
// SECURITY FEATURES
// ============================================================================

/**
 * Get the highest severity level from a list of vulnerabilities
 */
function getHighestSeverity(issues) {
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  let highest = 'low';
  let highestValue = 0;
  
  issues.forEach(issue => {
    const value = severityOrder[issue.severity] || 0;
    if (value > highestValue) {
      highestValue = value;
      highest = issue.severity;
    }
  });
  
  return highest;
}

/**
 * Format security issue details in a human-readable way
 */
function formatSecurityDetails(issue) {
  const details = issue.details;
  let html = '<div class="security-detail-items">';
  
  // Location of the issue
  if (issue.location) {
    html += `<div class="security-detail-item">
      <strong>Location:</strong> <code>${SecurityUtils.escapeHtml(issue.location)}</code>
    </div>`;
  }
  
  // Handle different types of details based on the issue type
  if (details.type) {
    html += `<div class="security-detail-item">
      <strong>Type:</strong> ${SecurityUtils.escapeHtml(details.type)}
    </div>`;
  }
  
  // Show matched pattern or example
  if (details.example) {
    html += `<div class="security-detail-item">
      <strong>Found:</strong> <code>${SecurityUtils.escapeHtml(details.example)}</code>
    </div>`;
  }
  
  if (details.sample) {
    html += `<div class="security-detail-item">
      <strong>Sample:</strong> <code>${SecurityUtils.escapeHtml(details.sample)}</code>
    </div>`;
  }
  
  // Show pattern that matched
  if (details.pattern) {
    html += `<div class="security-detail-item">
      <strong>Pattern Matched:</strong> <code>${SecurityUtils.escapeHtml(details.pattern)}</code>
    </div>`;
  }
  
  // Show affected fields/parameters
  if (details.fields && Array.isArray(details.fields)) {
    html += `<div class="security-detail-item">
      <strong>Affected Fields:</strong> <code>${details.fields.map(f => SecurityUtils.escapeHtml(f)).join(', ')}</code>
    </div>`;
  }
  
  if (details.params && Array.isArray(details.params)) {
    html += `<div class="security-detail-item">
      <strong>Affected Parameters:</strong> <code>${details.params.map(p => SecurityUtils.escapeHtml(p)).join(', ')}</code>
    </div>`;
  }
  
  if (details.header) {
    html += `<div class="security-detail-item">
      <strong>Header:</strong> <code>${SecurityUtils.escapeHtml(details.header)}</code>
    </div>`;
  }
  
  if (details.missingHeaders && Array.isArray(details.missingHeaders)) {
    html += `<div class="security-detail-item">
      <strong>Missing Headers:</strong> <code>${details.missingHeaders.map(h => SecurityUtils.escapeHtml(h)).join(', ')}</code>
    </div>`;
  }
  
  // Protocol info
  if (details.protocol) {
    html += `<div class="security-detail-item">
      <strong>Protocol:</strong> <code>${SecurityUtils.escapeHtml(details.protocol)}</code>
    </div>`;
  }
  
  // Origin info
  if (details.origin) {
    html += `<div class="security-detail-item">
      <strong>Origin:</strong> <code>${SecurityUtils.escapeHtml(details.origin)}</code>
    </div>`;
  }
  
  // IDs found
  if (details.ids && Array.isArray(details.ids)) {
    html += `<div class="security-detail-item">
      <strong>IDs Found:</strong> <code>${details.ids.map(id => SecurityUtils.escapeHtml(String(id))).join(', ')}</code>
    </div>`;
  }
  
  // Path
  if (details.path) {
    html += `<div class="security-detail-item">
      <strong>Path:</strong> <code>${SecurityUtils.escapeHtml(details.path)}</code>
    </div>`;
  }
  
  // Call frequency info
  if (details.callCount) {
    html += `<div class="security-detail-item">
      <strong>Call Count:</strong> ${details.callCount} calls in ${details.timeWindow}ms
    </div>`;
  }
  
  if (details.threshold) {
    html += `<div class="security-detail-item">
      <strong>Threshold:</strong> ${details.threshold} calls
    </div>`;
  }
  
  // Status code
  if (details.status) {
    html += `<div class="security-detail-item">
      <strong>Status Code:</strong> ${details.status}
    </div>`;
  }
  
  // Match count
  if (details.matchCount) {
    html += `<div class="security-detail-item">
      <strong>Occurrences:</strong> ${details.matchCount}
    </div>`;
  }
  
  // Password/length requirements
  if (details.actualLength !== undefined && details.requiredLength !== undefined) {
    html += `<div class="security-detail-item">
      <strong>Password Length:</strong> ${details.actualLength} (required: ${details.requiredLength})
    </div>`;
  }
  
  // Recommendation
  if (details.recommendation) {
    html += `<div class="security-detail-item security-recommendation">
      <strong>Recommendation:</strong> ${SecurityUtils.escapeHtml(details.recommendation)}
    </div>`;
  }
  
  // Reason
  if (details.reason) {
    html += `<div class="security-detail-item">
      <strong>Reason:</strong> ${SecurityUtils.escapeHtml(details.reason)}
    </div>`;
  }
  
  html += '</div>';
  return html;
}

/**
 * Update security summary display
 */
function updateSecuritySummary() {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  // Count unique vulnerabilities only from FILTERED endpoints (sum of unique issues per endpoint)
  const filteredEndpoints = getFilteredEndpoints();
  filteredEndpoints.forEach(([endpoint, data]) => {
    if (data.securityIssues && Array.isArray(data.securityIssues)) {
      // Deduplicate issues for this endpoint
      const uniqueIssues = new Map();
      data.securityIssues.forEach(issue => {
        // Create unique key from issue name and details
        const key = `${issue.severity}:${issue.rule}:${issue.message || ''}`;
        if (!uniqueIssues.has(key)) {
          uniqueIssues.set(key, issue);
        }
      });
      
      // Count unique issues by severity for this endpoint
      uniqueIssues.forEach(issue => {
        if (summary.hasOwnProperty(issue.severity)) {
          summary[issue.severity]++;
        }
      });
    }
  });

  // Update badges
  if (securitySummary) {
    const badges = securitySummary.querySelectorAll('.severity-badge');
    badges.forEach(badge => {
      const severity = Array.from(badge.classList).find(c => c !== 'severity-badge');
      if (severity && summary[severity] !== undefined) {
        badge.textContent = summary[severity];
        
        // Update title and active state
        const isActive = filterSeverity.has(severity);
        const titlePrefix = isActive ? '✓ ' : '';
        const filterText = filteredEndpoints.length < apiData.size ? ' (filtered)' : '';
        badge.title = `${titlePrefix}${severity} severity issues${filterText} (${summary[severity]} total)`;
        
        // Add/remove active class
        if (isActive) {
          badge.classList.add('active');
        } else {
          badge.classList.remove('active');
        }
        
        // Make badge clickable if there are issues
        if (summary[severity] > 0) {
          badge.style.cursor = 'pointer';
          badge.style.opacity = isActive ? '1' : '0.7';
        } else {
          badge.style.cursor = 'default';
          badge.style.opacity = '0.3';
        }
      }
    });
  }
  
  // Show/hide clear filter button
  if (clearSeverityFilterBtn) {
    if (filterSeverity.size > 0) {
      clearSeverityFilterBtn.style.display = 'inline-block';
    } else {
      clearSeverityFilterBtn.style.display = 'none';
    }
  }
}

/**
 * Generate combined AI prompt for all selected endpoints
 */
function generateCombinedAiPrompt() {
  let prompt = `I have analyzed the following API endpoints and found security vulnerabilities. Please summarize these issues, explain the risks, and suggest fixes.\n\n`;
  
  prompt += `| Endpoint | Method | Severity | Vulnerability | Description |\n`;
  prompt += `|---|---|---|---|---|\n`;
  
  let hasIssues = false;
  
  selectedEndpoints.forEach(endpoint => {
    const data = apiData.get(endpoint);
    if (data && data.securityIssues && data.securityIssues.length > 0) {
      hasIssues = true;
      data.securityIssues.forEach(issue => {
        const url = data.url || endpoint;
        const method = data.method || 'N/A';
        const severity = issue.severity || 'Unknown';
        const name = issue.name || 'Unknown Issue';
        const message = (issue.message || '').replace(/\n/g, ' '); // Remove newlines for table
        
        prompt += `| ${url} | ${method} | ${severity} | ${name} | ${message} |\n`;
      });
    }
  });
  
  if (!hasIssues) {
    return "No security issues found in the selected endpoints.";
  }
  
  prompt += `\n\nPlease provide a detailed summary of these vulnerabilities, grouped by type and severity. Also provide remediation steps for each type of vulnerability found.`;
  
  return prompt;
}

/**
 * Generate AI prompt for security issue
 */
function generateCurlCommand(call) {
  let curl = `curl -X ${call.method} "${call.url}"`;
  
  if (call.requestHeaders) {
    const headers = call.requestHeaders;
    if (typeof headers === 'object' && !Array.isArray(headers)) {
      Object.entries(headers).forEach(([key, value]) => {
        curl += ` \\\n  -H "${key}: ${value}"`;
      });
    }
  }
  
  if (call.requestBody) {
    let bodyStr = '';
    if (typeof call.requestBody === 'string') {
      bodyStr = call.requestBody;
    } else {
      try {
        bodyStr = JSON.stringify(call.requestBody);
      } catch (e) {
        bodyStr = '';
      }
    }
    
    if (bodyStr) {
      const escapedBody = bodyStr.replace(/'/g, "'\\''");
      curl += ` \\\n  -d '${escapedBody}'`;
    }
  }
  
  return curl;
}

function generateAiPrompt(issue, endpointData) {
  let prompt = `I found a security vulnerability in my application. Here are the details:\n\n`;
  prompt += `Name: ${issue.name}\n`;
  prompt += `Severity: ${issue.severity}\n`;
  prompt += `Message: ${issue.message}\n`;
  
  if (issue.location) {
    prompt += `Location: ${issue.location}\n`;
  }
  
  if (issue.details) {
    prompt += `\nTechnical Details:\n`;
    for (const [key, value] of Object.entries(issue.details)) {
      let displayValue = value;
      if (typeof value === 'object') {
        displayValue = JSON.stringify(value, null, 2);
      }
      prompt += `${key}: ${displayValue}\n`;
    }
  }

  if (endpointData) {
    prompt += `\nAPI Request Details:\n`;
    prompt += `URL: ${endpointData.url || 'N/A'}\n`;
    prompt += `Method: ${endpointData.method || 'N/A'}\n`;
    
    if (endpointData.requestHeaders) {
      prompt += `Request Headers: ${JSON.stringify(endpointData.requestHeaders, null, 2)}\n`;
    }
    
    if (endpointData.requestBodies && endpointData.requestBodies.length > 0) {
      prompt += `Request Body: ${JSON.stringify(endpointData.requestBodies[0], null, 2)}\n`;
    }

    if (endpointData.responseHeaders) {
      prompt += `Response Headers: ${JSON.stringify(endpointData.responseHeaders, null, 2)}\n`;
    }
  }
  
  prompt += `\nPlease explain this vulnerability in detail, why it is a risk, and how to fix it. Provide code examples if possible.`;
  return prompt;
}

// Helper to format security issues for clipboard
function formatSecurityIssuesForCopy(issues) {
  if (!issues || issues.length === 0) return 'No security issues detected.';
  
  return issues.map(issue => {
    let detailsStr = 'N/A';
    if (issue.details) {
      if (typeof issue.details === 'object') {
        // Format object details nicely
        const entries = Object.entries(issue.details);
        if (entries.length > 0) {
          detailsStr = entries
            .map(([key, value]) => `${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`)
            .join('\n  ');
        } else {
          detailsStr = JSON.stringify(issue.details);
        }
      } else {
        detailsStr = String(issue.details);
      }
    }
    
    return `[${issue.severity.toUpperCase()}] ${issue.name || issue.ruleId}\n${issue.message}\nDetails:\n  ${detailsStr}`;
  }).join('\n\n----------------------------------------\n\n');
}

/**
 * Create security issues display section
 */
function createSecurityIssuesSection(data) {
  const section = createElement('div', 'detail-section security-section');
  
  // Header row with copy button
  const headerRow = createElement('div', 'section-title-row');
  headerRow.style.background = 'transparent';
  headerRow.style.borderBottom = 'none';
  headerRow.style.padding = '0';
  headerRow.style.marginBottom = '1rem';
  headerRow.style.justifyContent = 'flex-start';
  headerRow.style.alignItems = 'center';
  headerRow.style.gap = '0.75rem';

  const copyBtn = createElement('button', 'copy-icon-btn', '');
  copyBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-copy" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1z"/></svg>';
  copyBtn.title = 'Copy All Security Vulnerabilities';
  
  if (data.securityIssues && data.securityIssues.length > 0) {
    const issuesText = formatSecurityIssuesForCopy(data.securityIssues);
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      navigator.clipboard.writeText(issuesText);
      const original = copyBtn.innerHTML;
      copyBtn.textContent = '✓';
      setTimeout(() => copyBtn.innerHTML = original, 1500);
    });
  } else {
    copyBtn.style.display = 'none';
  }

  const header = createElement('h3', null, 'Security Analysis');
  header.style.margin = '0';
  
  headerRow.appendChild(header);
  headerRow.appendChild(copyBtn);
  section.appendChild(headerRow);

  if (!data.securityIssues || data.securityIssues.length === 0) {
    const noIssues = createElement('div', 'security-no-issues');
    noIssues.innerHTML = 'No security issues detected';
    section.appendChild(noIssues);
    return section;
  }

  // Deduplicate issues first
  const uniqueIssuesMap = new Map();
  data.securityIssues.forEach(issue => {
    const key = `${issue.severity}:${issue.rule}:${issue.message || ''}`;
    if (!uniqueIssuesMap.has(key)) {
      uniqueIssuesMap.set(key, issue);
    }
  });

  // Group unique issues by severity
  const groupedIssues = {
    critical: [],
    high: [],
    medium: [],
    low: []
  };

  uniqueIssuesMap.forEach(issue => {
    if (groupedIssues[issue.severity]) {
      groupedIssues[issue.severity].push(issue);
    }
  });

  // Display issues by severity
  Object.entries(groupedIssues).forEach(([severity, issues]) => {
    if (issues.length > 0) {
      const severitySection = createElement('div', `security-severity-section ${severity}`);
      
      const severityHeader = createElement('div', 'security-severity-header');
      const badge = createElement('span', `severity-badge ${severity}`, issues.length);
      const title = createElement('span', 'security-severity-title', 
        `${severity.toUpperCase()} Severity Issues`);
      severityHeader.appendChild(badge);
      severityHeader.appendChild(title);
      severitySection.appendChild(severityHeader);

      // List issues
      const issuesList = createElement('div', 'security-issues-list');
      
      // Group by rule to avoid duplicates
      const uniqueIssues = new Map();
      issues.forEach(issue => {
        const key = `${issue.ruleId}-${issue.location}`;
        if (!uniqueIssues.has(key)) {
          uniqueIssues.set(key, issue);
        }
      });

      uniqueIssues.forEach(issue => {
        const issueItem = createElement('div', 'security-issue-item');
        
        const issueName = createElement('div', 'security-issue-name', issue.name);
        issueItem.appendChild(issueName);
        
        const issueMessage = createElement('div', 'security-issue-message', issue.message);
        issueItem.appendChild(issueMessage);

        // Add ASK AI button
        const askAiBtn = createElement('button', 'ai-button', '');
        askAiBtn.innerHTML = '<span class="ai-icon">✨</span> ASK AI';
        askAiBtn.style.marginTop = '8px';
        askAiBtn.style.marginBottom = '8px';
        askAiBtn.style.marginRight = '10px'; // Add margin between buttons
        askAiBtn.style.fontSize = '12px'; // Slightly smaller for list items
        askAiBtn.style.padding = '4px 10px'; // Slightly smaller padding
        
        askAiBtn.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          
          const prompt = generateAiPrompt(issue, data);
          navigator.clipboard.writeText(prompt).then(() => {
            // Save original state
            const originalHTML = '<span class="ai-icon">✨</span> ASK AI';
            
            // Change to success state
            askAiBtn.textContent = 'Prompt Copied!';
            askAiBtn.style.background = '#10b981'; // Success green
            askAiBtn.style.animation = 'none'; // Stop animation temporarily
            
            // Revert after 2 seconds
            setTimeout(() => {
              askAiBtn.innerHTML = originalHTML;
              askAiBtn.style.background = ''; // Revert to CSS gradient
              askAiBtn.style.animation = ''; // Restore animation
            }, 2000);
          }).catch(err => {
            console.error('Failed to copy text: ', err);
            alert('Failed to copy prompt to clipboard');
          });
        });
        
        issueItem.appendChild(askAiBtn);

        // Add Copy cURL button
        const copyCurlBtn = createElement('button', 'secondary-btn', 'Copy cURL');
        copyCurlBtn.style.marginTop = '8px';
        copyCurlBtn.style.marginBottom = '8px';
        copyCurlBtn.style.marginRight = '10px';
        copyCurlBtn.style.fontSize = '12px';
        copyCurlBtn.style.padding = '4px 10px';
        copyCurlBtn.title = 'Copy request as cURL command (Network tab selection is not supported by Chrome API)';
        
        copyCurlBtn.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          
          // Find the specific call that triggered this issue
          const call = data.calls.find(c => c.requestId === issue.requestId) || 
                       data.calls[data.calls.length - 1]; // Fallback to latest call
          
          if (call) {
            const curl = generateCurlCommand(call);
            navigator.clipboard.writeText(curl).then(() => {
              const originalText = 'Copy cURL';
              copyCurlBtn.textContent = 'Copied!';
              copyCurlBtn.style.background = '#10b981';
              copyCurlBtn.style.color = 'white';
              copyCurlBtn.style.borderColor = '#10b981';
              
              setTimeout(() => {
                copyCurlBtn.textContent = originalText;
                copyCurlBtn.style.background = '';
                copyCurlBtn.style.color = '';
                copyCurlBtn.style.borderColor = '';
              }, 2000);
            });
          } else {
            alert('Could not find request details to generate cURL');
          }
        });
        issueItem.appendChild(copyCurlBtn);
        
        if (issue.details && Object.keys(issue.details).length > 0) {
          const detailsBtn = createElement('button', 'security-details-btn', 'Details ▲');
          const detailsContent = createElement('div', 'security-details-content');
          detailsContent.style.display = 'block';
          
          // Format details in a more readable way
          const detailsFormatted = formatSecurityDetails(issue);
          const detailsDiv = createElement('div', 'security-details-formatted');
          detailsDiv.innerHTML = detailsFormatted;
          detailsContent.appendChild(detailsDiv);
          
          detailsBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            
            if (detailsContent.style.display === 'none') {
              detailsContent.style.display = 'block';
              detailsBtn.textContent = 'Details ▲';
            } else {
              detailsContent.style.display = 'none';
              detailsBtn.textContent = 'Details ▼';
            }
          });
          
          issueItem.appendChild(detailsBtn);
          issueItem.appendChild(detailsContent);
        }
        
        issuesList.appendChild(issueItem);
      });

      severitySection.appendChild(issuesList);
      section.appendChild(severitySection);
    }
  });

  return section;
}

/**
 * Load security rules configuration
 */
async function loadSecurityRules() {
  try {
    // Try to load from storage first
    const stored = await chrome.storage.local.get('securityRulesConfig');
    if (stored.securityRulesConfig) {
      securityRulesConfig = stored.securityRulesConfig;
    } else {
      // Load default from file
      const response = await fetch(chrome.runtime.getURL('security-rules.json'));
      const config = await response.json();
      securityRulesConfig = config;
    }
  } catch (error) {
    console.error('Error loading security rules:', error);
  }
}

/**
 * Save security rules configuration
 */
async function saveSecurityRules() {
  try {
    await chrome.storage.local.set({ securityRulesConfig });
    alert('Security rules saved successfully!');
    
    // Reload the security analyzer with new rules
    if (securityAnalyzer) {
      await securityAnalyzer.init();
    }
  } catch (error) {
    console.error('Error saving security rules:', error);
    alert('Failed to save security rules: ' + error.message);
  }
}

/**
 * Reset security rules to defaults
 */
async function resetSecurityRules() {
  if (!confirm('Reset all security rules to defaults?')) {
    return;
  }
  
  try {
    await chrome.storage.local.remove('securityRulesConfig');
    await loadSecurityRules();
    displaySecurityRulesModal();
    alert('Security rules reset to defaults!');
  } catch (error) {
    console.error('Error resetting security rules:', error);
    alert('Failed to reset security rules: ' + error.message);
  }
}

/**
 * Display security rules configuration modal
 */
function displaySecurityRulesModal() {
  if (!securityRulesConfig || !securityRulesConfig.rules) {
    return;
  }

  const container = document.getElementById('security-rules-container');
  container.innerHTML = '';

  const intro = createElement('p', 'rules-intro');
  intro.textContent = 'Enable or disable security vulnerability detection rules:';
  container.appendChild(intro);

  const rulesContainer = createElement('div', 'security-rules-list');

  Object.entries(securityRulesConfig.rules).forEach(([ruleId, rule]) => {
    const ruleItem = createElement('div', 'security-rule-item');
    
    const ruleHeader = createElement('div', 'security-rule-header');
    
    const checkbox = createElement('input', 'security-rule-checkbox', '', {
      type: 'checkbox',
      id: `rule-${ruleId}`,
      'data-rule-id': ruleId
    });
    checkbox.checked = rule.enabled;
    
    const severityBadge = createElement('span', `severity-badge ${rule.severity} small`, 
      rule.severity.toUpperCase());
    
    const label = createElement('label', 'security-rule-label', rule.name, {
      for: `rule-${ruleId}`
    });
    
    ruleHeader.appendChild(checkbox);
    ruleHeader.appendChild(severityBadge);
    ruleHeader.appendChild(label);
    
    const description = createElement('div', 'security-rule-description', rule.description);
    
    ruleItem.appendChild(ruleHeader);
    ruleItem.appendChild(description);
    rulesContainer.appendChild(ruleItem);

    // Update rule when checkbox changes
    checkbox.addEventListener('change', (e) => {
      securityRulesConfig.rules[ruleId].enabled = e.target.checked;
    });
  });

  container.appendChild(rulesContainer);
  securityModal.style.display = 'flex';
}

/**
 * Initialize security UI event listeners
 */
function initSecurityUI() {
  // Load security rules
  loadSecurityRules().then(() => {
    console.log('Security rules loaded');
  });

  // Security severity filter badges - make them clickable
  if (securitySummary) {
    const badges = securitySummary.querySelectorAll('.severity-badge');
    badges.forEach(badge => {
      // Find the severity class (critical, high, medium, low)
      const severityClasses = ['critical', 'high', 'medium', 'low'];
      const severity = Array.from(badge.classList).find(c => severityClasses.includes(c));
      
      if (severity) {
        badge.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          
          // Toggle severity filter
          if (filterSeverity.has(severity)) {
            filterSeverity.delete(severity);
          } else {
            filterSeverity.add(severity);
          }
          
          // Update UI
          updateSecuritySummary();
          updateEndpointsList();
        });
      }
    });
  }

  // Clear severity filter button
  if (clearSeverityFilterBtn) {
    clearSeverityFilterBtn.addEventListener('click', () => {
      filterSeverity.clear();
      updateSecuritySummary();
      updateEndpointsList();
    });
  }

  // Security settings button
  if (securitySettingsBtn) {
    securitySettingsBtn.addEventListener('click', () => {
      displaySecurityRulesModal();
    });
  }

  // Modal close button
  if (modalCloseBtn) {
    modalCloseBtn.addEventListener('click', () => {
      securityModal.style.display = 'none';
    });
  }

  // Close modal when clicking outside
  if (securityModal) {
    securityModal.addEventListener('click', (e) => {
      if (e.target === securityModal) {
        securityModal.style.display = 'none';
      }
    });
  }

  // Save rules button
  if (saveRulesBtn) {
    saveRulesBtn.addEventListener('click', () => {
      saveSecurityRules();
      securityModal.style.display = 'none';
    });
  }

  // Reset rules button
  if (resetRulesBtn) {
    resetRulesBtn.addEventListener('click', () => {
      resetSecurityRules();
    });
  }
}

// Initialize security UI
initSecurityUI();


