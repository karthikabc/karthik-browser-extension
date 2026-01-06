# GAMX Browser Extension - Code Overview for Junior Developers

Welcome to the GAMX Browser Extension project! This document is designed to help you understand the codebase, architecture, and key components of the extension.

## 1. Project Overview

GAMX is a browser extension (compatible with Chrome, Edge, and Firefox) designed for developers and security analysts. Its primary functions are:
*   **API Monitoring:** Captures and logs HTTP/HTTPS requests made by the browser tab.
*   **Security Analysis:** Analyzes API calls in real-time for common security vulnerabilities (like PII leaks, weak authentication, etc.).
*   **Documentation:** Helps generate API documentation from captured traffic.

## 2. Architecture & Key Components

The extension follows the standard Manifest V3 architecture (and V2 for Firefox where applicable).

### Core Files

*   **`manifest.json`**: The configuration file that defines the extension's permissions, background scripts, and UI entry points.
    *   *Key Permissions:* `webRequest`, `debugger` (for body capture), `storage`.
*   **`devtools.html` & `devtools.js`**: The entry point for the DevTools panel. When you open F12 -> GAMX tab, this script runs first and creates the actual panel.
*   **`panel.html` & `panel.js`**: The main UI of the extension. This is where the user sees the list of API calls, security warnings, and details.
*   **`background.js`**: The service worker (in Chrome/Edge) that runs in the background. It acts as the central hub, managing data storage, coordinating between components, and maintaining state even when the DevTools panel is closed.
*   **`security-analyzer.js`**: The "brain" of the security features. It contains the logic to check requests against a set of rules.
*   **`security-rules.json`**: A configuration file defining the specific regex patterns and rules used by the `security-analyzer.js`.
*   **`response-capture.js`**: A helper module that uses the Chrome Debugger API to fetch the full response bodies of requests (since standard `webRequest` APIs often don't provide the body).

## 3. Data Flow

1.  **Capture:**
    *   The browser makes a network request.
    *   `background.js` (via `webRequest` listeners) captures headers, method, and URL.
    *   `response-capture.js` (via `debugger` API) attaches to the tab to fetch the response body.

2.  **Analysis:**
    *   `background.js` passes the captured request details to `security-analyzer.js`.
    *   The analyzer checks the data against `security-rules.json`.
    *   Vulnerabilities are flagged and attached to the request object.

3.  **Display:**
    *   The `panel.js` (UI) polls or receives messages from `background.js` containing the latest list of API calls.
    *   The UI renders the list, highlighting any security issues.

## 4. Key Modules Explained

### `security-analyzer.js`
This class loads rules from `security-rules.json` and provides the `analyzeCall(callDetails)` method.
*   **How it works:** It iterates through enabled rules. For each rule, it calls a specific checker function (e.g., `checkSensitiveDataInUrl`).
*   **Adding a new rule:**
    1.  Add the rule definition to `security-rules.json`.
    2.  Create a checker function in `SecurityAnalyzer` class.
    3.  Register the function in `getRuleChecker()`.

### `response-capture.js`
This module handles the complex task of getting response bodies.
*   **Why is it complex?** Standard extension APIs are restrictive about reading response bodies for privacy/performance. We use the `chrome.debugger` API as a workaround, which is powerful but requires the user to accept a "Debugging started" banner.

## 5. Firefox vs. Chrome/Edge

You will notice a `firefox/` folder.
*   **Root folder:** Contains the source for Chromium-based browsers (Chrome, Edge, Brave).
*   **`firefox/` folder:** Contains the source specifically for Firefox.
*   **Why?** Firefox handles Manifest V3 differently (e.g., background scripts vs. service workers) and has slightly different API implementations. When making changes, **ensure you update both locations** to keep feature parity.

## 6. Getting Started with Development

1.  **Load the Extension:**
    *   **Chrome/Edge:** Go to `chrome://extensions`, enable "Developer mode", click "Load unpacked", and select the root folder.
    *   **Firefox:** Go to `about:debugging`, click "This Firefox", "Load Temporary Add-on", and select the `manifest.json` inside the `firefox/` folder.
2.  **Debug:**
    *   Open the extension panel (F12 -> GAMX).
    *   Right-click inside the panel and choose "Inspect" to debug the UI (`panel.js`).
    *   Go to the Extensions page and click "Inspect views: service worker" to debug `background.js`.

`.


