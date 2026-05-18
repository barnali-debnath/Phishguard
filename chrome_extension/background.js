// background.js
// Runs as the extension's service worker (Manifest V3).
// Responsibilities:
// 1. Detect when a tab finishes loading.
// 2. Send the tab URL to the backend API (or use mock data).
// 3. Store the result in chrome.storage.local.
// 4. Notify content.js if the site is dangerous.

// Backend API URL (replace with your deployed FastAPI URL later)
const API_URL = "http://127.0.0.1:5000/analyze";

// Ignore Chrome internal pages
function isScannableUrl(url) {
  return (
    url &&
    (url.startsWith("http://") || url.startsWith("https://"))
  );
}

// Temporary mock response if backend is not available yet
function getMockResult(url) {
  return {
    url,
    prediction: "phishing",
    probability: 0.97,
    risk_score: 96,
    reasons: [
      "Contains suspicious keyword 'login'",
      "Domain age is less than 7 days",
      "VirusTotal reports 8 malicious detections"
    ],
    scanned_at: new Date().toISOString()
  };
}

// Call backend API
async function scanUrl(url) {
  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.warn("Backend unavailable, using mock data:", error);
    return getMockResult(url);
  }
}

// Main handler: scan URL and process result
async function processTab(tabId, url) {
  if (!isScannableUrl(url)) return;

  const result = await scanUrl(url);

  // Save latest scan result for popup.js
  await chrome.storage.local.set({
    latestScan: result
  });

  // Optional: maintain history
  const stored = await chrome.storage.local.get("scanHistory");
  const history = stored.scanHistory || [];

  history.unshift(result); // Add to beginning

  // Keep only latest 50 scans
  if (history.length > 50) {
    history.length = 50;
  }

  await chrome.storage.local.set({
    scanHistory: history
  });

  // Notify content.js if risky
  if (result.risk_score >= 80) {
    try {
      await chrome.tabs.sendMessage(tabId, {
        action: "showWarning",
        data: result
      });
    } catch (err) {
      // content.js may not be loaded on some pages
      console.warn("Could not send message to content script:", err);
    }
  }
}

// Trigger when a tab finishes loading
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    processTab(tabId, tab.url);
  }
});

// Trigger when user switches tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);

  if (tab.url) {
    processTab(tab.id, tab.url);
  }
});

// Handle manual scan requests from popup.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "scanCurrentUrl") {
    chrome.tabs.query(
      { active: true, currentWindow: true },
      async (tabs) => {
        const tab = tabs[0];

        if (!tab || !tab.url || !isScannableUrl(tab.url)) {
          sendResponse({
            success: false,
            error: "This page cannot be scanned."
          });
          return;
        }

        const result = await scanUrl(tab.url);

        await chrome.storage.local.set({
          latestScan: result
        });

        sendResponse({
          success: true,
          data: result
        });
      }
    );

    // Required because sendResponse is called asynchronously
    return true;
  }
});