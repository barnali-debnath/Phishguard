// content.js
// Runs inside every webpage matched in manifest.json.
// Its job is to display a warning banner when background.js
// sends a message indicating that the site is risky.

// Prevent duplicate banners
let warningBanner = null;

// Create and display the warning banner
function showWarning(data) {
  // If banner already exists, remove it first
  if (warningBanner) {
    warningBanner.remove();
  }

  const {
    risk_score = 0,
    prediction = "unknown",
    reasons = []
  } = data;

  // Create banner container
  warningBanner = document.createElement("div");
  warningBanner.id = "phishguard-warning-banner";

  // Banner HTML
  warningBanner.innerHTML = `
    <div class="phishguard-content">
      <div class="phishguard-title">
        ⚠ Warning: Potential Phishing Website Detected
      </div>
      <div class="phishguard-details">
        Prediction: <strong>${prediction.toUpperCase()}</strong>
        | Risk Score: <strong>${risk_score}/100</strong>
      </div>
      <ul class="phishguard-reasons">
        ${reasons.map(reason => `<li>${reason}</li>`).join("")}
      </ul>
      <button id="phishguard-close-btn">Dismiss</button>
    </div>
  `;

  // Inline CSS styles
  warningBanner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    background: linear-gradient(90deg, #8B0000, #FF0000);
    color: white;
    z-index: 2147483647;
    font-family: Arial, sans-serif;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    padding: 16px;
    box-sizing: border-box;
  `;

  // Optional styling for inner content
  const style = document.createElement("style");
  style.textContent = `
    #phishguard-warning-banner .phishguard-title {
      font-size: 18px;
      font-weight: bold;
      margin-bottom: 8px;
    }

    #phishguard-warning-banner .phishguard-details {
      font-size: 14px;
      margin-bottom: 10px;
    }

    #phishguard-warning-banner .phishguard-reasons {
      margin: 0 0 10px 20px;
      padding: 0;
      font-size: 13px;
    }

    #phishguard-warning-banner .phishguard-reasons li {
      margin-bottom: 4px;
    }

    #phishguard-warning-banner button {
      background: white;
      color: #c62828;
      border: none;
      padding: 8px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: bold;
    }

    #phishguard-warning-banner button:hover {
      opacity: 0.9;
    }
  `;
  document.head.appendChild(style);

  // Add banner to page
  document.body.prepend(warningBanner);

  // Close button functionality
  const closeBtn = document.getElementById("phishguard-close-btn");
  closeBtn.addEventListener("click", () => {
    warningBanner.remove();
    warningBanner = null;
  });
}

// Listen for messages from background.js
chrome.runtime.onMessage.addListener((message) => {
  if (message.action === "showWarning") {
    showWarning(message.data);
  }
});