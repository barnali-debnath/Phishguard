// popup.js

document.addEventListener("DOMContentLoaded", () => {

  const analyzeBtn =
    document.getElementById("analyzeBtn");

  const statusText =
    document.getElementById("status");

  const riskText =
    document.getElementById("risk");

  const reasonText =
    document.getElementById("reason");

  const urlText =
    document.getElementById("url");

  const dashboardBtn =
  document.getElementById("openDashboard");

  dashboardBtn.addEventListener("click", () => {
    chrome.tabs.create({
      url: chrome.runtime.getURL("dashboard/index.html")
    });
  });

  // Function to update popup UI
  function updateUI(result) {

    if (!result) return;

    statusText.textContent =
      result.prediction;

    riskText.textContent =
      "Risk Score: " +
      result.risk_score +
      "%";

    urlText.textContent =
      result.url;

    if (
      result.reasons &&
      result.reasons.length > 0
    ) {

      reasonText.textContent =
        result.reasons.join(", ");

    } else {

      reasonText.textContent =
        "No major phishing indicators detected";

    }

  }

  // Load latest autoscan result immediately
  chrome.storage.local.get(
    ["latestScan"],
    (data) => {

      if (data.latestScan) {

        updateUI(data.latestScan);

      }

    }
  );

  // Auto-update popup when background scan changes
  chrome.storage.onChanged.addListener(
    (changes, areaName) => {

      if (
        areaName === "local" &&
        changes.latestScan
      ) {

        updateUI(
          changes.latestScan.newValue
        );

      }

    }
  );

  // Manual Analyze Button Still Works
  analyzeBtn.addEventListener(
    "click",
    async () => {

      statusText.textContent =
        "Analyzing...";

      chrome.tabs.query(
        {
          active: true,
          currentWindow: true
        },

        async (tabs) => {

          try {

            const currentUrl =
              tabs[0].url;

            const response =
              await fetch(
                "http://127.0.0.1:5000/analyze",
                {
                  method: "POST",

                  headers: {
                    "Content-Type":
                      "application/json"
                  },

                  body: JSON.stringify({
                    url: currentUrl
                  })
                }
              );

            const result =
              await response.json();

            updateUI(result);

            // Save latest result and maintain scan history
            chrome.storage.local.get(["scanHistory"], (data) => {
              const history = data.scanHistory || [];

              const newEntry = {
                ...result,
                id: Date.now(),
                timestamp: new Date().toLocaleString()
              };

              history.unshift(newEntry);

              // Keep only the latest 100 scans
              const trimmedHistory = history.slice(0, 100);

              chrome.storage.local.set({
                latestScan: result,
                scanHistory: trimmedHistory
              });
            });

          } catch (error) {

            console.error(error);

            statusText.textContent =
              "Backend Error";

            riskText.textContent = "";

            reasonText.textContent =
              "Could not connect to backend";

          }

        }
      );

    }
  );

});