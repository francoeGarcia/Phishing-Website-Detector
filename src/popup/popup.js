const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const errorEl = document.getElementById("error");
const scanBtn = document.getElementById("scanBtn");

function showError(msg) {
  errorEl.textContent = msg;
  errorEl.classList.remove("hidden");
  resultEl.classList.add("hidden");
}

function showResult(data) {
  resultEl.innerHTML = `
    <div><strong>Prediction:</strong> ${data.label}</div>
    <div><strong>Raw Prediction:</strong> ${data.raw_pred}</div>
    ${
      data.probability !== undefined
        ? `<div><strong>Confidence:</strong> ${Math.round(data.probability * 100)}%</div>`
        : ""
    }
  `;
  resultEl.classList.remove("hidden");
  errorEl.classList.add("hidden");
}

scanBtn.addEventListener("click", async () => {
  statusEl.textContent = "Scanning...";
  resultEl.classList.add("hidden");
  errorEl.classList.add("hidden");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("No active tab found.");

    const featureResp = await chrome.tabs.sendMessage(tab.id, { type: "EXTRACT_FEATURES" });
    if (!featureResp?.ok) {
      throw new Error(featureResp?.error || "Could not extract features.");
    }

    const response = await fetch("http://localhost:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(featureResp.features)
    });

    const text = await response.text();
    console.log("Raw server response:", text);

    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      throw new Error(`Server did not return JSON. Response starts with: ${text.slice(0, 120)}`);
    }
    
    if (!response.ok) {
      throw new Error(data.error || "Prediction failed.");
    }

    showResult(data);
    statusEl.textContent = "Done";
  } catch (err) {
    showError(err.message || String(err));
    statusEl.textContent = "Error";
  }
});