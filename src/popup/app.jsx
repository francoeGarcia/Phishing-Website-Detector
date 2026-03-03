import React, { useState } from "react";

export default function App() {
  const [status, setStatus] = useState("idle"); // idle | scanning | done | error
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function scanActiveTab() {
    setStatus("scanning");
    setError("");
    setResult(null);

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) throw new Error("No active tab found.");

      // Ask background to scan this tab (background will ask content script for features, then call Flask)
      const resp = await chrome.runtime.sendMessage({
        type: "SCAN_ACTIVE_TAB",
        tabId: tab.id,
        url: tab.url ?? ""
      });

      if (!resp?.ok) {
        throw new Error(resp?.error || "Scan failed.");
      }

      setResult(resp.data); // { label, probability, ... }
      setStatus("done");
    } catch (e) {
      setError(e?.message || String(e));
      setStatus("error");
    }
  }

  const badge =
    status === "done"
      ? result?.label === "phishing"
        ? "Likely Phishing"
        : "Likely Legit"
      : status === "scanning"
        ? "Scanning..."
        : "Ready";

  return (
    <div className="wrap">
      <header className="header">
        <div className="title">Phishing Detector</div>
        <div className={`badge ${status}`}>{badge}</div>
      </header>

      <main className="main">
        <button className="btn" onClick={scanActiveTab} disabled={status === "scanning"}>
          {status === "scanning" ? "Scanning..." : "Scan this page"}
        </button>

        {status === "done" && result && (
          <div className="card">
            <div className="row">
              <span className="k">Prediction</span>
              <span className="v">{result.label}</span>
            </div>
            {"probability" in result && (
              <div className="row">
                <span className="k">Confidence</span>
                <span className="v">{Math.round(result.probability * 100)}%</span>
              </div>
            )}
            {result?.notes && (
              <div className="notes">
                <div className="k">Notes</div>
                <div className="v">{result.notes}</div>
              </div>
            )}
          </div>
        )}

        {status === "error" && <div className="error">{error}</div>}

        <div className="small">
          Backend: <code>http://localhost:5000</code>
        </div>
      </main>
    </div>
  );
}