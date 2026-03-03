import { extractFeatures } from "./features.js";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type !== "EXTRACT_FEATURES") return;

  try {
    const features = extractFeatures(window);
    sendResponse({ ok: true, features });
  } catch (e) {
    sendResponse({ ok: false, error: e?.message || String(e) });
  }

  return true;
});