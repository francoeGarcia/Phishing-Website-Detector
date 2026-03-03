function hasIPAddress(hostname) {
  // IPv4 basic check
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function countChar(s, ch) {
  let n = 0;
  for (const c of s) if (c === ch) n++;
  return n;
}

function isShortener(host) {
  const shorteners = new Set([
    "bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","buff.ly","is.gd","cutt.ly","rebrand.ly"
  ]);
  return shorteners.has(host.toLowerCase());
}

function getAllLinks(doc) {
  return Array.from(doc.querySelectorAll("a[href]")).map(a => a.getAttribute("href") || "");
}

function isExternal(urlObj, href) {
  try {
    const u = new URL(href, urlObj.href);
    return u.hostname !== urlObj.hostname;
  } catch {
    return false;
  }
}

export function extractFeatures(win) {
  const doc = win.document;
  const urlObj = new URL(win.location.href);

  const url = urlObj.href;
  const host = urlObj.hostname;

  const links = getAllLinks(doc);
  const externalLinks = links.filter(h => isExternal(urlObj, h));
  const totalLinks = links.length || 1;

  const forms = Array.from(doc.querySelectorAll("form"));
  const iframes = doc.querySelectorAll("iframe").length;

  // Heuristic placeholders: your Kaggle datasets often use -1 / 0 / 1 encoding.
  // You MUST align these with what your model expects.
  // For a skeleton, we'll output numeric values but keep unknowns = 0.
  const features = {
    index: 0,

    // URL based
    having_IPhaving_IP_Address: hasIPAddress(host) ? 1 : 0,
    URLURL_Length: url.length,
    Shortining_Service: isShortener(host) ? 1 : 0,
    having_At_Symbol: url.includes("@") ? 1 : 0,
    double_slash_redirecting: url.slice(8).includes("//") ? 1 : 0, // beyond protocol
    Prefix_Suffix: host.includes("-") ? 1 : 0,
    having_Sub_Domain: countChar(host, ".") >= 2 ? 1 : 0,

    // SSL / protocol signals
    SSLfinal_State: urlObj.protocol === "https:" ? 1 : 0,
    HTTPS_token: url.toLowerCase().includes("https") && urlObj.protocol !== "https:" ? 1 : 0,

    // DOM based
    Favicon: (() => {
      const icon = doc.querySelector('link[rel~="icon"]')?.getAttribute("href");
      if (!icon) return 0;
      return isExternal(urlObj, icon) ? 1 : 0;
    })(),

    port: (urlObj.port && urlObj.port !== "80" && urlObj.port !== "443") ? 1 : 0,

    Request_URL: externalLinks.length / totalLinks, // ratio (0..1)
    URL_of_Anchor: (() => {
      // ratio of “unsafe” anchors: javascript:, #, empty
      const unsafe = links.filter(h => !h || h === "#" || h.toLowerCase().startsWith("javascript:")).length;
      return unsafe / totalLinks;
    })(),

    Links_in_tags: (() => {
      const metas = doc.querySelectorAll("meta[content], link[href], script[src]");
      const arr = Array.from(metas).map(el => el.getAttribute("src") || el.getAttribute("href") || el.getAttribute("content") || "");
      const ext = arr.filter(v => isExternal(urlObj, v)).length;
      const denom = arr.length || 1;
      return ext / denom;
    })(),

    SFH: (() => {
      // Server Form Handler: suspicious if empty or external action
      if (forms.length === 0) return 0;
      let suspicious = 0;
      for (const f of forms) {
        const action = (f.getAttribute("action") || "").trim();
        if (!action || action === "about:blank") suspicious++;
        else if (isExternal(urlObj, action)) suspicious++;
      }
      return suspicious / (forms.length || 1);
    })(),

    Submitting_to_email: (() => {
      return forms.some(f => (f.getAttribute("action") || "").toLowerCase().startsWith("mailto:")) ? 1 : 0;
    })(),

    Abnormal_URL: 0, // typically needs hostname + whois/brand checks; placeholder
    Redirect: 0,     // can be derived from performance navigation entries but keep placeholder initially
    on_mouseover: doc.documentElement?.outerHTML?.toLowerCase().includes("onmouseover") ? 1 : 0,
    RightClick: doc.documentElement?.outerHTML?.toLowerCase().includes("oncontextmenu") ? 1 : 0,
    popUpWidnow: doc.documentElement?.outerHTML?.toLowerCase().includes("window.open") ? 1 : 0,
    Iframe: iframes > 0 ? 1 : 0,

    // Backend-only / API-needed signals (initial placeholders)
    Domain_registeration_length: 0,
    age_of_domain: 0,
    DNSRecord: 0,
    web_traffic: 0,
    Page_Rank: 0,
    Google_Index: 0,
    Links_pointing_to_page: 0,
    Statistical_report: 0
  };

  return features;
}