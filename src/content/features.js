function clampTri(v) {
  // ensure only -1/0/1
  if (v > 0) return 1;
  if (v < 0) return -1;
  return 0;
}

function hasIPv4(hostname) {
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

function safeURL(href, base) {
  try { return new URL(href, base); } catch { return null; }
}

export function extractFeatures(win) {
  const doc = win.document;
  const urlObj = new URL(win.location.href);
  const url = urlObj.href;
  const host = urlObj.hostname;

  // --- URL-based features ---
  const having_IPhaving_IP_Address = hasIPv4(host) ? -1 : 1;

  // Common dataset bins: <=54 => 1, 55-75 => 0, >75 => -1
  const URLURL_Length =
    url.length <= 54 ? 1 : (url.length <= 75 ? 0 : -1);

  const Shortining_Service = isShortener(host) ? -1 : 1;

  const having_At_Symbol = url.includes("@") ? -1 : 1;

  // if there is a '//' after the protocol section, suspicious
  const double_slash_redirecting = url.slice(urlObj.protocol.length + 2).includes("//") ? -1 : 1;

  // prefix/suffix: '-' in domain is suspicious
  const Prefix_Suffix = host.includes("-") ? -1 : 1;

  // subdomain: 0-1 dot => 1, 2 dots => 0, >=3 dots => -1 (rough bin)
  const dots = countChar(host, ".");
  const having_Sub_Domain = dots <= 1 ? 1 : (dots === 2 ? 0 : -1);

  // SSLfinal_State: https => 1 else -1 (dataset sometimes uses more nuance; keep simple)
  const SSLfinal_State = urlObj.protocol === "https:" ? 1 : -1;

  // port: explicit non-standard port is suspicious
  const port = (urlObj.port && urlObj.port !== "80" && urlObj.port !== "443") ? -1 : 1;

  // HTTPS_token: if the string "https" appears in the domain/path while protocol isn't https, suspicious
  const HTTPS_token = (urlObj.protocol !== "https:" && url.toLowerCase().includes("https")) ? -1 : 1;

  // --- DOM-based link computations ---
  const anchors = Array.from(doc.querySelectorAll("a[href]"));
  const totalA = anchors.length || 1;

  const externalA = anchors.filter(a => {
    const u = safeURL(a.getAttribute("href"), urlObj.href);
    return u && u.hostname && u.hostname !== host;
  }).length;

  // Request_URL (often "Request_URL" / "Request_URL" in datasets):
  // percent of external objects/links; approximate using anchors ratio
  const extRatio = externalA / totalA;
  // bin: <0.22 => 1, 0.22-0.61 => 0, >0.61 => -1 (common dataset thresholds)
  const Request_URL = extRatio < 0.22 ? 1 : (extRatio <= 0.61 ? 0 : -1);

  // URL_of_Anchor: unsafe anchors: empty/#/javascript
  const unsafeAnchors = anchors.filter(a => {
    const h = (a.getAttribute("href") || "").trim().toLowerCase();
    return !h || h === "#" || h.startsWith("javascript:");
  }).length;
  const unsafeRatio = unsafeAnchors / totalA;
  // bin: <0.31 => 1, 0.31-0.67 => 0, >0.67 => -1 (common)
  const URL_of_Anchor = unsafeRatio < 0.31 ? 1 : (unsafeRatio <= 0.67 ? 0 : -1);

  // Links_in_tags: look at <meta>, <script>, <link> that reference external
  const tagEls = [
    ...Array.from(doc.querySelectorAll("meta[content]")),
    ...Array.from(doc.querySelectorAll("script[src]")),
    ...Array.from(doc.querySelectorAll("link[href]"))
  ];

  const tagRefs = tagEls
    .map(el => el.getAttribute("src") || el.getAttribute("href") || el.getAttribute("content") || "")
    .filter(Boolean);

  const totalTags = tagRefs.length || 1;
  const extTags = tagRefs.filter(ref => {
    const u = safeURL(ref, urlObj.href);
    return u && u.hostname && u.hostname !== host;
  }).length;

  const tagRatio = extTags / totalTags;
  // bin: <0.17 => 1, 0.17-0.81 => 0, >0.81 => -1 (common-ish)
  const Links_in_tags = tagRatio < 0.17 ? 1 : (tagRatio <= 0.81 ? 0 : -1);

  // SFH: form handler
  const forms = Array.from(doc.querySelectorAll("form"));
  let SFH = 1;
  if (forms.length > 0) {
    let suspicious = 0;
    for (const f of forms) {
      const action = (f.getAttribute("action") || "").trim();
      if (!action || action === "about:blank") suspicious++;
      else {
        const u = safeURL(action, urlObj.href);
        if (u && u.hostname && u.hostname !== host) suspicious++;
      }
    }
    const sRatio = suspicious / forms.length;
    SFH = sRatio === 0 ? 1 : (sRatio < 1 ? 0 : -1);
  }

  const Submitting_to_email = forms.some(f =>
    (f.getAttribute("action") || "").trim().toLowerCase().startsWith("mailto:")
  ) ? -1 : 1;

  // Favicon: external favicon often suspicious
  const iconHref = doc.querySelector('link[rel~="icon"]')?.getAttribute("href") || "";
  let Favicon = 1;
  if (iconHref) {
    const u = safeURL(iconHref, urlObj.href);
    if (u && u.hostname && u.hostname !== host) Favicon = -1;
  }

  // Simple JS/DOM signals
  const html = (doc.documentElement?.outerHTML || "").toLowerCase();
  const on_mouseover = html.includes("onmouseover") ? -1 : 1;
  const RightClick = html.includes("oncontextmenu") ? -1 : 1;
  const popUpWidnow = html.includes("window.open") ? -1 : 1;
  const Iframe = doc.querySelectorAll("iframe").length > 0 ? -1 : 1;

  // Redirect: hard to detect reliably from content script; unknown => 0
  const Redirect = 0;

  // Abnormal_URL: would need deeper checks; unknown => 0
  const Abnormal_URL = 0;

  // --- Backend/API-required features (set unknown=0 for now) ---
  const Domain_registeration_length = 0;
  const age_of_domain = 0;
  const DNSRecord = 0;
  const web_traffic = 0;
  const Page_Rank = 0;
  const Google_Index = 0;
  const Links_pointing_to_page = 0;
  const Statistical_report = 0;

  return {
    having_IPhaving_IP_Address,
    URLURL_Length,
    Shortining_Service,
    having_At_Symbol,
    double_slash_redirecting,
    Prefix_Suffix,
    having_Sub_Domain,
    SSLfinal_State,
    Domain_registeration_length,
    Favicon,
    port,
    HTTPS_token,
    Request_URL,
    URL_of_Anchor,
    Links_in_tags,
    SFH,
    Submitting_to_email,
    Abnormal_URL,
    Redirect,
    on_mouseover,
    RightClick,
    popUpWidnow,
    Iframe,
    age_of_domain,
    DNSRecord,
    web_traffic,
    Page_Rank,
    Google_Index,
    Links_pointing_to_page,
    Statistical_report
  };
}