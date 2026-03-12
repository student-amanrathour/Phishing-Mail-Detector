console.log("[PhishDetector] Background Loaded");

const VT_CACHE_KEY = "VT_CACHE";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
let globalStats = { checked: 0, clean: 0, suspicious: 0 };

// Helper: get cache
async function getPersistentCache() {
  try {
    const res = await chrome.storage.local.get([VT_CACHE_KEY]);
    return res[VT_CACHE_KEY] || {};
  } catch (e) {
    console.warn("[Background] Storage get failed", e);
    return {};
  }
}

// Helper: set cache
async function setPersistentCache(obj) {
  try {
    const toStore = {};
    toStore[VT_CACHE_KEY] = obj;
    await chrome.storage.local.set(toStore);
  } catch (e) {
    console.warn("[Background] Storage set failed", e);
  }
}

// Update stats
function updateGlobalStats(vtStats) {
  globalStats.checked++;
  const maliciousCount = vtStats?.malicious || 0;
  if (maliciousCount > 0) globalStats.suspicious++;
  else globalStats.clean++;
}

// -------------------- MAIN MESSAGE HANDLER --------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // -------------------- DASHBOARD ACTIONS --------------------
  if (message.action === "get_stats") {
    sendResponse(globalStats);
    return;
  }

  if (message.action === "clear_cache") {
    chrome.storage.local.remove(VT_CACHE_KEY, () => {
      globalStats = { checked: 0, clean: 0, suspicious: 0 };
      console.log("[Background] Cache Cleared");
      sendResponse({ success: true });
    });
    return true;
  }

  // -------------------- VIRUSTOTAL CHECK --------------------
  if (message.action === "check_url" && message.url) {
    const href = message.url;
    (async () => {
      try {
        const cache = await getPersistentCache();
        const entry = cache[href];
        const now = Date.now();

        // Cache hit
        if (entry && (now - entry.ts) < CACHE_TTL_MS && entry.vtStats) {
          sendResponse({ vtStats: entry.vtStats, cached: true });
          return;
        }

        // Fetch API key
        const data = await chrome.storage.local.get(["VT_API_KEY"]);
        const apiKey = data.VT_API_KEY;
        if (!apiKey) {
          sendResponse({ error: "API key not set in options" });
          return;
        }

        // Submit URL
        const submitRep = await fetch("https://www.virustotal.com/api/v3/urls", {
          method: "POST",
          headers: {
            "x-apikey": apiKey,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: `url=${encodeURIComponent(href)}`,
        });

        if (!submitRep.ok) {
          sendResponse({ error: `Submit failed (${submitRep.status})` });
          return;
        }

        const submitData = await submitRep.json();
        const analysisId = submitData?.data?.id;
        if (!analysisId) {
          sendResponse({ error: "No analysis ID returned" });
          return;
        }

        // Get analysis result
        const resultRep = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: { "x-apikey": apiKey },
        });

        if (!resultRep.ok) {
          sendResponse({ error: `Result fetch failed (${resultRep.status})` });
          return;
        }

        const resultData = await resultRep.json();
        const vtStats = resultData?.data?.attributes?.stats || {};

        // Cache and update stats
        cache[href] = { vtStats, ts: Date.now() };
        await setPersistentCache(cache);
        updateGlobalStats(vtStats);

        sendResponse({ vtStats, cached: false });
      } catch (err) {
        console.error("[Background] VT API Error:", err);
        sendResponse({ error: "Failed to query VirusTotal" });
      }
    })();
    return true;
  }

  // -------------------- AI MODEL CHECK --------------------
  if (message.action === "checkAI" && message.url) {
  const href = message.url;
  (async () => {
    try {
      const res = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: href }),
      });
      const data = await res.json();

      // Save AI result to cache
      const cache = await getPersistentCache();
      cache[href] = cache[href] || {};
      cache[href].aiResult = data;
      cache[href].ts = Date.now();
      await setPersistentCache(cache);

      // Update stats if AI says phishing
      if (data.label === "phishing") {
        globalStats.suspicious++;
      } else {
        globalStats.clean++;
      }
      globalStats.checked++;

      sendResponse({ result: data });
    } catch (err) {
      console.error("[Background] AI API error:", err);
      sendResponse({ result: { label: "error", probability: 0 } });
    }
  })();
  return true;
  }
});

