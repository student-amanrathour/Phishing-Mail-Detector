document.addEventListener("DOMContentLoaded", () => {
  const riskLevelEl = document.getElementById("riskLevel");
  const scoreTextEl = document.getElementById("scoreText");
  const listEl = document.getElementById("maliciousList");
  const refreshBtn = document.getElementById("refreshBtn");
  const clearBtn = document.getElementById("clearBtn");

  // --- Get stats from background ---
  chrome.runtime.sendMessage({ action: "get_stats" }, (stats) => {
    updateDashboard(stats);
  });

  refreshBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "get_stats" }, (stats) => {
      updateDashboard(stats);
    });
  });

  clearBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "clear_cache" }, () => {
      listEl.innerHTML = "<li>Cache Cleared</li>";
      riskLevelEl.textContent = "Idle";
      riskLevelEl.className = "";
      scoreTextEl.textContent = "Risk Score: 0";
    });
  });

  function updateDashboard(stats) {
    const { checked, clean, suspicious } = stats || {};
    const total = checked || 0;
    chrome.storage.local.get("VT_CACHE", (res) => {
      const cache = res["VT_CACHE"] || {};
      let aiSuspicious = 0;

      for (const entry of Object.values(cache)) {
        const aiResult = entry.aiResult;
        if (aiResult && aiResult.label === "phishing" && aiResult.probability > 0.6) {
          aiSuspicious++;
        }
      }

      const totalSuspicious = suspicious + aiSuspicious;
      const total = checked || 1;
      const riskScore = Math.round((totalSuspicious / total) * 100);

      scoreTextEl.textContent = `Risk Score: ${riskScore}%`;
    });

    const riskScore = total ? Math.round((suspicious / total) * 100) : 0;

    // Update score visuals
    scoreTextEl.textContent = `Risk Score: ${riskScore}%`;

    if (riskScore < 30) {
      riskLevelEl.textContent = "SAFE";
      riskLevelEl.className = "safe";
    } else if (riskScore < 70) {
      riskLevelEl.textContent = "SUSPICIOUS";
      riskLevelEl.className = "suspicious";
    } else {
      riskLevelEl.textContent = "MALICIOUS";
      riskLevelEl.className = "malicious";
    }

    // --- Malicious list display ---
    if (suspicious > 0) {
      listEl.innerHTML = "";
      chrome.storage.local.get("VT_CACHE", (res) => {
        const cache = res["VT_CACHE"] || {};
        for (const [url, entry] of Object.entries(cache)) {
          const vtStats = entry.vtStats || {};
          const aiResult = entry.aiResult || {};
          const vtMal = vtStats.malicious || 0;
          const aiPhish = aiResult.label === "phishing" && aiResult.probability > 0.6;

          if (vtMal > 0 || aiPhish) {
          const li = document.createElement("li");
          const vtText = vtMal > 0 ? `${vtMal} VT detections` : "";
          const aiText = aiPhish ? `AI: ${(aiResult.probability * 100).toFixed(1)}% phishing` : "";
          li.innerHTML = `<b>${url}</b> → ${[vtText, aiText].filter(Boolean).join(" | ")}`;
          listEl.appendChild(li);
        }
      }

      });
    } else {
      listEl.innerHTML = "<li>No malicious URLs detected.</li>";
    }
  }
});

