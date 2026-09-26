// SRE Production Deployment Risk Analyzer - Main App Controller

let currentAnalysisData = null;
let lastAnalysisRequest = null;
let timerInterval = null;

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("analyzeForm");
  const scenarioBtns = document.querySelectorAll(".btn-scenario");

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const repoUrl = document.getElementById("repoUrl").value.trim();
      const branch = document.getElementById("branch").value.trim();
      const commitSha = document.getElementById("commitSha").value.trim();

      if (!repoUrl) return;

      await triggerAnalysis("/api/analyze", {
        repo_url: repoUrl,
        branch: branch || null,
        commit_sha: commitSha || null,
        bypass_cache: false
      });
    });
  }

  // Handle 1-Click Demo Scenarios & Live Repos
  scenarioBtns.forEach(btn => {
    btn.addEventListener("click", async () => {
      const liveRepo = btn.getAttribute("data-repo");
      if (liveRepo) {
        const repoInput = document.getElementById("repoUrl");
        if (repoInput) repoInput.value = liveRepo;
        await triggerAnalysis("/api/analyze", {
          repo_url: liveRepo,
          bypass_cache: false
        });
        return;
      }

      const scenarioId = btn.getAttribute("data-scenario");
      if (!scenarioId) return;

      await triggerAnalysis("/api/analyze-scenario", {
        scenario_id: scenarioId,
        bypass_cache: false
      });
    });
  });
});

async function triggerAnalysis(endpoint, payload) {
  dismissError();
  showLoading();
  lastAnalysisRequest = { endpoint, payload };

  const stepOrder = [
    "step-connect",
    "step-baseline",
    "step-code",
    "step-dep",
    "step-infra",
    "step-db",
    "step-cfg",
    "step-ext",
    "step-graph",
    "step-inc",
    "step-ai"
  ];

  let currentStepIdx = 0;
  const stepperInterval = setInterval(() => {
    if (currentStepIdx < stepOrder.length) {
      if (currentStepIdx > 0) {
        const prev = document.getElementById(stepOrder[currentStepIdx - 1]);
        if (prev) {
          prev.classList.remove("active");
          prev.classList.add("done");
          prev.querySelector(".step-icon").textContent = "✓";
        }
      }
      const curr = document.getElementById(stepOrder[currentStepIdx]);
      if (curr) {
        curr.classList.add("active");
        curr.querySelector(".step-icon").textContent = "●";
      }
      currentStepIdx++;
    }
  }, 220);

  // Live Elapsed Timer
  const timerEl = document.getElementById("stepperTimer");
  const startTime = Date.now();
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    if (timerEl) {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      timerEl.textContent = `Elapsed: ${elapsed}s`;
    }
  }, 100);

  try {
    const resp = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    clearInterval(stepperInterval);
    if (timerInterval) clearInterval(timerInterval);

    // Complete all steps
    stepOrder.forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.classList.remove("active");
        el.classList.add("done");
        el.querySelector(".step-icon").textContent = "✓";
      }
    });

    if (!resp.ok) {
      const errData = await resp.json().catch(() => ({}));
      throw new Error(errData.detail || `Server returned HTTP ${resp.status}`);
    }

    const data = await resp.json();
    currentAnalysisData = data;

    setTimeout(() => {
      hideLoading();
      renderDashboard(data);
      const dashEl = document.getElementById("dashboardSection");
      if (dashEl) {
        dashEl.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 350);

  } catch (err) {
    clearInterval(stepperInterval);
    if (timerInterval) clearInterval(timerInterval);
    hideLoading();
    showError("Deployment Analysis Failed", err.message);
  }
}

async function reanalyzeCurrent() {
  if (!lastAnalysisRequest) return;
  const { endpoint, payload } = lastAnalysisRequest;
  const newPayload = { ...payload, bypass_cache: true };
  await triggerAnalysis(endpoint, newPayload);
}

function showLoading() {
  const overlay = document.getElementById("loadingOverlay");
  if (overlay) {
    // Reset stepper
    const steps = overlay.querySelectorAll(".step-item");
    steps.forEach(s => {
      s.classList.remove("active", "done");
      s.querySelector(".step-icon").textContent = "○";
    });
    overlay.classList.remove("hidden");
  }
}

function hideLoading() {
  const overlay = document.getElementById("loadingOverlay");
  if (overlay) {
    overlay.classList.add("hidden");
  }
}

function showError(title, message) {
  const alertEl = document.getElementById("errorAlert");
  const titleEl = document.getElementById("errorTitle");
  const msgEl = document.getElementById("errorMessage");

  if (titleEl) titleEl.textContent = title;
  if (msgEl) msgEl.textContent = message;
  if (alertEl) alertEl.classList.remove("hidden");
}

function dismissError() {
  const alertEl = document.getElementById("errorAlert");
  if (alertEl) alertEl.classList.add("hidden");
}

function copyEvidenceJson() {
  if (!currentAnalysisData) return;
  const jsonStr = JSON.stringify(currentAnalysisData, null, 2);
  navigator.clipboard.writeText(jsonStr).then(() => {
    const btn = document.getElementById("copyEvidenceBtn");
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = "Copied to Clipboard! ✓";
      setTimeout(() => { btn.textContent = orig; }, 2000);
    }
  });
}
