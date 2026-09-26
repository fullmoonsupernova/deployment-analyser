// SRE Production Deployment Risk Analyzer - Dashboard & Visualization Controller

let activeScenarioIndex = 0;
let cachedTopologyNodes = [];
let cachedTopologyEdges = [];
let activeCategoryFilter = "all";
let activeSearchQuery = "";

document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupFindingsFilters();
});

function setupTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPane = document.getElementById(btn.getAttribute("data-tab"));
      if (targetPane) {
        targetPane.classList.add("active");
        if (btn.getAttribute("data-tab") === "tab-topology") {
          // Re-render topology to ensure correct dimensions
          renderTopologyGraph(cachedTopologyNodes, cachedTopologyEdges);
        }
      }
    });
  });
}

function renderDashboard(data) {
  const dashSection = document.getElementById("dashboardSection");
  if (!dashSection) return;
  dashSection.classList.remove("hidden");

  // Save globally for exports & quick actions
  window.currentAnalysisData = data;

  // 1. Repo Metadata
  try {
    const repo = data.repository || {};
    const repoTitle = document.getElementById("dashRepoTitle");
    if (repoTitle) {
      repoTitle.textContent = repo.full_name || `${repo.owner}/${repo.name}` || "Repository Analysis";
    }
    const repoDesc = document.getElementById("dashRepoDesc");
    if (repoDesc) {
      repoDesc.textContent = repo.description || "Production Repository Revision Analysis";
    }

    // 2. Commit SHAs
    const baseSha = document.getElementById("dashBaselineSha");
    if (baseSha) {
      baseSha.textContent = (data.baseline_commit || "0000000").substring(0, 8);
      baseSha.title = data.baseline_commit || "";
    }
    const candSha = document.getElementById("dashCandidateSha");
    if (candSha) {
      candSha.textContent = (data.deployment_commit || "0000000").substring(0, 8);
      candSha.title = data.deployment_commit || "";
    }
  } catch (err) {
    console.warn("Error rendering repo metadata:", err);
  }

  // 3. Risk Gauge, Verdict Card & Observability Pillars
  try {
    renderRiskGauge(data.deterministic_risk_score, data.deterministic_risk_level);
    renderSreVerdict(data);
    renderObservabilityPillars(data);

    const riskBadge = document.getElementById("riskLevelBadge");
    const riskHeadline = document.getElementById("riskHeadline");
    const cacheBadge = document.getElementById("cacheBadge");

    const level = (data.deterministic_risk_level || "MEDIUM").toLowerCase();
    if (riskBadge) {
      riskBadge.className = `risk-badge ${level}`;
      riskBadge.textContent = `${data.deterministic_risk_level || "MEDIUM"} RISK`;
    }
    if (riskHeadline) {
      const factors = data.significant_factors_count || 0;
      riskHeadline.textContent = `${factors} significant risk factor${factors === 1 ? '' : 's'}`;
    }
    if (cacheBadge) {
      if (data.cached) {
        cacheBadge.classList.remove("hidden");
      } else {
        cacheBadge.classList.add("hidden");
      }
    }
  } catch (err) {
    console.warn("Error rendering risk overview:", err);
  }

  // 4. Executive Summary
  try {
    const execSummary = document.getElementById("executiveSummaryText");
    if (execSummary) {
      execSummary.textContent = data.ai_analysis?.summary || "Comprehensive analysis generated based on deterministic signals.";
    }
  } catch (err) {
    console.warn("Error rendering executive summary:", err);
  }

  // 5. Update Tab Counts
  const scenarios = data.ai_analysis?.failure_scenarios || [];
  const findings = data.findings || [];
  const services = data.services || [];
  const incidents = data.historical_matches || [];

  try {
    const countSc = document.getElementById("countScenarios");
    if (countSc) countSc.textContent = scenarios.length;
    const countSv = document.getElementById("countServices");
    if (countSv) countSv.textContent = services.length;
    const countFd = document.getElementById("countFindings");
    if (countFd) countFd.textContent = findings.length;
    const countIn = document.getElementById("countIncidents");
    if (countIn) countIn.textContent = incidents.length;
  } catch (err) {
    console.warn("Error updating tab counts:", err);
  }

  // Cache topology data
  cachedTopologyNodes = services;
  cachedTopologyEdges = data.relationships || [];

  // 6. Render Subcomponents with independent error boundaries
  try { renderScenarios(scenarios, findings); } catch (e) { console.error("renderScenarios error:", e); }
  try { renderTopologyGraph(cachedTopologyNodes, cachedTopologyEdges); } catch (e) { console.error("renderTopologyGraph error:", e); }
  try { renderFindings(findings); } catch (e) { console.error("renderFindings error:", e); }
  try { renderIncidents(incidents); } catch (e) { console.error("renderIncidents error:", e); }
  try { renderRolloutStrategy(data.ai_analysis?.rollout_strategy); } catch (e) { console.error("renderRolloutStrategy error:", e); }
  try { renderMonitoring(data.ai_analysis?.monitoring, data.ai_analysis?.rollback_conditions); } catch (e) { console.error("renderMonitoring error:", e); }
  try { renderEvidenceJson(data); } catch (e) { console.error("renderEvidenceJson error:", e); }

  // Automatically select first scenario
  if (scenarios.length > 0) {
    try { selectScenario(0, scenarios); } catch (e) { console.error("selectScenario error:", e); }
  }
}

/* =========================================================================
   SCENARIOS & FAILURE CHAIN
   ========================================================================= */

function renderScenarios(scenarios, findings) {
  const container = document.getElementById("scenariosList");
  if (!container) return;
  container.innerHTML = "";

  if (scenarios.length === 0) {
    container.innerHTML = `<div class="chain-viewer-placeholder">No critical production failure modes identified.</div>`;
    return;
  }

  scenarios.forEach((sc, idx) => {
    const card = document.createElement("div");
    card.className = `scenario-card ${idx === 0 ? 'active' : ''}`;
    card.setAttribute("data-sc-idx", idx);

    const sevClass = `badge-${sc.severity === 'critical' ? 'crit' : sc.severity === 'high' ? 'high' : 'medium'}`;

    card.innerHTML = `
      <div class="sc-header">
        <span class="sc-badge ${sevClass}">${sc.severity.toUpperCase()}</span>
        <span class="sc-tag">Confidence: ${(sc.confidence * 100).toFixed(0)}%</span>
      </div>
      <div class="sc-title">${sc.title}</div>
      <div class="sc-meta">
        ${(sc.affected_services || []).map(s => `<span class="sc-tag">⚡ ${s}</span>`).join("")}
        <span class="sc-tag">Evidence: ${(sc.evidence_ids || []).length} factors</span>
      </div>
    `;

    card.addEventListener("click", () => {
      document.querySelectorAll(".scenario-card").forEach(c => c.classList.remove("active"));
      card.classList.add("active");
      selectScenario(idx, scenarios);
    });

    container.appendChild(card);
  });
}

function selectScenario(index, scenarios) {
  activeScenarioIndex = index;
  const sc = scenarios[index];
  const viewer = document.getElementById("scenarioChainViewer");
  if (!viewer || !sc) return;

  const sevClass = `badge-${sc.severity === 'critical' ? 'crit' : sc.severity === 'high' ? 'high' : 'medium'}`;

  // Build Failure Chain Flowchart
  const chainHtml = (sc.failure_chain || []).map((step, stepIdx, arr) => {
    const isLast = stepIdx === arr.length - 1;
    return `
      <div class="chain-step ${isLast ? 'last-step' : ''}">
        <div class="chain-step-num">${stepIdx + 1}</div>
        <div class="chain-step-text">${step}</div>
      </div>
      ${!isLast ? '<div class="chain-arrow">↓</div>' : ''}
    `;
  }).join("");

  viewer.innerHTML = `
    <div class="chain-header-block">
      <div class="sc-header">
        <span class="sc-badge ${sevClass}">${sc.severity.toUpperCase()} RISK</span>
        <span class="sc-tag">Confidence: ${(sc.confidence * 100).toFixed(0)}%</span>
      </div>
      <h3 class="chain-header-title">${sc.title}</h3>
      <div class="sc-meta">
        ${(sc.affected_services || []).map(s => `<span class="sc-tag">⚡ ${s}</span>`).join("")}
      </div>
    </div>

    <!-- Visual Failure Chain -->
    <div>
      <div class="chain-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
        PRODUCTION FAILURE CASCADE SEQUENCE
      </div>
      <div class="failure-chain-flow">
        ${chainHtml}
      </div>
    </div>

    <!-- Why Tests Miss It -->
    <div class="chain-detail-box">
      <div class="chain-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        WHY UNIT/STAGING TESTS FAILED TO EXPOSE THIS
      </div>
      <p>${sc.why_tests_may_miss_it || "Not specified."}</p>
    </div>

    <!-- Blast Radius & Mitigation -->
    <div class="chain-detail-box">
      <div class="chain-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        BLAST RADIUS & MITIGATION
      </div>
      <p><strong>Blast Radius:</strong> ${sc.blast_radius || "Application level"}</p>
      <p style="margin-top: 0.4rem;"><strong>Immediate Mitigation:</strong> ${sc.mitigation || "Follow phased rollout"}</p>
    </div>
  `;

  // Highlight affected services on the SVG Topology Graph
  highlightTopologyServices(sc.affected_services || []);
}

/* =========================================================================
   SVG TOPOLOGY GRAPH (Pure Vanilla SVG, Zero NPM)
   ========================================================================= */

function renderTopologyGraph(nodes, edges) {
  const svg = document.getElementById("topologySvg");
  if (!svg) return;
  svg.innerHTML = "";

  if (!nodes || nodes.length === 0) {
    svg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="#64748b" font-family="monospace">No service nodes detected</text>`;
    return;
  }

  const width = svg.clientWidth || 900;
  const height = svg.clientHeight || 500;

  // Layout algorithm: Group by roles/layers
  // Layer 0 (Top): Frontend / Client
  // Layer 1 (Mid): Primary API / Backend
  // Layer 2 (Bottom): Databases, Caches, Workers, External APIs
  const layer0 = nodes.filter(n => n.type === "frontend");
  const layer1 = nodes.filter(n => n.type === "api" || n.type === "service");
  const layer2 = nodes.filter(n => ["database", "cache", "external_api", "worker", "queue"].includes(n.type));

  const positions = {};

  // Position Layer 0
  const l0Y = 80;
  layer0.forEach((n, i) => {
    const spacing = width / (layer0.length + 1);
    positions[n.id] = { x: spacing * (i + 1), y: l0Y };
  });

  // Position Layer 1
  const l1Y = 240;
  layer1.forEach((n, i) => {
    const spacing = width / (layer1.length + 1);
    positions[n.id] = { x: spacing * (i + 1), y: l1Y };
  });

  // Position Layer 2
  const l2Y = 410;
  layer2.forEach((n, i) => {
    const spacing = width / (layer2.length + 1);
    positions[n.id] = { x: spacing * (i + 1), y: l2Y };
  });

  // Handle any orphan nodes
  nodes.forEach((n, i) => {
    if (!positions[n.id]) {
      positions[n.id] = { x: 100 + (i * 120) % (width - 200), y: 320 };
    }
  });

  // SVG Definitions for arrow marker & glow filters
  svg.innerHTML = `
    <defs>
      <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#475569" />
      </marker>
      <marker id="arrow-danger" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#ef4444" />
      </marker>
      <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="4" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
    </defs>
  `;

  // Draw Edges (curved paths)
  edges.forEach((edge, eIdx) => {
    const fromPos = positions[edge.from_node];
    const toPos = positions[edge.to_node];
    if (!fromPos || !toPos) return;

    const dx = toPos.x - fromPos.x;
    const dy = toPos.y - fromPos.y;
    const cx1 = fromPos.x + dx * 0.2;
    const cy1 = fromPos.y + dy * 0.5;
    const cx2 = fromPos.x + dx * 0.8;
    const cy2 = fromPos.y + dy * 0.5;

    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", `M ${fromPos.x} ${fromPos.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${toPos.x} ${toPos.y}`);
    path.setAttribute("stroke", "#334155");
    path.setAttribute("stroke-width", "2");
    path.setAttribute("fill", "none");
    path.setAttribute("marker-end", "url(#arrow)");
    path.setAttribute("class", "graph-edge");
    path.setAttribute("id", `edge-${edge.from_node}-${edge.to_node}`);
    svg.appendChild(path);
  });

  // Draw Nodes
  nodes.forEach(node => {
    const pos = positions[node.id];
    if (!pos) return;

    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.setAttribute("class", "graph-node");
    g.setAttribute("id", `node-${node.id}`);
    g.setAttribute("data-node-name", node.name);
    g.setAttribute("transform", `translate(${pos.x}, ${pos.y})`);

    // Node Type Colors
    let fillColor = "#1e293b";
    let strokeColor = "#3b82f6";
    let icon = "⚙️";

    if (node.type === "frontend") {
      strokeColor = "#38bdf8";
      icon = "🌐";
    } else if (node.type === "database") {
      strokeColor = "#10b981";
      icon = "🗄️";
    } else if (node.type === "cache") {
      strokeColor = "#f59e0b";
      icon = "⚡";
    } else if (node.type === "external_api") {
      strokeColor = "#8b5cf6";
      icon = "☁️";
    }

    g.innerHTML = `
      <rect x="-70" y="-24" width="140" height="48" rx="8" fill="${fillColor}" stroke="${strokeColor}" stroke-width="2" class="node-box" />
      <text x="-56" y="5" font-size="14" class="node-icon">${icon}</text>
      <text x="-32" y="-4" fill="#f8fafc" font-size="12" font-weight="700" font-family="'Plus Jakarta Sans', sans-serif" class="node-text">${node.name.substring(0, 14)}</text>
      <text x="-32" y="11" fill="#64748b" font-size="9" font-family="'JetBrains Mono', monospace" class="node-type">${node.type.toUpperCase()}</text>
    `;

    svg.appendChild(g);
  });
}

function highlightTopologyServices(affectedServices) {
  // Normalize affected service names
  const affected = affectedServices.map(s => s.toLowerCase());

  document.querySelectorAll(".graph-node").forEach(g => {
    const nodeName = (g.getAttribute("data-node-name") || "").toLowerCase();
    const isAffected = affected.some(a => nodeName.includes(a) || a.includes(nodeName));
    const box = g.querySelector(".node-box");

    if (box) {
      if (isAffected) {
        box.setAttribute("stroke", "#ef4444");
        box.setAttribute("stroke-width", "3");
        box.setAttribute("fill", "rgba(239, 68, 68, 0.2)");
        box.setAttribute("filter", "url(#glow)");
        box.classList.add("pulsing-danger");
      } else {
        box.removeAttribute("filter");
        box.setAttribute("stroke-width", "1.5");
        box.setAttribute("fill", "#111827");
        box.classList.remove("pulsing-danger");
      }
    }
  });
}

/* =========================================================================
   FINDINGS GRID & FILTERS
   ========================================================================= */

let allFindingsData = [];

function setupFindingsFilters() {
  const filterBtns = document.querySelectorAll(".btn-filter");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeCategoryFilter = btn.getAttribute("data-filter") || "all";
      applyFindingsFilter();
    });
  });

  const searchInput = document.getElementById("findingSearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      activeSearchQuery = (e.target.value || "").trim().toLowerCase();
      applyFindingsFilter();
    });
  }
}

function renderFindings(findings) {
  allFindingsData = findings || [];
  activeCategoryFilter = "all";
  activeSearchQuery = "";
  const searchInput = document.getElementById("findingSearchInput");
  if (searchInput) searchInput.value = "";
  const filterBtns = document.querySelectorAll(".btn-filter");
  filterBtns.forEach(b => {
    b.classList.toggle("active", b.getAttribute("data-filter") === "all");
  });
  applyFindingsFilter();
}

function applyFindingsFilter() {
  const container = document.getElementById("findingsGrid");
  const countLabel = document.getElementById("filteredCountLabel");
  if (!container) return;

  const filtered = allFindingsData.filter(f => {
    if (activeCategoryFilter !== "all" && f.category.toLowerCase() !== activeCategoryFilter.toLowerCase()) {
      return false;
    }
    if (activeSearchQuery) {
      const desc = (f.description || "").toLowerCase();
      const evid = (f.evidence || "").toLowerCase();
      const file = (f.file || "").toLowerCase();
      const type = (f.type || "").toLowerCase();
      const cat = (f.category || "").toLowerCase();
      const meta = JSON.stringify(f.metadata || {}).toLowerCase();
      const matches = desc.includes(activeSearchQuery) ||
                      evid.includes(activeSearchQuery) ||
                      file.includes(activeSearchQuery) ||
                      type.includes(activeSearchQuery) ||
                      cat.includes(activeSearchQuery) ||
                      meta.includes(activeSearchQuery);
      if (!matches) return false;
    }
    return true;
  });

  if (countLabel) {
    if (activeSearchQuery || activeCategoryFilter !== "all") {
      countLabel.textContent = `Showing ${filtered.length} of ${allFindingsData.length} findings`;
    } else {
      countLabel.textContent = `Showing all ${allFindingsData.length} findings`;
    }
  }

  container.innerHTML = "";

  if (filtered.length === 0) {
    container.innerHTML = `<div class="chain-viewer-placeholder">No matching findings found. Try a different keyword or category.</div>`;
    return;
  }

  filtered.forEach(f => {
    const card = document.createElement("div");
    card.className = "finding-card";

    const sev = f.severity_hint.toLowerCase();
    const sevBadge = `badge-${sev === 'critical' ? 'crit' : sev === 'high' ? 'high' : 'medium'}`;

    card.innerHTML = `
      <div class="fc-top">
        <span class="fc-category">${f.category.replace('_', ' ')}</span>
        <span class="sc-badge ${sevBadge}">${f.severity_hint.toUpperCase()}</span>
      </div>
      <div class="fc-desc">${f.description}</div>
      <div class="fc-file-meta">
        <span>📄</span>
        <span>${f.file}${f.line ? `:${f.line}` : ''}</span>
      </div>
      <button type="button" class="fc-evidence-toggle" onclick="toggleEvidence(this)">
        ▶ Show Code Evidence / Diff
      </button>
      <div class="fc-evidence-box hidden">${escapeHtml(f.evidence)}</div>
    `;

    container.appendChild(card);
  });
}

function toggleEvidence(btn) {
  const box = btn.nextElementSibling;
  if (!box) return;
  if (box.classList.contains("hidden")) {
    box.classList.remove("hidden");
    btn.textContent = "▼ Hide Code Evidence / Diff";
  } else {
    box.classList.add("hidden");
    btn.textContent = "▶ Show Code Evidence / Diff";
  }
}

/* =========================================================================
   INCIDENTS, ROLLOUT & MONITORING
   ========================================================================= */

function renderIncidents(incidents) {
  const container = document.getElementById("incidentsGrid");
  if (!container) return;
  container.innerHTML = "";

  if (incidents.length === 0) {
    container.innerHTML = `<div class="chain-viewer-placeholder">No historical incident archetypes matched.</div>`;
    return;
  }

  incidents.forEach(inc => {
    const card = document.createElement("div");
    card.className = "incident-card";

    card.innerHTML = `
      <div class="inc-header">
        <span class="inc-id">${inc.incident_id}</span>
        <span class="sc-badge badge-high">${inc.severity.toUpperCase()} IMPACT</span>
      </div>
      <div class="inc-title">${inc.title}</div>
      <div class="inc-box">
        <strong>Failure Mechanism:</strong>
        ${inc.failure_summary}
      </div>
      <div class="inc-box">
        <strong>Historical Production Impact:</strong>
        ${inc.historic_impact}
      </div>
      <div class="inc-patterns">
        ${(inc.matched_patterns || []).map(p => `<span class="sc-tag">⚡ ${p}</span>`).join("")}
      </div>
    `;

    container.appendChild(card);
  });
}

function renderRolloutStrategy(strategyObj) {
  const badge = document.getElementById("strategyNameBadge");
  const container = document.getElementById("rolloutStepsContainer");
  if (!container) return;
  container.innerHTML = "";

  if (!strategyObj) {
    container.innerHTML = `<div class="chain-viewer-placeholder">Standard release plan recommended.</div>`;
    return;
  }

  if (badge) {
    badge.textContent = strategyObj.strategy.toUpperCase();
  }

  const steps = strategyObj.steps || [];
  steps.forEach((step, idx) => {
    const card = document.createElement("div");
    card.className = "rollout-step-card";
    card.innerHTML = `
      <div class="rollout-step-idx">${idx + 1}</div>
      <div class="rollout-step-text">${step}</div>
    `;
    container.appendChild(card);
  });
}

function renderMonitoring(monitoringList, rollbackConditions) {
  const monContainer = document.getElementById("monitoringList");
  const rbContainer = document.getElementById("rollbackList");

  if (monContainer) {
    monContainer.innerHTML = "";
    (monitoringList || []).forEach(m => {
      const item = document.createElement("div");
      item.className = "mon-item";
      item.innerHTML = `
        <div class="mon-metric">${m.metric}</div>
        <div class="mon-reason">${m.reason}</div>
      `;
      monContainer.appendChild(item);
    });
  }

  if (rbContainer) {
    rbContainer.innerHTML = "";
    (rollbackConditions || []).forEach(r => {
      const item = document.createElement("div");
      item.className = "rollback-item";
      item.innerHTML = `
        <span class="rollback-bullet">🛑</span>
        <div class="rollback-text">${r}</div>
      `;
      rbContainer.appendChild(item);
    });
  }
}

function renderEvidenceJson(data) {
  const pre = document.getElementById("evidenceJsonPre");
  if (pre) {
    pre.textContent = JSON.stringify(data, null, 2);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* =========================================================================
   SRE CONTROL ROOM COMPONENTS (GAUGE, VERDICT, OBSERVABILITY)
   ========================================================================= */

function renderRiskGauge(score, level) {
  const progressCircle = document.getElementById("gaugeProgress");
  const valueText = document.getElementById("gaugeValue");
  const numScore = Math.max(0, Math.min(100, Number(score) || 0));

  // SVG circle r=50 -> Circumference = 2 * pi * 50 ~= 314.159
  const circumference = 314.16;
  const offset = circumference * (1 - numScore / 100);

  if (progressCircle) {
    progressCircle.style.strokeDasharray = `${circumference}`;
    const normLevel = (level || "MEDIUM").toLowerCase();
    if (normLevel === "critical") {
      progressCircle.style.stroke = "#ef4444";
    } else if (normLevel === "high") {
      progressCircle.style.stroke = "#f97316";
    } else if (normLevel === "medium") {
      progressCircle.style.stroke = "#eab308";
    } else {
      progressCircle.style.stroke = "#10b981";
    }

    setTimeout(() => {
      progressCircle.style.strokeDashoffset = `${offset}`;
    }, 50);
  }

  if (valueText) {
    const duration = 600;
    const startTime = performance.now();

    function updateGauge() {
      const now = performance.now();
      const progress = Math.min(Math.max((now - startTime) / duration, 0), 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      valueText.textContent = Math.round(ease * numScore);
      if (progress < 1) {
        requestAnimationFrame(updateGauge);
      } else {
        valueText.textContent = numScore;
      }
    }
    requestAnimationFrame(updateGauge);
  }
}

function renderSreVerdict(data) {
  const card = document.getElementById("sreVerdictCard");
  const icon = document.getElementById("verdictIcon");
  const title = document.getElementById("verdictTitle");
  const desc = document.getElementById("verdictDesc");
  const rolloutTag = document.getElementById("verdictRolloutTag");
  const canaryTag = document.getElementById("verdictCanaryTag");

  const level = (data.deterministic_risk_level || "MEDIUM").toUpperCase();
  const factors = data.significant_factors_count || 0;
  const strategy = data.ai_analysis?.rollout_strategy?.strategy || "Canary";

  if (!card) return;

  card.className = "verdict-card";

  if (level === "CRITICAL") {
    card.classList.add("verdict-critical");
    if (icon) icon.textContent = "🛑";
    if (title) title.textContent = "DEPLOYMENT BLOCKED";
    if (desc) desc.textContent = `${factors} critical hazard signals detected (destructive schema, single replica, or breaking contracts). Hard gate active: requires Senior SRE sign-off and multi-stage migration.`;
    if (rolloutTag) rolloutTag.textContent = "Multi-Stage Expand/Contract";
    if (canaryTag) canaryTag.textContent = "Deployment Gated";
  } else if (level === "HIGH") {
    card.classList.add("verdict-high");
    if (icon) icon.textContent = "⚠️";
    if (title) title.textContent = "MANDATORY CANARY";
    if (desc) desc.textContent = `${factors} high-impact production risk factors identified. Automated direct release rejected. Gated canary rollout with automated rollback triggers required.`;
    if (rolloutTag) rolloutTag.textContent = `Strategy: ${strategy.toUpperCase()}`;
    if (canaryTag) canaryTag.textContent = "Automated Rollback Active";
  } else if (level === "MEDIUM") {
    card.classList.add("verdict-medium");
    if (icon) icon.textContent = "🛡️";
    if (title) title.textContent = "GUARDED ROLLOUT";
    if (desc) desc.textContent = `Moderate production risk detected across ${factors} signal${factors === 1 ? '' : 's'}. Proceed with canary traffic split and real-time metric thresholds.`;
    if (rolloutTag) rolloutTag.textContent = `Strategy: ${strategy.toUpperCase()}`;
    if (canaryTag) canaryTag.textContent = "Metric Gating Active";
  } else {
    card.classList.add("verdict-low");
    if (icon) icon.textContent = "✅";
    if (title) title.textContent = "STANDARD CANARY APPROVED";
    if (desc) desc.textContent = `Low production release risk. No breaking architectural or destructive changes detected. Safe for automated deployment pipeline with standard canary verification.`;
    if (rolloutTag) rolloutTag.textContent = "Standard Progressive Rollout";
    if (canaryTag) canaryTag.textContent = "Health Probes Active";
  }
}

function renderObservabilityPillars(data) {
  const pCode = document.getElementById("pillarCode");
  const pDep = document.getElementById("pillarDep");
  const pInfra = document.getElementById("pillarInfra");
  const pConfig = document.getElementById("pillarConfig");
  const confBadge = document.getElementById("confidenceBadge");
  const confText = document.getElementById("riskConfidenceText");

  const findings = data.findings || [];
  const hasCode = findings.some(f => f.category === "code" || f.category === "traffic");
  const hasDep = findings.some(f => f.category === "dependency");
  const hasInfra = findings.some(f => f.category === "infrastructure" || f.category === "external_service");
  const hasConfig = findings.some(f => f.category === "configuration" || f.category === "database");

  if (pCode) pCode.classList.toggle("active", hasCode);
  if (pDep) pDep.classList.toggle("active", hasDep);
  if (pInfra) pInfra.classList.toggle("active", hasInfra);
  if (pConfig) pConfig.classList.toggle("active", hasConfig);

  const conf = (data.analysis_confidence || "HIGH").toUpperCase();
  if (confBadge) {
    confBadge.className = `confidence-badge ${conf.toLowerCase()}`;
    confBadge.textContent = `CONFIDENCE: ${conf}`;
  }

  if (confText) {
    confText.textContent = data.confidence_reason || "Deterministic AST & manifest coverage verified.";
  }
}

/* =========================================================================
   QUICK ACTION TOOLBAR: PR MARKDOWN, SRE REPORT, EVIDENCE JSON
   ========================================================================= */

function copyPrMarkdown() {
  const d = window.currentAnalysisData;
  if (!d) return;
  const level = d.deterministic_risk_level || "MEDIUM";
  const score = d.deterministic_risk_score || 0;
  const confidence = d.analysis_confidence || "HIGH";
  const factors = d.significant_factors_count || 0;
  const repoName = d.repository?.full_name || "Repository";
  const baseSha = (d.baseline_commit || "0000000").substring(0, 8);
  const candSha = (d.deployment_commit || "0000000").substring(0, 8);
  const scenarios = d.ai_analysis?.failure_scenarios || [];
  const strategy = d.ai_analysis?.rollout_strategy?.strategy || "Guarded Canary";
  const steps = d.ai_analysis?.rollout_strategy?.steps || [];
  const rollbacks = d.ai_analysis?.rollback_conditions || [];

  let verdictEmoji = "🛑";
  let verdictText = "DEPLOYMENT BLOCKED";
  if (level === "CRITICAL") {
    verdictEmoji = "🛑";
    verdictText = "DEPLOYMENT BLOCKED";
  } else if (level === "HIGH") {
    verdictEmoji = "⚠️";
    verdictText = "MANDATORY CANARY GATING";
  } else if (level === "MEDIUM") {
    verdictEmoji = "🛡️";
    verdictText = "GUARDED ROLLOUT";
  } else {
    verdictEmoji = "✅";
    verdictText = "STANDARD CANARY APPROVED";
  }

  let md = `## ${verdictEmoji} SRE Production Deployment Risk Assessment\n\n`;
  md += `**Repository**: \`${repoName}\` (\`${baseSha}\` → \`${candSha}\`)\n`;
  md += `**Release Verdict**: **${verdictText}**\n`;
  md += `**Deterministic Risk Score**: **${score}/100** (${level} RISK) | **Confidence**: **${confidence}**\n`;
  md += `**Signals Detected**: ${factors} significant production-risk factors\n\n`;
  
  md += `### 📋 Executive Summary\n${d.ai_analysis?.summary || "Analysis completed based on deterministic code, infrastructure, and dependency changes."}\n\n`;

  if (scenarios.length > 0) {
    md += `### ⚡ Production Failure Modes\n`;
    scenarios.forEach((sc, i) => {
      md += `${i + 1}. **${sc.title}** (${sc.severity.toUpperCase()} RISK - ${Math.round(sc.confidence * 100)}% conf)\n`;
      md += `   - **Blast Radius**: ${sc.blast_radius || "Application level"}\n`;
      md += `   - **Why Tests Miss It**: ${sc.why_tests_may_miss_it || "N/A"}\n`;
      md += `   - **Mitigation**: ${sc.mitigation || "Follow phased rollout"}\n`;
    });
    md += `\n`;
  }

  md += `### 🚀 Recommended Rollout Strategy (\`${strategy.toUpperCase()}\`)\n`;
  steps.forEach((step, i) => {
    md += `${i + 1}. ${step}\n`;
  });
  md += `\n`;

  if (rollbacks.length > 0) {
    md += `### 🛑 Automated Rollback Triggers\n`;
    rollbacks.forEach(rb => {
      md += `- ${rb}\n`;
    });
    md += `\n`;
  }

  md += `---\n*Generated by SRE Production Deployment Risk Analyzer (BITnBUILD)*\n`;

  navigator.clipboard.writeText(md).then(() => {
    const btn = document.getElementById("copyPrMarkdownBtn");
    if (btn) {
      const origHtml = btn.innerHTML;
      btn.classList.add("copied");
      btn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg><span>Copied PR Review! ✓</span>`;
      setTimeout(() => {
        btn.classList.remove("copied");
        btn.innerHTML = origHtml;
      }, 2000);
    }
  }).catch(err => {
    console.error("Clipboard write failed:", err);
  });
}

function exportMarkdownReport() {
  const d = window.currentAnalysisData;
  if (!d) return;
  const repoName = (d.repository?.name || "deployment").replace(/[^a-zA-Z0-9_-]/g, "_");
  const filename = `sre-risk-report-${repoName}.md`;

  let md = `# SRE Production Deployment Risk Report\n\n`;
  md += `**Generated**: ${new Date().toUTCString()}\n`;
  md += `**Repository**: ${d.repository?.full_name || "Unknown"}\n`;
  md += `**Baseline Commit**: \`${d.baseline_commit || "N/A"}\`\n`;
  md += `**Candidate Commit**: \`${d.deployment_commit || "N/A"}\`\n`;
  md += `**Deterministic Score**: ${d.deterministic_risk_score} / 100 (${d.deterministic_risk_level} RISK)\n`;
  md += `**Confidence**: ${d.analysis_confidence} (${d.confidence_reason || ""})\n\n`;

  md += `## 1. Executive Summary\n\n`;
  md += `${d.ai_analysis?.summary || "No summary available."}\n\n`;

  md += `## 2. Production Failure Cascade Scenarios\n\n`;
  (d.ai_analysis?.failure_scenarios || []).forEach((sc, i) => {
    md += `### Scenario ${i + 1}: ${sc.title} [${sc.severity.toUpperCase()}]\n\n`;
    md += `- **Confidence**: ${(sc.confidence * 100).toFixed(0)}%\n`;
    md += `- **Affected Services**: ${(sc.affected_services || []).join(", ") || "None"}\n`;
    md += `- **Blast Radius**: ${sc.blast_radius || "N/A"}\n\n`;
    md += `#### Cascade Sequence:\n`;
    (sc.failure_chain || []).forEach((step, sIdx) => {
      md += `${sIdx + 1}. ${step}\n`;
    });
    md += `\n**Why Unit/Staging Tests Miss It**:\n${sc.why_tests_may_miss_it || "N/A"}\n\n`;
    md += `**Mitigation**:\n${sc.mitigation || "Follow safe rollout"}\n\n`;
  });

  md += `## 3. Detected Signals & Findings\n\n`;
  (d.findings || []).forEach((f, idx) => {
    md += `### Finding ${idx + 1}: [${f.category.toUpperCase()}] ${f.type} (${f.severity_hint.toUpperCase()})\n`;
    md += `- **Description**: ${f.description}\n`;
    md += `- **Location**: \`${f.file}${f.line ? `:${f.line}` : ""}\`\n`;
    if (f.evidence) {
      md += `\`\`\`\n${f.evidence}\n\`\`\`\n`;
    }
    md += `\n`;
  });

  md += `## 4. Rollout Strategy & Safe Progression\n\n`;
  md += `**Recommended Strategy**: ${d.ai_analysis?.rollout_strategy?.strategy?.toUpperCase() || "CANARY"}\n\n`;
  (d.ai_analysis?.rollout_strategy?.steps || []).forEach((step, idx) => {
    md += `${idx + 1}. ${step}\n`;
  });
  md += `\n`;

  md += `## 5. Rollback Conditions & Telemetry Alerts\n\n`;
  md += `### Rollback Triggers:\n`;
  (d.ai_analysis?.rollback_conditions || []).forEach(rb => {
    md += `- 🛑 ${rb}\n`;
  });
  md += `\n### Key Observability Metrics:\n`;
  (d.ai_analysis?.monitoring || []).forEach(m => {
    md += `- **${m.metric}**: ${m.reason}\n`;
  });

  const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function copyEvidenceJson() {
  const d = window.currentAnalysisData;
  if (!d) return;
  const jsonStr = JSON.stringify(d, null, 2);
  navigator.clipboard.writeText(jsonStr).then(() => {
    const btn = document.getElementById("copyJsonBtn") || document.getElementById("copyEvidenceBtn");
    if (btn) {
      const origHtml = btn.innerHTML;
      btn.classList.add("copied");
      btn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg><span>Copied JSON! ✓</span>`;
      setTimeout(() => {
        btn.classList.remove("copied");
        btn.innerHTML = origHtml;
      }, 2000);
    }
  }).catch(err => {
    console.error("JSON copy failed:", err);
  });
}
