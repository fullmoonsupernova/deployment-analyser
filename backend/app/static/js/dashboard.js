// SRE Production Deployment Risk Analyzer - Dashboard & Visualization Controller

let activeScenarioIndex = 0;
let cachedTopologyNodes = [];
let cachedTopologyEdges = [];

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

  // 1. Repo Metadata
  const repo = data.repository || {};
  const repoTitle = document.getElementById("dashRepoTitle");
  if (repoTitle) {
    repoTitle.textContent = repo.full_name || `${repo.owner}/${repo.name}`;
  }
  const repoDesc = document.getElementById("dashRepoDesc");
  if (repoDesc) {
    repoDesc.textContent = repo.description || "Production Repository Revision Analysis";
  }

  // 2. Commit SHAs
  const baseSha = document.getElementById("dashBaselineSha");
  if (baseSha) {
    baseSha.textContent = (data.baseline_commit || "0000000").substring(0, 8);
    baseSha.title = data.baseline_commit;
  }
  const candSha = document.getElementById("dashCandidateSha");
  if (candSha) {
    candSha.textContent = (data.deployment_commit || "0000000").substring(0, 8);
    candSha.title = data.deployment_commit;
  }

  // 3. Risk Banner & Confidence
  const riskBadge = document.getElementById("riskLevelBadge");
  const riskHeadline = document.getElementById("riskHeadline");
  const riskConfText = document.getElementById("riskConfidenceText");
  const riskScorePill = document.getElementById("riskScorePill");
  const cacheBadge = document.getElementById("cacheBadge");

  const level = (data.deterministic_risk_level || "MEDIUM").toLowerCase();
  if (riskBadge) {
    riskBadge.className = `risk-badge ${level}`;
    riskBadge.textContent = `${data.deterministic_risk_level} RISK`;
  }
  if (riskScorePill) {
    riskScorePill.textContent = `Deterministic Score: ${data.deterministic_risk_score} / 100`;
  }
  if (riskHeadline) {
    const factors = data.significant_factors_count || 0;
    riskHeadline.textContent = `${factors} significant production-risk factor${factors === 1 ? '' : 's'} detected`;
  }
  if (riskConfText) {
    riskConfText.textContent = `Analysis confidence: ${data.analysis_confidence} — ${data.confidence_reason}`;
  }
  if (cacheBadge) {
    if (data.cached) {
      cacheBadge.classList.remove("hidden");
    } else {
      cacheBadge.classList.add("hidden");
    }
  }

  // 4. Executive Summary
  const execSummary = document.getElementById("executiveSummaryText");
  if (execSummary) {
    execSummary.textContent = data.ai_analysis?.summary || "Comprehensive analysis generated based on deterministic signals.";
  }

  // 5. Update Tab Counts
  const scenarios = data.ai_analysis?.failure_scenarios || [];
  const findings = data.findings || [];
  const services = data.services || [];
  const incidents = data.historical_matches || [];

  document.getElementById("countScenarios").textContent = scenarios.length;
  document.getElementById("countServices").textContent = services.length;
  document.getElementById("countFindings").textContent = findings.length;
  document.getElementById("countIncidents").textContent = incidents.length;

  // Cache topology data
  cachedTopologyNodes = services;
  cachedTopologyEdges = data.relationships || [];

  // 6. Render Subcomponents
  renderScenarios(scenarios, findings);
  renderTopologyGraph(cachedTopologyNodes, cachedTopologyEdges);
  renderFindings(findings);
  renderIncidents(incidents);
  renderRolloutStrategy(data.ai_analysis?.rollout_strategy);
  renderMonitoring(data.ai_analysis?.monitoring, data.ai_analysis?.rollback_conditions);
  renderEvidenceJson(data);

  // Automatically select first scenario
  if (scenarios.length > 0) {
    selectScenario(0, scenarios);
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
      } else {
        box.removeAttribute("filter");
        box.setAttribute("stroke-width", "1.5");
        box.setAttribute("fill", "#111827");
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
      const category = btn.getAttribute("data-filter");
      filterFindingsByCategory(category);
    });
  });
}

function renderFindings(findings) {
  allFindingsData = findings;
  filterFindingsByCategory("all");
}

function filterFindingsByCategory(category) {
  const container = document.getElementById("findingsGrid");
  const countLabel = document.getElementById("filteredCountLabel");
  if (!container) return;

  const filtered = category === "all" 
    ? allFindingsData 
    : allFindingsData.filter(f => f.category.toLowerCase() === category.toLowerCase());

  if (countLabel) {
    countLabel.textContent = `Showing ${filtered.length} of ${allFindingsData.length} findings`;
  }

  container.innerHTML = "";

  if (filtered.length === 0) {
    container.innerHTML = `<div class="chain-viewer-placeholder">No findings in this category.</div>`;
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
