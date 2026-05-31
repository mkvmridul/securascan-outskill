/**
 * HTML Report Generator
 * Generates a styled HTML security report from scan results
 */

import { writeFileSync } from 'fs';

const severityColors = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
  info: '#6b7280'
};

const severityBgColors = {
  critical: '#fef2f2',
  high: '#fff7ed',
  medium: '#fefce8',
  low: '#eff6ff',
  info: '#f9fafb'
};

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getRiskColor(score) {
  if (score >= 80) return '#dc2626';
  if (score >= 60) return '#ea580c';
  if (score >= 40) return '#ca8a04';
  if (score >= 20) return '#2563eb';
  return '#16a34a';
}

function getRiskLabel(score) {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  if (score >= 20) return 'Low';
  return 'Minimal';
}

export async function generateHTML(report, outputPath) {
  const findings = report.findings || [];
  const riskScore = report.riskScore ?? report.risk_score ?? 0;
  const summary = report.summary || report.scan_metadata || {};
  const agentsRun = summary.agentsRun ?? summary.agents_invoked?.length ?? 'N/A';
  const sandboxSummary = report.sandbox_summary || {};
  const replayData = findings.map((finding, index) => ({
    index,
    title: finding.title || finding.issue || finding.type || `Finding #${index + 1}`,
    severity: finding.severity || 'info',
    verification: finding.sandbox_verification || null
  })).filter(item => item.verification);
  const replayJson = JSON.stringify(replayData).replace(/</g, '\\u003c');
  
  // Count by severity
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => {
    const sev = (f.severity || 'info').toLowerCase();
    if (severityCounts[sev] !== undefined) severityCounts[sev]++;
  });
  
  // Count by category
  const categoryCounts = {};
  findings.forEach(f => {
    const cat = f.category || 'Other';
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecuraScan Security Report</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      color: #1f2937;
      background: #f3f4f6;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    
    /* Header */
    .header {
      background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 100%);
      color: white;
      padding: 2rem;
      border-radius: 12px;
      margin-bottom: 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .header h1 { font-size: 1.75rem; font-weight: 700; }
    .header .subtitle { opacity: 0.9; font-size: 0.9rem; margin-top: 0.25rem; }
    .risk-badge {
      background: white;
      padding: 1rem 1.5rem;
      border-radius: 12px;
      text-align: center;
      min-width: 120px;
    }
    .risk-score {
      font-size: 2.5rem;
      font-weight: 800;
      line-height: 1;
    }
    .risk-label { font-size: 0.85rem; font-weight: 600; margin-top: 0.25rem; }
    
    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .stat-card {
      background: white;
      padding: 1.25rem;
      border-radius: 10px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .stat-card h3 { font-size: 0.8rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
    .stat-value { font-size: 1.75rem; font-weight: 700; margin-top: 0.25rem; }
    
    /* Severity Pills */
    .severity-row {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      margin-top: 0.5rem;
    }
    .severity-pill {
      padding: 0.25rem 0.75rem;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 600;
      color: white;
    }
    
    /* Categories */
    .categories {
      background: white;
      padding: 1.5rem;
      border-radius: 10px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      margin-bottom: 1.5rem;
    }
    .categories h2 { font-size: 1rem; margin-bottom: 1rem; color: #374151; }
    .category-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .category-tag {
      background: #e0e7ff;
      color: #3730a3;
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 500;
    }
    
    /* Findings */
    .findings-section { margin-bottom: 2rem; }
    .findings-section h2 {
      font-size: 1.25rem;
      margin-bottom: 1rem;
      color: #111827;
    }
    .finding-card {
      background: white;
      border-radius: 10px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      margin-bottom: 1rem;
      overflow: hidden;
    }
    .finding-header {
      padding: 1rem 1.25rem;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1rem;
      border-left: 4px solid;
    }
    .finding-title { font-weight: 600; font-size: 1rem; }
    .finding-meta {
      display: flex;
      gap: 0.5rem;
      margin-top: 0.5rem;
      flex-wrap: wrap;
    }
    .meta-tag {
      background: #f3f4f6;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      color: #4b5563;
    }
    .finding-severity {
      padding: 0.3rem 0.8rem;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      white-space: nowrap;
    }
    .finding-body { padding: 1rem 1.25rem; border-top: 1px solid #e5e7eb; }
    .finding-body p { margin-bottom: 0.75rem; color: #4b5563; font-size: 0.9rem; }
    .finding-body strong { color: #111827; }
    .code-block {
      background: #1f2937;
      color: #e5e7eb;
      padding: 1rem;
      border-radius: 6px;
      font-family: 'Fira Code', 'Consolas', monospace;
      font-size: 0.8rem;
      overflow-x: auto;
      margin: 0.75rem 0;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .recommendation {
      background: #ecfdf5;
      border-left: 3px solid #10b981;
      padding: 0.75rem 1rem;
      margin-top: 0.75rem;
      border-radius: 0 6px 6px 0;
      font-size: 0.85rem;
      color: #065f46;
    }
    .verification-row {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
      margin-top: 0.75rem;
    }
    .verification-badge {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 0.35rem 0.75rem;
      font-size: 0.75rem;
      font-weight: 800;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .verification-badge.confirmed_exploitable { background: #fee2e2; color: #991b1b; }
    .verification-badge.probably_safe { background: #dcfce7; color: #166534; }
    .verification-badge.could_not_verify { background: #fef3c7; color: #92400e; }
    .replay-button, .panel-button {
      border: 1px solid #111827;
      background: #111827;
      color: white;
      border-radius: 6px;
      padding: 0.45rem 0.75rem;
      font-size: 0.8rem;
      font-weight: 700;
      cursor: pointer;
    }
    .panel-button.secondary {
      background: white;
      color: #111827;
      border-color: #d1d5db;
    }
    .replay-button:hover, .panel-button:hover { filter: brightness(0.95); }
    .replay-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(17, 24, 39, 0.52);
      display: none;
      z-index: 40;
    }
    .replay-backdrop.open { display: block; }
    .replay-panel {
      position: fixed;
      top: 0;
      right: 0;
      width: min(560px, 100vw);
      height: 100vh;
      background: #0b1020;
      color: #e5e7eb;
      box-shadow: -20px 0 40px rgba(0,0,0,0.28);
      transform: translateX(100%);
      transition: transform 160ms ease;
      z-index: 50;
      display: flex;
      flex-direction: column;
    }
    .replay-panel.open { transform: translateX(0); }
    .replay-panel-header {
      padding: 1rem;
      border-bottom: 1px solid rgba(255,255,255,0.12);
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: flex-start;
    }
    .replay-panel-title { font-weight: 800; line-height: 1.3; }
    .replay-panel-subtitle { color: #9ca3af; font-size: 0.85rem; margin-top: 0.25rem; }
    .replay-controls {
      display: flex;
      gap: 0.5rem;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid rgba(255,255,255,0.12);
      flex-wrap: wrap;
    }
    .timeline {
      padding: 1rem;
      overflow: auto;
      font-family: 'Fira Code', 'Consolas', monospace;
      font-size: 0.82rem;
    }
    .timeline-line {
      display: grid;
      grid-template-columns: 76px 1fr;
      gap: 0.75rem;
      padding: 0.65rem 0;
      border-bottom: 1px solid rgba(255,255,255,0.08);
      opacity: 0;
      transform: translateY(4px);
      animation: lineIn 120ms ease forwards;
    }
    .timeline-time { color: #60a5fa; }
    .timeline-label { color: #f9fafb; font-weight: 800; }
    .timeline-detail { color: #cbd5e1; margin-top: 0.15rem; white-space: pre-wrap; word-break: break-word; }
    .timeline-extra {
      margin-top: 0.5rem;
      color: #a7f3d0;
      background: rgba(255,255,255,0.06);
      border-radius: 6px;
      padding: 0.55rem;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 220px;
      overflow: auto;
    }
    @keyframes lineIn {
      to { opacity: 1; transform: translateY(0); }
    }
    
    /* Footer */
    .footer {
      text-align: center;
      padding: 1.5rem;
      color: #6b7280;
      font-size: 0.85rem;
    }
    
    /* Empty state */
    .empty-state {
      text-align: center;
      padding: 3rem;
      background: white;
      border-radius: 10px;
      color: #6b7280;
    }
    .empty-state .icon { font-size: 3rem; margin-bottom: 1rem; }
    
    @media (max-width: 640px) {
      body { padding: 1rem; }
      .header { flex-direction: column; text-align: center; }
      .stats-grid { grid-template-columns: 1fr 1fr; }
      .replay-panel { width: 100vw; }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div class="header">
      <div>
        <h1>🛡️ SecuraScan Report</h1>
        <div class="subtitle">Generated: ${new Date().toLocaleString()}</div>
        ${report.target ? `<div class="subtitle">Target: ${escapeHtml(report.target)}</div>` : ''}
      </div>
      <div class="risk-badge">
        <div class="risk-score" style="color: ${getRiskColor(riskScore)}">${riskScore}</div>
        <div class="risk-label" style="color: ${getRiskColor(riskScore)}">${getRiskLabel(riskScore)} Risk</div>
      </div>
    </div>
    
    <!-- Stats Grid -->
    <div class="stats-grid">
      <div class="stat-card">
        <h3>Total Findings</h3>
        <div class="stat-value">${findings.length}</div>
      </div>
      <div class="stat-card">
        <h3>Files Scanned</h3>
        <div class="stat-value">${summary.filesScanned || 'N/A'}</div>
      </div>
      <div class="stat-card">
        <h3>Agents Run</h3>
        <div class="stat-value">${agentsRun}</div>
      </div>
      <div class="stat-card">
        <h3>Severity Breakdown</h3>
        <div class="severity-row">
          ${severityCounts.critical > 0 ? `<span class="severity-pill" style="background:${severityColors.critical}">${severityCounts.critical} Crit</span>` : ''}
          ${severityCounts.high > 0 ? `<span class="severity-pill" style="background:${severityColors.high}">${severityCounts.high} High</span>` : ''}
          ${severityCounts.medium > 0 ? `<span class="severity-pill" style="background:${severityColors.medium}">${severityCounts.medium} Med</span>` : ''}
          ${severityCounts.low > 0 ? `<span class="severity-pill" style="background:${severityColors.low}">${severityCounts.low} Low</span>` : ''}
          ${severityCounts.info > 0 ? `<span class="severity-pill" style="background:${severityColors.info}">${severityCounts.info} Info</span>` : ''}
          ${findings.length === 0 ? '<span style="color:#6b7280;font-size:0.85rem">No issues found</span>' : ''}
        </div>
      </div>
      <div class="stat-card">
        <h3>Sandbox Replay</h3>
        <div class="stat-value">${sandboxSummary.status ? escapeHtml(sandboxSummary.status).replace(/_/g, ' ') : 'Off'}</div>
        <div class="severity-row">
          ${sandboxSummary.confirmed_exploitable ? `<span class="severity-pill" style="background:#dc2626">${sandboxSummary.confirmed_exploitable} confirmed</span>` : ''}
          ${sandboxSummary.probably_safe ? `<span class="severity-pill" style="background:#16a34a">${sandboxSummary.probably_safe} safe</span>` : ''}
          ${sandboxSummary.could_not_verify ? `<span class="severity-pill" style="background:#ca8a04">${sandboxSummary.could_not_verify} unverified</span>` : ''}
          ${!sandboxSummary.status ? '<span style="color:#6b7280;font-size:0.85rem">Run with --sandbox</span>' : ''}
        </div>
      </div>
    </div>
    
    <!-- Categories -->
    ${Object.keys(categoryCounts).length > 0 ? `
    <div class="categories">
      <h2>📊 Vulnerability Categories</h2>
      <div class="category-grid">
        ${Object.entries(categoryCounts).map(([cat, count]) => 
          `<span class="category-tag">${escapeHtml(cat)} (${count})</span>`
        ).join('')}
      </div>
    </div>
    ` : ''}
    
    <!-- Findings -->
    <div class="findings-section">
      <h2>🔍 Findings (${findings.length})</h2>
      
      ${findings.length === 0 ? `
      <div class="empty-state">
        <div class="icon">✅</div>
        <h3>No vulnerabilities detected</h3>
        <p>The scan completed successfully with no security issues found.</p>
      </div>
      ` : ''}
      
      ${findings.map((f, idx) => {
        const sev = (f.severity || 'info').toLowerCase();
        const verification = f.sandbox_verification;
        return `
        <div class="finding-card">
          <div class="finding-header" style="border-color: ${severityColors[sev] || severityColors.info}; background: ${severityBgColors[sev] || severityBgColors.info}">
            <div>
              <div class="finding-title">${escapeHtml(f.title || f.issue || `Finding #${idx + 1}`)}</div>
              <div class="finding-meta">
                ${f.category ? `<span class="meta-tag">📁 ${escapeHtml(f.category)}</span>` : ''}
                ${f.file ? `<span class="meta-tag">📄 ${escapeHtml(f.file)}${f.line ? `:${f.line}` : ''}</span>` : ''}
                ${f.agent ? `<span class="meta-tag">🤖 ${escapeHtml(f.agent)}</span>` : ''}
              </div>
            </div>
            <span class="finding-severity" style="background: ${severityColors[sev] || severityColors.info}; color: white">${sev}</span>
          </div>
          <div class="finding-body">
            ${f.description ? `<p>${escapeHtml(f.description)}</p>` : ''}
            ${f.evidence || f.code ? `<div class="code-block">${escapeHtml(f.evidence || f.code)}</div>` : ''}
            ${verification ? `
            <div class="verification-row">
              <span class="verification-badge ${escapeHtml(verification.status)}">${escapeHtml(verification.badge || verification.status)}</span>
              <button class="replay-button" data-replay-index="${idx}" type="button">Replay attack</button>
            </div>
            <p>${escapeHtml(verification.reason || '')}</p>
            ` : ''}
            ${f.recommendation || f.fix || f.remediation ? `<div class="recommendation"><strong>💡 Recommendation:</strong> ${escapeHtml(f.recommendation || f.fix || f.remediation)}</div>` : ''}
          </div>
        </div>
        `;
      }).join('')}
    </div>
    
    <!-- Footer -->
    <div class="footer">
      <p>Generated by SecuraScan • AI-Powered Security Scanner</p>
    </div>
  </div>
  <div class="replay-backdrop" id="replayBackdrop"></div>
  <aside class="replay-panel" id="replayPanel" aria-hidden="true">
    <div class="replay-panel-header">
      <div>
        <div class="replay-panel-title" id="replayTitle">Sandbox Replay</div>
        <div class="replay-panel-subtitle" id="replaySubtitle"></div>
      </div>
      <button class="panel-button secondary" id="replayClose" type="button">Close</button>
    </div>
    <div class="replay-controls">
      <button class="panel-button" id="replayPlay" type="button">Play</button>
      <button class="panel-button secondary" id="replaySlow" type="button">0.5x</button>
      <button class="panel-button secondary" id="replayInstant" type="button">Show all</button>
    </div>
    <div class="timeline" id="replayTimeline"></div>
  </aside>
  <script id="sandboxReplayData" type="application/json">${replayJson}</script>
  <script>
    const replayData = JSON.parse(document.getElementById('sandboxReplayData').textContent || '[]');
    const replayByIndex = new Map(replayData.map(item => [String(item.index), item]));
    const panel = document.getElementById('replayPanel');
    const backdrop = document.getElementById('replayBackdrop');
    const title = document.getElementById('replayTitle');
    const subtitle = document.getElementById('replaySubtitle');
    const timelineEl = document.getElementById('replayTimeline');
    let activeReplay = null;
    let timers = [];
    let speed = 1;

    function clearTimers() {
      timers.forEach(timer => clearTimeout(timer));
      timers = [];
    }

    function closeReplay() {
      clearTimers();
      panel.classList.remove('open');
      backdrop.classList.remove('open');
      panel.setAttribute('aria-hidden', 'true');
    }

    function lineText(entry) {
      return [entry.result, entry.attack, entry.request, entry.response]
        .filter(Boolean)
        .map(value => String(value))
        .join('\\n');
    }

    function appendLine(entry) {
      const row = document.createElement('div');
      row.className = 'timeline-line';

      const time = document.createElement('div');
      time.className = 'timeline-time';
      time.textContent = entry.timestamp || '00:00:00';

      const content = document.createElement('div');
      const label = document.createElement('div');
      label.className = 'timeline-label';
      label.textContent = entry.label || 'Event';
      const detail = document.createElement('div');
      detail.className = 'timeline-detail';
      detail.textContent = entry.detail || '';
      content.appendChild(label);
      content.appendChild(detail);

      const extraText = lineText(entry);
      if (extraText) {
        const extra = document.createElement('div');
        extra.className = 'timeline-extra';
        extra.textContent = extraText;
        content.appendChild(extra);
      }

      row.appendChild(time);
      row.appendChild(content);
      timelineEl.appendChild(row);
      timelineEl.scrollTop = timelineEl.scrollHeight;
    }

    function renderReplay(instant = false) {
      if (!activeReplay) return;
      clearTimers();
      timelineEl.innerHTML = '';
      const entries = activeReplay.verification.timeline || [];
      entries.forEach((entry, index) => {
        const delay = instant ? 0 : Math.min(1800, Math.max(120, (entry.offset_ms || index * 350) / speed));
        timers.push(setTimeout(() => appendLine(entry), delay));
      });
    }

    function openReplay(index) {
      activeReplay = replayByIndex.get(String(index));
      if (!activeReplay) return;
      speed = 1;
      title.textContent = activeReplay.title;
      const verification = activeReplay.verification || {};
      subtitle.textContent = (verification.badge || verification.status || 'Sandbox replay') + ' - ' + (verification.reason || '');
      panel.classList.add('open');
      backdrop.classList.add('open');
      panel.setAttribute('aria-hidden', 'false');
      renderReplay(false);
    }

    document.querySelectorAll('[data-replay-index]').forEach(button => {
      button.addEventListener('click', () => openReplay(button.getAttribute('data-replay-index')));
    });
    document.getElementById('replayClose').addEventListener('click', closeReplay);
    backdrop.addEventListener('click', closeReplay);
    document.getElementById('replayPlay').addEventListener('click', () => {
      speed = 1;
      renderReplay(false);
    });
    document.getElementById('replaySlow').addEventListener('click', () => {
      speed = 0.5;
      renderReplay(false);
    });
    document.getElementById('replayInstant').addEventListener('click', () => renderReplay(true));
  </script>
</body>
</html>`;

  writeFileSync(outputPath, html);
  return outputPath;
}
