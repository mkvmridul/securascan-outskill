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
  const riskScore = report.riskScore || 0;
  const summary = report.summary || {};
  
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
        <div class="stat-value">${summary.agentsRun || 'N/A'}</div>
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
            ${f.recommendation || f.fix ? `<div class="recommendation"><strong>💡 Recommendation:</strong> ${escapeHtml(f.recommendation || f.fix)}</div>` : ''}
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
</body>
</html>`;

  writeFileSync(outputPath, html);
  return outputPath;
}
