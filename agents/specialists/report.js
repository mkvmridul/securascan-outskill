/**
 * Report generator - builds reports locally without LLM calls
 */

const OWASP_MAP = {
  'SQL_INJECTION': 'A03_Injection',
  'SQLI': 'A03_Injection',
  'XSS': 'A03_Injection',
  'INJECTION': 'A03_Injection',
  'IDOR': 'A01_Broken_Access_Control',
  'AUTH': 'A07_Auth_Failures',
  'SECRETS': 'A02_Cryptographic_Failures',
  'SECRET': 'A02_Cryptographic_Failures',
  'CRYPTO': 'A02_Cryptographic_Failures',
  'MISCONFIG': 'A05_Security_Misconfiguration',
  'LOGGING': 'A09_Logging_Failures',
  'PII_LEAK': 'A09_Logging_Failures',
  'EXCEPTION': 'A05_Security_Misconfiguration'
};

const SEVERITY_SCORE = { critical: 25, high: 10, medium: 4, low: 1 };

function mapToOwasp(type) {
  const upper = (type || '').toUpperCase();
  for (const [key, value] of Object.entries(OWASP_MAP)) {
    if (upper.includes(key)) return value;
  }
  return 'A05_Security_Misconfiguration';
}

function generateSummary(findings, triage) {
  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  
  if (findings.length === 0) {
    return 'No security vulnerabilities were detected in this codebase. The application appears to follow security best practices.';
  }
  
  const worstType = findings[0]?.type || 'security issue';
  const riskLevel = critical > 0 ? 'critical' : high > 0 ? 'high' : 'moderate';
  
  return `This ${triage?.app_type || 'application'} has ${findings.length} security findings with ${riskLevel} risk level. ` +
    `The most severe issue is ${worstType} which requires immediate attention. ` +
    `${critical + high} high-priority issues should be fixed before deployment.`;
}

function getTopActions(findings) {
  const sorted = [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] || 3) - (order[b.severity] || 3);
  });
  
  return sorted.slice(0, 3).map((f, i) => ({
    priority: i + 1,
    file: f.file || 'unknown',
    line: f.line || '?',
    action: f.description || f.type,
    code_fix: f.remediation || 'Review and fix this issue'
  }));
}

/**
 * Build report locally from agent findings - NO LLM CALL
 * @param {Object} orchestratorResult - Orchestrator triage result
 * @param {Object} agentFindings - Agent findings by agent name
 * @param {Object} _llmConfig - Unused, kept for compatibility
 */
export async function run(orchestratorResult, agentFindings, _llmConfig) {
  console.log('\x1b[33m[REPORT]\x1b[0m Building report locally...');
  const start = Date.now();
  
  // Flatten all findings
  const allFindings = Object.entries(agentFindings).flatMap(([agent, findings]) =>
    (findings || []).map((f, i) => ({
      id: `${agent}-${i}`,
      agent,
      severity: f.severity || 'medium',
      type: f.type || agent.replace('_AGENT', ''),
      category: f.category || f.subtype || mapToOwasp(f.type || agent),
      file: f.file || 'unknown',
      line: f.line || '?',
      description: f.description || 'Security issue detected',
      evidence: f.evidence || f.code || '',
      remediation: f.remediation || 'Review and fix',
      owasp_category: mapToOwasp(f.type || agent)
    }))
  );
  
  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allFindings.sort((a, b) => (severityOrder[a.severity] || 3) - (severityOrder[b.severity] || 3));
  
  // Count by severity
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  allFindings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  
  // Calculate risk score
  let riskScore = 0;
  allFindings.forEach(f => { riskScore += SEVERITY_SCORE[f.severity] || 1; });
  riskScore = Math.min(100, riskScore);
  
  // Build OWASP coverage
  const owaspCoverage = {};
  allFindings.forEach(f => {
    owaspCoverage[f.owasp_category] = (owaspCoverage[f.owasp_category] || 0) + 1;
  });
  
  const triage = orchestratorResult?.triage || {};
  
  const report = {
    risk_score: riskScore,
    executive_summary: generateSummary(allFindings, triage),
    triage: {
      languages: triage.languages || [],
      frameworks: triage.frameworks || [],
      app_type: triage.app_type || 'unknown',
      overall_risk_level: riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low'
    },
    owasp_coverage: owaspCoverage,
    top_priority_actions: getTopActions(allFindings),
    findings: allFindings,
    scan_metadata: {
      total_findings: allFindings.length,
      ...counts,
      agents_invoked: Object.keys(agentFindings)
    }
  };
  
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`\x1b[33m[REPORT]\x1b[0m Done in ${elapsed}s — Risk: ${riskScore}/100, ${allFindings.length} findings`);
  
  return report;
}
