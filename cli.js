#!/usr/bin/env node

import { readFileSync, existsSync, writeFileSync } from 'fs';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Ingestion modules
import { fetchGithubRepo } from './ingestion/githubFetcher.js';
import { parseZip } from './ingestion/zipParser.js';
import { scanLocalDirectory } from './ingestion/localScanner.js';

// Agent modules
import { runOrchestrator } from './agents/orchestrator.js';
import * as secretsAgent from './agents/specialists/secrets.js';
import * as sqliAgent from './agents/specialists/sqli.js';
import * as xssAgent from './agents/specialists/xss.js';
import * as authAgent from './agents/specialists/auth.js';
import * as injectionAgent from './agents/specialists/injection.js';
import * as idorAgent from './agents/specialists/idor.js';
import * as misconfigAgent from './agents/specialists/misconfig.js';
import * as cryptoAgent from './agents/specialists/crypto.js';
import * as loggingAgent from './agents/specialists/logging.js';
import * as piiLoggingAgent from './agents/specialists/piiLogging.js';
import * as exceptionAgent from './agents/specialists/exception.js';
import * as reportAgent from './agents/specialists/report.js';

// HTML generator
import { generateHTML } from './utils/htmlGenerator.js';

// Load .env file if present
const envPath = join(dirname(fileURLToPath(import.meta.url)), '.env');
if (existsSync(envPath)) {
  const envContent = readFileSync(envPath, 'utf8');
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
    if (!process.env[key]) process.env[key] = val;
  }
}

// Config file path
const CONFIG_PATH = join(__dirname, '.securascan.json');

// Map agent names to modules (support both short and full names)
const AGENT_MAP = {
  'SECRETS_AGENT': secretsAgent,
  'SECRETS': secretsAgent,
  'SQLI_AGENT': sqliAgent,
  'SQLI': sqliAgent,
  'XSS_AGENT': xssAgent,
  'XSS': xssAgent,
  'AUTH_AGENT': authAgent,
  'AUTH': authAgent,
  'INJECTION_AGENT': injectionAgent,
  'INJECTION': injectionAgent,
  'IDOR_AGENT': idorAgent,
  'IDOR': idorAgent,
  'MISCONFIG_AGENT': misconfigAgent,
  'MISCONFIG': misconfigAgent,
  'CRYPTO_AGENT': cryptoAgent,
  'CRYPTO': cryptoAgent,
  'LOGGING_AGENT': loggingAgent,
  'LOGGING': loggingAgent,
  'PII_LOGGING_AGENT': piiLoggingAgent,
  'PII_LOGGING': piiLoggingAgent,
  'PII_LOG': piiLoggingAgent,
  'EXCEPTION_AGENT': exceptionAgent,
  'EXCEPTION': exceptionAgent
};

// ANSI colors
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

function log(msg, color = '') {
  console.log(`${color}${msg}${colors.reset}`);
}

function logStep(step, status) {
  const icons = { start: '⏳', done: '✅', skip: '⏭️', error: '❌' };
  log(`${icons[status] || '•'} ${step}`);
}

function loadConfig() {
  if (existsSync(CONFIG_PATH)) {
    try {
      return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
    } catch {
      return {};
    }
  }
  return {};
}

function saveConfig(config) {
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

function printHelp() {
  console.log(`
${colors.bright}${colors.cyan}🔒 SecuraScan - AI Security Scanner${colors.reset}

${colors.bright}USAGE:${colors.reset}
  securascan <command> [options]

${colors.bright}COMMANDS:${colors.reset}
  ${colors.green}config${colors.reset}                     Configure API key and model
  ${colors.green}scan <path>${colors.reset}                Scan a local directory
  ${colors.green}scan-github <url>${colors.reset}          Scan a GitHub repository
  ${colors.green}scan-zip <file>${colors.reset}            Scan a ZIP archive
  ${colors.green}status${colors.reset}                     Show current configuration
  ${colors.green}help${colors.reset}                       Show this help message

${colors.bright}EXAMPLES:${colors.reset}
  ${colors.gray}# Configure your API key${colors.reset}
  node cli.js config --provider anthropic --model claude-opus-4-5 --key sk-ant-xxx

  ${colors.gray}# Basic scan (fast, lightweight)${colors.reset}
  node cli.js scan .

  ${colors.gray}# Advanced scan (deeper analysis, more tokens)${colors.reset}
  node cli.js scan . --mode advanced

  ${colors.gray}# Scan a GitHub repo${colors.reset}
  node cli.js scan-github https://github.com/owner/repo

  ${colors.gray}# Output report to JSON + PDF${colors.reset}
  node cli.js scan . --output report.json

${colors.bright}CONFIG OPTIONS:${colors.reset}
  --provider <provider>    ${colors.gray}anthropic, openai, or gemini${colors.reset}
  --model <model>          ${colors.gray}e.g., claude-opus-4-5, gpt-4o, gemini-2.0-flash${colors.reset}
  --key <api-key>          ${colors.gray}Your API key (stored locally)${colors.reset}

${colors.bright}SCAN OPTIONS:${colors.reset}
  --mode <mode>            ${colors.gray}basic (fast) or advanced (deep) - default: basic${colors.reset}
  --output, -o <file>      ${colors.gray}Save report to JSON + PDF${colors.reset}
  --pdf <file>             ${colors.gray}Save PDF report only${colors.reset}
  --json                   ${colors.gray}Output raw JSON (no formatting)${colors.reset}
  --verbose, -v            ${colors.gray}Show detailed progress${colors.reset}
`);
}

function printStatus() {
  const config = loadConfig();
  
  console.log(`\n${colors.bright}${colors.cyan}🔒 SecuraScan Configuration${colors.reset}\n`);
  
  const provider = config.provider || process.env.SECURASCAN_PROVIDER;
  const model = config.model || process.env.SECURASCAN_MODEL;
  const envKeyMap = { anthropic: 'ANTHROPIC_API_KEY', openai: 'OPENAI_API_KEY', gemini: 'GEMINI_API_KEY' };
  const apiKey = config.apiKey || process.env[envKeyMap[provider] || ''] || process.env.SECURASCAN_API_KEY;
  const keySource = config.apiKey ? 'config' : process.env[envKeyMap[provider] || ''] ? `.env (${envKeyMap[provider]})` : process.env.SECURASCAN_API_KEY ? '.env (SECURASCAN_API_KEY)' : null;

  if (!provider && !model && !apiKey) {
    log('No configuration found. Run: securascan config --provider <provider> --model <model> --key <key>', colors.yellow);
    return;
  }
  
  console.log(`  Provider: ${provider ? colors.green + provider : colors.gray + 'not set'}${colors.reset}`);
  console.log(`  Model:    ${model ? colors.green + model : colors.gray + 'not set'}${colors.reset}`);
  console.log(`  API Key:  ${apiKey ? colors.green + apiKey.slice(0, 8) + '****' + colors.reset + colors.gray + ` (from ${keySource})` : colors.gray + 'not set'}${colors.reset}`);
  console.log(`\n  Config file: ${colors.gray}${CONFIG_PATH}${colors.reset}\n`);
}

function parseArgs(args) {
  const parsed = { _: [] };
  let i = 0;
  
  while (i < args.length) {
    const arg = args[i];
    
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = args[i + 1];
      
      if (next && !next.startsWith('-')) {
        parsed[key] = next;
        i += 2;
      } else {
        parsed[key] = true;
        i++;
      }
    } else if (arg.startsWith('-')) {
      const key = arg.slice(1);
      const next = args[i + 1];
      
      if (next && !next.startsWith('-')) {
        parsed[key] = next;
        i += 2;
      } else {
        parsed[key] = true;
        i++;
      }
    } else {
      parsed._.push(arg);
      i++;
    }
  }
  
  return parsed;
}

async function runScan(codebaseText, llmConfig, options = {}) {
  const verbose = options.verbose || options.v;
  const mode = options.mode || 'basic';
  const startTime = Date.now();
  
  console.log(`\x1b[90m   Scan mode: ${mode}\x1b[0m`);
  
  try {
    // Step 1: Orchestrator
    if (verbose) logStep('Running orchestrator...', 'start');
    
    const orchestratorResult = await runOrchestrator(codebaseText, llmConfig, mode);
    
    if (verbose) {
      logStep(`Triage complete: ${orchestratorResult.triage?.app_type || 'unknown'} (${orchestratorResult.triage?.overall_risk_level || 'unknown'} risk)`, 'done');
      log(`   Languages: ${orchestratorResult.triage?.languages?.join(', ') || 'none detected'}`, colors.gray);
      log(`   Frameworks: ${orchestratorResult.triage?.frameworks?.join(', ') || 'none detected'}`, colors.gray);
    }
    
    // Step 2: Run specialist agents
    const agentsToInvoke = orchestratorResult.agents_to_invoke || [];
    const agentFindings = {};
    
    if (agentsToInvoke.length > 0) {
      if (verbose) {
        logStep(`Running ${agentsToInvoke.length} specialist agents...`, 'start');
      }
      
      // Always run agents sequentially — concurrency controller ensures 1 LLM call at a time
      for (const agentInfo of agentsToInvoke) {
        const agentName = agentInfo.agent;
        const agentModule = AGENT_MAP[agentName];
        
        if (!agentModule) {
          if (verbose) log(`   ⏭️ ${agentName}: unknown agent, skipping`, colors.yellow);
          agentFindings[agentName] = [];
          continue;
        }
        
        try {
          if (verbose) log(`   ⏳ ${agentName}...`, colors.gray);
          
          const findings = await agentModule.run(codebaseText, llmConfig, mode);
          
          if (verbose) log(`   ✓ ${agentName}: ${findings.length} findings`, colors.gray);
          
          agentFindings[agentName] = findings;
        } catch (error) {
          if (verbose) log(`   ✗ ${agentName}: ${error.message}`, colors.red);
          agentFindings[agentName] = [];
        }
      }
      
      if (verbose) logStep('All agents completed', 'done');
    } else {
      if (verbose) logStep('No specialist agents needed', 'skip');
    }
    
    // Step 3: Generate report
    if (verbose) logStep('Generating report...', 'start');
    
    const finalReport = await reportAgent.run(orchestratorResult, agentFindings, llmConfig);
    
    const endTime = Date.now();
    finalReport.scan_metadata = finalReport.scan_metadata || {};
    finalReport.scan_metadata.scan_duration_ms = endTime - startTime;
    finalReport.scan_metadata.agents_invoked = agentsToInvoke.map(a => a.agent);
    
    if (verbose) logStep('Report generated', 'done');
    
    return finalReport;
    
  } catch (error) {
    log(`\n❌ Scan failed: ${error.message}`, colors.red);
    process.exit(1);
  }
}

function printReport(report) {
  console.log(`\n${colors.bright}${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.bright}${colors.cyan}                    SECURASCAN REPORT${colors.reset}`);
  console.log(`${colors.bright}${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}\n`);
  
  // Risk Score
  const riskColor = report.risk_score >= 75 ? colors.red : 
                    report.risk_score >= 50 ? colors.yellow : 
                    report.risk_score >= 25 ? colors.blue : colors.green;
  
  console.log(`${colors.bright}Risk Score:${colors.reset} ${riskColor}${report.risk_score}/100${colors.reset}`);
  console.log();
  
  // Executive Summary
  console.log(`${colors.bright}Executive Summary:${colors.reset}`);
  console.log(`${colors.gray}${report.executive_summary}${colors.reset}`);
  console.log();
  
  // Findings Summary
  const meta = report.scan_metadata || {};
  console.log(`${colors.bright}Findings:${colors.reset}`);
  console.log(`  ${colors.red}Critical: ${meta.critical || 0}${colors.reset}`);
  console.log(`  ${colors.yellow}High: ${meta.high || 0}${colors.reset}`);
  console.log(`  ${colors.blue}Medium: ${meta.medium || 0}${colors.reset}`);
  console.log(`  ${colors.gray}Low: ${meta.low || 0}${colors.reset}`);
  console.log();
  
  // Top Priority Actions
  if (report.top_priority_actions?.length > 0) {
    console.log(`${colors.bright}Top Priority Actions:${colors.reset}`);
    for (const action of report.top_priority_actions) {
      console.log(`  ${colors.red}${action.priority}.${colors.reset} ${action.file}:${action.line}`);
      console.log(`     ${action.action}`);
      if (action.code_fix) {
        console.log(`     ${colors.green}Fix: ${action.code_fix}${colors.reset}`);
      }
    }
    console.log();
  }
  
  // Detailed Findings
  if (report.findings?.length > 0) {
    console.log(`${colors.bright}Detailed Findings:${colors.reset}`);
    console.log(`${colors.gray}───────────────────────────────────────────────────────────────${colors.reset}`);
    
    for (const finding of report.findings) {
      const sevColor = finding.severity === 'critical' ? colors.red :
                       finding.severity === 'high' ? colors.yellow :
                       finding.severity === 'medium' ? colors.blue : colors.gray;
      
      console.log(`\n  ${sevColor}[${finding.severity.toUpperCase()}]${colors.reset} ${finding.type}`);
      console.log(`  ${colors.gray}File: ${finding.file}:${finding.line}${colors.reset}`);
      console.log(`  ${finding.description}`);
      if (finding.remediation) {
        console.log(`  ${colors.green}→ ${finding.remediation}${colors.reset}`);
      }
    }
    console.log();
  }
  
  // Scan Metadata
  console.log(`${colors.gray}───────────────────────────────────────────────────────────────${colors.reset}`);
  console.log(`${colors.gray}Scan completed in ${(meta.scan_duration_ms / 1000).toFixed(1)}s | Agents: ${meta.agents_invoked?.join(', ') || 'none'}${colors.reset}`);
  console.log();
}

async function main() {
  const args = process.argv.slice(2);
  const parsed = parseArgs(args);
  const command = parsed._[0];
  
  if (!command || command === 'help') {
    printHelp();
    return;
  }
  
  if (command === 'status') {
    printStatus();
    return;
  }
  
  if (command === 'config') {
    const config = loadConfig();
    
    if (parsed.provider) config.provider = parsed.provider;
    if (parsed.model) config.model = parsed.model;
    if (parsed.key) config.apiKey = parsed.key;
    
    if (!parsed.provider && !parsed.model && !parsed.key) {
      log('\nUsage: securascan config --provider <provider> --model <model> --key <api-key>', colors.yellow);
      log('\nExample:', colors.gray);
      log('  securascan config --provider anthropic --model claude-opus-4-5 --key sk-ant-xxx', colors.gray);
      return;
    }
    
    saveConfig(config);
    log('\n✅ Configuration saved!', colors.green);
    printStatus();
    return;
  }
  
  // Load config for scan commands
  const config = loadConfig();
  
  // Pick API key from env vars if not in config
  const envKeyMap = {
    anthropic: 'ANTHROPIC_API_KEY',
    openai: 'OPENAI_API_KEY',
    gemini: 'GEMINI_API_KEY'
  };
  
  const provider = config.provider || process.env.SECURASCAN_PROVIDER;
  const model = config.model || process.env.SECURASCAN_MODEL;
  const apiKey = config.apiKey 
    || process.env[envKeyMap[provider] || ''] 
    || process.env.SECURASCAN_API_KEY;

  if (!apiKey || !provider || !model) {
    log('\n❌ Configuration incomplete.', colors.red);
    log('Either run: node cli.js config --provider <provider> --model <model> --key <key>', colors.yellow);
    log('Or set env vars: ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY', colors.yellow);
    process.exit(1);
  }
  
  const llmConfig = { apiKey, provider, model };
  
  let codebaseText;
  
  if (command === 'scan') {
    const targetPath = parsed._[1] || '.';
    const absolutePath = resolve(targetPath);
    
    if (!existsSync(absolutePath)) {
      log(`\n❌ Path not found: ${absolutePath}`, colors.red);
      process.exit(1);
    }
    
    log(`\n${colors.bright}🔒 Scanning: ${absolutePath}${colors.reset}\n`);
    
    logStep('Scanning local directory...', 'start');
    codebaseText = await scanLocalDirectory(absolutePath);
    logStep('Directory scanned', 'done');
    
  } else if (command === 'scan-github') {
    const repoUrl = parsed._[1];
    
    if (!repoUrl) {
      log('\n❌ GitHub URL required. Usage: securascan scan-github <url>', colors.red);
      process.exit(1);
    }
    
    log(`\n${colors.bright}🔒 Scanning: ${repoUrl}${colors.reset}\n`);
    
    logStep('Fetching GitHub repository...', 'start');
    codebaseText = await fetchGithubRepo(repoUrl);
    logStep('Repository fetched', 'done');
    
  } else if (command === 'scan-zip') {
    const zipPath = parsed._[1];
    
    if (!zipPath) {
      log('\n❌ ZIP file path required. Usage: securascan scan-zip <file>', colors.red);
      process.exit(1);
    }
    
    const absolutePath = resolve(zipPath);
    
    if (!existsSync(absolutePath)) {
      log(`\n❌ File not found: ${absolutePath}`, colors.red);
      process.exit(1);
    }
    
    log(`\n${colors.bright}🔒 Scanning: ${absolutePath}${colors.reset}\n`);
    
    logStep('Parsing ZIP archive...', 'start');
    const buffer = readFileSync(absolutePath);
    codebaseText = parseZip(buffer);
    logStep('ZIP parsed', 'done');
    
  } else {
    log(`\n❌ Unknown command: ${command}`, colors.red);
    printHelp();
    process.exit(1);
  }
  
  // Run the scan
  const report = await runScan(codebaseText, llmConfig, parsed);
  
  // Output
  if (parsed.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printReport(report);
  }
  
  // Save to file if requested
  const outputPath = parsed.output || parsed.o;
  if (outputPath) {
    writeFileSync(outputPath, JSON.stringify(report, null, 2));
    log(`\n📄 JSON report saved to: ${outputPath}`, colors.green);
    
    // Also generate HTML
    const htmlPath = outputPath.replace(/\.json$/, '.html');
    await generateHTML(report, htmlPath);
    log(`📄 HTML report saved to: ${htmlPath}`, colors.green);
  }
  
  // Generate HTML only if --html flag is passed
  const htmlOnlyPath = parsed.html;
  if (htmlOnlyPath && !outputPath) {
    await generateHTML(report, htmlOnlyPath);
  }
}

main().catch(err => {
  log(`\n❌ Error: ${err.message}`, colors.red);
  process.exit(1);
});
