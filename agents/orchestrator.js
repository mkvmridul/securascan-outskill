import { callLLM, safeParseJSON } from '../utils/llmClient.js';
import { ORCHESTRATOR_PROMPT as BASIC_PROMPT } from './prompts/basic.js';
import { ORCHESTRATOR_PROMPT as ADVANCED_PROMPT } from './prompts/advanced.js';

/**
 * Run the orchestrator to triage the codebase and decide which agents to invoke
 * @param {string} codebaseText - The concatenated codebase text
 * @param {Object} llmConfig - LLM configuration (provider, apiKey, model)
 * @param {string} mode - 'basic' or 'advanced'
 * @returns {Promise<Object>} - Orchestrator decision
 */
export async function runOrchestrator(codebaseText, llmConfig, mode = 'basic') {
  const prompt = mode === 'advanced' ? ADVANCED_PROMPT : BASIC_PROMPT;
  console.log(`\x1b[35m[ORCHESTRATOR]\x1b[0m Analyzing codebase (${mode} mode)...`);
  const startTime = Date.now();
  
  try {
    const result = await callLLM(
      prompt,
      `Analyse this codebase and decide which security agents to invoke:\n\n${codebaseText}`,
      {
        ...llmConfig,
        temperature: 0.1
      }
    );
    
    console.log(`\x1b[35m[ORCHESTRATOR]\x1b[0m Raw LLM response (first 500 chars): ${result?.substring(0, 500)}`);
    
    const parsed = safeParseJSON(result, null);
    
    if (!parsed || !parsed.agents_to_invoke || parsed.agents_to_invoke.length === 0) {
      console.log(`\x1b[33m[ORCHESTRATOR]\x1b[0m Warning: LLM returned no agents, falling back to full scan`);
      return {
        triage: { languages: ['unknown'], frameworks: ['unknown'], app_type: 'web_application', overall_risk_level: 'high' },
        agents_to_invoke: [
          { agent: 'SECRETS', confidence: 0.8 },
          { agent: 'SQLI', confidence: 0.8 },
          { agent: 'XSS', confidence: 0.8 },
          { agent: 'AUTH', confidence: 0.8 },
          { agent: 'INJECTION', confidence: 0.8 },
          { agent: 'IDOR', confidence: 0.8 },
          { agent: 'MISCONFIG', confidence: 0.8 },
          { agent: 'CRYPTO', confidence: 0.8 },
          { agent: 'LOGGING', confidence: 0.8 },
          { agent: 'PII_LOGGING', confidence: 0.8 },
          { agent: 'EXCEPTION', confidence: 0.8 }
        ],
        agents_skipped: []
      };
    }
    
    // Deduplicate agents (in case LLM returns duplicates)
    const uniqueAgents = [];
    const seenAgents = new Set();
    for (const agent of (parsed.agents_to_invoke || [])) {
      if (!seenAgents.has(agent.agent)) {
        seenAgents.add(agent.agent);
        uniqueAgents.push(agent);
      }
    }
    parsed.agents_to_invoke = uniqueAgents;
    
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`\x1b[35m[ORCHESTRATOR]\x1b[0m Triage complete in ${elapsed}s`);
    console.log(`\x1b[35m[ORCHESTRATOR]\x1b[0m App type: ${parsed.triage?.app_type || 'unknown'} | Risk: ${parsed.triage?.overall_risk_level || 'unknown'}`);
    console.log(`\x1b[35m[ORCHESTRATOR]\x1b[0m Invoking ${parsed.agents_to_invoke?.length || 0} agents: ${parsed.agents_to_invoke?.map(a => a.agent).join(', ') || 'none'}`);
    
    return parsed;
  } catch (error) {
    console.error(`\x1b[31m[ORCHESTRATOR]\x1b[0m Error: ${error.message}`);
    
    // Fail fast on non-retryable errors (bad model, bad key, etc.)
    const isFatal = error.message?.includes('404') || 
                    error.message?.includes('401') || 
                    error.message?.includes('403') ||
                    error.message?.includes('not_found') ||
                    error.message?.includes('invalid_api_key');
    
    if (isFatal) {
      throw new Error(`LLM configuration error: ${error.message}`);
    }
    
    // For transient errors, fallback to running all common agents
    return {
      triage: {
        languages: ['unknown'],
        frameworks: ['unknown'],
        app_type: 'web_application',
        overall_risk_level: 'high'
      },
      agents_to_invoke: [
        { agent: 'SECRETS_AGENT', confidence: 0.8 },
        { agent: 'SQLI_AGENT', confidence: 0.8 },
        { agent: 'XSS_AGENT', confidence: 0.8 },
        { agent: 'AUTH_AGENT', confidence: 0.8 },
        { agent: 'INJECTION_AGENT', confidence: 0.8 },
        { agent: 'IDOR_AGENT', confidence: 0.8 },
        { agent: 'MISCONFIG_AGENT', confidence: 0.8 }
      ],
      agents_skipped: []
    };
  }
}
