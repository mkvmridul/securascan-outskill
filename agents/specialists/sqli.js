import { callLLM, safeParseJSON } from '../../utils/llmClient.js';
import { SQLI_PROMPT as BASIC_PROMPT } from '../prompts/basic.js';
import { SQLI_PROMPT as ADVANCED_PROMPT } from '../prompts/advanced.js';

export async function run(codebaseText, llmConfig, mode = 'basic') {
  const prompt = mode === 'advanced' ? ADVANCED_PROMPT : BASIC_PROMPT;
  console.log(`\x1b[36m[SQLI]\x1b[0m Scanning (${mode})...`);
  const start = Date.now();
  try {
    const result = await callLLM(prompt, codebaseText, { ...llmConfig, temperature: 0 });
    const findings = safeParseJSON(result, []);
    console.log(`\x1b[36m[SQLI]\x1b[0m ${findings.length} found (${((Date.now()-start)/1000).toFixed(1)}s)`);
    return findings;
  } catch (e) { console.log(`\x1b[36m[SQLI]\x1b[0m Error: ${e.message}`); return []; }
}
