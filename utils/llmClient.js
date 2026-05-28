import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import { GoogleGenerativeAI } from '@google/generative-ai';

/**
 * Sleep for a given number of milliseconds
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Concurrency Controller - ensures only ONE LLM call at a time
 * with a configurable delay between calls
 */
class ConcurrencyController {
  constructor() {
    this.queue = [];
    this.isProcessing = false;
    this.lastCallTime = 0;
    this.minDelayMs = 1000; // 1 second minimum between calls
  }

  setMinDelay(ms) {
    this.minDelayMs = ms;
  }

  async acquire() {
    return new Promise((resolve) => {
      this.queue.push(resolve);
      this.processQueue();
    });
  }

  release() {
    this.lastCallTime = Date.now();
    this.isProcessing = false;
    this.processQueue();
  }

  async processQueue() {
    if (this.isProcessing || this.queue.length === 0) return;
    
    this.isProcessing = true;
    const resolve = this.queue.shift();
    
    // Ensure minimum delay between calls
    const timeSinceLastCall = Date.now() - this.lastCallTime;
    if (this.lastCallTime > 0 && timeSinceLastCall < this.minDelayMs) {
      const waitTime = this.minDelayMs - timeSinceLastCall;
      await sleep(waitTime);
    }
    
    resolve();
  }
}

// Global singleton controller
const controller = new ConcurrencyController();

/**
 * Set minimum delay between LLM calls (in milliseconds)
 */
export function setRateLimit(delayMs) {
  controller.setMinDelay(delayMs);
  console.log(`[RATE LIMIT] Set to 1 call per ${delayMs}ms`);
}

/**
 * Call LLM with retry logic for rate limits
 */
async function callWithRetry(fn, maxRetries = 3, baseDelay = 2000) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      const isRateLimit = error.message?.includes('429') || 
                          error.message?.includes('Too Many Requests') ||
                          error.message?.includes('Resource exhausted') ||
                          error.status === 429;
      
      if (isRateLimit && attempt < maxRetries) {
        const delay = baseDelay * Math.pow(2, attempt); // Exponential backoff
        console.log(`[RATE LIMIT] 429 received. Retrying in ${delay/1000}s... (attempt ${attempt + 1}/${maxRetries})`);
        await sleep(delay);
        continue;
      }
      throw error;
    }
  }
}

/**
 * Call LLM with the specified provider (Anthropic, OpenAI, or Gemini)
 * Uses concurrency controller to ensure only ONE call at a time
 * @param {string} systemPrompt - The system prompt
 * @param {string} userContent - The user message content
 * @param {Object} config - Configuration object
 * @param {string} config.provider - 'anthropic', 'openai', or 'gemini'
 * @param {string} config.apiKey - API key (passed per request, never stored)
 * @param {string} config.model - Model name (e.g., 'claude-opus-4-5', 'gpt-4o', 'gemini-1.5-pro')
 * @param {number} [config.temperature=0.0] - Temperature setting
 * @returns {Promise<string>} - The LLM response text
 */
export async function callLLM(systemPrompt, userContent, config) {
  const { provider, apiKey, model, temperature = 0.0 } = config;

  // Acquire lock - only one call at a time
  await controller.acquire();
  
  try {
    if (provider === 'anthropic') {
      const client = new Anthropic({ apiKey });
      return await callWithRetry(async () => {
        const response = await client.messages.create({
          model,
          max_tokens: 4096,
          temperature,
          system: systemPrompt,
          messages: [{ role: 'user', content: userContent }]
        });
        return response.content[0].text;
      });
    } else if (provider === 'openai') {
      const client = new OpenAI({ apiKey });
      return await callWithRetry(async () => {
        const response = await client.chat.completions.create({
          model,
          temperature,
          max_tokens: 4096,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userContent }
          ]
        });
        return response.choices[0].message.content;
      });
    } else if (provider === 'gemini') {
      const client = new GoogleGenerativeAI(apiKey);
      const genModel = client.getGenerativeModel({ model });
      return await callWithRetry(async () => {
        const response = await genModel.generateContent({
          contents: [{
            role: 'user',
            parts: [{ text: `${systemPrompt}\n\n${userContent}` }]
          }],
          generationConfig: {
            temperature,
            maxOutputTokens: 4096
          }
        });
        return response.response.text();
      }, 5, 3000); // More retries and longer delay for Gemini
    } else {
      throw new Error(`Unsupported provider: ${provider}`);
    }
  } catch (error) {
    console.error(`LLM call failed for provider ${provider}:`, error.message);
    throw error;
  } finally {
    // Always release the lock
    controller.release();
  }
}

/**
 * Safely parse JSON from LLM response, handling markdown fences
 * @param {string} text - The text to parse
 * @param {*} [fallback=[]] - Fallback value on parse failure
 * @returns {*} - Parsed JSON or fallback
 */
export function safeParseJSON(text, fallback = []) {
  try {
    // Strip markdown code fences if present
    let cleaned = text.trim();
    
    // Remove ```json ... ``` or ``` ... ``` fences
    if (cleaned.startsWith('```json')) {
      cleaned = cleaned.slice(7);
    } else if (cleaned.startsWith('```')) {
      cleaned = cleaned.slice(3);
    }
    
    if (cleaned.endsWith('```')) {
      cleaned = cleaned.slice(0, -3);
    }
    
    cleaned = cleaned.trim();
    
    return JSON.parse(cleaned);
  } catch (error) {
    // Never throw - return fallback on any error
    return fallback;
  }
}
