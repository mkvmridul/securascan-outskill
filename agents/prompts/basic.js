// Basic prompts for fast, lightweight security scanning
// These are concise and consume fewer tokens

export const SECRETS_PROMPT = `Find hardcoded secrets: API keys, passwords, tokens, DB URLs, private keys. Skip placeholders.
Return JSON: [{"type":"string","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const SQLI_PROMPT = `Find SQL injection: string concatenation in queries, template literals in SQL, raw() with user input.
Skip parameterized queries.
Return JSON: [{"type":"SQL_INJECTION","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const XSS_PROMPT = `Find XSS: innerHTML with user input, dangerouslySetInnerHTML, unescaped template output, HTML string building.
Skip React JSX {}, textContent, sanitized content.
Return JSON: [{"type":"XSS","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const AUTH_PROMPT = `Find auth issues: weak JWT secrets, no rate limiting on login, missing session destroy, insecure cookies, weak password hashing (MD5/SHA1).
Return JSON: [{"type":"AUTH","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const INJECTION_PROMPT = `Find command/code injection: exec() with user input, eval(), spawn with shell:true, unsafe deserialization, dynamic require().
Return JSON: [{"type":"INJECTION","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const IDOR_PROMPT = `Find broken access control: routes fetching by ID without ownership check, missing role validation, SSRF from user URLs.
Return JSON: [{"type":"IDOR","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const MISCONFIG_PROMPT = `Find misconfigurations: CORS *, debug mode in prod, stack traces in responses, default credentials, missing security headers.
Return JSON: [{"type":"MISCONFIG","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const CRYPTO_PROMPT = `Find crypto issues: MD5/SHA1 for passwords, weak bcrypt cost, Math.random() for tokens, static IV, deprecated ciphers.
Return JSON: [{"type":"CRYPTO","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const LOGGING_PROMPT = `Find logging gaps: missing login failure logs, no audit trail for admin actions, console.log for security events.
Return JSON: [{"type":"LOGGING","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const PII_LOGGING_PROMPT = `Find PII in logs: passwords logged, full request body on auth routes, tokens in logs, credit card numbers.
Return JSON: [{"type":"PII_LEAK","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const EXCEPTION_PROMPT = `Find exception handling issues: catch blocks that allow auth bypass, stack traces sent to client, unhandled rejections.
Return JSON: [{"type":"EXCEPTION","severity":"critical|high|medium|low","file":"path","line":"num","description":"brief","remediation":"fix"}]
Return [] if none.`;

export const ORCHESTRATOR_PROMPT = `You are a security triage expert. Analyze the provided source code and decide which security scanning agents should run.

Available agents:
- SECRETS (hardcoded keys, passwords, tokens)
- SQLI (SQL injection)
- XSS (cross-site scripting)
- AUTH (authentication/authorization flaws)
- INJECTION (command/code injection, eval, exec)
- IDOR (insecure direct object references, broken access control)
- MISCONFIG (security misconfiguration, CORS, headers)
- CRYPTO (weak cryptography, hashing)
- LOGGING (missing security logging)
- PII_LOGGING (sensitive data in logs)
- EXCEPTION (error handling, fail-open logic)

Analyze the code carefully. For a typical web app with a database, most agents should be invoked.

Return ONLY valid JSON (no markdown, no explanation):
{"triage":{"languages":["javascript"],"frameworks":["express"],"app_type":"web_application","overall_risk_level":"high"},"agents_to_invoke":[{"agent":"SECRETS","confidence":0.8,"evidence":"found .env and config files"}],"agents_skipped":[{"agent":"CRYPTO","reason":"no crypto usage found"}]}`;
