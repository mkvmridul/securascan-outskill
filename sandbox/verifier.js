import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomUUID } from 'crypto';
import { spawn } from 'child_process';

const VERIFY_TIMEOUT_MS = 60_000;
const STARTUP_TIMEOUT_MS = 60_000;
const DEFAULT_PORTS = [3000, 8080, 5000, 8000, 4000, 5173];
const SQLI_PAYLOAD = "' OR '1'='1 --";

function now(startedAt) {
  return Date.now() - startedAt;
}

function addTimeline(timeline, startedAt, label, detail = '', extra = {}) {
  timeline.push({
    offset_ms: now(startedAt),
    timestamp: formatOffset(now(startedAt)),
    label,
    detail,
    ...extra
  });
}

function formatOffset(ms) {
  const totalSeconds = Math.floor(ms / 1000);
  const hours = String(Math.floor(totalSeconds / 3600)).padStart(2, '0');
  const minutes = String(Math.floor((totalSeconds % 3600) / 60)).padStart(2, '0');
  const seconds = String(totalSeconds % 60).padStart(2, '0');
  return `${hours}:${minutes}:${seconds}`;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const timer = options.timeoutMs ? setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, options.timeoutMs) : null;

    child.stdout.on('data', chunk => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', chunk => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', code => {
      if (timer) clearTimeout(timer);
      const result = { code, stdout, stderr, timedOut };
      if (code === 0 && !timedOut) {
        resolve(result);
      } else {
        const output = (stderr || stdout || '').trim().split('\n').slice(-4).join(' ').slice(0, 500);
        const detail = output ? `: ${output}` : '';
        const error = new Error(timedOut ? `${command} timed out${detail}` : `${command} exited with ${code}${detail}`);
        error.result = result;
        reject(error);
      }
    });
  });
}

function isNodeApp(projectPath) {
  return Boolean(projectPath && existsSync(join(projectPath, 'package.json')));
}

function classifyFinding(finding) {
  const text = [
    finding.type,
    finding.description,
    finding.file,
    finding.owasp_category
  ].filter(Boolean).join(' ').toUpperCase();

  if (text.includes('SQLI') || text.includes('SQL_INJECTION') || text.includes('SQL INJECTION')) {
    return 'sqli';
  }
  if (text.includes('IDOR') || text.includes('BROKEN_ACCESS') || text.includes('BROKEN ACCESS') || text.includes('OBJECT REFERENCE')) {
    return 'idor';
  }
  if (
    text.includes('EXPOSED') ||
    text.includes('UNAUTHENTICATED') ||
    text.includes('NO AUTH') ||
    text.includes('DEBUG') ||
    text.includes('METRICS') ||
    text.includes('ADMIN')
  ) {
    return 'exposed_endpoint';
  }
  return null;
}

function selectTargets(findings) {
  const selected = new Map();
  findings.forEach((finding, index) => {
    const type = classifyFinding(finding);
    if (type && !selected.has(type)) {
      selected.set(type, { finding, index, type });
    }
  });
  return [...selected.values()].slice(0, 3);
}

function dockerfileContents() {
  return `FROM node:20-alpine
WORKDIR /app
COPY . .
RUN rm -rf node_modules && if [ -f package-lock.json ]; then npm ci --omit=dev || npm install --omit=dev; else npm install --omit=dev; fi
ENV NODE_ENV=development
ENV PORT=3000
ENV HOST=0.0.0.0
EXPOSE 3000 4000 5000 5173 8000 8080
CMD ["sh", "-lc", "if node -e \\"process.exit(require('./package.json').scripts?.start ? 0 : 1)\\"; then npm start; elif node -e \\"process.exit(require('./package.json').scripts?.dev ? 0 : 1)\\"; then npm run dev -- --host 0.0.0.0; elif [ -f server.js ]; then node server.js; elif [ -f app.js ]; then node app.js; elif [ -f index.js ]; then node index.js; else echo 'No known Node startup command'; exit 1; fi"]
`;
}

async function buildImage(projectPath, imageTag, timeline, startedAt) {
  const tmpDir = mkdtempSync(join(tmpdir(), 'securascan-sandbox-'));
  const dockerfilePath = join(tmpDir, 'Dockerfile');
  writeFileSync(dockerfilePath, dockerfileContents());

  try {
    addTimeline(timeline, startedAt, 'Container build started', `Docker image ${imageTag}`);
    await runCommand('docker', ['build', '-f', dockerfilePath, '-t', imageTag, projectPath], {
      timeoutMs: 180_000
    });
    addTimeline(timeline, startedAt, 'Container build complete', 'Node.js app image is ready');
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function startContainer(imageTag, containerName, timeline, startedAt) {
  addTimeline(timeline, startedAt, 'Container starting', 'Runtime network disabled, 512MB RAM, 1 CPU');
  await runCommand('docker', [
    'run',
    '-d',
    '--rm',
    '--name',
    containerName,
    '--network',
    'none',
    '--memory',
    '512m',
    '--cpus',
    '1',
    '-e',
    'PORT=3000',
    '-e',
    'HOST=0.0.0.0',
    imageTag
  ], { timeoutMs: 30_000 });
}

async function stopContainer(containerName) {
  try {
    await runCommand('docker', ['rm', '-f', containerName], { timeoutMs: 15_000 });
  } catch {
    // Best effort cleanup: the scan report should not fail because teardown failed.
  }
}

async function removeImage(imageTag) {
  try {
    await runCommand('docker', ['rmi', '-f', imageTag], { timeoutMs: 30_000 });
  } catch {
    // Best effort cleanup.
  }
}

function fetchScript(request) {
  return `
const request = ${JSON.stringify(request)};
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), request.timeoutMs || 5000);
try {
  const response = await fetch(request.url, {
    method: request.method || 'GET',
    headers: request.headers || {},
    body: request.body,
    redirect: 'manual',
    signal: controller.signal
  });
  const body = await response.text();
  console.log(JSON.stringify({
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body: body.slice(0, 5000)
  }));
} catch (error) {
  console.log(JSON.stringify({ error: error.message }));
} finally {
  clearTimeout(timer);
}
`;
}

async function requestInContainer(containerName, port, path, options = {}) {
  const request = {
    url: `http://127.0.0.1:${port}${path}`,
    method: options.method || 'GET',
    headers: options.headers || {},
    body: options.body,
    timeoutMs: options.timeoutMs || 5000
  };
  const result = await runCommand('docker', ['exec', containerName, 'node', '-e', fetchScript(request)], {
    timeoutMs: options.timeoutMs ? options.timeoutMs + 2000 : 7000
  });
  try {
    return JSON.parse(result.stdout.trim() || '{}');
  } catch {
    return { error: result.stdout.trim() || 'Invalid response from attack runner' };
  }
}

async function waitForReady(containerName, timeline, startedAt) {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  let lastError = 'App did not respond';

  while (Date.now() < deadline) {
    for (const port of DEFAULT_PORTS) {
      const response = await requestInContainer(containerName, port, '/', { timeoutMs: 3000 });
      if (!response.error && response.status && response.status < 500) {
        addTimeline(timeline, startedAt, 'App ready', `http://127.0.0.1:${port} inside sandbox`, {
          result: `HTTP ${response.status}`
        });
        return port;
      }
      lastError = response.error || `HTTP ${response.status}`;
    }
    await sleep(1500);
  }

  throw new Error(`App readiness timeout: ${lastError}`);
}

function hasLoginSuccess(response) {
  const headers = response.headers || {};
  const body = (response.body || '').toLowerCase();
  const location = (headers.location || '').toLowerCase();
  const cookie = headers['set-cookie'] || '';

  return (
    response.status === 200 ||
    response.status === 201 ||
    response.status === 302 ||
    response.status === 303
  ) && (
    Boolean(cookie) ||
    location.includes('dashboard') ||
    location.includes('admin') ||
    body.includes('welcome') ||
    body.includes('dashboard') ||
    body.includes('access granted') ||
    body.includes('logged in')
  );
}

function hasNonTrivialBody(response) {
  return (response.body || '').trim().length >= 80;
}

function responseSummary(response) {
  if (response.error) return response.error;
  const cookie = response.headers?.['set-cookie'] ? 'session cookie set' : 'no session cookie';
  const body = (response.body || '').replace(/\s+/g, ' ').trim().slice(0, 120);
  return `HTTP ${response.status} · ${cookie}${body ? ` · response: "${body}"` : ''}`;
}

async function runSqlInjection(containerName, port, timeline, startedAt) {
  const endpoints = ['/login', '/api/login'];
  const bodies = [
    {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'x', username: 'x', password: SQLI_PAYLOAD })
    },
    {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ email: 'x', username: 'x', password: SQLI_PAYLOAD }).toString()
    }
  ];

  addTimeline(timeline, startedAt, 'Attack selected', 'SQL injection login bypass');

  for (const endpoint of endpoints) {
    for (const body of bodies) {
      addTimeline(timeline, startedAt, 'TARGET', `POST ${endpoint}`, {
        attack: `password: ${SQLI_PAYLOAD}`
      });
      const response = await requestInContainer(containerName, port, endpoint, {
        method: 'POST',
        headers: body.headers,
        body: body.body,
        timeoutMs: VERIFY_TIMEOUT_MS
      });
      addTimeline(timeline, startedAt, 'RESULT', responseSummary(response), {
        request: body.body,
        response: response.body,
        status: response.status
      });

      if (hasLoginSuccess(response)) {
        return {
          status: 'confirmed_exploitable',
          badge: 'CONFIRMED EXPLOITABLE',
          reason: `Login bypass succeeded against ${endpoint}: ${responseSummary(response)}`
        };
      }
    }
  }

  return {
    status: 'probably_safe',
    badge: 'PROBABLY SAFE',
    reason: 'The SQL injection login-bypass payload did not create an authenticated response.'
  };
}

async function getSessionCookie(containerName, port) {
  const attempts = [
    { email: 'user@example.com', username: 'user', password: 'password' },
    { email: 'alice@example.com', username: 'alice', password: 'password' },
    { email: 'admin@example.com', username: 'admin', password: 'admin' },
    { email: 'admin', username: 'admin', password: 'admin' }
  ];

  for (const endpoint of ['/login', '/api/login']) {
    for (const credentials of attempts) {
      const response = await requestInContainer(containerName, port, endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(credentials),
        timeoutMs: 8000
      });
      const setCookie = response.headers?.['set-cookie'];
      if (setCookie && (response.status === 200 || response.status === 302 || response.status === 303)) {
        return setCookie.split(';')[0];
      }
    }
  }

  return '';
}

async function runIdor(containerName, port, timeline, startedAt) {
  addTimeline(timeline, startedAt, 'Attack selected', 'IDOR order access replay');
  const cookie = await getSessionCookie(containerName, port);
  addTimeline(timeline, startedAt, 'Session setup', cookie ? 'Logged in with demo credentials' : 'No demo login worked; trying direct requests');

  const headers = cookie ? { cookie } : {};
  const first = await requestInContainer(containerName, port, '/api/orders/1', { headers, timeoutMs: VERIFY_TIMEOUT_MS });
  addTimeline(timeline, startedAt, 'TARGET', 'GET /api/orders/1', {
    result: responseSummary(first),
    response: first.body,
    status: first.status
  });

  const second = await requestInContainer(containerName, port, '/api/orders/2', { headers, timeoutMs: VERIFY_TIMEOUT_MS });
  addTimeline(timeline, startedAt, 'ATTACK', 'GET /api/orders/2 as the same user', {
    result: responseSummary(second),
    response: second.body,
    status: second.status
  });

  if (first.status === 200 && second.status === 200 && hasNonTrivialBody(second)) {
    return {
      status: 'confirmed_exploitable',
      badge: 'CONFIRMED EXPLOITABLE',
      reason: 'The sandbox returned another object with the same session context.'
    };
  }

  return {
    status: 'probably_safe',
    badge: 'PROBABLY SAFE',
    reason: 'The IDOR replay did not expose the second object.'
  };
}

async function runExposedEndpoint(containerName, port, timeline, startedAt) {
  addTimeline(timeline, startedAt, 'Attack selected', 'Unauthenticated exposed endpoint probe');

  for (const endpoint of ['/admin', '/debug', '/metrics']) {
    addTimeline(timeline, startedAt, 'TARGET', `GET ${endpoint} without auth`);
    const response = await requestInContainer(containerName, port, endpoint, { timeoutMs: VERIFY_TIMEOUT_MS });
    addTimeline(timeline, startedAt, 'RESULT', responseSummary(response), {
      response: response.body,
      status: response.status
    });

    if (response.status === 200 && hasNonTrivialBody(response)) {
      return {
        status: 'confirmed_exploitable',
        badge: 'CONFIRMED EXPLOITABLE',
        reason: `${endpoint} returned a non-trivial unauthenticated response.`
      };
    }
  }

  return {
    status: 'probably_safe',
    badge: 'PROBABLY SAFE',
    reason: 'No v0.1 exposed endpoint probe returned a public 200 response.'
  };
}

async function runPlaybook(type, containerName, port, timeline, startedAt) {
  if (type === 'sqli') return runSqlInjection(containerName, port, timeline, startedAt);
  if (type === 'idor') return runIdor(containerName, port, timeline, startedAt);
  return runExposedEndpoint(containerName, port, timeline, startedAt);
}

function summarize(report) {
  const verifications = (report.findings || [])
    .map(finding => finding.sandbox_verification)
    .filter(Boolean);

  return {
    status: verifications.length ? 'completed' : 'not_run',
    total_replayed: verifications.length,
    confirmed_exploitable: verifications.filter(v => v.status === 'confirmed_exploitable').length,
    probably_safe: verifications.filter(v => v.status === 'probably_safe').length,
    could_not_verify: verifications.filter(v => v.status === 'could_not_verify').length
  };
}

export async function verifyFindingsInSandbox(report, projectPath, options = {}) {
  const findings = report.findings || [];
  const targets = selectTargets(findings);
  report.sandbox_summary = {
    status: 'not_run',
    total_replayed: 0,
    confirmed_exploitable: 0,
    probably_safe: 0,
    could_not_verify: 0
  };

  if (!targets.length) {
    report.sandbox_summary.reason = 'No SQLi, IDOR, or exposed endpoint findings were selected for v0.1 replay.';
    return report.sandbox_summary;
  }

  if (!isNodeApp(projectPath)) {
    report.sandbox_summary.reason = 'Sandbox replay currently supports local Node.js apps with package.json.';
    return report.sandbox_summary;
  }

  try {
    await runCommand('docker', ['--version'], { timeoutMs: 10_000 });
  } catch {
    report.sandbox_summary.reason = 'Docker is not available, so static findings were left unchanged.';
    return report.sandbox_summary;
  }

  const id = randomUUID().slice(0, 8);
  const imageTag = `securascan-sandbox:${id}`;
  const containerName = `securascan-${id}`;
  const setupTimeline = [];
  const setupStartedAt = Date.now();
  let port;

  try {
    await buildImage(projectPath, imageTag, setupTimeline, setupStartedAt);
    await startContainer(imageTag, containerName, setupTimeline, setupStartedAt);
    port = await waitForReady(containerName, setupTimeline, setupStartedAt);

    for (const target of targets) {
      const timeline = setupTimeline.map(entry => ({ ...entry }));
      const startedAt = setupStartedAt;
      try {
        const result = await runPlaybook(target.type, containerName, port, timeline, startedAt);
        findings[target.index].sandbox_verification = {
          attack_type: target.type,
          ...result,
          target: `http://127.0.0.1:${port}`,
          timeline
        };
      } catch (error) {
        addTimeline(timeline, startedAt, 'Verifier stopped', error.message);
        findings[target.index].sandbox_verification = {
          attack_type: target.type,
          status: 'could_not_verify',
          badge: 'COULD NOT VERIFY',
          reason: error.message,
          target: port ? `http://127.0.0.1:${port}` : 'sandbox',
          timeline
        };
      }
    }
  } catch (error) {
    report.sandbox_summary = {
      status: 'failed',
      total_replayed: 0,
      confirmed_exploitable: 0,
      probably_safe: 0,
      could_not_verify: targets.length,
      reason: error.message
    };
    return report.sandbox_summary;
  } finally {
    await stopContainer(containerName);
    await removeImage(imageTag);
  }

  report.sandbox_summary = summarize(report);
  if (options.verbose) {
    console.log(`\x1b[33m[SANDBOX]\x1b[0m Replayed ${report.sandbox_summary.total_replayed} attack(s): ${report.sandbox_summary.confirmed_exploitable} confirmed`);
  }
  return report.sandbox_summary;
}

export const _internals = {
  classifyFinding,
  selectTargets
};
