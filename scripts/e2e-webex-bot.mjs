#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import fs from 'node:fs/promises';
import { createServer } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const DEFAULT_ROOM_ID =
  'Y2lzY29zcGFyazovL3VzL1JPT00vNjI1MzcwNzAtNmJjOS0xMWYxLWFiMGEtMDUxM2Y2OGNiOGM0';
const DEFAULT_ROOM_TITLE = 'miku bot test';
const DEFAULT_SELF_PERSON_ID =
  'Y2lzY29zcGFyazovL3VzL1BFT1BMRS9iYTcyOTQzZi1jNjdlLTRlNjUtOGYyYi01MGQwNmJlNGM0MzQ';
const DEFAULT_GENERIC_ACCOUNT_EMAIL = 'miku.gen@cisco.com';
const DEFAULT_ACCESS_TOKEN_FILE = path.resolve(
  REPO_ROOT,
  '../Webex-headless-messenger/.codex-tmp/webex-test/access-token',
);
const DEFAULT_SIDECAR_SCRIPT = path.resolve(
  REPO_ROOT,
  '../Webex-headless-messenger/examples/sidecar-js/index.mjs',
);
const DEFAULT_CONFIG_PATH = path.resolve(REPO_ROOT, '.codex-tmp/miku-bot-test/e2e-config.toml');
const DEFAULT_CODEX_CWD = path.resolve(
  os.tmpdir(),
  'webex-generic-account-bot-e2e/codex-cwd',
);
const DEFAULT_STATE_FILE = path.resolve(REPO_ROOT, '.codex-tmp/miku-bot-test/e2e-state.jsonl');
const WEBEX_API_BASE = 'https://webexapis.com/v1';

export function parseDotenv(contents) {
  const result = {};
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) {
      continue;
    }
    const [, key, rawValue] = match;
    result[key] = parseEnvValue(rawValue.trim());
  }
  return result;
}

export function parseAccessTokenFile(contents) {
  const trimmed = contents.trim();
  if (!trimmed) {
    throw new Error('access token file is empty');
  }
  if (!trimmed.startsWith('{')) {
    return trimmed;
  }
  const tokenSet = JSON.parse(trimmed);
  const token = tokenSet.accessToken;
  if (typeof token !== 'string' || !token.trim()) {
    throw new Error('access token file JSON has an empty accessToken');
  }
  return token.trim();
}

export function renderBotConfig(options) {
  return `state_file = ${tomlString(options.stateFile)}
self_person_id = ${tomlString(options.selfPersonId)}

[server]
bind = ${tomlString(options.botBind)}
event_path = "/webex/events"
health_path = "/healthz"
sidecar_token_env = "WEBEX_SIDECAR_TOKEN"
allow_unauthenticated = false
max_concurrent_requests = 1
attempt_lease_secs = 900

[webex]
access_token_file = ${tomlString(options.accessTokenFile)}

[codex]
bin = ${tomlString(options.codexBin)}
cwd = ${tomlString(options.codexCwd)}
codex_home = ${tomlString(options.codexHome)}
sandbox = ${tomlString(options.codexSandbox)}
approval_policy = "never"
timeout_secs = ${options.codexTimeoutSecs}
output_limit_chars = 4000
skip_git_repo_check = false
ephemeral = true

[codex.isolation]
mode = "current-user"

[[rooms]]
name = ${tomlString(options.roomTitle)}
room_id = ${tomlString(options.roomId)}
trigger = "prefix"
prefixes = [${tomlString(options.prefix)}]
allowed_person_emails = [${tomlString(options.senderEmail)}]
prompt_template = """
You are Codex running from a Webex generic-account bot.

Reply concisely in Simplified Chinese unless the user asks otherwise.

Room: {room_id}
Message ID: {message_id}
Sender: {person_email}

User message:
{body}
"""
`;
}

export function buildE2eOptions(env = process.env) {
  const botToken = requiredEnv(env, 'E2E_BOT_ACCESS_TOKEN');
  const senderEmail = requiredEnv(env, 'E2E_BOT_EMAIL');
  const botBind = env.E2E_BOT_BIND || '127.0.0.1:8787';
  const sidecarHealthBind = env.E2E_SIDECAR_HEALTH_BIND || '127.0.0.1:8788';
  const prefix = env.E2E_PREFIX || '/codex-e2e';
  const marker = env.E2E_MARKER || `webex-generic-bot-e2e-${Date.now()}-${randomUUID()}`;
  const prompt =
    env.E2E_PROMPT ||
    `${prefix} Reply with exactly this marker and no extra text: ${marker}`;
  return {
    accessTokenFile: path.resolve(env.E2E_ACCESS_TOKEN_FILE || DEFAULT_ACCESS_TOKEN_FILE),
    botBind,
    botToken,
    cargoBin: env.E2E_CARGO_BIN || resolveExecutable('cargo', env.PATH) || 'cargo',
    codexBin: env.E2E_CODEX_BIN || resolveExecutable('codex', env.PATH) || 'codex',
    codexCwd: path.resolve(env.E2E_CODEX_CWD || DEFAULT_CODEX_CWD),
    codexHome: path.resolve(env.E2E_CODEX_HOME || env.CODEX_HOME || path.join(os.homedir(), '.codex')),
    codexSandbox: env.E2E_CODEX_SANDBOX || 'read-only',
    codexTimeoutSecs: parsePositiveInteger(env.E2E_CODEX_TIMEOUT_SECS, 300),
    configPath: path.resolve(env.E2E_CONFIG_PATH || DEFAULT_CONFIG_PATH),
    genericAccountEmail: env.E2E_GENERIC_ACCOUNT_EMAIL || DEFAULT_GENERIC_ACCOUNT_EMAIL,
    keepProcesses: env.E2E_KEEP_PROCESSES === '1',
    marker,
    pollIntervalMs: parsePositiveInteger(env.E2E_POLL_INTERVAL_MS, 5000),
    prefix,
    prompt,
    replyTimeoutMs: parsePositiveInteger(env.E2E_REPLY_TIMEOUT_MS, 420000),
    roomId: env.E2E_ROOM_ID || DEFAULT_ROOM_ID,
    roomTitle: env.E2E_ROOM_TITLE || DEFAULT_ROOM_TITLE,
    selfPersonId: env.E2E_SELF_PERSON_ID || DEFAULT_SELF_PERSON_ID,
    senderEmail,
    sidecarHealthBind,
    sidecarScript: path.resolve(env.E2E_SIDECAR_SCRIPT || DEFAULT_SIDECAR_SCRIPT),
    sidecarToken: env.E2E_SIDECAR_TOKEN || `e2e-${randomUUID()}`,
    stateFile: path.resolve(env.E2E_STATE_FILE || DEFAULT_STATE_FILE),
  };
}

export function expectedReply(replies, { marker, selfPersonId, selfPersonEmail }) {
  const reply = replies.find((message) => message.personId === selfPersonId);
  if (!reply) {
    return null;
  }
  const body = `${reply.markdown ?? ''}\n${reply.text ?? ''}`;
  if (!body.includes(marker)) {
    throw new Error(`generic account reply did not contain marker reply_id=${reply.id ?? '<unknown>'}`);
  }
  const replyEmail = reply.personEmail ?? reply.person_email;
  if (
    selfPersonEmail &&
    replyEmail &&
    replyEmail.toLowerCase() !== selfPersonEmail.toLowerCase()
  ) {
    throw new Error(
      `generic account reply email mismatch reply_id=${reply.id ?? '<unknown>'} email=${replyEmail}`,
    );
  }
  return { ...reply, markerFound: true };
}

export function childBaseEnv(env = process.env) {
  const allowedKeys = [
    'PATH',
    'HOME',
    'USER',
    'LOGNAME',
    'SHELL',
    'TMPDIR',
    'TEMP',
    'TMP',
    'LANG',
    'LC_ALL',
    'SSL_CERT_FILE',
    'SSL_CERT_DIR',
    'NODE_EXTRA_CA_CERTS',
    'RUSTUP_HOME',
    'CARGO_HOME',
  ];
  return Object.fromEntries(
    allowedKeys
      .filter((key) => typeof env[key] === 'string' && env[key].length > 0)
      .map((key) => [key, env[key]]),
  );
}

export function botProcessEnv(options, env = process.env) {
  return {
    ...childBaseEnv(env),
    RUST_LOG: env.RUST_LOG || 'webex_generic_account_bot=info',
    WEBEX_SIDECAR_TOKEN: options.sidecarToken,
  };
}

export function sidecarProcessEnv(options, env = process.env) {
  return {
    ...childBaseEnv(env),
    WEBEX_ACCESS_TOKEN_FILE: options.accessTokenFile,
    WEBEX_SIDECAR_FORWARD_RETRIES: '1',
    WEBEX_SIDECAR_FORWARD_TIMEOUT_MS: String(options.replyTimeoutMs + 30000),
    WEBEX_SIDECAR_HEALTH_BIND: options.sidecarHealthBind,
    WEBEX_SIDECAR_MAX_IN_FLIGHT: '1',
    WEBEX_SIDECAR_MESSAGE_EVENTS: 'created',
    WEBEX_SIDECAR_RETRY_BASE_MS: '1000',
    WEBEX_SIDECAR_RETRY_MAX_MS: '5000',
    WEBEX_SIDECAR_TARGET_URL: `http://${options.botBind}/webex/events`,
    WEBEX_SIDECAR_TOKEN: options.sidecarToken,
    WEBEX_SIDECAR_TOKEN_RELOAD_INTERVAL_MS: '0',
  };
}

async function main() {
  const env = await loadEnvironment();
  const options = buildE2eOptions(env);
  validateOptions(options);
  await assertTcpBindAvailable(options.botBind, 'bot bind');
  await assertTcpBindAvailable(options.sidecarHealthBind, 'sidecar health bind');
  await writeConfig(options);

  const children = [];
  let sentMessage = null;
  let reply = null;
  try {
    const bot = startBot(options);
    children.push(bot);
    await withProcessWatch(
      waitForHttpOk(`http://${options.botBind}/healthz`, {
        timeoutMs: 60000,
        label: 'bot health',
        headers: { Authorization: `Bearer ${options.sidecarToken}` },
      }),
      [bot],
    );

    const sidecar = startSidecar(options);
    children.push(sidecar);
    await withProcessWatch(
      waitForHttpOk(`http://${options.sidecarHealthBind}/readyz`, {
        timeoutMs: 120000,
        label: 'sidecar readiness',
      }),
      children,
    );

    sentMessage = await withProcessWatch(
      createMessage({
        accessToken: options.botToken,
        body: {
          roomId: options.roomId,
          markdown: options.prompt,
        },
      }),
      children,
    );
    console.log(
      `e2e_message_sent=true room="${options.roomTitle}" message_id=${sentMessage.id} sender=${options.senderEmail}`,
    );

    const mikuToken = parseAccessTokenFile(await fs.readFile(options.accessTokenFile, 'utf8'));
    reply = await withProcessWatch(
      waitForReply({
        accessToken: mikuToken,
        marker: options.marker,
        parentId: sentMessage.id,
        pollIntervalMs: options.pollIntervalMs,
        roomId: options.roomId,
        selfPersonEmail: options.genericAccountEmail,
        selfPersonId: options.selfPersonId,
        timeoutMs: options.replyTimeoutMs,
      }),
      children,
    );

    console.log(
      `e2e_reply_received=true reply_id=${reply.id} parent_id=${sentMessage.id} marker_found=${reply.markerFound}`,
    );
    console.log('e2e_ok=true');
  } finally {
    if (options.keepProcesses) {
      console.log('e2e_keep_processes=true');
    } else {
      await stopChildren(children);
    }
  }
}

async function loadEnvironment() {
  let fileEnv = {};
  const dotenvPath = path.resolve(REPO_ROOT, '.env');
  if (existsSync(dotenvPath)) {
    fileEnv = parseDotenv(await fs.readFile(dotenvPath, 'utf8'));
  }
  return { ...fileEnv, ...process.env };
}

function parseEnvValue(value) {
  if (value.length >= 2) {
    const quote = value[0];
    if ((quote === '"' || quote === "'" || quote === '`') && value.at(-1) === quote) {
      const inner = value.slice(1, -1);
      return quote === '"' ? inner.replaceAll('\\"', '"').replaceAll('\\\\', '\\') : inner;
    }
  }
  const hashIndex = value.search(/\s#/);
  return (hashIndex === -1 ? value : value.slice(0, hashIndex)).trim();
}

function requiredEnv(env, key) {
  const value = env[key];
  if (!value || !value.trim()) {
    throw new Error(`${key} is required`);
  }
  return value.trim();
}

function parsePositiveInteger(value, fallback) {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function resolveExecutable(name, searchPath = process.env.PATH) {
  const entries = (searchPath || '').split(path.delimiter).filter(Boolean);
  for (const entry of entries) {
    const candidate = path.join(entry, name);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function validateOptions(options) {
  for (const [label, file] of [
    ['miku access token file', options.accessTokenFile],
    ['sidecar script', options.sidecarScript],
  ]) {
    if (!existsSync(file)) {
      throw new Error(`${label} does not exist: ${file}`);
    }
  }
  if (!options.prompt.trimStart().startsWith(options.prefix)) {
    throw new Error(`E2E_PROMPT must start with prefix ${options.prefix}`);
  }
}

async function assertTcpBindAvailable(bind, label) {
  const { host, port } = parseBind(bind);
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', (error) => {
      reject(new Error(`${label} ${bind} is not available: ${error.message}`));
    });
    server.listen(port, host, () => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });
}

function parseBind(bind) {
  const parsed = new URL(bind.includes('://') ? bind : `http://${bind}`);
  const port = Number.parseInt(parsed.port, 10);
  if (!parsed.hostname || !Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error(`invalid bind address: ${bind}`);
  }
  return { host: parsed.hostname.replace(/^\[(.*)\]$/, '$1'), port };
}

async function writeConfig(options) {
  await fs.mkdir(path.dirname(options.configPath), { recursive: true });
  await fs.mkdir(options.codexCwd, { recursive: true });
  await fs.writeFile(options.configPath, renderBotConfig(options), 'utf8');
  console.log(`e2e_config=${path.relative(REPO_ROOT, options.configPath)}`);
}

function startBot(options) {
  return startProcess('bot', options.cargoBin, ['run', '--quiet', '--', '--config', options.configPath], {
    cwd: REPO_ROOT,
    env: botProcessEnv(options),
  });
}

function startSidecar(options) {
  return startProcess('sidecar', process.execPath, [options.sidecarScript], {
    cwd: path.dirname(options.sidecarScript),
    env: sidecarProcessEnv(options),
  });
}

function startProcess(label, command, args, options) {
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => writeProcessLog(label, chunk, false));
  child.stderr.on('data', (chunk) => writeProcessLog(label, chunk, true));
  const processInfo = {
    label,
    child,
    exit: null,
  };
  processInfo.exit = new Promise((resolve) => {
    child.once('error', (error) => {
      resolve({ error });
    });
    child.once('exit', (code, signal) => {
      resolve({ code, signal });
    });
  });
  child.once('exit', (code, signal) => {
    if (code !== 0 && signal !== 'SIGTERM') {
      console.error(`${label}_exited code=${code} signal=${signal ?? ''}`);
    }
  });
  return processInfo;
}

function writeProcessLog(label, chunk, isError) {
  const output = String(chunk)
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => `[${label}] ${line}`)
    .join('\n');
  if (!output) {
    return;
  }
  (isError ? process.stderr : process.stdout).write(`${output}\n`);
}

async function stopChildren(children) {
  await Promise.all(children.reverse().map((processInfo) => terminate(processInfo)));
}

async function terminate({ child }) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  child.kill('SIGTERM');
  const exited = await Promise.race([
    onceExit(child).then(() => true),
    sleep(5000).then(() => false),
  ]);
  if (!exited) {
    child.kill('SIGKILL');
    await onceExit(child);
  }
}

function onceExit(child) {
  return new Promise((resolve) => child.once('exit', resolve));
}

async function withProcessWatch(work, processes) {
  if (processes.length === 0) {
    return work;
  }
  return Promise.race([
    work,
    ...processes.map((processInfo) =>
      processInfo.exit.then((status) => {
        if (status.error) {
          throw new Error(`${processInfo.label} failed to start: ${status.error.message}`);
        }
        throw new Error(
          `${processInfo.label} exited before E2E completed code=${status.code ?? ''} signal=${
            status.signal ?? ''
          }`,
        );
      }),
    ),
  ]);
}

async function waitForHttpOk(url, { timeoutMs, label, headers = {} }) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { headers });
      if (response.ok) {
        console.log(`${label.replaceAll(' ', '_')}_ok=true`);
        return;
      }
      lastError = new Error(`${label} returned HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(1000);
  }
  throw new Error(`${label} did not become ready: ${lastError?.message ?? 'timeout'}`);
}

async function createMessage({ accessToken, body }) {
  return webexJson('/messages', {
    accessToken,
    method: 'POST',
    body,
  });
}

async function listReplies({ accessToken, roomId, parentId }) {
  const query = new URLSearchParams({ roomId, parentId, max: '10' });
  const page = await webexJson(
    `/messages?${query}`,
    {
      accessToken,
      method: 'GET',
    },
    { notFound: 'empty' },
  );
  return Array.isArray(page.items) ? page.items : [];
}

async function waitForReply({
  accessToken,
  marker,
  parentId,
  pollIntervalMs,
  roomId,
  selfPersonEmail,
  selfPersonId,
  timeoutMs,
}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const replies = await listReplies({ accessToken, roomId, parentId });
    const reply = expectedReply(replies, { marker, selfPersonEmail, selfPersonId });
    if (reply) {
      return reply;
    }
    await sleep(pollIntervalMs);
  }
  throw new Error(`timed out waiting for reply to message ${parentId}`);
}

async function webexJson(pathname, { accessToken, method, body }, options = {}) {
  const response = await fetch(`${WEBEX_API_BASE}${pathname}`, {
    method,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let parsed = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch (_) {
      parsed = { raw: text.slice(0, 500) };
    }
  }
  if (!response.ok) {
    const message = parsed?.message || parsed?.raw || response.statusText;
    if (response.status === 404 && options.notFound === 'empty') {
      return {};
    }
    throw new Error(`Webex API ${method} ${pathname} failed status=${response.status}: ${message}`);
  }
  return parsed ?? {};
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function tomlString(value) {
  return JSON.stringify(String(value));
}

function isDirectRun() {
  return process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
}

if (isDirectRun()) {
  main().catch((error) => {
    console.error(`e2e_failed=${JSON.stringify(error.message)}`);
    process.exitCode = 1;
  });
}
