#!/usr/bin/env node
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_TAIL_LINES = 160;
const DEFAULT_ENV_FILE = '/etc/webex-generic-account-bot/jenkins.env';
const DEFAULT_MAX_NODES = 100;
const DEFAULT_MAX_TOTAL_LOG_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAX_LOG_BYTES_PER_NODE = 200 * 1024 * 1024;
const DEFAULT_MAX_API_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_MAX_FETCH_SECONDS = 600;
const DEFAULT_FETCH_RETRIES = 3;
const DEFAULT_MAX_PARALLEL_FETCHES = 6;
const MAX_JENKINS_URL_CHARS = 4096;
const MAX_RETAINED_LOG_LINE_BYTES = 4096;
const MAX_RETAINED_LOG_LINES = 20_000;

export function parseEnvFile(contents) {
  const env = {};
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
    env[key] = parseEnvValue(rawValue.trim());
  }
  return env;
}

export function extractJenkinsUrls(text, baseUrl) {
  const base = normalizeBaseUrl(baseUrl);
  const urls = new Set();
  const pattern = /https?:\/\/[^\s<>"')\]]+/g;
  for (const match of text.matchAll(pattern)) {
    const candidate = trimTrailingUrlPunctuation(match[0]);
    try {
      const url = normalizeJenkinsUrl(candidate, base);
      urls.add(url.toString());
    } catch (_) {
      // Ignore non-Jenkins or malformed URLs.
    }
  }
  return [...urls];
}

export function normalizeJenkinsUrl(value, baseUrl) {
  const base = normalizeBaseUrl(baseUrl);
  if (String(value).length > MAX_JENKINS_URL_CHARS) {
    throw new Error(`Jenkins URL exceeds ${MAX_JENKINS_URL_CHARS} characters`);
  }
  const url = new URL(value);
  if (!url.toString().startsWith(base.toString())) {
    throw new Error(`url is outside configured Jenkins base URL: ${url.origin}${url.pathname}`);
  }
  url.hash = '';
  return url;
}

export function buildUrlFromJenkinsUrl(value, baseUrl) {
  const base = normalizeBaseUrl(baseUrl);
  const url = normalizeJenkinsUrl(value, baseUrl);
  const relativePath = url.pathname.slice(base.pathname.length);
  const parts = relativePath.split('/').filter(Boolean);
  const terminalConsoleSegment = ['console', 'consoleText'].includes(parts.at(-1));
  if (terminalConsoleSegment) {
    parts.pop();
  }
  const buildNumber = parts.at(-1);
  const jobParts = parts.slice(0, -1);
  if (
    !/^\d+$/.test(buildNumber ?? '')
    || jobParts.length < 2
    || jobParts.length % 2 !== 0
    || jobParts.some((part, index) => (index % 2 === 0 ? part !== 'job' : !part))
  ) {
    throw new Error(`Jenkins URL must identify a build under /job/.../<build-number>/: ${url.pathname}`);
  }
  url.pathname = `${base.pathname}${parts.join('/')}/`;
  url.search = '';
  return url;
}

export function classifyInfraSignals(lines) {
  const rules = [
    {
      kind: 'dns',
      pattern: /could not resolve hostname|temporary failure in name resolution|getaddrinfo|name or service not known/i,
    },
    {
      kind: 'agent-channel',
      pattern:
        /channel.*closing|channel is already closed|agent was removed|connection.*closed|broken pipe|unexpected termination of the channel|backing channel .*disconnected|hudson\.remoting\.Channel/i,
    },
    {
      kind: 'agent-capacity',
      pattern: /cannot find any nodes to run the job|no nodes? (?:is |are )?available|waiting for next available executor/i,
    },
    {
      kind: 'checkout',
      pattern: /fatal: unable to access|early eof|connection reset|timeout.*git|failed to connect/i,
    },
    {
      kind: 'workspace',
      pattern: /no space left on device|disk quota exceeded|cannot allocate memory|device or resource busy/i,
    },
  ];

  const matches = [];
  for (const line of lines) {
    for (const rule of rules) {
      if (rule.pattern.test(line)) {
        matches.push({ kind: rule.kind, line });
        break;
      }
    }
  }
  return matches;
}

export function discoverBuildUrls(text, baseUrl) {
  const urls = new Set();
  for (const jenkinsUrl of extractJenkinsUrls(text, baseUrl)) {
    try {
      const buildUrl = buildUrlFromJenkinsUrl(jenkinsUrl, baseUrl).toString();
      if (buildIdFromUrl(buildUrl)) {
        urls.add(buildUrl);
      }
    } catch (_) {
      // Ignore URLs under Jenkins that are not build pages.
    }
  }
  return [...urls];
}

async function main() {
  const { command, envFile, url, text, tailLines, artifactDir, limits } = parseArgs(process.argv.slice(2));
  const config = await loadJenkinsConfig(envFile);

  if (command === 'extract-urls') {
    const input = text ?? (await readStdin());
    for (const jenkinsUrl of extractJenkinsUrls(input, config.baseUrl)) {
      console.log(jenkinsUrl);
    }
    return;
  }

  if (command === 'diagnose') {
    if (!url) {
      throw new Error('diagnose requires --url');
    }
    if (artifactDir) {
      const bundle = await diagnoseBundle({ config, url, tailLines, artifactDir, limits });
      console.log(formatBundleStdout(bundle));
      return;
    }
    const report = await diagnoseBuild({ config, url, tailLines, limits });
    console.log(formatReport(report));
    return;
  }

  throw new Error(`unknown command: ${command}`);
}

export async function diagnoseBundle({ config, url, tailLines, artifactDir, limits }) {
  const rootDir = path.resolve(artifactDir);
  const logsDir = path.join(rootDir, 'logs');
  await fs.mkdir(logsDir, { recursive: true, mode: 0o700 });

  const fetcher = new GraphFetcher({ config, tailLines, logsDir, limits });
  const initialUrl = buildUrlFromJenkinsUrl(url, config.baseUrl).toString();
  const rootUrl = await findRootBuildUrl({ fetcher, initialUrl });
  await collectBuildGraph({ fetcher, rootUrl });

  const graph = buildGraphSummary({
    initialUrl,
    rootUrl,
    nodes: [...fetcher.nodes.values()],
    limits,
    stopReason: fetcher.stopReason,
  });
  const graphPath = path.join(rootDir, 'graph.json');
  const summaryPath = path.join(rootDir, 'summary.md');
  const logIndexPath = path.join(logsDir, 'index.json');
  const logIndex = buildLogIndex(graph);
  await fs.writeFile(graphPath, `${JSON.stringify(graph, null, 2)}\n`, 'utf8');
  await fs.writeFile(logIndexPath, `${JSON.stringify(logIndex, null, 2)}\n`, 'utf8');
  await fs.writeFile(summaryPath, formatBundleSummary(graph), 'utf8');

  return {
    artifactDir: rootDir,
    summaryPath,
    graphPath,
    logIndexPath,
    graph,
  };
}

class GraphFetcher {
  constructor({ config, tailLines, logsDir, limits }) {
    this.config = config;
    this.tailLines = tailLines;
    this.logsDir = logsDir;
    this.limits = limits;
    this.nodes = new Map();
    this.totalLogBytes = 0;
    this.reservedLogBytes = 0;
    this.stopReason = null;
  }

  async fetch(url, parentUrl = null) {
    const buildUrl = buildUrlFromJenkinsUrl(url, this.config.baseUrl).toString();
    const parentUrls = Array.isArray(parentUrl) ? parentUrl.filter(Boolean) : [parentUrl].filter(Boolean);
    const existing = this.nodes.get(buildUrl);
    if (existing) {
      for (const parent of parentUrls) {
        existing.parentUrls.add(parent);
      }
      return existing;
    }
    if (this.nodes.size >= this.limits.maxNodes) {
      this.stop(`Jenkins diagnostics reached max_nodes=${this.limits.maxNodes}`);
      return null;
    }

    const node = {
      buildUrl,
      consoleUrl: guiConsoleUrl(buildUrl).toString(),
      consoleTextUrl: new URL('consoleText', buildUrl).toString(),
      parentUrls: new Set(parentUrls),
      childUrls: new Set(),
      fetchError: null,
    };
    this.nodes.set(buildUrl, node);

    let reservedLogBytes = 0;
    try {
      reservedLogBytes = this.reserveLogBytes();
      const report = await fetchBuildReport({
        config: this.config,
        url: buildUrl,
        tailLines: this.tailLines,
        maxLogBytes: reservedLogBytes,
        maxApiResponseBytes:
          this.limits.maxApiResponseBytes ?? DEFAULT_MAX_API_RESPONSE_BYTES,
        fetchTimeoutMs: this.limits.maxFetchSeconds * 1000,
        fetchRetries: this.limits.fetchRetries,
        onLogBytesRead: (bytes) => this.consumeLogBytes(bytes),
      });
      const logBudgetExceeded = /exceeded max_log_bytes_per_node=/.test(
        report.consoleFetchError ?? '',
      );
      const logFile = report.consoleFetchError
        ? null
        : path.join(this.logsDir, jenkinsLogFileName(report, buildUrl));
      if (logFile) {
        await fs.writeFile(logFile, redactLog(report.consoleText), 'utf8');
      }
      Object.assign(node, {
        fullDisplayName: report.fullDisplayName,
        number: report.number,
        result: report.result,
        artifacts: report.artifacts,
        signalLines: report.signalLines,
        infraSignals: report.infraSignals,
        downstreamBuilds: report.downstreamBuilds,
        downstreamFailedBuilds: report.downstreamFailedBuilds,
        tail: report.tail,
        upstreamUrl: report.upstreamUrl,
        localLog: logFile,
        localLogRelative: logFile ? path.relative(path.dirname(this.logsDir), logFile) : null,
        logBytes: report.logBytes,
        logFetchError: report.consoleFetchError,
      });
      if (
        logBudgetExceeded
        && this.totalLogBytes >= this.limits.maxTotalLogBytes
      ) {
        node.logFetchError = this.stop(
          `Jenkins diagnostics exceeded max_total_log_bytes=${this.limits.maxTotalLogBytes}`,
        );
      }
      return node;
    } catch (error) {
      if (error instanceof JenkinsBudgetStopError) {
        node.fetchError = this.stop(error.message);
      } else if (
        reservedLogBytes > 0
        && reservedLogBytes < this.limits.maxLogBytesPerNode
        && /exceeded max_log_bytes_per_node=/.test(error.message)
      ) {
        node.fetchError = this.stop(
          `Jenkins diagnostics exceeded max_total_log_bytes=${this.limits.maxTotalLogBytes}`,
        );
      } else {
        node.fetchError = error.message;
      }
      return node;
    } finally {
      if (reservedLogBytes > 0) {
        this.releaseLogBytes(reservedLogBytes);
      }
    }
  }

  reserveLogBytes() {
    if (this.stopReason) {
      throw new JenkinsBudgetStopError(this.stopReason);
    }
    const remaining = this.limits.maxTotalLogBytes - this.totalLogBytes - this.reservedLogBytes;
    if (remaining <= 0) {
      throw new JenkinsBudgetStopError(
        this.stop(`Jenkins diagnostics exceeded max_total_log_bytes=${this.limits.maxTotalLogBytes}`),
      );
    }
    const reserved = Math.min(this.limits.maxLogBytesPerNode, remaining);
    this.reservedLogBytes += reserved;
    return reserved;
  }

  consumeLogBytes(bytes) {
    const nextTotal = this.totalLogBytes + bytes;
    if (nextTotal > this.limits.maxTotalLogBytes) {
      this.totalLogBytes = this.limits.maxTotalLogBytes;
      throw new JenkinsBudgetStopError(
        this.stop(`Jenkins diagnostics exceeded max_total_log_bytes=${this.limits.maxTotalLogBytes}`),
      );
    }
    this.totalLogBytes = nextTotal;
  }

  releaseLogBytes(bytes) {
    this.reservedLogBytes = Math.max(0, this.reservedLogBytes - bytes);
  }

  shouldStop() {
    return Boolean(this.stopReason);
  }

  stop(reason) {
    if (!this.stopReason) {
      this.stopReason = reason;
    }
    return this.stopReason;
  }
}

class JenkinsBudgetStopError extends Error {}

async function findRootBuildUrl({ fetcher, initialUrl }) {
  let currentUrl = initialUrl;
  const visited = new Set();
  for (;;) {
    if (visited.has(currentUrl)) {
      return currentUrl;
    }
    visited.add(currentUrl);
    const node = await fetcher.fetch(currentUrl);
    if (!node || node.fetchError || !node.upstreamUrl) {
      return currentUrl;
    }
    currentUrl = node.upstreamUrl;
  }
}

export async function collectBuildGraph({ fetcher, rootUrl }) {
  const queued = [rootUrl];
  const queuedUrls = new Set([rootUrl]);
  const queuedParents = new Map([[rootUrl, new Set()]]);
  const expanded = new Set();

  while (queued.length > 0 && fetcher.nodes.size < fetcher.limits.maxNodes && !graphShouldStop(fetcher)) {
    const batch = queued.splice(0, fetcher.limits.maxParallelFetches);
    for (const url of batch) {
      queuedUrls.delete(url);
    }
    const nodes = await Promise.all(batch.map((url) => {
      const parentUrls = [...(queuedParents.get(url) ?? [])];
      queuedParents.delete(url);
      return fetcher.fetch(url, parentUrls);
    }));
    for (const node of nodes) {
      if (graphShouldStop(fetcher) || !node || node.fetchError || expanded.has(node.buildUrl)) {
        continue;
      }
      expanded.add(node.buildUrl);
      for (const downstream of node.downstreamBuilds ?? []) {
        const childUrl = downstream.url;
        node.childUrls.add(childUrl);
        const existing = fetcher.nodes.get(childUrl);
        if (existing) {
          existing.parentUrls.add(node.buildUrl);
          if (!expanded.has(childUrl) && !queuedUrls.has(childUrl)) {
            queued.push(childUrl);
            queuedUrls.add(childUrl);
            queuedParents.set(childUrl, new Set([node.buildUrl]));
          }
          continue;
        }
        if (!queuedUrls.has(childUrl)) {
          if (fetcher.nodes.size + queuedUrls.size >= fetcher.limits.maxNodes) {
            stopGraph(fetcher, `Jenkins diagnostics reached max_nodes=${fetcher.limits.maxNodes}`);
            break;
          }
          queued.push(childUrl);
          queuedUrls.add(childUrl);
          queuedParents.set(childUrl, new Set());
        }
        queuedParents.get(childUrl).add(node.buildUrl);
      }
    }
  }
  if (queued.length > 0 && fetcher.nodes.size >= fetcher.limits.maxNodes && !graphShouldStop(fetcher)) {
    stopGraph(fetcher, `Jenkins diagnostics reached max_nodes=${fetcher.limits.maxNodes}`);
  }
}

function graphShouldStop(fetcher) {
  return typeof fetcher.shouldStop === 'function' ? fetcher.shouldStop() : Boolean(fetcher.stopReason);
}

function stopGraph(fetcher, reason) {
  if (typeof fetcher.stop === 'function') {
    return fetcher.stop(reason);
  }
  if (!fetcher.stopReason) {
    fetcher.stopReason = reason;
  }
  return fetcher.stopReason;
}

export async function fetchBuildReport({
  config,
  url,
  tailLines,
  maxLogBytes,
  maxApiResponseBytes = DEFAULT_MAX_API_RESPONSE_BYTES,
  fetchTimeoutMs,
  fetchRetries,
  onLogBytesRead = () => {},
}) {
  const buildUrl = buildUrlFromJenkinsUrl(url, config.baseUrl);
  const buildApiUrl = new URL('api/json', buildUrl);
  buildApiUrl.searchParams.set(
    'tree',
    [
      'result',
      'building',
      'duration',
      'timestamp',
      'url',
      'fullDisplayName',
      'number',
      'actions[causes[shortDescription,userId,userName,upstreamProject,upstreamBuild,upstreamUrl],builds[fullDisplayName,fullName,displayName,name,jobName,number,buildNumber,buildNumberStr,result,url],triggeredBuilds[fullDisplayName,fullName,displayName,name,jobName,number,buildNumber,buildNumberStr,result,url],downstreamBuilds[fullDisplayName,fullName,displayName,name,jobName,number,buildNumber,buildNumberStr,result,url]]',
      'downstreamBuilds[fullDisplayName,fullName,displayName,name,jobName,number,buildNumber,buildNumberStr,result,url]',
      'subBuilds[fullDisplayName,fullName,displayName,name,jobName,jobAlias,number,buildNumber,buildNumberStr,result,url]',
      'artifacts[fileName,relativePath]',
    ].join(','),
  );
  const consoleTextUrl = new URL('consoleText', buildUrl);

  const build = await withRetries(
    () => getJsonLimited(buildApiUrl, config, {
      maxBytes: maxApiResponseBytes,
      timeoutMs: fetchTimeoutMs,
    }),
    fetchRetries,
  );
  let consoleText = '';
  let consoleFetchError = null;
  try {
    consoleText = await withRetries(
      () => getTextLimited(consoleTextUrl, config, {
        maxBytes: maxLogBytes,
        timeoutMs: fetchTimeoutMs,
        onBytesRead: onLogBytesRead,
      }),
      fetchRetries,
    );
  } catch (error) {
    if (error instanceof JenkinsBudgetStopError) {
      throw error;
    }
    consoleFetchError = redactLog(error.message);
  }
  const redactedConsoleLines = redactedConsoleLinesFromText(consoleText);
  const tail = redactedConsoleLines.slice(-tailLines).filter(Boolean);
  const signalLines = selectSignalLines(redactedConsoleLines);
  const infraSignals = classifyInfraSignals(signalLines.concat(tail));
  const relatedBuilds = extractStructuredDownstreamBuilds(build, config.baseUrl);
  const downstreamFailedBuilds = relatedBuilds.filter((downstream) => isFailedBuildResult(downstream.result));

  return {
    buildUrl: buildUrl.toString(),
    consoleUrl: guiConsoleUrl(buildUrl).toString(),
    consoleTextUrl: consoleTextUrl.toString(),
    fullDisplayName: build.fullDisplayName ?? '',
    result: build.result ?? (build.building ? 'BUILDING' : 'UNKNOWN'),
    number: build.number ?? '',
    artifacts: Array.isArray(build.artifacts) ? build.artifacts : [],
    signalLines: signalLines.slice(-30),
    infraSignals: infraSignals.slice(-20),
    downstreamBuilds: relatedBuilds,
    downstreamFailedBuilds,
    tail,
    upstreamUrl: upstreamBuildUrl(build, config.baseUrl),
    consoleText,
    consoleFetchError,
    logBytes: Buffer.byteLength(consoleText, 'utf8'),
  };
}

function dedupeDiscoveredBuilds(builds) {
  const seen = new Set();
  return builds.filter((build) => {
    const key = build.url || `${build.displayName}#${build.number}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function extractStructuredDownstreamBuilds(build, baseUrl) {
  const candidates = [
    ...asArray(build.downstreamBuilds),
    ...asArray(build.subBuilds),
    ...asArray(build.actions).flatMap((action) => [
      ...asArray(action.builds),
      ...asArray(action.triggeredBuilds),
      ...asArray(action.downstreamBuilds),
      ...asArray(action.subBuilds),
    ]),
  ];
  return dedupeDiscoveredBuilds(
    candidates
      .map((candidate) => structuredBuildCandidate(candidate, baseUrl))
      .filter(Boolean),
  );
}

function structuredBuildCandidate(candidate, baseUrl) {
  if (!candidate || typeof candidate !== 'object') {
    return null;
  }
  const url = structuredBuildUrl(candidate, baseUrl);
  if (!url) {
    return null;
  }
  const number = structuredBuildNumber(candidate) || buildNumberFromUrl(url) || '';
  const displayName = structuredBuildDisplayName(candidate, number) || buildIdFromUrl(url) || url;
  return {
    displayName,
    number,
    result: normaliseBuildResult(candidate.result ?? candidate.buildResult ?? candidate.status),
    url,
    consoleUrl: guiConsoleUrl(url).toString(),
    discovery: 'jenkins-api',
  };
}

function structuredBuildUrl(candidate, baseUrl) {
  if (typeof candidate.url === 'string' && candidate.url.trim()) {
    try {
      return buildUrlFromJenkinsUrl(candidate.url, baseUrl).toString();
    } catch (_) {
      return null;
    }
  }
  const number = structuredBuildNumber(candidate);
  const segments = structuredJobSegments(candidate);
  if (!number || segments.length === 0) {
    return null;
  }
  const base = normalizeBaseUrl(baseUrl);
  const url = new URL(base.toString());
  const baseParts = base.pathname.split('/').filter(Boolean);
  const jobParts = segments.flatMap((segment) => ['job', encodeURIComponent(segment)]);
  url.pathname = `/${[...baseParts, ...jobParts, encodeURIComponent(number)].join('/')}/`;
  url.search = '';
  url.hash = '';
  return url.toString();
}

function structuredBuildNumber(candidate) {
  const raw = candidate.number ?? candidate.buildNumber ?? candidate.buildNumberStr;
  if (raw !== undefined && raw !== null) {
    const value = String(raw).trim();
    if (/^\d+$/.test(value)) {
      return value;
    }
  }
  for (const value of [
    candidate.fullDisplayName,
    candidate.displayName,
    candidate.name,
  ]) {
    const match = /\s#(\d+)\s*$/.exec(String(value ?? ''));
    if (match) {
      return match[1];
    }
  }
  return '';
}

function buildNumberFromUrl(value) {
  try {
    const parts = new URL(value).pathname.split('/').filter(Boolean);
    const last = parts.at(-1);
    return /^\d+$/.test(last ?? '') ? last : '';
  } catch (_) {
    return '';
  }
}

function structuredJobSegments(candidate) {
  for (const value of [
    candidate.fullName,
    candidate.jobName,
    candidate.fullDisplayName,
    candidate.name,
    candidate.jobAlias,
  ]) {
    const segments = splitStructuredJobName(value);
    if (segments.length > 0 && !segments.every((segment) => /^#?\d+$/.test(segment))) {
      return segments;
    }
  }
  return [];
}

function splitStructuredJobName(value) {
  const text = String(value ?? '').trim().replace(/\s+#\d+\s*$/, '');
  if (!text) {
    return [];
  }
  const delimiter = text.includes('»') ? /\s*»\s*/ : /\/+/;
  return text.split(delimiter).map((segment) => segment.trim()).filter(Boolean);
}

function structuredBuildDisplayName(candidate, number) {
  for (const value of [
    candidate.fullDisplayName,
    candidate.fullName,
    candidate.jobName,
    candidate.name,
    candidate.jobAlias,
    candidate.displayName,
  ]) {
    const text = String(value ?? '').trim();
    if (!text || text === `#${number}` || text === number) {
      continue;
    }
    return text.replace(/\s+#\d+\s*$/, '');
  }
  return '';
}

function normaliseBuildResult(value) {
  const result = String(value ?? 'UNKNOWN').trim();
  return result ? result.toUpperCase() : 'UNKNOWN';
}

function isFailedBuildResult(value) {
  return ['FAILURE', 'UNSTABLE', 'ABORTED', 'NOT_BUILT'].includes(normaliseBuildResult(value));
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

export async function diagnoseBuild({ config, url, tailLines, limits }) {
  const buildUrl = buildUrlFromJenkinsUrl(url, config.baseUrl);
  const buildApiUrl = new URL('api/json', buildUrl);
  buildApiUrl.searchParams.set(
    'tree',
    [
      'result',
      'building',
      'duration',
      'timestamp',
      'url',
      'fullDisplayName',
      'number',
      'actions[causes[shortDescription,userId,userName],builds[fullDisplayName,fullName,displayName,name,jobName,number,buildNumber,buildNumberStr,result,url],triggeredBuilds[fullDisplayName,fullName,displayName,name,jobName,number,buildNumber,buildNumberStr,result,url],downstreamBuilds[fullDisplayName,fullName,displayName,name,jobName,number,buildNumber,buildNumberStr,result,url]]',
      'downstreamBuilds[fullDisplayName,fullName,displayName,name,jobName,number,buildNumber,buildNumberStr,result,url]',
      'subBuilds[fullDisplayName,fullName,displayName,name,jobName,jobAlias,number,buildNumber,buildNumberStr,result,url]',
      'artifacts[fileName,relativePath]',
    ].join(','),
  );
  const consoleTextUrl = new URL('consoleText', buildUrl);
  const consoleUrl = guiConsoleUrl(buildUrl);
  const fetchTimeoutMs = limits.maxFetchSeconds * 1000;
  const maxLogBytes = Math.min(limits.maxLogBytesPerNode, limits.maxTotalLogBytes);
  let downloadedLogBytes = 0;
  const consumeLogBytes = (bytes) => {
    downloadedLogBytes += bytes;
    if (downloadedLogBytes > limits.maxTotalLogBytes) {
      throw new JenkinsBudgetStopError(
        `Jenkins diagnostics exceeded max_total_log_bytes=${limits.maxTotalLogBytes}`,
      );
    }
  };

  const [build, consoleText] = await Promise.all([
    withRetries(
      () => getJsonLimited(buildApiUrl, config, {
        maxBytes: limits.maxApiResponseBytes ?? DEFAULT_MAX_API_RESPONSE_BYTES,
        timeoutMs: fetchTimeoutMs,
      }),
      limits.fetchRetries,
    ),
    withRetries(
      () => getTextLimited(consoleTextUrl, config, {
        maxBytes: maxLogBytes,
        timeoutMs: fetchTimeoutMs,
        onBytesRead: consumeLogBytes,
      }),
      limits.fetchRetries,
    ),
  ]);
  const redactedConsoleLines = redactedConsoleLinesFromText(consoleText);
  const tail = redactedConsoleLines.slice(-tailLines).filter(Boolean);
  const signalLines = selectSignalLines(redactedConsoleLines);
  const infraSignals = classifyInfraSignals(signalLines.concat(tail));
  const downstreamFailedBuilds = extractStructuredDownstreamBuilds(build, config.baseUrl)
    .filter((downstream) => isFailedBuildResult(downstream.result))
    .map(({ displayName, number, url }) => ({ displayName, number, url }));

  return {
    buildUrl: buildUrl.toString(),
    consoleUrl: consoleUrl.toString(),
    fullDisplayName: build.fullDisplayName ?? '',
    result: build.result ?? (build.building ? 'BUILDING' : 'UNKNOWN'),
    number: build.number ?? '',
    artifacts: Array.isArray(build.artifacts) ? build.artifacts : [],
    signalLines: signalLines.slice(-30),
    infraSignals: infraSignals.slice(-20),
    downstreamFailedBuilds: downstreamFailedBuilds.slice(-10),
    tail,
  };
}

export function buildGraphSummary({ initialUrl, rootUrl, nodes, limits, stopReason = null }) {
  const rawNodes = nodes.map((node) => {
    const childUrls = [...(node.childUrls ?? [])];
    const failedChildUrls = childUrls.filter((childUrl) => {
      const child = nodes.find((candidate) => candidate.buildUrl === childUrl);
      return isFailedBuildResult(child?.result);
    });
    const failed = isFailedBuildResult(node.result);
    const failureHandler = isFailureHandler(node.fullDisplayName || node.buildUrl);
    const triggerJob = isTriggerJob(node.fullDisplayName || node.buildUrl);
    const role = failed && (triggerJob || failedChildUrls.length > 0)
      ? 'failed_trigger_job'
      : failed
        ? 'failed_job'
        : node.buildUrl === rootUrl
          ? 'root'
          : 'downstream';
    return {
      id: buildId(node),
      role,
      result: node.result || 'UNKNOWN',
      failure_handler: failureHandler,
      job: node.fullDisplayName || '',
      build_number: node.number || '',
      build_url: node.buildUrl,
      jenkins_console: node.consoleUrl,
      jenkins_console_text: node.consoleTextUrl,
      local_log: node.localLog || null,
      local_log_relative: node.localLogRelative || null,
      parent_ids: [...(node.parentUrls ?? [])].map((url) => buildId(nodes.find((candidate) => candidate.buildUrl === url) || { buildUrl: url })),
      child_ids: childUrls.map((url) => buildId(nodes.find((candidate) => candidate.buildUrl === url) || { buildUrl: url })),
      infra_signals: (node.infraSignals ?? []).map((signal) => ({
        kind: signal.kind,
        line: redactLog(signal.line ?? ''),
      })),
      failure_signals: (node.signalLines ?? []).map((line) => redactLog(line)),
      fetch_error: node.fetchError || node.logFetchError || null,
      log_bytes: node.logBytes || 0,
    };
  });

  const recommended = rawNodes
    .filter((node) => ['failed_job', 'failed_trigger_job'].includes(node.role))
    .sort((left, right) => nodePriority(left) - nodePriority(right));

  const counts = buildGraphCounts(rawNodes, recommended);

  return {
    version: 1,
    initial_url: initialUrl,
    root_url: rootUrl,
    partial: Boolean(stopReason),
    stop_reason: stopReason ? redactLog(stopReason) : null,
    limits: {
      max_nodes: limits.maxNodes,
      max_total_log_bytes: limits.maxTotalLogBytes,
      max_log_bytes_per_node: limits.maxLogBytesPerNode,
      max_fetch_seconds: limits.maxFetchSeconds,
      fetch_retries: limits.fetchRetries,
      max_parallel_fetches: limits.maxParallelFetches,
    },
    counts,
    instructions: [
      'Read summary.md first, then inspect the local_log files for the highest priority failed jobs.',
      'Use logs/index.json to map every discovered Jenkins job to its local log file, result, role, and Jenkins console link.',
      'For WME pipelines, wrapper/root pipeline failures usually point to downstream jobs; the likely root cause is in failed downstream jobs.',
      'Use jenkins_console links in final replies. Do not report consoleText links.',
      'Failure-handler jobs are secondary unless no other failed job explains the failure.',
    ],
    recommended_reading_order: recommended.map((node, index) => ({
      rank: index + 1,
      id: node.id,
      role: node.role,
      result: node.result,
      local_log: node.local_log,
      local_log_relative: node.local_log_relative,
      jenkins_console: node.jenkins_console,
      infra_signals: node.infra_signals,
    })),
    nodes: rawNodes,
  };
}

function buildGraphCounts(nodes, recommended) {
  return {
    total_jobs_discovered: nodes.length,
    log_files_written: nodes.filter((node) => Boolean(node.local_log)).length,
    fetch_error_jobs: nodes.filter((node) => Boolean(node.fetch_error)).length,
    recommended_failed_jobs: recommended.length,
    failed_jobs: nodes.filter((node) => node.role === 'failed_job').length,
    failed_trigger_jobs: nodes.filter((node) => node.role === 'failed_trigger_job').length,
    failure_handler_jobs: nodes.filter((node) => node.failure_handler).length,
    successful_jobs: nodes.filter((node) => node.result === 'SUCCESS').length,
    unknown_jobs: nodes.filter((node) => node.result === 'UNKNOWN').length,
  };
}

export function buildLogIndex(graph) {
  return {
    version: 1,
    partial: graph.partial,
    stop_reason: graph.stop_reason,
    counts: graph.counts,
    instructions: [
      'Each jobs entry maps one discovered Jenkins job to its local log file and Jenkins GUI console link.',
      'local_log is null when the helper could not fetch that build; inspect fetch_error for the reason.',
      'Use jenkins_console in replies, not jenkins_console_text.',
    ],
    jobs: graph.nodes.map((node) => ({
      id: node.id,
      role: node.role,
      result: node.result,
      failure_handler: node.failure_handler,
      job: node.job,
      build_number: node.build_number,
      local_log: node.local_log,
      local_log_relative: node.local_log_relative,
      jenkins_console: node.jenkins_console,
      jenkins_console_text: node.jenkins_console_text,
      parent_ids: node.parent_ids,
      child_ids: node.child_ids,
      infra_signal_count: node.infra_signals.length,
      fetch_error: node.fetch_error,
      log_bytes: node.log_bytes,
    })),
  };
}

export function formatBundleSummary(graph) {
  const lines = [
    '# Jenkins Diagnostics Summary',
    '',
    `Initial URL: ${graph.initial_url}`,
    `Root URL: ${graph.root_url}`,
    `Partial: ${graph.partial ? 'true' : 'false'}`,
    ...(graph.stop_reason ? [`Stop Reason: ${graph.stop_reason}`] : []),
    '',
    '## Collection Counts',
    '',
    `- total_jobs_discovered: ${graph.counts.total_jobs_discovered}`,
    `- log_files_written: ${graph.counts.log_files_written}`,
    `- fetch_error_jobs: ${graph.counts.fetch_error_jobs}`,
    `- recommended_failed_jobs: ${graph.counts.recommended_failed_jobs}`,
    `- failed_jobs: ${graph.counts.failed_jobs}`,
    `- failed_trigger_jobs: ${graph.counts.failed_trigger_jobs}`,
    `- successful_jobs: ${graph.counts.successful_jobs}`,
    '',
    '## How To Read',
    '',
    '- Read this summary first, then inspect the local log files listed below.',
    '- Use `logs/index.json` to map every discovered Jenkins job to its local log file and Jenkins GUI console link.',
    '- For WME pipelines, prioritise failed downstream jobs over wrapper/root trigger jobs.',
    '- Use `jenkins_console` GUI links in the final reply. Do not report `consoleText` links.',
    '- Treat failure-handler jobs as secondary unless no other failed job explains the failure.',
    '',
    '## Recommended Reading Order',
    '',
  ];

  if (graph.recommended_reading_order.length === 0) {
    lines.push('- No failed jobs were identified.');
  } else {
    for (const item of graph.recommended_reading_order) {
      lines.push(`${item.rank}. ${item.role}: ${item.id}`);
      lines.push(`   - local_log: ${item.local_log ?? 'unavailable'}`);
      lines.push(`   - jenkins_console: ${item.jenkins_console}`);
      if (item.infra_signals.length === 0) {
        lines.push('   - infra_signals: none');
      } else {
        lines.push('   - infra_signals:');
        for (const signal of item.infra_signals.slice(0, 5)) {
          lines.push(`     - ${signal.kind}: ${redactLog(signal.line)}`);
        }
      }
    }
  }

  lines.push('', '## All Local Logs', '');
  const nodesWithLogs = graph.nodes.filter((node) => node.local_log);
  if (nodesWithLogs.length === 0) {
    lines.push('- No local log files were written.');
  } else {
    for (const node of nodesWithLogs) {
      lines.push(`- ${node.id}`);
      lines.push(`  - role: ${node.role}`);
      lines.push(`  - result: ${node.result}`);
      lines.push(`  - local_log: ${node.local_log}`);
      lines.push(`  - jenkins_console: ${node.jenkins_console}`);
    }
  }

  lines.push('', '## Build Graph', '');
  for (const node of graph.nodes) {
    lines.push(`- ${node.id}`);
    lines.push(`  - role: ${node.role}`);
    lines.push(`  - result: ${node.result}`);
    lines.push(`  - local_log: ${node.local_log ?? 'unavailable'}`);
    lines.push(`  - jenkins_console: ${node.jenkins_console}`);
    if (node.parent_ids.length > 0) {
      lines.push(`  - parents: ${node.parent_ids.join(', ')}`);
    }
    if (node.child_ids.length > 0) {
      lines.push(`  - children: ${node.child_ids.join(', ')}`);
    }
    if (node.failure_handler) {
      lines.push('  - failure_handler: true');
    }
    if (node.fetch_error) {
      lines.push(`  - fetch_error: ${node.fetch_error}`);
    }
  }

  return `${lines.join('\n')}\n`;
}

export function formatBundleStdout(bundle) {
  const first = bundle.graph.recommended_reading_order[0];
  const nodesWithLocalEvidence = bundle.graph.nodes.filter(
    (node) => node.local_log && node.log_bytes > 0,
  );
  const lines = [
    'jenkins_diagnostics_bundle=true',
    'prefetched_jenkins_console_urls:',
    ...nodesWithLocalEvidence.map(
      (node) => `- jenkins_console: ${stdoutScalar(node.jenkins_console)}`,
    ),
    'prefetched_jenkins_console_urls_end=true',
    '',
    `artifact_dir=${stdoutScalar(bundle.artifactDir)}`,
    `summary_file=${stdoutScalar(bundle.summaryPath)}`,
    `graph_file=${stdoutScalar(bundle.graphPath)}`,
    `log_index_file=${stdoutScalar(bundle.logIndexPath)}`,
    `logs_dir=${stdoutScalar(path.join(bundle.artifactDir, 'logs'))}`,
    `total_jobs_discovered=${bundle.graph.counts.total_jobs_discovered}`,
    `log_files_written=${bundle.graph.counts.log_files_written}`,
    `fetch_error_jobs=${bundle.graph.counts.fetch_error_jobs}`,
    `recommended_failed_jobs=${bundle.graph.counts.recommended_failed_jobs}`,
    `failed_jobs=${bundle.graph.counts.failed_jobs}`,
    `failed_trigger_jobs=${bundle.graph.counts.failed_trigger_jobs}`,
    `failure_handler_jobs=${bundle.graph.counts.failure_handler_jobs}`,
    `partial=${bundle.graph.partial ? 'true' : 'false'}`,
    ...(bundle.graph.stop_reason ? [`stop_reason=${stdoutScalar(bundle.graph.stop_reason)}`] : []),
    first ? `recommended_first=${stdoutScalar(first.id)}` : 'recommended_first=none',
    '',
    'Read summary_file first. Use log_index_file to count every discovered job and map each job to its local_log. Use local_log files for evidence and jenkins_console GUI links in the final reply.',
  ];
  if (bundle.graph.recommended_reading_order.length > 0) {
    lines.push('', 'recommended_reading_order_preview:');
    for (const item of bundle.graph.recommended_reading_order.slice(0, 5)) {
      lines.push(`- ${stdoutScalar(item.role)}: ${stdoutScalar(item.id)}`);
      lines.push(`  local_log: ${stdoutScalar(item.local_log ?? 'unavailable')}`);
      lines.push(`  jenkins_console: ${stdoutScalar(item.jenkins_console)}`);
      if (item.infra_signals.length === 0) {
        lines.push('  infra_signals: none');
      } else {
        lines.push('  infra_signals:');
        for (const signal of item.infra_signals.slice(0, 5)) {
          lines.push(
            `    - ${stdoutScalar(signal.kind)}: ${stdoutScalar(redactLog(signal.line))}`,
          );
        }
      }
    }
  }
  return lines.join('\n');
}

function stdoutScalar(value) {
  return String(value).replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
}

export function formatReport(report) {
  const lines = [
    'jenkins_readonly=true',
    `build_url=${report.buildUrl}`,
    `console_url=${report.consoleUrl}`,
    `job=${report.fullDisplayName}`,
    `build_number=${report.number}`,
    `result=${report.result}`,
    `artifacts=${report.artifacts.map((artifact) => artifact.relativePath || artifact.fileName).filter(Boolean).join(',')}`,
    '',
    'infra_signals:',
  ];

  if (report.infraSignals.length === 0) {
    lines.push('- none');
  } else {
    for (const signal of report.infraSignals) {
      lines.push(`- ${signal.kind}: ${redactLog(signal.line)}`);
    }
  }

  lines.push('', 'downstream_failed_builds:');
  if (report.downstreamFailedBuilds.length === 0) {
    lines.push('- none');
  } else {
    for (const build of report.downstreamFailedBuilds) {
      lines.push(`- ${build.displayName} #${build.number}: ${build.url}`);
    }
  }

  lines.push('', 'failure_signals:');
  if (report.signalLines.length === 0) {
    lines.push('- none');
  } else {
    for (const line of report.signalLines) {
      lines.push(`- ${redactLog(line)}`);
    }
  }

  lines.push('', 'console_tail:');
  for (const line of report.tail) {
    lines.push(redactLog(line));
  }
  return lines.join('\n');
}

function selectSignalLines(lines) {
  const pattern =
    /(^|\b)(error|failed|failure|exception|fatal|abort|timeout|could not|cannot|unable|channel|ssh|dns|agent|offline|disconnect)(\b|:)/i;
  return lines.filter((line) => pattern.test(line)).map((line) => line.trim()).filter(Boolean);
}

function guiConsoleUrl(buildUrl) {
  return new URL('console', buildUrl);
}

function upstreamBuildUrl(build, baseUrl) {
  const causes = (build.actions ?? []).flatMap((action) => action.causes ?? []);
  for (const cause of causes) {
    if (
      !cause.upstreamUrl
      || cause.upstreamBuild === undefined
      || cause.upstreamBuild === null
    ) {
      continue;
    }
    const upstreamBuild = String(cause.upstreamBuild).trim();
    if (!/^\d+$/.test(upstreamBuild)) {
      continue;
    }
    try {
      const upstreamJobUrl = new URL(cause.upstreamUrl, normalizeBaseUrl(baseUrl));
      const pathname = upstreamJobUrl.pathname.endsWith('/')
        ? upstreamJobUrl.pathname
        : `${upstreamJobUrl.pathname}/`;
      upstreamJobUrl.pathname = `${pathname}${upstreamBuild}/`;
      upstreamJobUrl.search = '';
      upstreamJobUrl.hash = '';
      return buildUrlFromJenkinsUrl(upstreamJobUrl.toString(), baseUrl).toString();
    } catch (_) {
      // Ignore malformed or non-build upstream metadata without discarding this build's evidence.
    }
  }
  return null;
}

async function withRetries(operation, retries) {
  let lastError = null;
  for (let attempt = 1; attempt <= retries; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof JenkinsResponseBudgetError || error instanceof JenkinsBudgetStopError) {
        throw error;
      }
      lastError = error;
      if (attempt < retries) {
        await sleep(250 * attempt);
      }
    }
  }
  throw lastError;
}

async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

class JenkinsResponseBudgetError extends Error {}

class JenkinsLogBudgetError extends JenkinsResponseBudgetError {}

class JenkinsApiBudgetError extends JenkinsResponseBudgetError {}

async function getTextLimited(url, config, { maxBytes, timeoutMs, onBytesRead = () => {} }) {
  const response = await get(url, config, { timeoutMs });
  const body = await readResponseBodyLimited(
    response,
    url,
    maxBytes,
    'max_log_bytes_per_node',
    JenkinsLogBudgetError,
    onBytesRead,
  );
  return body.toString('utf8');
}

async function getJsonLimited(url, config, { maxBytes, timeoutMs }) {
  const response = await get(url, config, { timeoutMs });
  const body = await readResponseBodyLimited(
    response,
    url,
    maxBytes,
    'max_api_response_bytes',
    JenkinsApiBudgetError,
  );
  return JSON.parse(body.toString('utf8'));
}

async function readResponseBodyLimited(
  response,
  url,
  maxBytes,
  budgetName,
  ErrorType,
  onBytesRead = () => {},
) {
  const contentLength = Number.parseInt(response.headers.get('content-length') ?? '', 10);
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    await response.body?.cancel?.().catch(() => {});
    throw new ErrorType(`GET ${url.pathname} exceeded ${budgetName}=${maxBytes}`);
  }
  const reader = response.body?.getReader();
  if (!reader) {
    throw new ErrorType(`GET ${url.pathname} cannot enforce ${budgetName}=${maxBytes}`);
  }

  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    try {
      onBytesRead(value.byteLength);
    } catch (error) {
      await reader.cancel?.().catch(() => {});
      throw error;
    }
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel?.().catch(() => {});
      throw new ErrorType(`GET ${url.pathname} exceeded ${budgetName}=${maxBytes}`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

export function redactLog(text) {
  const secretKey = [
    '[A-Za-z0-9_.-]*(?:password|passwd|token|secret|credential)[A-Za-z0-9_.-]*',
    '[A-Za-z0-9_.-]*(?:api|access|private|client)[_.-]?key[A-Za-z0-9_.-]*',
  ].join('|');
  return text
    .replace(
      /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----/g,
      '[REDACTED PRIVATE KEY]',
    )
    .replace(/(https?:\/\/)([^/\s:@]+(?::[^@\s/]*)?)(@)/gi, '$1[REDACTED]$3')
    .replace(
      new RegExp(`(["'](?:${secretKey})["']\\s*:\\s*)(["'])([^\\r\\n"']*)(\\2)`, 'gi'),
      '$1$2[REDACTED]$4',
    )
    .replace(
      new RegExp(`(\\b(?:${secretKey})\\b\\s*[:=]\\s*)(["'])([^\\r\\n"']*)(\\2)`, 'gi'),
      '$1$2[REDACTED]$4',
    )
    .replace(
      new RegExp(`(\\b(?:${secretKey})\\b\\s*[:=]\\s*)([^\\s'"<>]+)`, 'gi'),
      '$1[REDACTED]',
    )
    .replace(/(Authorization:\s*(?:Basic|Bearer)\s+)([A-Za-z0-9._~+/=-]+)/gi, '$1[REDACTED]');
}

export function redactedConsoleLinesFromText(text) {
  const redacted = redactLog(text);
  const lines = [];
  let end = redacted.length;
  while (lines.length < MAX_RETAINED_LOG_LINES && end >= 0) {
    const newline = redacted.lastIndexOf('\n', end - 1);
    const start = newline + 1;
    const line = redacted.slice(start, end).replace(/\r$/, '');
    lines.push(limitRetainedLogLine(line));
    if (newline < 0) {
      end = -1;
      break;
    }
    end = newline;
  }
  lines.reverse();
  if (end >= 0) {
    lines[0] = '[earlier log lines omitted]';
  }
  return lines;
}

function limitRetainedLogLine(line) {
  if (Buffer.byteLength(line, 'utf8') <= MAX_RETAINED_LOG_LINE_BYTES) {
    return line;
  }
  const suffix = ' [line truncated]';
  const byteBudget = MAX_RETAINED_LOG_LINE_BYTES - Buffer.byteLength(suffix, 'utf8');
  let prefix = '';
  let bytes = 0;
  for (const character of line) {
    const characterBytes = Buffer.byteLength(character, 'utf8');
    if (bytes + characterBytes > byteBudget) {
      break;
    }
    prefix += character;
    bytes += characterBytes;
  }
  return `${prefix}${suffix}`;
}

function buildId(node) {
  const fromUrl = buildIdFromUrl(node.buildUrl);
  if (fromUrl) {
    return fromUrl;
  }
  return node.buildUrl;
}

function buildIdFromUrl(value) {
  try {
    const url = new URL(value);
    const parts = url.pathname.split('/').filter(Boolean);
    const jobs = [];
    for (let index = 0; index < parts.length; index += 1) {
      if (parts[index] === 'job' && parts[index + 1]) {
        jobs.push(decodeURIComponent(parts[index + 1]));
        index += 1;
      }
    }
    const buildNumber = parts.at(-1);
    if (jobs.length === 0 || !/^\d+$/.test(buildNumber)) {
      return null;
    }
    return `${jobs.join('/')}#${buildNumber}`;
  } catch (_) {
    return null;
  }
}

function nodePriority(node) {
  const hasInfra = node.infra_signals.length > 0 ? 0 : 1;
  const rolePriority = node.role === 'failed_job' ? 0 : node.role === 'failed_trigger_job' ? 1 : 2;
  const failureHandlerPenalty = node.failure_handler ? 2 : 0;
  return (rolePriority + failureHandlerPenalty) * 10 + hasInfra;
}

function isFailureHandler(value) {
  return /handler[-_ ]failure|failure[-_ ]handler/i.test(value);
}

function isTriggerJob(value) {
  return /(?:^|[ »/_-])Trigger[-_]/i.test(value);
}

function safeFileName(value) {
  const safe = String(value)
    .replace(/\s+#\d+$/, '')
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 160);
  return safe || 'jenkins-build';
}

export function jenkinsLogFileName(report, buildUrl) {
  const label = safeFileName(report.fullDisplayName || buildUrl);
  const number = safeFileName(report.number || 'unknown');
  const digest = createHash('sha256').update(String(buildUrl)).digest('hex').slice(0, 12);
  return `${label}-${number}-${digest}.log`;
}

async function loadJenkinsConfig(envFile) {
  const fileEnv = parseEnvFile(await fs.readFile(envFile, 'utf8'));
  const baseUrl = fileEnv.BASE_URL || process.env.JENKINS_BASE_URL;
  const username = fileEnv.USERNAME || fileEnv.JENKINS_USERNAME || process.env.JENKINS_USERNAME;
  const token = fileEnv.TOKEN || fileEnv.JENKINS_TOKEN || process.env.JENKINS_TOKEN;

  if (!baseUrl || !username || !token) {
    throw new Error('jenkins env requires BASE_URL, USERNAME, and TOKEN');
  }

  return {
    baseUrl: normalizeBaseUrl(baseUrl),
    username,
    token,
  };
}

async function get(url, config, options = {}) {
  normalizeJenkinsUrl(url.toString(), config.baseUrl);
  const response = await fetch(url, {
    method: 'GET',
    redirect: 'manual',
    headers: {
      Authorization: `Basic ${Buffer.from(`${config.username}:${config.token}`).toString('base64')}`,
      Accept: 'application/json,text/plain,*/*',
    },
    signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`GET ${url.pathname} failed status=${response.status}`);
  }
  return response;
}

function parseArgs(args) {
  const options = {
    command: null,
    envFile: DEFAULT_ENV_FILE,
    artifactDir: null,
    url: null,
    text: null,
    tailLines: DEFAULT_TAIL_LINES,
    limits: {
      maxNodes: DEFAULT_MAX_NODES,
      maxTotalLogBytes: DEFAULT_MAX_TOTAL_LOG_BYTES,
      maxLogBytesPerNode: DEFAULT_MAX_LOG_BYTES_PER_NODE,
      maxApiResponseBytes: DEFAULT_MAX_API_RESPONSE_BYTES,
      maxFetchSeconds: DEFAULT_MAX_FETCH_SECONDS,
      fetchRetries: DEFAULT_FETCH_RETRIES,
      maxParallelFetches: DEFAULT_MAX_PARALLEL_FETCHES,
    },
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--env-file') {
      options.envFile = requiredValue(args, (index += 1), arg);
    } else if (arg === '--artifact-dir') {
      options.artifactDir = requiredValue(args, (index += 1), arg);
    } else if (arg === '--url') {
      options.url = requiredValue(args, (index += 1), arg);
    } else if (arg === '--text') {
      options.text = requiredValue(args, (index += 1), arg);
    } else if (arg === '--tail-lines') {
      options.tailLines = parsePositiveInteger(requiredValue(args, (index += 1), arg));
    } else if (arg === '--max-nodes') {
      options.limits.maxNodes = parsePositiveInteger(requiredValue(args, (index += 1), arg));
    } else if (arg === '--max-total-log-bytes') {
      options.limits.maxTotalLogBytes = parsePositiveInteger(requiredValue(args, (index += 1), arg));
    } else if (arg === '--max-log-bytes-per-node') {
      options.limits.maxLogBytesPerNode = parsePositiveInteger(requiredValue(args, (index += 1), arg));
    } else if (arg === '--max-api-response-bytes') {
      options.limits.maxApiResponseBytes = parsePositiveInteger(requiredValue(args, (index += 1), arg));
    } else if (arg === '--max-fetch-seconds') {
      options.limits.maxFetchSeconds = parsePositiveInteger(requiredValue(args, (index += 1), arg));
    } else if (arg === '--fetch-retries') {
      options.limits.fetchRetries = parsePositiveInteger(requiredValue(args, (index += 1), arg));
    } else if (arg === '--max-parallel-fetches') {
      options.limits.maxParallelFetches = parsePositiveInteger(requiredValue(args, (index += 1), arg));
    } else if (!options.command) {
      options.command = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!options.command) {
    throw new Error('command is required: extract-urls or diagnose');
  }
  return options;
}

function requiredValue(args, index, flag) {
  const value = args[index];
  if (!value || value.startsWith('--')) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function parsePositiveInteger(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`expected positive integer, got ${value}`);
  }
  return parsed;
}

function parseEnvValue(value) {
  if (value.length >= 2) {
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.at(-1) === quote) {
      return value.slice(1, -1);
    }
  }
  return value.replace(/\s+#.*$/, '').trim();
}

function normalizeBaseUrl(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:') {
    throw new Error('BASE_URL must use https');
  }
  if (!url.pathname.endsWith('/')) {
    url.pathname = `${url.pathname}/`;
  }
  url.search = '';
  url.hash = '';
  return url;
}

function trimTrailingUrlPunctuation(value) {
  return value.replace(/[.,;:!?]+$/g, '');
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function isDirectRun() {
  return process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
}

if (isDirectRun()) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
