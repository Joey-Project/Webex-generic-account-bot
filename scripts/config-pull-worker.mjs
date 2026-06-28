#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { TextDecoder } from 'node:util';
import { pathToFileURL } from 'node:url';

export const DEFAULTS = Object.freeze({
  socketPath: '/run/webex-config-pull/config-pull.sock',
  stateRoot: '/var/lib/webex-generic-account-bot/config-actions',
  queueDir: '/var/lib/webex-generic-account-bot/config-actions/queue',
  stateDir: '/var/lib/webex-generic-account-bot/config-actions/state',
  publicStatusFile: '/var/lib/webex-generic-account-bot/config-actions/public-status.json',
  stagedConfigFile:
    '/var/lib/webex-generic-account-bot/config-staging/production.toml.staged',
  stagedMetadataFile:
    '/var/lib/webex-generic-account-bot/config-staging/production.toml.staged.json',
  requestTimeoutMs: 5_000,
  commandTimeoutMs: 900_000,
  outputLimitBytes: 64 * 1024,
});

export const PREPARE_COMMAND = Object.freeze({
  bin: '/usr/bin/node',
  args: Object.freeze([
    '/opt/webex-generic-account-bot/code/scripts/deploy-config.mjs',
    '--prepare',
    '--json',
    '--request-id',
  ]),
});

export const PREPARE_ENV = Object.freeze({
  PATH: '/usr/bin:/bin',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_SYSTEM: '/dev/null',
  GIT_TERMINAL_PROMPT: '0',
  GIT_LFS_SKIP_SMUDGE: '1',
});

export const MAX_REQUEST_BYTES = 4 * 1024;
export const MAX_MESSAGE_ID_BYTES = 256;

const MAX_REQUEST_RECORD_BYTES = 1024;
const MAX_STATE_RECORD_BYTES = 2048;
const MAX_STAGED_CONFIG_BYTES = 4 * 1024 * 1024;
const SOCKET_MODE = 0o660;
const SHARED_DIRECTORY_MODE = 0o750;
const PUBLIC_STATE_ROOT_MODE = 0o755;
const PRIVATE_DIRECTORY_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const PUBLIC_FILE_MODE = 0o644;
const ACTION_ID_PATTERN = /^[0-9a-f]{64}$/;
const CONFIG_REVISION_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const UUID_PATTERN = '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const REQUEST_TEMPORARY_PATTERN = new RegExp(
  `^\\.request-([0-9a-f]{64})-([1-9][0-9]*)-(${UUID_PATTERN})\\.tmp$`,
);
const STATE_TEMPORARY_PATTERN = new RegExp(
  `^\\.atomic-([0-9a-f]{64})\\.json-([1-9][0-9]*)-(${UUID_PATTERN})\\.tmp$`,
);
const PUBLIC_STATUS_TEMPORARY_PATTERN = new RegExp(
  `^\\.atomic-public-status\\.json-([1-9][0-9]*)-(${UUID_PATTERN})\\.tmp$`,
);
const TERMINAL_STATES = new Set(['succeeded', 'failed']);
const ACTION_STATES = new Set(['queued', 'running', ...TERMINAL_STATES]);
const STATE_PROGRESS = Object.freeze({ queued: 0, running: 1, failed: 2, succeeded: 2 });
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
const PREPARED_KEYS = [
  'bot_code_dir',
  'config_ref',
  'config_repo',
  'config_revision',
  'config_sha256',
  'prepared_at',
  'rendered_config',
  'request_id',
  'service',
  'staged_config',
  'status',
  'version',
];
const REQUEST_KEYS = ['action', 'message_id', 'version'];
const REQUEST_RECORD_KEYS = [
  'action',
  'action_id',
  'enqueue_sequence',
  'message_id',
  'version',
];
const STATE_KEYS = [
  'action',
  'action_id',
  'config_revision',
  'config_sha256',
  'enqueue_sequence',
  'failure_code',
  'prepared_at',
  'status',
  'updated_at',
  'version',
];
const PUBLIC_STATUS_KEYS = [
  'action',
  'action_id',
  'config_revision',
  'state',
  'updated_at',
  'version',
];
const PREPARED_POLICY = Object.freeze({
  configRepo: 'git@github.com:WebexServices-staging/webex-generic-account-bot-config.git',
  configRef: 'main',
  botCodeDir: '/opt/webex-generic-account-bot/code',
  renderedConfig: '/var/lib/webex-generic-account-bot/rendered/production.toml',
  stagedConfig: DEFAULTS.stagedConfigFile,
  service: 'webex-generic-account-bot',
});

class ProtocolError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProtocolError';
  }
}

export class WorkerFailure extends Error {
  constructor(code) {
    super(code);
    this.name = 'WorkerFailure';
    this.code = code;
  }
}

export function actionIdForMessageId(messageId) {
  validateMessageId(messageId);
  return createHash('sha256').update(messageId, 'utf8').digest('hex');
}

export function validateEnqueueRequest(value) {
  try {
    assertExactObject(value, REQUEST_KEYS, 'request');
    if (value.version !== 1 || value.action !== 'pull') {
      throw new ProtocolError('unsupported request');
    }
    validateMessageId(value.message_id);
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    throw new ProtocolError('request schema is invalid');
  }
  return Object.freeze({
    version: 1,
    action: 'pull',
    message_id: value.message_id,
  });
}

export function parsePreparedResult(encoded, expectedActionId) {
  validateActionId(expectedActionId);
  const buffer = Buffer.isBuffer(encoded) ? encoded : Buffer.from(encoded);
  if (buffer.length === 0 || buffer.length > DEFAULTS.outputLimitBytes) {
    throw new WorkerFailure('prepare_output_invalid');
  }

  let parsed;
  try {
    parsed = JSON.parse(UTF8_DECODER.decode(buffer));
  } catch (_) {
    throw new WorkerFailure('prepare_output_invalid');
  }
  return preparedProjectionFromValue(parsed, expectedActionId);
}

export async function readPreparedMetadataForAction({
  stagedMetadataFile = DEFAULTS.stagedMetadataFile,
  actionId,
  fsApi = fs,
}) {
  validateActionId(actionId);
  const metadata = await readBoundedJsonFile(
    stagedMetadataFile,
    DEFAULTS.outputLimitBytes,
    PRIVATE_FILE_MODE,
    fsApi,
  );
  return preparedProjectionFromValue(metadata, actionId);
}

async function readDurablePreparedResultForAction({
  stagedConfigFile,
  stagedMetadataFile,
  actionId,
  fsApi,
}) {
  validateActionId(actionId);
  const directories = [
    ...new Set([path.dirname(stagedConfigFile), path.dirname(stagedMetadataFile)]),
  ];
  let configRecord = null;
  let metadataRecord = null;

  try {
    for (const directory of directories) {
      await assertTrustedDirectory(directory, PRIVATE_DIRECTORY_MODE, fsApi);
    }
    metadataRecord = await openBoundedRegularFile(
      stagedMetadataFile,
      DEFAULTS.outputLimitBytes,
      PRIVATE_FILE_MODE,
      fsApi,
    );
    const metadata = parseBoundedJson(metadataRecord.contents, stagedMetadataFile);
    const prepared = preparedProjectionFromValue(metadata, actionId);

    configRecord = await openBoundedRegularFile(
      stagedConfigFile,
      MAX_STAGED_CONFIG_BYTES,
      PRIVATE_FILE_MODE,
      fsApi,
    );
    const digest = createHash('sha256').update(configRecord.contents).digest('hex');
    if (digest !== prepared.configSha256) {
      throw new Error(`staged config digest mismatch: ${stagedConfigFile}`);
    }

    await configRecord.handle.sync();
    await metadataRecord.handle.sync();
    for (const directory of directories) await syncDirectory(directory, fsApi);
    await assertPublishedFileIdentity(stagedConfigFile, configRecord, fsApi);
    await assertPublishedFileIdentity(stagedMetadataFile, metadataRecord, fsApi);
    return prepared;
  } finally {
    await configRecord?.handle.close().catch(() => {});
    await metadataRecord?.handle.close().catch(() => {});
  }
}

export async function prepareStorage({
  stateRoot,
  queueDir,
  stateDir,
  fsApi = fs,
}) {
  await assertTrustedStateRootAncestors(stateRoot, fsApi);
  await ensureTrustedDirectory(stateRoot, PUBLIC_STATE_ROOT_MODE, fsApi);
  await ensureTrustedDirectory(queueDir, PRIVATE_DIRECTORY_MODE, fsApi);
  await ensureTrustedDirectory(stateDir, PRIVATE_DIRECTORY_MODE, fsApi);
}

export async function publishRequestRecord({
  queueDir,
  request,
  enqueueSequence,
  fsApi = fs,
}) {
  const validated = validateEnqueueRequest(request);
  validateEnqueueSequence(enqueueSequence);
  const actionId = actionIdForMessageId(validated.message_id);
  const record = Object.freeze({
    version: 1,
    action_id: actionId,
    action: 'pull',
    enqueue_sequence: enqueueSequence,
    message_id: validated.message_id,
  });
  const finalPath = requestRecordPath(queueDir, actionId);
  const temporary = path.join(
    queueDir,
    `.request-${actionId}-${process.pid}-${randomUUID()}.tmp`,
  );
  const payload = encodeBoundedJson(record, MAX_REQUEST_RECORD_BYTES, 'request record');
  let handle = null;
  let linked = false;
  let temporaryIdentity = null;

  try {
    handle = await fsApi.open(temporary, 'wx', PRIVATE_FILE_MODE);
    await handle.chmod(PRIVATE_FILE_MODE);
    await handle.writeFile(payload);
    await handle.sync();
    temporaryIdentity = await handle.stat();
    await handle.close();
    handle = null;

    try {
      await fsApi.link(temporary, finalPath);
      linked = true;
    } catch (error) {
      if (!error || error.code !== 'EEXIST') {
        throw error;
      }
      await fsApi.unlink(temporary);
      const existing = await readRequestRecord(queueDir, actionId, fsApi);
      await syncDirectory(queueDir, fsApi);
      if (!sameRequestRecord(existing, record)) {
        throw new Error(`request record conflict: ${actionId}`);
      }
      return Object.freeze({ status: 'existing', actionId, record: existing });
    }

    await fsApi.unlink(temporary);
    await syncDirectory(queueDir, fsApi);
    return Object.freeze({ status: 'queued', actionId, record });
  } catch (error) {
    if (linked) {
      try {
        const published = await fsApi.lstat(finalPath);
        if (temporaryIdentity && sameFileIdentity(published, temporaryIdentity)) {
          await fsApi.unlink(finalPath);
        }
        await syncDirectory(queueDir, fsApi);
      } catch (cleanupError) {
        throw new Error(
          `request publication failed and cleanup was incomplete: ${cleanupError.code || 'unknown'}`,
          { cause: error },
        );
      }
    }
    throw error;
  } finally {
    if (handle) {
      await handle.close().catch(() => {});
    }
    await fsApi.unlink(temporary).catch((error) => {
      if (error?.code !== 'ENOENT') {
        throw error;
      }
    });
  }
}

export async function readRequestRecord(queueDir, actionId, fsApi = fs) {
  validateActionId(actionId);
  const record = await readBoundedJsonFile(
    requestRecordPath(queueDir, actionId),
    MAX_REQUEST_RECORD_BYTES,
    PRIVATE_FILE_MODE,
    fsApi,
  );
  validateRequestRecord(record, actionId);
  return record;
}

export async function writeActionState({ stateDir, state, fsApi = fs }) {
  validateActionState(state);
  const file = stateRecordPath(stateDir, state.action_id);
  await writeJsonAtomically(file, state, PRIVATE_FILE_MODE, MAX_STATE_RECORD_BYTES, fsApi);
}

export async function readActionState(stateDir, actionId, fsApi = fs) {
  validateActionId(actionId);
  try {
    const state = await readBoundedJsonFile(
      stateRecordPath(stateDir, actionId),
      MAX_STATE_RECORD_BYTES,
      PRIVATE_FILE_MODE,
      fsApi,
    );
    validateActionState(state, actionId);
    return state;
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

export async function writePublicStatus({ publicStatusFile, state, fsApi = fs }) {
  validateActionState(state);
  const status = {
    version: 1,
    action_id: state.action_id,
    action: 'pull',
    state: state.status,
    config_revision: state.config_revision,
    updated_at: state.updated_at,
  };
  assertExactObject(status, PUBLIC_STATUS_KEYS, 'public status');
  await writeJsonAtomically(
    publicStatusFile,
    status,
    PUBLIC_FILE_MODE,
    MAX_STATE_RECORD_BYTES,
    fsApi,
  );
}

export async function runPrepareCommand({
  actionId,
  spawnImpl = spawn,
  timeoutMs = DEFAULTS.commandTimeoutMs,
  outputLimitBytes = DEFAULTS.outputLimitBytes,
  signal = null,
  killImpl = process.kill.bind(process),
} = {}) {
  validateActionId(actionId);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 3_600_000) {
    throw new WorkerFailure('prepare_policy_invalid');
  }
  if (
    !Number.isSafeInteger(outputLimitBytes)
    || outputLimitBytes <= 0
    || outputLimitBytes > 1024 * 1024
  ) {
    throw new WorkerFailure('prepare_policy_invalid');
  }
  if (signal?.aborted) {
    throw new WorkerFailure('worker_stopping');
  }

  return await new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImpl(PREPARE_COMMAND.bin, [...PREPARE_COMMAND.args, actionId], {
        cwd: '/',
        env: { ...PREPARE_ENV },
        shell: false,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (_) {
      reject(new WorkerFailure('prepare_spawn_failed'));
      return;
    }

    if (!child?.stdout || !child?.stderr) {
      reject(new WorkerFailure('prepare_spawn_failed'));
      return;
    }

    const stdout = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let failure = null;
    let settled = false;
    let killTimer = null;
    let closeTimer = null;

    const cleanup = () => {
      clearTimeout(timeoutTimer);
      signal?.removeEventListener('abort', onAbort);
      if (killTimer) clearTimeout(killTimer);
      if (closeTimer) clearTimeout(closeTimer);
    };
    const rejectOnce = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const terminate = (error) => {
      if (failure || settled) return;
      failure = error;
      killChild(child, 'SIGTERM', killImpl);
      killTimer = setTimeout(() => {
        killChild(child, 'SIGKILL', killImpl);
        closeTimer = setTimeout(() => {
          child.stdout.destroy();
          child.stderr.destroy();
          rejectOnce(failure);
        }, 1_000);
      }, 1_000);
    };
    const onAbort = () => terminate(new WorkerFailure('worker_stopping'));
    const timeoutTimer = setTimeout(
      () => terminate(new WorkerFailure('prepare_timeout')),
      timeoutMs,
    );

    signal?.addEventListener('abort', onAbort, { once: true });
    child.stdout.on('data', (chunk) => {
      const buffer = Buffer.from(chunk);
      stdoutBytes += buffer.length;
      if (stdoutBytes > outputLimitBytes) {
        terminate(new WorkerFailure('prepare_output_too_large'));
        return;
      }
      stdout.push(buffer);
    });
    child.stderr.on('data', (chunk) => {
      stderrBytes += Buffer.byteLength(chunk);
      if (stderrBytes > outputLimitBytes) {
        terminate(new WorkerFailure('prepare_output_too_large'));
      }
    });
    child.once('error', () => terminate(new WorkerFailure('prepare_spawn_failed')));
    child.once('close', (code, closeSignal) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (failure) {
        reject(failure);
        return;
      }
      if (code !== 0 || closeSignal) {
        reject(new WorkerFailure('prepare_failed'));
        return;
      }
      try {
        resolve(parsePreparedResult(Buffer.concat(stdout, stdoutBytes), actionId));
      } catch (error) {
        reject(error);
      }
    });
  });
}

export async function writeSocketResponse(socket, response) {
  await new Promise((resolve) => {
    let settled = false;
    const settle = () => {
      if (settled) return;
      settled = true;
      resolve();
    };
    const onError = () => settle();
    const onClose = () => {
      socket.off('error', onError);
      settle();
    };
    socket.once('error', onError);
    socket.once('close', onClose);
    try {
      socket.end(response, settle);
    } catch (_) {
      socket.off('error', onError);
      socket.off('close', onClose);
      settle();
    }
  });
}

export class ConfigPullWorker {
  constructor(options = {}) {
    this.options = resolveWorkerOptions(options);
    this.fsApi = options.fsApi || fs;
    this.now = options.now || (() => new Date());
    this.prepareRunner = options.prepareRunner || (({ actionId, signal }) => runPrepareCommand({
      actionId,
      spawnImpl: options.spawnImpl || spawn,
      timeoutMs: this.options.commandTimeoutMs,
      outputLimitBytes: this.options.outputLimitBytes,
      signal,
    }));
    this.server = null;
    this.socketIdentity = null;
    this.connections = new Set();
    this.enqueueTail = Promise.resolve();
    this.nextEnqueueSequence = null;
    this.publicStatusTail = Promise.resolve();
    this.latestPublicState = null;
    this.drainPromise = null;
    this.drainRequested = false;
    this.abortController = new AbortController();
    this.stopping = false;
    this.started = false;
    this.fatalError = null;
    this.fatalPromise = new Promise((resolve) => {
      this.resolveFatal = resolve;
    });
  }

  async start() {
    if (this.started) throw new Error('worker is already started');
    await prepareStorage({ ...this.options, fsApi: this.fsApi });
    await this.#cleanStaleTemporaryFiles();
    await this.#recoverQueue();
    await this.#listen();
    this.started = true;
    setImmediate(() => this.#kickDrain());
    return this;
  }

  async stop() {
    if (this.stopping) return;
    this.stopping = true;
    this.abortController.abort();
    for (const connection of this.connections) connection.destroy();
    if (this.server) {
      await new Promise((resolve) => this.server.close(() => resolve()));
    }
    await this.enqueueTail.catch(() => {});
    await this.drainPromise?.catch(() => {});
    await this.publicStatusTail.catch(() => {});
    await this.#removeOwnedSocket();
    this.started = false;
  }

  async waitForIdle() {
    await new Promise((resolve) => setImmediate(resolve));
    await this.enqueueTail;
    while (this.drainPromise || this.drainRequested) {
      await this.drainPromise;
      await new Promise((resolve) => setImmediate(resolve));
    }
    if (this.fatalError) throw this.fatalError;
  }

  waitForFatal() {
    return this.fatalPromise;
  }

  async #listen() {
    await ensureTrustedDirectory(
      path.dirname(this.options.socketPath),
      SHARED_DIRECTORY_MODE,
      this.fsApi,
    );
    await this.#removeStaleSocket();
    const server = net.createServer({ allowHalfOpen: true }, (socket) => {
      this.connections.add(socket);
      socket.once('close', () => this.connections.delete(socket));
      this.#handleConnection(socket).catch((error) => {
        socket.destroy();
        if (!(error instanceof ProtocolError)) this.#fail(error);
      });
    });
    this.server = server;
    server.on('error', (error) => this.#fail(error));

    await new Promise((resolve, reject) => {
      const onError = (error) => reject(error);
      server.once('error', onError);
      server.listen(this.options.socketPath, () => {
        server.off('error', onError);
        resolve();
      });
    });
    await this.fsApi.chmod(this.options.socketPath, SOCKET_MODE);
    const socketStat = await this.fsApi.lstat(this.options.socketPath);
    assertSocketMetadata(socketStat, this.options.socketPath);
    this.socketIdentity = socketStat;
    await syncDirectory(path.dirname(this.options.socketPath), this.fsApi);
  }

  async #handleConnection(socket) {
    await this.#assertOwnedSocket();
    const request = await readSocketRequest(socket, this.options.requestTimeoutMs);
    const result = await this.#serialEnqueue(request);
    const response = Buffer.from(`${JSON.stringify({
      version: 1,
      status: result.status,
      action: 'pull',
      action_id: result.actionId,
    })}\n`, 'utf8');
    this.#kickDrain();
    await writeSocketResponse(socket, response);
  }

  #serialEnqueue(request) {
    const operation = this.enqueueTail.then(() => this.#enqueue(request));
    this.enqueueTail = operation.catch(() => {});
    return operation;
  }

  async #enqueue(request) {
    validateEnqueueSequence(this.nextEnqueueSequence);
    const publication = await publishRequestRecord({
      queueDir: this.options.queueDir,
      request,
      enqueueSequence: this.nextEnqueueSequence,
      fsApi: this.fsApi,
    });
    if (publication.status === 'queued') {
      this.nextEnqueueSequence = incrementEnqueueSequence(publication.record.enqueue_sequence);
    }
    const existingState = await readActionState(
      this.options.stateDir,
      publication.actionId,
      this.fsApi,
    );
    if (publication.status === 'queued' && existingState) {
      throw new Error(`state exists without an immutable request: ${publication.actionId}`);
    }
    if (!existingState) {
      await this.#persistState(this.#makeState(publication.record, 'queued'));
    } else {
      assertStateMatchesRecord(existingState, publication.record);
      await this.#publishPublicStatus(existingState);
    }
    return publication;
  }

  async #recoverQueue() {
    const records = await this.#listRequestRecords();
    this.nextEnqueueSequence = records.length === 0
      ? 1
      : incrementEnqueueSequence(records.at(-1).enqueue_sequence);
    let newestState = null;
    for (const record of records) {
      let state = await readActionState(this.options.stateDir, record.action_id, this.fsApi);
      if (!state) {
        state = this.#makeState(record, 'queued');
        await writeActionState({ stateDir: this.options.stateDir, state, fsApi: this.fsApi });
      } else {
        assertStateMatchesRecord(state, record);
      }
      if (state.status === 'running') {
        let prepared = null;
        try {
          prepared = await readDurablePreparedResultForAction({
            stagedConfigFile: this.options.stagedConfigFile,
            stagedMetadataFile: this.options.stagedMetadataFile,
            actionId: record.action_id,
            fsApi: this.fsApi,
          });
        } catch (_) {}
        state = prepared
          ? this.#makeState(record, 'succeeded', prepared)
          : this.#makeState(record, 'queued');
        await writeActionState({ stateDir: this.options.stateDir, state, fsApi: this.fsApi });
      }
      if (!newestState || shouldPublishPublicState(state, newestState)) newestState = state;
    }
    if (newestState) {
      await this.#publishPublicStatus(newestState);
    }
  }

  #kickDrain() {
    if (this.stopping || this.fatalError) return;
    if (this.drainPromise) {
      this.drainRequested = true;
      return;
    }
    this.drainRequested = false;
    const operation = this.#drain();
    this.drainPromise = operation
      .catch((error) => this.#fail(error))
      .finally(() => {
        this.drainPromise = null;
        if (this.drainRequested) setImmediate(() => this.#kickDrain());
      });
  }

  async #drain() {
    const records = await this.#listRequestRecords();
    for (const record of records) {
      if (this.stopping) return;
      let state = await readActionState(this.options.stateDir, record.action_id, this.fsApi);
      if (!state) {
        await this.enqueueTail;
        state = await readActionState(this.options.stateDir, record.action_id, this.fsApi);
      }
      if (!state) {
        state = this.#makeState(record, 'queued');
        await this.#persistState(state);
      } else {
        assertStateMatchesRecord(state, record);
      }
      if (TERMINAL_STATES.has(state.status)) continue;
      if (state.status !== 'queued') {
        throw new Error(`request state cannot be drained: ${record.action_id}`);
      }
      await this.#processRecord(record);
    }
  }

  async #processRecord(record) {
    await this.#persistState(this.#makeState(record, 'running'));
    let prepared;
    try {
      prepared = await this.prepareRunner({
        actionId: record.action_id,
        signal: this.abortController.signal,
      });
      validatePreparedProjection(prepared);
    } catch (error) {
      if (this.stopping || this.abortController.signal.aborted) return;
      const failureCode = error instanceof WorkerFailure ? error.code : 'prepare_failed';
      await this.#persistState(this.#makeState(record, 'failed', { failureCode }));
      return;
    }
    await this.#persistState(this.#makeState(record, 'succeeded', prepared));
  }

  async #persistState(state) {
    await writeActionState({ stateDir: this.options.stateDir, state, fsApi: this.fsApi });
    await this.#publishPublicStatus(state);
  }

  #publishPublicStatus(state) {
    validateActionState(state);
    const operation = this.publicStatusTail.then(async () => {
      if (!shouldPublishPublicState(state, this.latestPublicState)) return false;
      await writePublicStatus({
        publicStatusFile: this.options.publicStatusFile,
        state,
        fsApi: this.fsApi,
      });
      this.latestPublicState = state;
      return true;
    });
    this.publicStatusTail = operation.catch(() => {});
    return operation;
  }

  #makeState(record, status, details = {}) {
    const timestamp = this.now();
    const updatedAt = timestamp instanceof Date ? timestamp.toISOString() : String(timestamp);
    const state = {
      version: 1,
      action_id: record.action_id,
      action: 'pull',
      enqueue_sequence: record.enqueue_sequence,
      status,
      config_revision: details.configRevision ?? null,
      config_sha256: details.configSha256 ?? null,
      prepared_at: details.preparedAt ?? null,
      failure_code: details.failureCode ?? null,
      updated_at: updatedAt,
    };
    validateActionState(state);
    return state;
  }

  async #listRequestRecords() {
    const entries = await this.fsApi.readdir(this.options.queueDir, { withFileTypes: true });
    const records = [];
    const sequences = new Set();
    for (const { name } of entries) {
      if (REQUEST_TEMPORARY_PATTERN.test(name)) {
        await this.#assertTrustedTemporaryFile(path.join(this.options.queueDir, name));
        continue;
      }
      if (!/^[0-9a-f]{64}\.json$/.test(name)) {
        throw new Error(`unexpected queue entry: ${name}`);
      }
      const actionId = name.slice(0, -'.json'.length);
      const record = await readRequestRecord(this.options.queueDir, actionId, this.fsApi);
      if (sequences.has(record.enqueue_sequence)) {
        throw new Error(`duplicate enqueue sequence: ${record.enqueue_sequence}`);
      }
      sequences.add(record.enqueue_sequence);
      records.push(record);
    }
    return records.sort((left, right) => left.enqueue_sequence - right.enqueue_sequence);
  }

  async #cleanStaleTemporaryFiles() {
    for (const [directory, pattern, expectedMode] of [
      [this.options.stateRoot, PUBLIC_STATUS_TEMPORARY_PATTERN, PUBLIC_FILE_MODE],
      [this.options.queueDir, REQUEST_TEMPORARY_PATTERN, PRIVATE_FILE_MODE],
      [this.options.stateDir, STATE_TEMPORARY_PATTERN, PRIVATE_FILE_MODE],
    ]) {
      const entries = await this.fsApi.readdir(directory, { withFileTypes: true });
      let changed = false;
      for (const entry of entries) {
        const hasTemporaryPrefix = entry.name.startsWith('.request-')
          || entry.name.startsWith('.atomic-');
        if (!hasTemporaryPrefix) continue;
        if (!pattern.test(entry.name)) {
          throw new Error(`unexpected temporary entry: ${entry.name}`);
        }
        const temporary = path.join(directory, entry.name);
        const stat = await this.fsApi.lstat(temporary);
        assertOwnedRegularTemporaryFile(stat, temporary, expectedMode);
        await this.fsApi.unlink(temporary);
        changed = true;
      }
      if (changed) await syncDirectory(directory, this.fsApi);
    }
  }

  async #assertTrustedTemporaryFile(temporary) {
    try {
      const stat = await this.fsApi.lstat(temporary);
      assertOwnedRegularTemporaryFile(stat, temporary, PRIVATE_FILE_MODE);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }

  async #removeStaleSocket() {
    let stat;
    try {
      stat = await this.fsApi.lstat(this.options.socketPath);
    } catch (error) {
      if (error?.code === 'ENOENT') return;
      throw error;
    }
    if (!stat.isSocket() || stat.isSymbolicLink()) {
      throw new Error(`socket path is not a socket: ${this.options.socketPath}`);
    }
    if (await socketAcceptsConnections(this.options.socketPath)) {
      throw new Error(`socket path is already active: ${this.options.socketPath}`);
    }
    const current = await this.fsApi.lstat(this.options.socketPath);
    if (!sameFileIdentity(stat, current) || !current.isSocket()) {
      throw new Error(`socket path changed during startup: ${this.options.socketPath}`);
    }
    await this.fsApi.unlink(this.options.socketPath);
    await syncDirectory(path.dirname(this.options.socketPath), this.fsApi);
  }

  async #assertOwnedSocket() {
    const current = await this.fsApi.lstat(this.options.socketPath);
    assertSocketMetadata(current, this.options.socketPath);
    if (!this.socketIdentity || !sameFileIdentity(current, this.socketIdentity)) {
      throw new Error(`socket path was replaced: ${this.options.socketPath}`);
    }
  }

  async #removeOwnedSocket() {
    if (!this.socketIdentity) return;
    try {
      const current = await this.fsApi.lstat(this.options.socketPath);
      if (sameFileIdentity(current, this.socketIdentity) && current.isSocket()) {
        await this.fsApi.unlink(this.options.socketPath);
        await syncDirectory(path.dirname(this.options.socketPath), this.fsApi);
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    this.socketIdentity = null;
  }

  #fail(error) {
    if (this.fatalError || this.stopping) return;
    this.fatalError = error instanceof Error ? error : new Error('worker failed');
    this.resolveFatal(this.fatalError);
  }
}

export async function runCli({
  argv = process.argv.slice(2),
  stderr = process.stderr,
  processApi = process,
  worker = null,
} = {}) {
  if (argv.length !== 0) {
    stderr.write('config pull worker does not accept command-line arguments\n');
    return 2;
  }
  const activeWorker = worker || new ConfigPullWorker();
  let resolveSignal;
  const signalPromise = new Promise((resolve) => {
    resolveSignal = resolve;
  });
  const onSignal = () => resolveSignal(null);
  processApi.once('SIGINT', onSignal);
  processApi.once('SIGTERM', onSignal);
  try {
    await activeWorker.start();
    const fatal = await Promise.race([signalPromise, activeWorker.waitForFatal()]);
    return fatal ? 1 : 0;
  } catch (_) {
    stderr.write('config pull worker failed\n');
    return 1;
  } finally {
    processApi.off('SIGINT', onSignal);
    processApi.off('SIGTERM', onSignal);
    await activeWorker.stop().catch(() => {});
  }
}

async function readSocketRequest(socket, timeoutMs) {
  const contents = await new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let settled = false;
    const cleanup = () => {
      socket.setTimeout(0);
      socket.off('data', onData);
      socket.off('end', onEnd);
      socket.off('error', onError);
      socket.off('timeout', onTimeout);
    };
    const rejectOnce = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onData = (chunk) => {
      length += chunk.length;
      if (length > MAX_REQUEST_BYTES) {
        rejectOnce(new ProtocolError('request is too large'));
        socket.destroy();
        return;
      }
      chunks.push(Buffer.from(chunk));
    };
    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks, length));
    };
    const onError = () => rejectOnce(new ProtocolError('request read failed'));
    const onTimeout = () => {
      rejectOnce(new ProtocolError('request timed out'));
      socket.destroy();
    };
    socket.on('data', onData);
    socket.once('end', onEnd);
    socket.once('error', onError);
    socket.once('timeout', onTimeout);
    socket.setTimeout(timeoutMs);
  });
  const length = contents.length;
  if (length === 0) throw new ProtocolError('request is empty');
  let parsed;
  try {
    parsed = JSON.parse(UTF8_DECODER.decode(contents));
  } catch (_) {
    throw new ProtocolError('request is not valid JSON');
  }
  return validateEnqueueRequest(parsed);
}

async function readBoundedJsonFile(file, maxBytes, expectedMode, fsApi) {
  let record = null;
  try {
    record = await openBoundedRegularFile(file, maxBytes, expectedMode, fsApi);
    return parseBoundedJson(record.contents, file);
  } finally {
    await record?.handle.close().catch(() => {});
  }
}

async function openBoundedRegularFile(file, maxBytes, expectedMode, fsApi) {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await fsApi.open(file, flags);
    const stat = await handle.stat();
    assertOwnedRegularFile(stat, file, expectedMode);
    if (stat.size <= 0 || stat.size > maxBytes) throw new Error(`record size is invalid: ${file}`);
    const contents = await readFileHandleBounded(handle, maxBytes);
    if (contents.length <= 0 || contents.length > maxBytes) {
      throw new Error(`record size is invalid: ${file}`);
    }
    const finalStat = await handle.stat();
    assertOwnedRegularFile(finalStat, file, expectedMode);
    if (!sameFileIdentity(stat, finalStat) || finalStat.size !== contents.length) {
      throw new Error(`record changed while reading: ${file}`);
    }
    return { handle, stat: finalStat, contents };
  } catch (error) {
    await handle?.close().catch(() => {});
    throw error;
  }
}

async function readFileHandleBounded(handle, maxBytes) {
  const buffer = Buffer.alloc(maxBytes + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      buffer.length - offset,
      offset,
    );
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  return buffer.subarray(0, offset);
}

function parseBoundedJson(contents, file) {
  try {
    return JSON.parse(UTF8_DECODER.decode(contents));
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof TypeError) {
      throw new Error(`record is corrupt: ${file}`);
    }
    throw error;
  }
}

async function writeJsonAtomically(file, value, mode, maxBytes, fsApi) {
  const directory = path.dirname(file);
  const temporary = path.join(
    directory,
    `.atomic-${path.basename(file)}-${process.pid}-${randomUUID()}.tmp`,
  );
  const payload = encodeBoundedJson(value, maxBytes, 'state record');
  let handle = null;
  try {
    try {
      const current = await fsApi.lstat(file);
      assertOwnedRegularFile(current, file, mode);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    handle = await fsApi.open(temporary, 'wx', mode);
    await handle.chmod(mode);
    await handle.writeFile(payload);
    await handle.sync();
    await handle.close();
    handle = null;
    await fsApi.rename(temporary, file);
    await syncDirectory(directory, fsApi);
    const published = await fsApi.lstat(file);
    assertOwnedRegularFile(published, file, mode);
  } finally {
    await handle?.close().catch(() => {});
    await fsApi.unlink(temporary).catch((error) => {
      if (error?.code !== 'ENOENT') throw error;
    });
  }
}

async function ensureTrustedDirectory(directory, mode, fsApi) {
  if (!path.isAbsolute(directory)) throw new Error(`directory must be absolute: ${directory}`);
  await assertNoSymlinkComponents(directory, fsApi);
  await fsApi.mkdir(directory, { recursive: true, mode });
  await assertNoSymlinkComponents(directory, fsApi);
  const stat = await fsApi.lstat(directory);
  const actualMode = stat.mode & 0o7777;
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.uid !== currentUid(stat.uid)
    || stat.gid !== currentGid(stat.gid)
    || actualMode !== mode
  ) {
    throw new Error(`directory metadata is not trusted: ${directory}`);
  }
}

async function assertTrustedDirectory(directory, mode, fsApi) {
  if (!path.isAbsolute(directory)) throw new Error(`directory must be absolute: ${directory}`);
  await assertNoSymlinkComponents(directory, fsApi);
  const stat = await fsApi.lstat(directory);
  const actualMode = stat.mode & 0o7777;
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.uid !== currentUid(stat.uid)
    || stat.gid !== currentGid(stat.gid)
    || actualMode !== mode
  ) {
    throw new Error(`directory metadata is not trusted: ${directory}`);
  }
}

async function assertTrustedStateRootAncestors(stateRoot, fsApi) {
  if (!path.isAbsolute(stateRoot)) {
    throw new Error(`state root must be absolute: ${stateRoot}`);
  }
  const ancestors = [];
  let current = path.dirname(path.resolve(stateRoot));
  for (;;) {
    ancestors.push(current);
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }

  for (const ancestor of ancestors.reverse()) {
    const stat = await fsApi.lstat(ancestor);
    const actualMode = stat.mode & 0o7777;
    const writableByNonRoot = (actualMode & 0o022) !== 0;
    const allowedStickyTemporaryAncestor = ancestor === '/tmp'
      && (actualMode & 0o1000) !== 0;
    if (
      !stat.isDirectory()
      || stat.isSymbolicLink()
      || stat.uid !== 0
      || stat.gid !== 0
      || (writableByNonRoot && !allowedStickyTemporaryAncestor)
    ) {
      throw new Error(`state root ancestor metadata is not trusted: ${ancestor}`);
    }
  }
}

async function assertNoSymlinkComponents(target, fsApi) {
  const resolved = path.resolve(target);
  const parts = resolved.split(path.sep).filter(Boolean);
  let current = path.parse(resolved).root;
  for (const part of parts) {
    current = path.join(current, part);
    try {
      const stat = await fsApi.lstat(current);
      if (stat.isSymbolicLink()) throw new Error(`path contains a symlink: ${current}`);
    } catch (error) {
      if (error?.code === 'ENOENT') return;
      throw error;
    }
  }
}

async function syncDirectory(directory, fsApi) {
  const handle = await fsApi.open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function resolveWorkerOptions(options) {
  const stateRoot = path.resolve(options.stateRoot || DEFAULTS.stateRoot);
  const resolved = {
    socketPath: path.resolve(options.socketPath || DEFAULTS.socketPath),
    stateRoot,
    queueDir: path.resolve(options.queueDir || path.join(stateRoot, 'queue')),
    stateDir: path.resolve(options.stateDir || path.join(stateRoot, 'state')),
    publicStatusFile: path.resolve(
      options.publicStatusFile || path.join(stateRoot, 'public-status.json'),
    ),
    stagedConfigFile: path.resolve(options.stagedConfigFile || DEFAULTS.stagedConfigFile),
    stagedMetadataFile: path.resolve(options.stagedMetadataFile || DEFAULTS.stagedMetadataFile),
    requestTimeoutMs: options.requestTimeoutMs || DEFAULTS.requestTimeoutMs,
    commandTimeoutMs: options.commandTimeoutMs || DEFAULTS.commandTimeoutMs,
    outputLimitBytes: options.outputLimitBytes || DEFAULTS.outputLimitBytes,
  };
  for (const [label, candidate] of [
    ['queue directory', resolved.queueDir],
    ['state directory', resolved.stateDir],
    ['public status file', resolved.publicStatusFile],
  ]) {
    if (!isStrictSubpath(stateRoot, candidate)) {
      throw new Error(`${label} must be inside the state root`);
    }
  }
  if (resolved.queueDir === resolved.stateDir) {
    throw new Error('queue and state directories must be separate');
  }
  return Object.freeze(resolved);
}

function validateMessageId(messageId) {
  if (
    typeof messageId !== 'string'
    || messageId.length === 0
    || Buffer.byteLength(messageId, 'utf8') > MAX_MESSAGE_ID_BYTES
    || [...messageId].some((character) => {
      const code = character.codePointAt(0);
      return code > 0x7f || code < 0x20 || code === 0x7f;
    })
  ) {
    throw new ProtocolError('message_id is invalid');
  }
}

function validateRequestRecord(record, expectedActionId) {
  assertExactObject(record, REQUEST_RECORD_KEYS, 'request record');
  validateEnqueueSequence(record.enqueue_sequence);
  const request = validateEnqueueRequest({
    version: record.version,
    action: record.action,
    message_id: record.message_id,
  });
  const derived = actionIdForMessageId(request.message_id);
  if (record.action_id !== derived || record.action_id !== expectedActionId) {
    throw new Error(`request record identity mismatch: ${expectedActionId}`);
  }
}

function validateActionState(state, expectedActionId = null) {
  assertExactObject(state, STATE_KEYS, 'action state');
  validateActionId(state.action_id);
  validateEnqueueSequence(state.enqueue_sequence);
  if (expectedActionId && state.action_id !== expectedActionId) {
    throw new Error(`state identity mismatch: ${expectedActionId}`);
  }
  if (state.version !== 1 || state.action !== 'pull' || !ACTION_STATES.has(state.status)) {
    throw new Error('action state has an unsupported value');
  }
  validateIsoTimestamp(state.updated_at, 'updated_at');
  if (state.status === 'succeeded') {
    if (
      !CONFIG_REVISION_PATTERN.test(state.config_revision ?? '')
      || !SHA256_PATTERN.test(state.config_sha256 ?? '')
      || state.failure_code !== null
    ) {
      throw new Error('succeeded state is invalid');
    }
    validateIsoTimestamp(state.prepared_at, 'prepared_at');
  } else if (state.status === 'failed') {
    if (
      state.config_revision !== null
      || state.config_sha256 !== null
      || state.prepared_at !== null
      || typeof state.failure_code !== 'string'
      || !/^[a-z0-9_]{1,64}$/.test(state.failure_code)
    ) {
      throw new Error('failed state is invalid');
    }
  } else if (
    state.config_revision !== null
    || state.config_sha256 !== null
    || state.prepared_at !== null
    || state.failure_code !== null
  ) {
    throw new Error('non-terminal state contains terminal details');
  }
}

function validatePreparedProjection(prepared) {
  if (!prepared || typeof prepared !== 'object' || Array.isArray(prepared)) {
    throw new WorkerFailure('prepare_output_invalid');
  }
  const keys = Object.keys(prepared).sort();
  if (keys.join('\0') !== ['configRevision', 'configSha256', 'preparedAt'].join('\0')) {
    throw new WorkerFailure('prepare_output_invalid');
  }
  if (
    !CONFIG_REVISION_PATTERN.test(prepared.configRevision ?? '')
    || !SHA256_PATTERN.test(prepared.configSha256 ?? '')
  ) {
    throw new WorkerFailure('prepare_output_invalid');
  }
  try {
    validateIsoTimestamp(prepared.preparedAt, 'preparedAt');
  } catch (_) {
    throw new WorkerFailure('prepare_output_invalid');
  }
}

function preparedProjectionFromValue(parsed, expectedActionId) {
  try {
    assertExactObject(parsed, PREPARED_KEYS, 'prepared result');
    if (
      parsed.version !== 1
      || parsed.status !== 'prepared'
      || parsed.request_id !== expectedActionId
    ) {
      throw new Error('unsupported prepared result');
    }
    if (
      parsed.config_repo !== PREPARED_POLICY.configRepo
      || parsed.config_ref !== PREPARED_POLICY.configRef
      || parsed.bot_code_dir !== PREPARED_POLICY.botCodeDir
      || parsed.rendered_config !== PREPARED_POLICY.renderedConfig
      || parsed.staged_config !== PREPARED_POLICY.stagedConfig
      || parsed.service !== PREPARED_POLICY.service
    ) {
      throw new Error('prepared result violates host policy');
    }
    if (!CONFIG_REVISION_PATTERN.test(parsed.config_revision)) {
      throw new Error('invalid config revision');
    }
    if (!SHA256_PATTERN.test(parsed.config_sha256)) {
      throw new Error('invalid config digest');
    }
    validateIsoTimestamp(parsed.prepared_at, 'prepared_at');
  } catch (_) {
    throw new WorkerFailure('prepare_output_invalid');
  }

  return Object.freeze({
    configRevision: parsed.config_revision,
    configSha256: parsed.config_sha256,
    preparedAt: parsed.prepared_at,
  });
}

function assertExactObject(value, expectedKeys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const keys = Object.keys(value).sort();
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
}

function validateIsoTimestamp(value, label) {
  if (typeof value !== 'string' || value.length > 32) {
    throw new Error(`${label} is invalid`);
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error(`${label} is invalid`);
  }
}

function validateActionId(actionId) {
  if (!ACTION_ID_PATTERN.test(actionId ?? '')) throw new Error('action ID is invalid');
}

function validateEnqueueSequence(sequence) {
  if (!Number.isSafeInteger(sequence) || sequence <= 0) {
    throw new Error('enqueue sequence is invalid');
  }
}

function incrementEnqueueSequence(sequence) {
  validateEnqueueSequence(sequence);
  if (sequence === Number.MAX_SAFE_INTEGER) {
    throw new Error('enqueue sequence overflow');
  }
  return sequence + 1;
}

function assertOwnedRegularFile(stat, file, expectedMode) {
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.uid !== currentUid(stat.uid)
    || stat.gid !== currentGid(stat.gid)
    || (stat.mode & 0o7777) !== expectedMode
  ) {
    throw new Error(`record metadata is not trusted: ${file}`);
  }
}

function assertOwnedRegularTemporaryFile(stat, file, finalMode) {
  const actualMode = stat.mode & 0o7777;
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.uid !== currentUid(stat.uid)
    || stat.gid !== currentGid(stat.gid)
    || (actualMode & ~finalMode) !== 0
  ) {
    throw new Error(`record metadata is not trusted: ${file}`);
  }
}

function assertSocketMetadata(stat, socketPath) {
  if (
    !stat.isSocket()
    || stat.isSymbolicLink()
    || stat.uid !== currentUid(stat.uid)
    || stat.gid !== currentGid(stat.gid)
    || (stat.mode & 0o7777) !== SOCKET_MODE
  ) {
    throw new Error(`socket metadata is not trusted: ${socketPath}`);
  }
}

function encodeBoundedJson(value, maxBytes, label) {
  const encoded = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  if (encoded.length === 0 || encoded.length > maxBytes) {
    throw new Error(`${label} is too large`);
  }
  return encoded;
}

function requestRecordPath(queueDir, actionId) {
  validateActionId(actionId);
  return path.join(queueDir, `${actionId}.json`);
}

function stateRecordPath(stateDir, actionId) {
  validateActionId(actionId);
  return path.join(stateDir, `${actionId}.json`);
}

function sameRequestRecord(left, right) {
  return left.version === right.version
    && left.action_id === right.action_id
    && left.action === right.action
    && left.message_id === right.message_id;
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function assertPublishedFileIdentity(file, record, fsApi) {
  const current = await fsApi.lstat(file);
  assertOwnedRegularFile(current, file, PRIVATE_FILE_MODE);
  if (!sameFileIdentity(current, record.stat) || current.size !== record.contents.length) {
    throw new Error(`record changed before recovery commit: ${file}`);
  }
}

function assertStateMatchesRecord(state, record) {
  if (
    state.action_id !== record.action_id
    || state.enqueue_sequence !== record.enqueue_sequence
  ) {
    throw new Error(`state enqueue sequence mismatch: ${record.action_id}`);
  }
}

function shouldPublishPublicState(candidate, current) {
  if (!current) return true;
  if (candidate.enqueue_sequence < current.enqueue_sequence) return false;
  if (candidate.enqueue_sequence > current.enqueue_sequence) return true;
  if (candidate.action_id !== current.action_id) return false;
  if (candidate.status === current.status) return true;
  if (TERMINAL_STATES.has(current.status)) return false;
  return STATE_PROGRESS[candidate.status] > STATE_PROGRESS[current.status];
}

function currentUid(fallback) {
  return typeof process.getuid === 'function' ? process.getuid() : fallback;
}

function currentGid(fallback) {
  return typeof process.getgid === 'function' ? process.getgid() : fallback;
}

function isStrictSubpath(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative !== '' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function killChild(child, signal, killImpl) {
  if (process.platform !== 'win32' && Number.isInteger(child.pid) && child.pid > 0) {
    try {
      killImpl(-child.pid, signal);
      return;
    } catch (_) {}
  }
  try {
    child.kill(signal);
  } catch (_) {}
}

async function socketAcceptsConnections(socketPath) {
  return await new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath);
    client.once('connect', () => {
      client.destroy();
      resolve(true);
    });
    client.once('error', (error) => {
      client.destroy();
      if (error?.code === 'ECONNREFUSED' || error?.code === 'ENOENT') {
        resolve(false);
      } else {
        reject(error);
      }
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runCli();
}
