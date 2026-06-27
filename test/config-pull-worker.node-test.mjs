import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';

import {
  ConfigPullWorker,
  MAX_REQUEST_BYTES,
  PREPARE_COMMAND,
  PREPARE_ENV,
  WorkerFailure,
  actionIdForMessageId,
  parsePreparedResult,
  prepareStorage,
  publishRequestRecord,
  readActionState,
  runPrepareCommand,
  writeActionState,
  writeSocketResponse,
} from '../scripts/config-pull-worker.mjs';

const CONFIG_REVISION = 'a'.repeat(40);
const CONFIG_SHA256 = 'b'.repeat(64);
const PREPARE_ACTION_ID = 'c'.repeat(64);
const PREPARED_AT = '2026-06-27T12:00:00.000Z';
const PREPARED_RESULT = Object.freeze({
  version: 1,
  status: 'prepared',
  config_repo: 'git@github.com:WebexServices-staging/webex-generic-account-bot-config.git',
  config_ref: 'main',
  config_revision: CONFIG_REVISION,
  config_sha256: CONFIG_SHA256,
  request_id: PREPARE_ACTION_ID,
  bot_code_dir: '/opt/webex-generic-account-bot/code',
  rendered_config: '/var/lib/webex-generic-account-bot/rendered/production.toml',
  staged_config: '/var/lib/webex-generic-account-bot/rendered/production.toml.staged',
  service: 'webex-generic-account-bot',
  prepared_at: PREPARED_AT,
});
const PREPARED_PROJECTION = Object.freeze({
  configRevision: CONFIG_REVISION,
  configSha256: CONFIG_SHA256,
  preparedAt: PREPARED_AT,
});

describe('config pull worker socket protocol', () => {
  it('durably queues before acknowledging over a real Unix socket', async (context) => {
    let releasePrepare;
    const prepareBlocked = new Promise((resolve) => {
      releasePrepare = resolve;
    });
    const fixture = await startWorker(context, {
      prepareRunner: async () => {
        await prepareBlocked;
        return PREPARED_PROJECTION;
      },
    });

    const response = await sendRequest(fixture.socketPath, {
        version: 1,
        message_id: 'webex-message-1',
        action: 'pull',
    });
    const actionId = actionIdForMessageId('webex-message-1');

    assert.deepEqual(response, {
      version: 1,
      status: 'queued',
      action: 'pull',
      action_id: actionId,
    });
    assert.deepEqual(
      JSON.parse(await fs.readFile(path.join(fixture.queueDir, `${actionId}.json`), 'utf8')),
      {
        version: 1,
        action_id: actionId,
        action: 'pull',
        message_id: 'webex-message-1',
      },
    );
    assert.equal((await fs.stat(path.join(fixture.queueDir, `${actionId}.json`))).mode & 0o777, 0o600);
    assert(await readActionState(fixture.stateDir, actionId));

    releasePrepare();
    await fixture.worker.waitForIdle();
  });

  it('returns the same action ID for duplicate requests and executes once', async (context) => {
    let executions = 0;
    const fixture = await startWorker(context, {
      prepareRunner: async () => {
        executions += 1;
        return PREPARED_PROJECTION;
      },
    });
    const request = { version: 1, message_id: 'duplicate-message', action: 'pull' };

    const first = await sendRequest(fixture.socketPath, request);
    await fixture.worker.waitForIdle();
    const second = await sendRequest(fixture.socketPath, request);
    await fixture.worker.waitForIdle();

    assert.equal(first.status, 'queued');
    assert.equal(second.status, 'existing');
    assert.equal(second.action_id, first.action_id);
    assert.equal(executions, 1);
    assert.deepEqual(await fs.readdir(fixture.queueDir), [`${first.action_id}.json`]);
  });

  it('republishes durable public status before acknowledging a duplicate retry', async (context) => {
    const layout = await createLayout(context);
    let failFirstPublicStatusWrite = true;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'open') return target[property];
        return async (file, flags, ...rest) => {
          if (
            failFirstPublicStatusWrite
            && flags === 'wx'
            && typeof file === 'string'
            && path.basename(file).startsWith('.atomic-public-status.json-')
          ) {
            failFirstPublicStatusWrite = false;
            const error = new Error('injected public status write failure');
            error.code = 'EIO';
            throw error;
          }
          return target.open(file, flags, ...rest);
        };
      },
    });
    const worker = new ConfigPullWorker({
      ...layout,
      fsApi,
      prepareRunner: async () => PREPARED_PROJECTION,
    });
    context.after(async () => worker.stop());
    await worker.start();
    const request = { version: 1, message_id: 'retry-after-public-failure', action: 'pull' };
    const actionId = actionIdForMessageId(request.message_id);

    assert.equal(
      (await sendRaw(layout.socketPath, Buffer.from(`${JSON.stringify(request)}\n`))).length,
      0,
    );
    assert.equal((await readActionState(layout.stateDir, actionId)).status, 'queued');
    await assert.rejects(fs.stat(layout.publicStatusFile), { code: 'ENOENT' });

    const retry = await sendRequest(layout.socketPath, request);
    assert.deepEqual(retry, {
      version: 1,
      status: 'existing',
      action: 'pull',
      action_id: actionId,
    });
    const publicStatus = JSON.parse(await fs.readFile(layout.publicStatusFile, 'utf8'));
    assert.equal(publicStatus.action_id, actionId);
    assert.equal(publicStatus.state, 'queued');
    assert.equal((await fs.stat(layout.publicStatusFile)).mode & 0o777, 0o644);
  });

  it('rejects oversized and schema-invalid requests without poisoning the server', async (context) => {
    let executions = 0;
    const fixture = await startWorker(context, {
      prepareRunner: async () => {
        executions += 1;
        return PREPARED_PROJECTION;
      },
    });

    assert.equal((await sendRaw(fixture.socketPath, Buffer.alloc(MAX_REQUEST_BYTES + 1, 0x78))).length, 0);
    assert.equal((await sendRaw(
      fixture.socketPath,
      Buffer.from('{"version":1,"message_id":"bad","action":"pull","extra":true}\n'),
    )).length, 0);
    assert.deepEqual(await fs.readdir(fixture.queueDir), []);

    const valid = await sendRequest(fixture.socketPath, {
      version: 1,
      message_id: 'still-healthy',
      action: 'pull',
    });
    await fixture.worker.waitForIdle();
    assert.equal(valid.status, 'queued');
    assert.equal(executions, 1);
  });

  it('keeps a late response EPIPE at the connection boundary', async () => {
    const socket = new EventEmitter();
    let response;
    socket.end = (payload, callback) => {
      response = Buffer.from(payload);
      callback();
      queueMicrotask(() => {
        const error = new Error('peer disconnected');
        error.code = 'EPIPE';
        socket.emit('error', error);
        socket.emit('close');
      });
    };

    await writeSocketResponse(socket, Buffer.from('{"version":1}\n'));
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(response.toString('utf8'), '{"version":1}\n');
  });
});

describe('config pull worker recovery', () => {
  it('replays a running request after restart', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const request = { version: 1, message_id: 'restart-running', action: 'pull' };
    const publication = await publishRequestRecord({ queueDir: layout.queueDir, request });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(publication.actionId, 'running', '2026-06-27T12:01:00.000Z'),
    });
    let executions = 0;
    const worker = new ConfigPullWorker({
      ...layout,
      prepareRunner: async () => {
        executions += 1;
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => worker.stop());

    await worker.start();
    await worker.waitForIdle();

    const recovered = await readActionState(layout.stateDir, publication.actionId);
    assert.equal(executions, 1);
    assert.equal(recovered.status, 'succeeded');
    assert.equal(recovered.config_revision, CONFIG_REVISION);
  });

  it('commits a matching staged result after a crash before state commit', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const request = { version: 1, message_id: 'prepared-before-crash', action: 'pull' };
    const publication = await publishRequestRecord({ queueDir: layout.queueDir, request });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(publication.actionId, 'running', '2026-06-27T12:01:30.000Z'),
    });
    await fs.writeFile(
      layout.stagedMetadataFile,
      `${JSON.stringify({ ...PREPARED_RESULT, request_id: publication.actionId })}\n`,
      { mode: 0o600 },
    );
    let executions = 0;
    const worker = new ConfigPullWorker({
      ...layout,
      prepareRunner: async () => {
        executions += 1;
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => worker.stop());

    await worker.start();
    await worker.waitForIdle();

    const recovered = await readActionState(layout.stateDir, publication.actionId);
    assert.equal(executions, 0);
    assert.equal(recovered.status, 'succeeded');
    assert.equal(recovered.config_revision, CONFIG_REVISION);
    assert.equal(recovered.config_sha256, CONFIG_SHA256);
  });

  it('reruns a running request when staged metadata belongs to another action', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const request = { version: 1, message_id: 'mismatched-staged-result', action: 'pull' };
    const publication = await publishRequestRecord({ queueDir: layout.queueDir, request });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(publication.actionId, 'running', '2026-06-27T12:01:45.000Z'),
    });
    await fs.writeFile(
      layout.stagedMetadataFile,
      `${JSON.stringify(PREPARED_RESULT)}\n`,
      { mode: 0o600 },
    );
    const runnerActionIds = [];
    const worker = new ConfigPullWorker({
      ...layout,
      prepareRunner: async ({ actionId }) => {
        runnerActionIds.push(actionId);
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => worker.stop());

    await worker.start();
    await worker.waitForIdle();

    assert.deepEqual(runnerActionIds, [publication.actionId]);
    assert.equal((await readActionState(layout.stateDir, publication.actionId)).status, 'succeeded');
  });

  it('skips succeeded and failed terminal requests', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const succeeded = await publishRequestRecord({
      queueDir: layout.queueDir,
      request: { version: 1, message_id: 'already-succeeded', action: 'pull' },
    });
    const failed = await publishRequestRecord({
      queueDir: layout.queueDir,
      request: { version: 1, message_id: 'already-failed', action: 'pull' },
    });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(
        succeeded.actionId,
        'succeeded',
        '2026-06-27T12:02:00.000Z',
        PREPARED_PROJECTION,
      ),
    });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(
        failed.actionId,
        'failed',
        '2026-06-27T12:03:00.000Z',
        { failureCode: 'prepare_failed' },
      ),
    });
    let executions = 0;
    const worker = new ConfigPullWorker({
      ...layout,
      prepareRunner: async () => {
        executions += 1;
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => worker.stop());

    await worker.start();
    await worker.waitForIdle();

    assert.equal(executions, 0);
    assert.equal((await readActionState(layout.stateDir, succeeded.actionId)).status, 'succeeded');
    assert.equal((await readActionState(layout.stateDir, failed.actionId)).status, 'failed');
  });

  it('recovers succeeded state when only final public status persistence fails', async (context) => {
    const layout = await createLayout(context);
    let publicStatusWrites = 0;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'open') return target[property];
        return async (file, flags, ...rest) => {
          if (
            flags === 'wx'
            && typeof file === 'string'
            && path.basename(file).startsWith('.atomic-public-status.json-')
          ) {
            publicStatusWrites += 1;
            if (publicStatusWrites === 3) {
              const error = new Error('injected final public status failure');
              error.code = 'EIO';
              throw error;
            }
          }
          return target.open(file, flags, ...rest);
        };
      },
    });
    const first = new ConfigPullWorker({
      ...layout,
      fsApi,
      prepareRunner: async () => PREPARED_PROJECTION,
    });
    context.after(async () => first.stop());
    await first.start();
    const response = await sendRequest(layout.socketPath, {
      version: 1,
      message_id: 'success-public-status-failure',
      action: 'pull',
    });
    await assert.rejects(first.waitForIdle(), /injected final public status failure/);
    assert.equal((await readActionState(layout.stateDir, response.action_id)).status, 'succeeded');
    await first.stop();

    let reruns = 0;
    const second = new ConfigPullWorker({
      ...layout,
      prepareRunner: async () => {
        reruns += 1;
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => second.stop());
    await second.start();
    await second.waitForIdle();

    assert.equal(reruns, 0);
    const publicStatus = JSON.parse(await fs.readFile(layout.publicStatusFile, 'utf8'));
    assert.equal(publicStatus.state, 'succeeded');
    assert.equal(publicStatus.action_id, response.action_id);
  });

  it('fails closed on symlink and corrupt immutable records', async (context) => {
    await context.test('symlink record', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      const actionId = actionIdForMessageId('symlink-record');
      const outside = path.join(layout.root, 'outside.json');
      await fs.writeFile(outside, '{}\n', { mode: 0o600 });
      await fs.symlink(outside, path.join(layout.queueDir, `${actionId}.json`));
      const worker = new ConfigPullWorker({ ...layout, prepareRunner: async () => PREPARED_PROJECTION });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /ELOOP|record metadata|symlink/);
    });

    await context.test('corrupt record', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      const actionId = actionIdForMessageId('corrupt-record');
      await fs.writeFile(path.join(layout.queueDir, `${actionId}.json`), '{not-json}\n', {
        mode: 0o600,
      });
      const worker = new ConfigPullWorker({ ...layout, prepareRunner: async () => PREPARED_PROJECTION });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /record is corrupt/);
    });
  });
});

describe('config pull worker execution boundary', () => {
  it('uses only the fixed argv, scrubbed environment, root cwd, and no shell', async () => {
    let invocation;
    const spawnImpl = (bin, args, options) => {
      invocation = { bin, args, options };
      return successfulChild(PREPARED_RESULT);
    };

    const result = await runPrepareCommand({
      actionId: PREPARE_ACTION_ID,
      spawnImpl,
      timeoutMs: 1_000,
    });

    assert.deepEqual(
      [invocation.bin, invocation.args],
      [PREPARE_COMMAND.bin, [...PREPARE_COMMAND.args, PREPARE_ACTION_ID]],
    );
    assert.deepEqual(invocation.options.env, PREPARE_ENV);
    assert.deepEqual(Object.keys(invocation.options.env).sort(), Object.keys(PREPARE_ENV).sort());
    assert.equal(invocation.options.cwd, '/');
    assert.equal(invocation.options.shell, false);
    assert.equal(invocation.options.detached, process.platform !== 'win32');
    assert.deepEqual(invocation.options.stdio, ['ignore', 'pipe', 'pipe']);
    assert.deepEqual(result, PREPARED_PROJECTION);
  });

  it('strictly validates prepared JSON and does not accept extra fields', () => {
    assert.deepEqual(
      parsePreparedResult(Buffer.from(JSON.stringify(PREPARED_RESULT)), PREPARE_ACTION_ID),
      PREPARED_PROJECTION,
    );
    assert.throws(
      () => parsePreparedResult(
        Buffer.from(JSON.stringify({ ...PREPARED_RESULT, stderr: 'secret' })),
        PREPARE_ACTION_ID,
      ),
      (error) => error instanceof WorkerFailure && error.code === 'prepare_output_invalid',
    );
  });

  it('terminates a child whose output exceeds the configured bound', async () => {
    let killed = false;
    const spawnImpl = () => {
      const child = new EventEmitter();
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      child.pid = 4_000_000;
      child.kill = () => {
        killed = true;
        queueMicrotask(() => child.emit('close', null, 'SIGTERM'));
      };
      queueMicrotask(() => child.stdout.write(Buffer.alloc(33, 0x78)));
      return child;
    };
    const missingGroup = () => {
      const error = new Error('missing process group');
      error.code = 'ESRCH';
      throw error;
    };

    await assert.rejects(
      runPrepareCommand({
        actionId: PREPARE_ACTION_ID,
        spawnImpl,
        outputLimitBytes: 32,
        timeoutMs: 1_000,
        killImpl: missingGroup,
      }),
      (error) => error instanceof WorkerFailure && error.code === 'prepare_output_too_large',
    );
    assert.equal(killed, true);
  });
});

describe('config pull worker durable files', () => {
  it('publishes the exact public status schema with mode 0644', async (context) => {
    const fixture = await startWorker(context, { prepareRunner: async () => PREPARED_PROJECTION });
    const response = await sendRequest(fixture.socketPath, {
      version: 1,
      message_id: 'public-status',
      action: 'pull',
    });
    await fixture.worker.waitForIdle();

    const publicStatus = JSON.parse(await fs.readFile(fixture.publicStatusFile, 'utf8'));
    assert.deepEqual(publicStatus, {
      version: 1,
      action_id: response.action_id,
      action: 'pull',
      state: 'succeeded',
      config_revision: CONFIG_REVISION,
      updated_at: publicStatus.updated_at,
    });
    assert.equal(new Date(publicStatus.updated_at).toISOString(), publicStatus.updated_at);
    assert.equal((await fs.stat(fixture.publicStatusFile)).mode & 0o777, 0o644);
    assert.equal((await fs.stat(fixture.queueDir)).mode & 0o777, 0o700);
    assert.equal((await fs.stat(fixture.stateDir)).mode & 0o777, 0o700);
  });

  it('removes a just-published request when the publication directory fsync fails', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    let failNextDirectorySync = true;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'open') return target[property];
        return async (file, flags, ...rest) => {
          const handle = await target.open(file, flags, ...rest);
          if (file === layout.queueDir && flags === 'r' && failNextDirectorySync) {
            failNextDirectorySync = false;
            return {
              async sync() {
                const error = new Error('injected directory fsync failure');
                error.code = 'EIO';
                throw error;
              },
              close: (...args) => handle.close(...args),
            };
          }
          return handle;
        };
      },
    });

    await assert.rejects(
      publishRequestRecord({
        queueDir: layout.queueDir,
        request: { version: 1, message_id: 'fsync-failure', action: 'pull' },
        fsApi,
      }),
      /injected directory fsync failure/,
    );
    assert.deepEqual(await fs.readdir(layout.queueDir), []);
  });

  it('rejects regular-file and symlink replacements at the socket path', async (context) => {
    await context.test('regular file', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      await fs.writeFile(layout.socketPath, 'not a socket');
      const worker = new ConfigPullWorker({ ...layout, prepareRunner: async () => PREPARED_PROJECTION });
      subcontext.after(async () => worker.stop());
      await assert.rejects(worker.start(), /socket path is not a socket/);
    });

    await context.test('symlink', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      const target = path.join(layout.root, 'socket-target');
      await fs.writeFile(target, 'not a socket');
      await fs.symlink(target, layout.socketPath);
      const worker = new ConfigPullWorker({ ...layout, prepareRunner: async () => PREPARED_PROJECTION });
      subcontext.after(async () => worker.stop());
      await assert.rejects(worker.start(), /socket path is not a socket/);
    });
  });
});

describe('config pull worker systemd boundary', () => {
  it('runs under a separate stable identity without lifecycle coupling to the bot', async () => {
    const unit = await fs.readFile(
      new URL('../deploy/systemd/webex-config-pull-worker.service', import.meta.url),
      'utf8',
    );

    assert.match(unit, /^User=webex-config-deploy$/m);
    assert.match(unit, /^Group=webex-config-pull$/m);
    assert.doesNotMatch(unit, /^Group=webex-generic-account-bot$/m);
    assert.match(
      unit,
      /^ExecStart=\/usr\/bin\/node \/opt\/webex-generic-account-bot\/code\/scripts\/config-pull-worker\.mjs$/m,
    );
    assert.match(unit, /^Restart=on-failure$/m);
    assert.match(unit, /^NoNewPrivileges=true$/m);
    assert.match(unit, /^ProtectSystem=strict$/m);
    assert.match(unit, /^ProtectHome=true$/m);
    assert.match(unit, /^PrivateTmp=true$/m);
    assert.match(unit, /^CapabilityBoundingSet=$/m);
    assert.doesNotMatch(unit, /^(?:PartOf|BindsTo)=/m);
    assert.doesNotMatch(unit, /^User=root$/m);
  });

  it('provisions only the worker identity and host-owned writable deployment roots', async () => {
    const [sysusers, tmpfiles, botDropIn] = await Promise.all([
      fs.readFile(
        new URL('../deploy/systemd/webex-config-pull-worker.sysusers.conf', import.meta.url),
        'utf8',
      ),
      fs.readFile(
        new URL('../deploy/systemd/webex-config-pull-worker.tmpfiles.conf', import.meta.url),
        'utf8',
      ),
      fs.readFile(
        new URL(
          '../deploy/systemd/webex-generic-account-bot.service.d/10-config-pull.conf',
          import.meta.url,
        ),
        'utf8',
      ),
    ]);

    assert.match(sysusers, /^u webex-config-deploy /m);
    assert.match(sysusers, /^g webex-config-pull -$/m);
    assert.doesNotMatch(sysusers, /^m /m);
    assert.doesNotMatch(sysusers, /^m webex-config-deploy webex-generic-account-bot$/m);
    assert.match(botDropIn, /^SupplementaryGroups=webex-config-pull$/m);
    assert.match(
      tmpfiles,
      /^d \/var\/lib\/webex-generic-account-bot\/config-checkout 0700 webex-config-deploy webex-config-pull -$/m,
    );
    assert.match(
      tmpfiles,
      /^d \/var\/lib\/webex-generic-account-bot\/rendered 0755 webex-config-deploy webex-config-pull -$/m,
    );
    assert.doesNotMatch(tmpfiles, /codex-home|jenkins\.env|access-token/);
  });
});

async function startWorker(context, options = {}) {
  const layout = await createLayout(context);
  const worker = new ConfigPullWorker({ ...layout, ...options });
  context.after(async () => worker.stop());
  await worker.start();
  return { ...layout, worker };
}

async function createLayout(context) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-config-pull-worker-test-'));
  await fs.chmod(root, 0o750);
  context.after(async () => fs.rm(root, { recursive: true, force: true }));
  const stateRoot = path.join(root, 'data');
  return {
    root,
    socketPath: path.join(root, 'config-pull.sock'),
    stateRoot,
    queueDir: path.join(stateRoot, 'queue'),
    stateDir: path.join(stateRoot, 'state'),
    publicStatusFile: path.join(stateRoot, 'public-status.json'),
    stagedMetadataFile: path.join(root, 'production.toml.staged.json'),
    requestTimeoutMs: 500,
    commandTimeoutMs: 1_000,
    outputLimitBytes: 4_096,
  };
}

async function sendRequest(socketPath, request) {
  const response = await sendRaw(socketPath, Buffer.from(`${JSON.stringify(request)}\n`, 'utf8'));
  return JSON.parse(response.toString('utf8'));
}

async function sendRaw(socketPath, payload) {
  return await new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath, allowHalfOpen: true });
    const chunks = [];
    let connected = false;
    let resolved = false;
    const finish = () => {
      if (resolved) return;
      resolved = true;
      resolve(Buffer.concat(chunks));
    };
    socket.on('connect', () => {
      connected = true;
      socket.end(payload);
    });
    socket.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    socket.on('end', finish);
    socket.on('close', finish);
    socket.on('error', (error) => {
      if (connected && ['ECONNRESET', 'EPIPE'].includes(error.code)) {
        finish();
      } else {
        reject(error);
      }
    });
  });
}

function actionState(actionId, status, updatedAt, details = {}) {
  return {
    version: 1,
    action_id: actionId,
    action: 'pull',
    status,
    config_revision: details.configRevision ?? null,
    config_sha256: details.configSha256 ?? null,
    prepared_at: details.preparedAt ?? null,
    failure_code: details.failureCode ?? null,
    updated_at: updatedAt,
  };
}

function successfulChild(result) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.pid = 4_000_001;
  child.kill = () => {};
  queueMicrotask(() => {
    child.stdout.end(`${JSON.stringify(result)}\n`);
    child.stderr.end('ignored child stderr containing token=secret');
    child.emit('close', 0, null);
  });
  return child;
}
