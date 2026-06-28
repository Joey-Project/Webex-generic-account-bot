import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';

import {
  ConfigPullWorker,
  DEFAULTS,
  MAX_REQUEST_BYTES,
  PREPARE_CLOSE_GRACE_MS,
  PREPARE_COMMAND,
  PREPARE_ENV,
  PREPARE_EXIT_LOCK_BUSY,
  PREPARE_EXIT_PROCESS_TREE_UNCONTAINED,
  PREPARE_TERMINATION_GRACE_MS,
  WorkerFailure,
  actionIdForMessageId,
  parsePreparedResult,
  prepareStorage,
  publishRequestRecord,
  readActionState,
  runCli,
  runPrepareCommand,
  socketAcceptsConnections,
  writeActionState,
  writeSocketResponse,
} from '../scripts/config-pull-worker.mjs';
import { buildDeployPlan, parseArgs } from '../scripts/deploy-config.mjs';

const CONFIG_REVISION = 'a'.repeat(40);
const STAGED_CONFIG = '[bot]\nname = "production"\n';
const CONFIG_SHA256 = createHash('sha256').update(STAGED_CONFIG).digest('hex');
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
  staged_config: '/var/lib/webex-generic-account-bot/config-staging/production.toml.staged',
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
        enqueue_sequence: 1,
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
    const third = await sendRequest(fixture.socketPath, {
      version: 1,
      message_id: 'after-duplicate',
      action: 'pull',
    });
    await fixture.worker.waitForIdle();

    const firstRecord = JSON.parse(
      await fs.readFile(path.join(fixture.queueDir, `${first.action_id}.json`), 'utf8'),
    );
    const thirdRecord = JSON.parse(
      await fs.readFile(path.join(fixture.queueDir, `${third.action_id}.json`), 'utf8'),
    );

    assert.equal(first.status, 'queued');
    assert.equal(second.status, 'existing');
    assert.equal(second.action_id, first.action_id);
    assert.equal(firstRecord.enqueue_sequence, 1);
    assert.equal(thirdRecord.enqueue_sequence, 2);
    assert.equal(executions, 2);
    assert.deepEqual(
      (await fs.readdir(fixture.queueDir)).sort(),
      [`${first.action_id}.json`, `${third.action_id}.json`].sort(),
    );
  });

  it('drains live requests in acceptance order while the first runner is blocked', async (context) => {
    const layout = await createLayout(context);
    const firstStarted = deferred();
    const releaseFirst = deferred();
    const requests = ['accepted-first', 'accepted-second', 'accepted-third'].map((messageId) => ({
      version: 1,
      message_id: messageId,
      action: 'pull',
    }));
    const actionIds = requests.map((request) => actionIdForMessageId(request.message_id));
    const executionOrder = [];
    const worker = new ConfigPullWorker({
      ...layout,
      prepareRunner: async ({ actionId }) => {
        executionOrder.push(actionId);
        if (actionId === actionIds[0]) {
          firstStarted.resolve();
          await releaseFirst.promise;
        }
        await stagePreparedResult(layout, actionId);
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => {
      releaseFirst.resolve();
      await worker.stop();
    });
    await worker.start();

    const responses = [await sendRequest(layout.socketPath, requests[0])];
    await firstStarted.promise;
    responses.push(await sendRequest(layout.socketPath, requests[1]));
    responses.push(await sendRequest(layout.socketPath, requests[2]));

    const records = await Promise.all(actionIds.map(async (actionId) => JSON.parse(
      await fs.readFile(path.join(layout.queueDir, `${actionId}.json`), 'utf8'),
    )));
    assert.notDeepEqual([...actionIds].sort(), actionIds);
    assert.deepEqual(responses.map((response) => response.action_id), actionIds);
    assert.deepEqual(records.map((record) => record.enqueue_sequence), [1, 2, 3]);

    releaseFirst.resolve();
    await worker.waitForIdle();

    const publicStatus = JSON.parse(await fs.readFile(layout.publicStatusFile, 'utf8'));
    const stagedMetadata = JSON.parse(await fs.readFile(layout.stagedMetadataFile, 'utf8'));
    assert.deepEqual(executionOrder, actionIds);
    assert.equal(publicStatus.action_id, actionIds.at(-1));
    assert.equal(publicStatus.state, 'succeeded');
    assert.equal(stagedMetadata.request_id, actionIds.at(-1));
  });

  it('keeps newer queued status visible when an older action finishes at the same time', async (context) => {
    const layout = await createLayout(context);
    const firstRequest = { version: 1, message_id: 'same-time-first', action: 'pull' };
    const secondRequest = { version: 1, message_id: 'same-time-second', action: 'pull' };
    const firstActionId = actionIdForMessageId(firstRequest.message_id);
    const secondActionId = actionIdForMessageId(secondRequest.message_id);
    const firstStarted = deferred();
    const releaseFirst = deferred();
    const secondRunningWriteBlocked = deferred();
    const releaseSecondRunningWrite = deferred();
    let secondStateWrites = 0;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'open') return target[property];
        return async (file, flags, ...rest) => {
          if (
            flags === 'wx'
            && path.dirname(file) === layout.stateDir
            && path.basename(file).startsWith(`.atomic-${secondActionId}.json-`)
          ) {
            secondStateWrites += 1;
            if (secondStateWrites === 2) {
              secondRunningWriteBlocked.resolve();
              await releaseSecondRunningWrite.promise;
            }
          }
          return target.open(file, flags, ...rest);
        };
      },
    });
    const worker = new ConfigPullWorker({
      ...layout,
      fsApi,
      now: () => new Date('2026-06-27T13:00:00.000Z'),
      prepareRunner: async ({ actionId }) => {
        if (actionId === firstActionId) {
          firstStarted.resolve();
          await releaseFirst.promise;
        }
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => {
      releaseFirst.resolve();
      releaseSecondRunningWrite.resolve();
      await worker.stop();
    });
    await worker.start();

    await sendRequest(layout.socketPath, firstRequest);
    await firstStarted.promise;
    await sendRequest(layout.socketPath, secondRequest);
    releaseFirst.resolve();
    await secondRunningWriteBlocked.promise;

    const publicStatus = JSON.parse(await fs.readFile(layout.publicStatusFile, 'utf8'));
    const firstState = await readActionState(layout.stateDir, firstActionId);
    const secondState = await readActionState(layout.stateDir, secondActionId);
    assert.equal(publicStatus.action_id, secondActionId);
    assert.equal(publicStatus.state, 'queued');
    assert.equal(firstState.enqueue_sequence, 1);
    assert.equal(firstState.status, 'succeeded');
    assert.equal(secondState.enqueue_sequence, 2);
    assert.equal(secondState.status, 'queued');

    releaseSecondRunningWrite.resolve();
    await worker.waitForIdle();
  });

  it('ignores a trusted request temporary file exposed during a live drain', async (context) => {
    const layout = await createLayout(context);
    const tempExposed = deferred();
    const tempInspected = deferred();
    const releasePublication = deferred();
    let observeLivePublication = false;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property === 'link') {
          return async (source, destination) => {
            if (
              observeLivePublication
              && path.dirname(source) === layout.queueDir
              && path.basename(source).startsWith('.request-')
            ) {
              tempExposed.resolve();
              await releasePublication.promise;
            }
            return target.link(source, destination);
          };
        }
        if (property === 'readdir') {
          return async (directory, options) => {
            if (observeLivePublication && directory === layout.queueDir) {
              await tempExposed.promise;
            }
            return target.readdir(directory, options);
          };
        }
        if (property === 'lstat') {
          return async (file) => {
            const stat = await target.lstat(file);
            if (
              observeLivePublication
              && path.dirname(file) === layout.queueDir
              && path.basename(file).startsWith('.request-')
            ) {
              tempInspected.resolve();
            }
            return stat;
          };
        }
        return target[property];
      },
    });
    const worker = new ConfigPullWorker({
      ...layout,
      fsApi,
      prepareRunner: async () => PREPARED_PROJECTION,
    });
    context.after(async () => {
      releasePublication.resolve();
      await worker.stop();
    });
    await worker.start();
    observeLivePublication = true;

    const responsePromise = sendRequest(layout.socketPath, {
      version: 1,
      message_id: 'live-request-temporary',
      action: 'pull',
    });
    await tempInspected.promise;
    releasePublication.resolve();
    const response = await responsePromise;
    await worker.waitForIdle();

    assert.equal(response.status, 'queued');
    assert.equal((await readActionState(layout.stateDir, response.action_id)).status, 'succeeded');
  });

  it('waits out a durable request published before its state during a live drain', async (context) => {
    const layout = await createLayout(context);
    const messageId = 'live-request-before-state';
    const actionId = actionIdForMessageId(messageId);
    const stateFile = path.join(layout.stateDir, `${actionId}.json`);
    const stateWriteBlocked = deferred();
    const drainObservedMissingState = deferred();
    const releaseStateWrite = deferred();
    let observeLivePublication = false;
    let stateReads = 0;
    let blockedStateWrite = false;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property === 'readdir') {
          return async (directory, options) => {
            if (observeLivePublication && directory === layout.queueDir) {
              await stateWriteBlocked.promise;
            }
            return target.readdir(directory, options);
          };
        }
        if (property === 'open') {
          return async (file, flags, ...rest) => {
            if (observeLivePublication && file === stateFile) {
              stateReads += 1;
              try {
                return await target.open(file, flags, ...rest);
              } finally {
                if (stateReads >= 2) drainObservedMissingState.resolve();
              }
            }
            if (
              observeLivePublication
              && !blockedStateWrite
              && flags === 'wx'
              && path.dirname(file) === layout.stateDir
              && path.basename(file).startsWith(`.atomic-${actionId}.json-`)
            ) {
              blockedStateWrite = true;
              stateWriteBlocked.resolve();
              await releaseStateWrite.promise;
            }
            return target.open(file, flags, ...rest);
          };
        }
        return target[property];
      },
    });
    const worker = new ConfigPullWorker({
      ...layout,
      fsApi,
      prepareRunner: async () => PREPARED_PROJECTION,
    });
    context.after(async () => {
      releaseStateWrite.resolve();
      await worker.stop();
    });
    await worker.start();
    observeLivePublication = true;

    const responsePromise = sendRequest(layout.socketPath, {
      version: 1,
      message_id: messageId,
      action: 'pull',
    });
    await drainObservedMissingState.promise;
    releaseStateWrite.resolve();
    const response = await responsePromise;
    await worker.waitForIdle();

    assert.equal(response.action_id, actionId);
    assert.equal((await readActionState(layout.stateDir, actionId)).status, 'succeeded');
  });

  it('skips a stale drain snapshot when request publication fsync fails', async (context) => {
    const layout = await createLayout(context);
    const staleRequest = {
      version: 1,
      message_id: 'stale-publication-snapshot',
      action: 'pull',
    };
    const liveRequest = {
      version: 1,
      message_id: 'live-request-during-stale-publication',
      action: 'pull',
    };
    const staleActionId = actionIdForMessageId(staleRequest.message_id);
    const liveActionId = actionIdForMessageId(liveRequest.message_id);
    const staleRecordFile = path.join(layout.queueDir, `${staleActionId}.json`);
    const publicationSyncBlocked = deferred();
    const releasePublicationSync = deferred();
    const liveStateWriteBlocked = deferred();
    const releaseLiveStateWrite = deferred();
    const staleSnapshotOpened = deferred();
    let observeRace = false;
    let failNextQueueSync = false;
    let blockNextQueueRead = true;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property === 'readdir') {
          return async (directory, options) => {
            if (observeRace && blockNextQueueRead && directory === layout.queueDir) {
              blockNextQueueRead = false;
              await liveStateWriteBlocked.promise;
            }
            return target.readdir(directory, options);
          };
        }
        if (property === 'open') {
          return async (file, flags, ...rest) => {
            if (
              observeRace
              && flags === 'wx'
              && path.dirname(file) === layout.stateDir
              && path.basename(file).startsWith(`.atomic-${liveActionId}.json-`)
            ) {
              liveStateWriteBlocked.resolve();
              await releaseLiveStateWrite.promise;
            }
            const handle = await target.open(file, flags, ...rest);
            if (observeRace && file === staleRecordFile && typeof flags === 'number') {
              staleSnapshotOpened.resolve();
            }
            if (file !== layout.queueDir || flags !== 'r' || !failNextQueueSync) {
              return handle;
            }
            failNextQueueSync = false;
            return new Proxy(handle, {
              get(handleTarget, handleProperty) {
                if (handleProperty === 'sync') {
                  return async () => {
                    publicationSyncBlocked.resolve();
                    await releasePublicationSync.promise;
                    const error = new Error('injected publication directory fsync failure');
                    error.code = 'EIO';
                    throw error;
                  };
                }
                const value = Reflect.get(handleTarget, handleProperty, handleTarget);
                return typeof value === 'function' ? value.bind(handleTarget) : value;
              },
            });
          };
        }
        return target[property];
      },
    });
    const preparedActionIds = [];
    const worker = new ConfigPullWorker({
      ...layout,
      fsApi,
      prepareRunner: async ({ actionId }) => {
        preparedActionIds.push(actionId);
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => {
      releasePublicationSync.resolve();
      releaseLiveStateWrite.resolve();
      await worker.stop();
    });
    await worker.start();
    observeRace = true;
    failNextQueueSync = true;

    const publicationFailure = assert.rejects(
      publishRequestRecord({
        queueDir: layout.queueDir,
        request: staleRequest,
        enqueueSequence: 2,
        fsApi,
      }),
      /injected publication directory fsync failure/,
    );
    await publicationSyncBlocked.promise;
    const liveResponsePromise = sendRequest(layout.socketPath, liveRequest);
    await liveStateWriteBlocked.promise;
    await staleSnapshotOpened.promise;

    releasePublicationSync.resolve();
    await publicationFailure;
    releaseLiveStateWrite.resolve();
    const liveResponse = await liveResponsePromise;
    await worker.waitForIdle();

    assert.equal(liveResponse.action_id, liveActionId);
    assert.equal(await readActionState(layout.stateDir, staleActionId), null);
    assert.deepEqual(preparedActionIds, [liveActionId]);
    assert.deepEqual(await fs.readdir(layout.queueDir), [`${liveActionId}.json`]);
  });

  it('orders live and replayed public status by sequence when the clock moves backwards', async (context) => {
    let timestamp = Date.parse('2026-06-27T13:00:00.000Z');
    const fixture = await startWorker(context, {
      now: () => {
        const current = new Date(timestamp);
        timestamp -= 1_000;
        return current;
      },
      prepareRunner: async () => PREPARED_PROJECTION,
    });
    const olderRequest = { version: 1, message_id: 'older-action', action: 'pull' };
    const newerRequest = { version: 1, message_id: 'newer-action', action: 'pull' };

    await sendRequest(fixture.socketPath, olderRequest);
    await fixture.worker.waitForIdle();
    const newer = await sendRequest(fixture.socketPath, newerRequest);
    await fixture.worker.waitForIdle();
    const duplicate = await sendRequest(fixture.socketPath, olderRequest);
    await fixture.worker.waitForIdle();

    const publicStatus = JSON.parse(await fs.readFile(fixture.publicStatusFile, 'utf8'));
    assert.equal(duplicate.status, 'existing');
    assert.equal(publicStatus.action_id, newer.action_id);
    assert.equal(publicStatus.state, 'succeeded');
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

  it('rejects restarting the same worker instance after stop', async (context) => {
    const layout = await createLayout(context);
    const worker = new ConfigPullWorker({
      ...layout,
      prepareRunner: async () => PREPARED_PROJECTION,
    });
    context.after(async () => worker.stop());

    await worker.start();
    await worker.stop();

    await assert.rejects(worker.start(), /worker cannot be restarted/);
    await assert.rejects(fs.stat(layout.socketPath), { code: 'ENOENT' });
  });

  it('requeues lock contention without letting newer work pass', async (context) => {
    const layout = await createLayout(context);
    const firstStarted = deferred();
    const releaseFirst = deferred();
    const retryScheduled = deferred();
    const requests = ['lock-busy-first', 'lock-busy-second'].map((messageId) => ({
      version: 1,
      message_id: messageId,
      action: 'pull',
    }));
    const actionIds = requests.map((request) => actionIdForMessageId(request.message_id));
    const attempts = [];
    let firstAttempts = 0;
    const worker = new ConfigPullWorker({
      ...layout,
      retryDelayMs: 17,
      setTimeoutImpl: (callback, delayMs) => {
        const timer = { callback, delayMs };
        retryScheduled.resolve(timer);
        return timer;
      },
      clearTimeoutImpl: () => {},
      prepareRunner: async ({ actionId }) => {
        attempts.push(actionId);
        if (actionId === actionIds[0] && firstAttempts++ === 0) {
          firstStarted.resolve();
          await releaseFirst.promise;
          throw new WorkerFailure('prepare_lock_busy');
        }
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => {
      releaseFirst.resolve();
      await worker.stop();
    });
    await worker.start();

    await sendRequest(layout.socketPath, requests[0]);
    await firstStarted.promise;
    await sendRequest(layout.socketPath, requests[1]);
    releaseFirst.resolve();
    const timer = await retryScheduled.promise;

    assert.equal(timer.delayMs, 17);
    assert.deepEqual(attempts, [actionIds[0]]);
    assert.equal((await readActionState(layout.stateDir, actionIds[0])).status, 'queued');
    assert.equal((await readActionState(layout.stateDir, actionIds[1])).status, 'queued');

    timer.callback();
    await worker.waitForIdle();

    assert.deepEqual(attempts, [actionIds[0], actionIds[0], actionIds[1]]);
    assert.equal((await readActionState(layout.stateDir, actionIds[0])).status, 'succeeded');
    assert.equal((await readActionState(layout.stateDir, actionIds[1])).status, 'succeeded');
  });

  it('clears a pending lock retry when stop begins', async (context) => {
    const layout = await createLayout(context);
    const retryScheduled = deferred();
    const clearedTimers = [];
    const worker = new ConfigPullWorker({
      ...layout,
      retryDelayMs: 23,
      setTimeoutImpl: (callback, delayMs) => {
        const timer = { callback, delayMs };
        retryScheduled.resolve(timer);
        return timer;
      },
      clearTimeoutImpl: (timer) => clearedTimers.push(timer),
      prepareRunner: async () => {
        throw new WorkerFailure('prepare_lock_busy');
      },
    });
    context.after(async () => worker.stop());
    await worker.start();

    const response = await sendRequest(layout.socketPath, {
      version: 1,
      message_id: 'lock-busy-stop',
      action: 'pull',
    });
    const timer = await retryScheduled.promise;
    const firstStop = worker.stop();
    const secondStop = worker.stop();

    assert.equal(firstStop, secondStop);
    await firstStop;
    assert.deepEqual(clearedTimers, [timer]);
    assert.equal((await readActionState(layout.stateDir, response.action_id)).status, 'queued');
    assert.equal(
      JSON.parse(await fs.readFile(layout.publicStatusFile, 'utf8')).state,
      'queued',
    );
    await assert.rejects(fs.stat(layout.socketPath), { code: 'ENOENT' });
  });
});

describe('config pull worker lifecycle', () => {
  it('waits for an aborted startup and removes a socket that started listening', async (context) => {
    const layout = await createLayout(context);
    const socketChmodStarted = deferred();
    const releaseSocketChmod = deferred();
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'chmod') return target[property];
        return async (file, mode) => {
          if (file === layout.socketPath) {
            socketChmodStarted.resolve();
            await releaseSocketChmod.promise;
          }
          return target.chmod(file, mode);
        };
      },
    });
    const worker = new ConfigPullWorker({
      ...layout,
      fsApi,
      prepareRunner: async () => PREPARED_PROJECTION,
    });
    context.after(async () => {
      releaseSocketChmod.resolve();
      await worker.stop();
    });

    const startPromise = worker.start();
    await socketChmodStarted.promise;
    const stopPromise = worker.stop();
    let stopSettled = false;
    stopPromise.then(() => {
      stopSettled = true;
    });
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(stopSettled, false);
    releaseSocketChmod.resolve();
    await assert.rejects(
      startPromise,
      (error) => error instanceof WorkerFailure && error.code === 'worker_stopping',
    );
    await stopPromise;
    await assert.rejects(fs.stat(layout.socketPath), { code: 'ENOENT' });
  });

  it('starts stop immediately when a CLI signal arrives during startup', async () => {
    for (const signal of ['SIGINT', 'SIGTERM']) {
      const processApi = new EventEmitter();
      const startup = deferred();
      const stopStarted = deferred();
      let stopCalls = 0;
      const worker = {
        start: () => startup.promise,
        stop: () => {
          stopCalls += 1;
          stopStarted.resolve();
          startup.reject(new WorkerFailure('worker_stopping'));
          return Promise.resolve();
        },
        waitForFatal: () => new Promise(() => {}),
      };
      const stderr = { write: () => {} };

      const result = runCli({ processApi, worker, stderr });
      processApi.emit(signal);
      await stopStarted.promise;

      assert.equal(await result, 0);
      assert.equal(stopCalls, 1);
    }
  });
});

describe('config pull worker recovery', () => {
  it('keeps integrity-fatal work recoverable and stops before newer records', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const publications = [];
    for (const [index, messageId] of ['fatal-first', 'fatal-second'].entries()) {
      publications.push(await publishRequestRecord({
        queueDir: layout.queueDir,
        request: { version: 1, message_id: messageId, action: 'pull' },
        enqueueSequence: index + 1,
      }));
    }
    const attempts = [];
    const worker = new ConfigPullWorker({
      ...layout,
      prepareRunner: async ({ actionId }) => {
        attempts.push(actionId);
        throw new WorkerFailure('prepare_process_tree_uncontained');
      },
    });
    const stderr = [];

    const exitCode = await runCli({
      worker,
      processApi: new EventEmitter(),
      stderr: { write: (message) => stderr.push(message) },
    });

    assert.equal(exitCode, 1);
    assert.deepEqual(attempts, [publications[0].actionId]);
    assert.equal(
      (await readActionState(layout.stateDir, publications[0].actionId)).status,
      'running',
    );
    assert.equal(
      (await readActionState(layout.stateDir, publications[1].actionId)).status,
      'queued',
    );
    assert.deepEqual(stderr, []);
    const fatal = await worker.waitForFatal();
    assert(fatal instanceof WorkerFailure);
    assert.equal(fatal.code, 'prepare_process_tree_uncontained');
  });

  it('cleans a stale trusted temporary and recovers its durable request without state', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const request = { version: 1, message_id: 'crash-before-request-state', action: 'pull' };
    const publication = await publishRequestRecord({
      queueDir: layout.queueDir,
      request,
      enqueueSequence: 1,
    });
    const staleTemporary = path.join(
      layout.queueDir,
      `.request-${publication.actionId}-1234-12345678-1234-4123-8123-123456789abc.tmp`,
    );
    await fs.writeFile(staleTemporary, 'stale publication\n', { mode: 0o600 });
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

    assert.equal(executions, 1);
    assert.deepEqual(await fs.readdir(layout.queueDir), [`${publication.actionId}.json`]);
    assert.equal((await readActionState(layout.stateDir, publication.actionId)).status, 'succeeded');
  });

  it('cleans and fsyncs stale public status temporaries in safe transitional modes', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const temporaryNames = [
      '.atomic-public-status.json-1234-12345678-1234-4123-8123-123456789abc.tmp',
      '.atomic-public-status.json-5678-abcdefab-cdef-4abc-8def-abcdefabcdef.tmp',
    ];
    const temporaryPaths = temporaryNames.map((name) => path.join(layout.stateRoot, name));
    await fs.writeFile(temporaryPaths[0], 'partial\n', { mode: 0o600 });
    await fs.writeFile(temporaryPaths[1], 'complete\n', { mode: 0o644 });
    await fs.chmod(temporaryPaths[0], 0o600);
    await fs.chmod(temporaryPaths[1], 0o644);
    const events = [];
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property === 'unlink') {
          return async (file) => {
            if (temporaryPaths.includes(file)) events.push(path.basename(file));
            return target.unlink(file);
          };
        }
        if (property !== 'open') return target[property];
        return async (file, flags, ...rest) => {
          const handle = await target.open(file, flags, ...rest);
          if (file !== layout.stateRoot || flags !== 'r') return handle;
          return new Proxy(handle, {
            get(handleTarget, handleProperty) {
              if (handleProperty === 'sync') {
                return async () => {
                  events.push('state-root-sync');
                  return handleTarget.sync();
                };
              }
              const value = Reflect.get(handleTarget, handleProperty, handleTarget);
              return typeof value === 'function' ? value.bind(handleTarget) : value;
            },
          });
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

    assert.deepEqual(events.slice(0, -1).sort(), [...temporaryNames].sort());
    assert.equal(events.at(-1), 'state-root-sync');
    await Promise.all(temporaryPaths.map(
      (file) => assert.rejects(fs.stat(file), { code: 'ENOENT' }),
    ));
  });

  it('rejects suspicious public status temporary entries', async (context) => {
    await context.test('malformed prefixed name', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      await fs.writeFile(
        path.join(layout.stateRoot, '.atomic-public-status.json-1234-not-a-uuid.tmp'),
        'unexpected\n',
        { mode: 0o600 },
      );
      const worker = new ConfigPullWorker({
        ...layout,
        prepareRunner: async () => PREPARED_PROJECTION,
      });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /unexpected temporary entry/);
    });

    await context.test('unsafe mode', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      const temporary = path.join(
        layout.stateRoot,
        '.atomic-public-status.json-1234-12345678-1234-4123-8123-123456789abc.tmp',
      );
      await fs.writeFile(temporary, 'unexpected\n', { mode: 0o600 });
      await fs.chmod(temporary, 0o666);
      const worker = new ConfigPullWorker({
        ...layout,
        prepareRunner: async () => PREPARED_PROJECTION,
      });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /record metadata is not trusted/);
    });
  });

  it('recovers pending requests in acceptance order and resumes at durable max plus one', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const requests = ['restart-first', 'restart-second', 'restart-third'].map((messageId) => ({
      version: 1,
      message_id: messageId,
      action: 'pull',
    }));
    const publications = [];
    for (const [index, request] of requests.entries()) {
      publications.push(await publishRequestRecord({
        queueDir: layout.queueDir,
        request,
        enqueueSequence: 40 + index,
      }));
    }
    const actionIds = publications.map((publication) => publication.actionId);
    const executionOrder = [];
    const worker = new ConfigPullWorker({
      ...layout,
      prepareRunner: async ({ actionId }) => {
        executionOrder.push(actionId);
        await stagePreparedResult(layout, actionId);
        return PREPARED_PROJECTION;
      },
    });
    context.after(async () => worker.stop());

    assert.notDeepEqual([...actionIds].sort(), actionIds);
    await worker.start();
    await worker.waitForIdle();

    let publicStatus = JSON.parse(await fs.readFile(layout.publicStatusFile, 'utf8'));
    let stagedMetadata = JSON.parse(await fs.readFile(layout.stagedMetadataFile, 'utf8'));
    assert.deepEqual(executionOrder, actionIds);
    assert.equal(publicStatus.action_id, actionIds.at(-1));
    assert.equal(stagedMetadata.request_id, actionIds.at(-1));

    const afterRestart = await sendRequest(layout.socketPath, {
      version: 1,
      message_id: 'restart-after-durable-publication',
      action: 'pull',
    });
    await worker.waitForIdle();

    const afterRestartRecord = JSON.parse(
      await fs.readFile(path.join(layout.queueDir, `${afterRestart.action_id}.json`), 'utf8'),
    );
    publicStatus = JSON.parse(await fs.readFile(layout.publicStatusFile, 'utf8'));
    stagedMetadata = JSON.parse(await fs.readFile(layout.stagedMetadataFile, 'utf8'));
    assert.equal(afterRestartRecord.enqueue_sequence, 43);
    assert.deepEqual(executionOrder, [...actionIds, afterRestart.action_id]);
    assert.equal(publicStatus.action_id, afterRestart.action_id);
    assert.equal(publicStatus.state, 'succeeded');
    assert.equal(stagedMetadata.request_id, afterRestart.action_id);
  });

  it('recovers the highest sequence across equal timestamps and a backwards clock', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const timestamps = [
      '2026-06-27T14:00:00.000Z',
      '2026-06-27T13:00:00.000Z',
      '2026-06-27T13:00:00.000Z',
    ];
    const publications = [];
    for (const [index, timestamp] of timestamps.entries()) {
      const publication = await publishRequestRecord({
        queueDir: layout.queueDir,
        request: {
          version: 1,
          message_id: `restart-clock-${index + 1}`,
          action: 'pull',
        },
        enqueueSequence: index + 1,
      });
      publications.push(publication);
      await writeActionState({
        stateDir: layout.stateDir,
        state: actionState(
          publication.actionId,
          index + 1,
          'failed',
          timestamp,
          { failureCode: 'prepare_failed' },
        ),
      });
    }
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

    const publicStatus = JSON.parse(await fs.readFile(layout.publicStatusFile, 'utf8'));
    assert.equal(executions, 0);
    assert.equal(publicStatus.action_id, publications.at(-1).actionId);
    assert.equal(publicStatus.state, 'failed');
  });

  it('replays a running request after restart', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const request = { version: 1, message_id: 'restart-running', action: 'pull' };
    const publication = await publishRequestRecord({
      queueDir: layout.queueDir,
      request,
      enqueueSequence: 1,
    });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(publication.actionId, 1, 'running', '2026-06-27T12:01:00.000Z'),
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
    const publication = await publishRequestRecord({
      queueDir: layout.queueDir,
      request,
      enqueueSequence: 1,
    });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(publication.actionId, 1, 'running', '2026-06-27T12:01:30.000Z'),
    });
    await fs.writeFile(layout.stagedConfigFile, STAGED_CONFIG, { mode: 0o600 });
    await fs.writeFile(
      layout.stagedMetadataFile,
      `${JSON.stringify({ ...PREPARED_RESULT, request_id: publication.actionId })}\n`,
      { mode: 0o600 },
    );
    const durabilityEvents = [];
    const fsApi = durabilityRecordingFsApi(layout, publication.actionId, durabilityEvents);
    let executions = 0;
    const worker = new ConfigPullWorker({
      ...layout,
      fsApi,
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
    assert.deepEqual(durabilityEvents.slice(0, 4), [
      'staged-config-sync',
      'staged-metadata-sync',
      'staging-directory-sync',
      'state-write',
    ]);
  });

  it('requeues running work when staged config validation or durability fails', async (context) => {
    for (const scenario of [
      { name: 'digest mismatch', contents: 'tampered config\n', mode: 0o600 },
      { name: 'oversized config', contents: Buffer.alloc(4 * 1024 * 1024 + 1, 0x78), mode: 0o600 },
      { name: 'untrusted mode', contents: STAGED_CONFIG, mode: 0o644 },
      {
        name: 'metadata fsync failure',
        contents: STAGED_CONFIG,
        mode: 0o600,
        failSyncLabel: 'staged-metadata-sync',
      },
      {
        name: 'directory fsync failure',
        contents: STAGED_CONFIG,
        mode: 0o600,
        failSyncLabel: 'staging-directory-sync',
      },
    ]) {
      await context.test(scenario.name, async (subcontext) => {
        const layout = await createLayout(subcontext);
        await prepareStorage(layout);
        const request = {
          version: 1,
          message_id: `staged-${scenario.name.replaceAll(' ', '-')}`,
          action: 'pull',
        };
        const publication = await publishRequestRecord({
          queueDir: layout.queueDir,
          request,
          enqueueSequence: 1,
        });
        await writeActionState({
          stateDir: layout.stateDir,
          state: actionState(publication.actionId, 1, 'running', '2026-06-27T12:01:35.000Z'),
        });
        await fs.writeFile(layout.stagedConfigFile, scenario.contents, { mode: scenario.mode });
        await fs.writeFile(
          layout.stagedMetadataFile,
          `${JSON.stringify({ ...PREPARED_RESULT, request_id: publication.actionId })}\n`,
          { mode: 0o600 },
        );
        const fsApi = scenario.failSyncLabel
          ? durabilityRecordingFsApi(layout, publication.actionId, [], {
              failSyncLabel: scenario.failSyncLabel,
            })
          : fs;
        let executions = 0;
        const worker = new ConfigPullWorker({
          ...layout,
          fsApi,
          prepareRunner: async () => {
            executions += 1;
            return PREPARED_PROJECTION;
          },
        });
        subcontext.after(async () => worker.stop());

        await worker.start();
        await worker.waitForIdle();

        assert.equal(executions, 1);
        assert.equal(
          (await readActionState(layout.stateDir, publication.actionId)).status,
          'succeeded',
        );
      });
    }
  });

  it('reruns a running request when staged metadata belongs to another action', async (context) => {
    const layout = await createLayout(context);
    await prepareStorage(layout);
    const request = { version: 1, message_id: 'mismatched-staged-result', action: 'pull' };
    const publication = await publishRequestRecord({
      queueDir: layout.queueDir,
      request,
      enqueueSequence: 1,
    });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(publication.actionId, 1, 'running', '2026-06-27T12:01:45.000Z'),
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
      enqueueSequence: 1,
    });
    const failed = await publishRequestRecord({
      queueDir: layout.queueDir,
      request: { version: 1, message_id: 'already-failed', action: 'pull' },
      enqueueSequence: 2,
    });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(
        succeeded.actionId,
        1,
        'succeeded',
        '2026-06-27T12:02:00.000Z',
        PREPARED_PROJECTION,
      ),
    });
    await writeActionState({
      stateDir: layout.stateDir,
      state: actionState(
        failed.actionId,
        2,
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

  it('fails closed on untrusted or invalid immutable records', async (context) => {
    await context.test('unexpected temporary record', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      await fs.writeFile(path.join(layout.queueDir, '.request-untrusted.tmp'), 'unexpected\n', {
        mode: 0o600,
      });
      const worker = new ConfigPullWorker({ ...layout, prepareRunner: async () => PREPARED_PROJECTION });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /unexpected temporary entry/);
    });

    await context.test('invalid enqueue sequence', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      const messageId = 'invalid-enqueue-sequence';
      const actionId = actionIdForMessageId(messageId);
      await fs.writeFile(
        path.join(layout.queueDir, `${actionId}.json`),
        `${JSON.stringify({
          version: 1,
          action_id: actionId,
          action: 'pull',
          enqueue_sequence: 0,
          message_id: messageId,
        })}\n`,
        { mode: 0o600 },
      );
      const worker = new ConfigPullWorker({ ...layout, prepareRunner: async () => PREPARED_PROJECTION });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /enqueue sequence is invalid/);
    });

    await context.test('action state without enqueue sequence', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      const publication = await publishRequestRecord({
        queueDir: layout.queueDir,
        request: { version: 1, message_id: 'state-without-sequence', action: 'pull' },
        enqueueSequence: 1,
      });
      const state = actionState(
        publication.actionId,
        1,
        'queued',
        '2026-06-27T12:04:00.000Z',
      );
      delete state.enqueue_sequence;
      await fs.writeFile(
        path.join(layout.stateDir, `${publication.actionId}.json`),
        `${JSON.stringify(state)}\n`,
        { mode: 0o600 },
      );
      const worker = new ConfigPullWorker({
        ...layout,
        prepareRunner: async () => PREPARED_PROJECTION,
      });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /action state contains unexpected fields/);
    });

    await context.test('action state sequence mismatch', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      const publication = await publishRequestRecord({
        queueDir: layout.queueDir,
        request: { version: 1, message_id: 'state-sequence-mismatch', action: 'pull' },
        enqueueSequence: 1,
      });
      await writeActionState({
        stateDir: layout.stateDir,
        state: actionState(
          publication.actionId,
          2,
          'queued',
          '2026-06-27T12:04:00.000Z',
        ),
      });
      const worker = new ConfigPullWorker({
        ...layout,
        prepareRunner: async () => PREPARED_PROJECTION,
      });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /state enqueue sequence mismatch/);
    });

    await context.test('duplicate enqueue sequence', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      await publishRequestRecord({
        queueDir: layout.queueDir,
        request: { version: 1, message_id: 'duplicate-sequence-first', action: 'pull' },
        enqueueSequence: 1,
      });
      await publishRequestRecord({
        queueDir: layout.queueDir,
        request: { version: 1, message_id: 'duplicate-sequence-second', action: 'pull' },
        enqueueSequence: 1,
      });
      const worker = new ConfigPullWorker({ ...layout, prepareRunner: async () => PREPARED_PROJECTION });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /duplicate enqueue sequence: 1/);
    });

    await context.test('enqueue sequence overflow', async (subcontext) => {
      const layout = await createLayout(subcontext);
      await prepareStorage(layout);
      await publishRequestRecord({
        queueDir: layout.queueDir,
        request: { version: 1, message_id: 'sequence-overflow', action: 'pull' },
        enqueueSequence: Number.MAX_SAFE_INTEGER,
      });
      const worker = new ConfigPullWorker({ ...layout, prepareRunner: async () => PREPARED_PROJECTION });
      subcontext.after(async () => worker.stop());

      await assert.rejects(worker.start(), /enqueue sequence overflow/);
    });

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
  it('maps structured deploy exits to worker failure codes', async () => {
    const deploySource = await fs.readFile(
      new URL('../scripts/deploy-config.mjs', import.meta.url),
      'utf8',
    );
    assert.equal(
      PREPARE_EXIT_LOCK_BUSY,
      sourceIntegerConstant(deploySource, 'DEPLOY_EXIT_LOCK_BUSY'),
    );
    assert.equal(
      PREPARE_EXIT_PROCESS_TREE_UNCONTAINED,
      sourceIntegerConstant(deploySource, 'DEPLOY_EXIT_PROCESS_TREE_UNCONTAINED'),
    );
    for (const { exitCode, failureCode } of [
      { exitCode: PREPARE_EXIT_LOCK_BUSY, failureCode: 'prepare_lock_busy' },
      {
        exitCode: PREPARE_EXIT_PROCESS_TREE_UNCONTAINED,
        failureCode: 'prepare_process_tree_uncontained',
      },
      { exitCode: 1, failureCode: 'prepare_failed' },
    ]) {
      await assert.rejects(
        runPrepareCommand({
          actionId: PREPARE_ACTION_ID,
          spawnImpl: () => exitedChild(exitCode),
          timeoutMs: 1_000,
        }),
        (error) => error instanceof WorkerFailure && error.code === failureCode,
      );
    }
  });

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

  it('lets deploy-config finish descendant cleanup before outer SIGKILL', async (context) => {
    const deploySource = await fs.readFile(
      new URL('../scripts/deploy-config.mjs', import.meta.url),
      'utf8',
    );
    const innerTerminationGraceMs = sourceIntegerConstant(
      deploySource,
      'CHILD_TERMINATION_GRACE_MS',
    );
    const innerCloseGraceMs = sourceIntegerConstant(
      deploySource,
      'CHILD_CLOSE_GRACE_MS',
    );
    const innerCleanupGraceMs = innerTerminationGraceMs + innerCloseGraceMs;
    assert.ok(PREPARE_TERMINATION_GRACE_MS > innerCleanupGraceMs);
    context.mock.timers.enable({ apis: ['setTimeout'] });
    const signals = [];
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.pid = 4_000_002;
    child.kill = () => {
      throw new Error('process-group signaling should succeed');
    };
    const result = runPrepareCommand({
      actionId: PREPARE_ACTION_ID,
      spawnImpl: () => child,
      timeoutMs: 100,
      killImpl: (_pid, signal) => signals.push(signal),
    });

    context.mock.timers.tick(100);
    assert.deepEqual(signals, ['SIGTERM']);
    context.mock.timers.tick(innerCleanupGraceMs);
    assert.deepEqual(signals, ['SIGTERM']);

    child.emit('close', null, 'SIGTERM');
    await assert.rejects(
      result,
      (error) => error instanceof WorkerFailure && error.code === 'prepare_timeout',
    );
    assert.deepEqual(signals, ['SIGTERM']);
  });

  it('fails closed when a stale socket probe times out or is aborted', async () => {
    await assert.rejects(
      socketAcceptsConnections('/tmp/stale.sock', {
        timeoutMs: 19,
        createConnection: () => {
          const socket = new EventEmitter();
          socket.destroy = () => {};
          return socket;
        },
        setTimeoutImpl: (callback, delayMs) => {
          assert.equal(delayMs, 19);
          queueMicrotask(callback);
          return 1;
        },
        clearTimeoutImpl: () => {},
      }),
      /socket probe timed out/,
    );

    const abortController = new AbortController();
    const socket = new EventEmitter();
    let destroyed = false;
    let timerCleared = false;
    socket.destroy = () => {
      destroyed = true;
    };
    const probe = socketAcceptsConnections('/tmp/stale.sock', {
      timeoutMs: 31,
      signal: abortController.signal,
      createConnection: () => socket,
      setTimeoutImpl: () => 2,
      clearTimeoutImpl: (timer) => {
        assert.equal(timer, 2);
        timerCleared = true;
      },
    });

    abortController.abort();
    await assert.rejects(
      probe,
      (error) => error instanceof WorkerFailure && error.code === 'worker_stopping',
    );
    assert.equal(destroyed, true);
    assert.equal(timerCleared, true);
  });

  it('strictly bounds retry and socket probe timing options', async (context) => {
    const layout = await createLayout(context);
    assert.equal(DEFAULTS.retryDelayMs, 1_000);
    assert.equal(DEFAULTS.socketProbeTimeoutMs, 1_000);
    assert.throws(() => new ConfigPullWorker({ ...layout, retryDelayMs: 0 }), /retry delay/);
    assert.throws(() => new ConfigPullWorker({ ...layout, retryDelayMs: 60_001 }), /retry delay/);
    assert.throws(
      () => new ConfigPullWorker({ ...layout, socketProbeTimeoutMs: 0 }),
      /socket probe timeout/,
    );
    assert.throws(
      () => new ConfigPullWorker({ ...layout, socketProbeTimeoutMs: 60_001 }),
      /socket probe timeout/,
    );
  });
});

describe('config pull worker durable files', () => {
  it('accepts a state root directly below the root-owned sticky temp directory', async (context) => {
    const layout = await createLayout(context);

    await prepareStorage(layout);

    assert.equal((await fs.stat(layout.stateRoot)).mode & 0o7777, 0o755);
    assert.equal((await fs.stat(layout.queueDir)).mode & 0o7777, 0o700);
    assert.equal((await fs.stat(layout.stateDir)).mode & 0o7777, 0o700);
  });

  it('rejects untrusted state root ancestors before creating private storage', async (context) => {
    await context.test('non-root owner', async (subcontext) => {
      const currentUid = typeof process.getuid === 'function' && process.getuid() !== 0
        ? process.getuid()
        : 1001;
      const untrustedOwners = [
        { uid: currentUid },
        { uid: 4242 },
        { gid: 4242 },
      ];
      for (const metadata of untrustedOwners) {
        const layout = await createLayout(subcontext);
        const fsApi = metadataOverridingFsApi(os.tmpdir(), metadata);

        await assert.rejects(
          prepareStorage({ ...layout, fsApi }),
          /state root ancestor metadata is not trusted/,
        );
        await assertPrivateStorageDoesNotExist(layout);
      }
    });

    await context.test('non-sticky writable mode', async (subcontext) => {
      const layout = await createLayout(subcontext);
      const fsApi = metadataOverridingFsApi(os.tmpdir(), { mode: 0o040777 });

      await assert.rejects(
        prepareStorage({ ...layout, fsApi }),
        /state root ancestor metadata is not trusted/,
      );
      await assertPrivateStorageDoesNotExist(layout);
    });

    await context.test('symlink', async (subcontext) => {
      const layout = await createLayout(subcontext);
      const symlinkParent = `${layout.stateRoot}-parent-link`;
      const stateRoot = path.join(symlinkParent, 'config-actions');
      const symlinkLayout = {
        ...layout,
        stateRoot,
        queueDir: path.join(stateRoot, 'queue'),
        stateDir: path.join(stateRoot, 'state'),
      };
      await fs.symlink(layout.root, symlinkParent);
      subcontext.after(async () => fs.rm(symlinkParent, { force: true }));

      await assert.rejects(
        prepareStorage(symlinkLayout),
        /state root ancestor metadata is not trusted/,
      );
      await assertPrivateStorageDoesNotExist(symlinkLayout);
    });
  });

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
    assert.equal((await fs.stat(fixture.stateRoot)).mode & 0o777, 0o755);
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
        enqueueSequence: 1,
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
    const timeoutStopMs = Number(unit.match(/^TimeoutStopSec=([0-9]+)s$/m)?.[1]) * 1_000;
    assert.ok(PREPARE_TERMINATION_GRACE_MS + PREPARE_CLOSE_GRACE_MS < timeoutStopMs);
    assert.doesNotMatch(unit, /^StateDirectory(?:Mode)?=/m);
    assert.deepEqual(unitDirectiveValues(unit, 'ReadOnlyPaths'), [
      '/run/webex-config-deploy',
      '-/var/lib/webex-generic-account-bot/rendered',
    ]);
    assert.deepEqual(unitDirectiveValues(unit, 'ReadWritePaths'), [
      '/run/webex-config-deploy/deploy-config.lock',
      '/run/webex-config-pull',
      '/var/lib/webex-generic-account-bot/config-actions',
      '/var/lib/webex-generic-account-bot/config-prepare-checkout',
      '/var/lib/webex-generic-account-bot/config-staging',
    ]);
    assert.match(unit, /^NoNewPrivileges=true$/m);
    assert.match(unit, /^ProtectSystem=strict$/m);
    assert.match(unit, /^ProtectHome=true$/m);
    assert.match(unit, /^PrivateTmp=true$/m);
    assert.match(unit, /^CapabilityBoundingSet=$/m);
    assert.doesNotMatch(unit, /^(?:PartOf|BindsTo)=/m);
    assert.doesNotMatch(unit, /^User=root$/m);
    assert.doesNotMatch(unit, /^SupplementaryGroups=.*webex-generic-account-bot/m);

    const plan = buildDeployPlan(parseArgs(['--prepare']));
    assert.equal(plan.lockDir, '/run/webex-config-deploy/deploy-config.lock');
    assert.equal(path.dirname(DEFAULTS.socketPath), '/run/webex-config-pull');
    assert.notEqual(path.dirname(plan.lockDir), path.dirname(DEFAULTS.socketPath));
    assert.equal(plan.stagedConfig, PREPARED_RESULT.staged_config);
    assert.equal(plan.stagedMetadataFile, DEFAULTS.stagedMetadataFile);
  });

  it('provisions only the worker identity and host-owned writable deployment roots', async () => {
    const [sysusers, tmpfiles] = await Promise.all([
      fs.readFile(
        new URL('../deploy/systemd/webex-config-pull-worker.sysusers.conf', import.meta.url),
        'utf8',
      ),
      fs.readFile(
        new URL('../deploy/systemd/webex-config-pull-worker.tmpfiles.conf', import.meta.url),
        'utf8',
      ),
    ]);

    assert.match(sysusers, /^u webex-config-deploy /m);
    assert.match(sysusers, /^g webex-config-pull -$/m);
    assert.doesNotMatch(sysusers, /^m /m);
    assert.doesNotMatch(sysusers, /^m webex-config-deploy webex-generic-account-bot$/m);
    await assert.rejects(
      fs.stat(
        new URL(
          '../deploy/systemd/webex-generic-account-bot.service.d/10-config-pull.conf',
          import.meta.url,
        ),
      ),
      { code: 'ENOENT' },
    );
    const tmpfilesRecords = tmpfiles.trim().split('\n').map((line) => line.split(/\s+/));
    assert.deepEqual(tmpfilesRecords, [
      ['d', '/run/webex-config-deploy', '0750', 'root', 'webex-config-pull', '-'],
      [
        'f',
        '/run/webex-config-deploy/deploy-config.lock',
        '0660',
        'root',
        'webex-config-pull',
        '-',
      ],
      [
        'd',
        '/run/webex-config-pull',
        '0750',
        'webex-config-deploy',
        'webex-config-pull',
        '-',
      ],
      ['d', '/var/lib/webex-generic-account-bot', '0755', 'root', 'root', '-'],
      ...[
        '/var/lib/webex-generic-account-bot/config-actions',
        '/var/lib/webex-generic-account-bot/config-actions/queue',
        '/var/lib/webex-generic-account-bot/config-actions/state',
        '/var/lib/webex-generic-account-bot/config-prepare-checkout',
        '/var/lib/webex-generic-account-bot/config-staging',
      ].map((recordPath, index) => [
        'd',
        recordPath,
        index === 0 ? '0755' : '0700',
        'webex-config-deploy',
        'webex-config-pull',
        '-',
      ]),
    ]);
    assert.equal(
      tmpfilesRecords.some((record) => record[3] === 'webex-generic-account-bot'
        || record[4] === 'webex-generic-account-bot'),
      false,
    );
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
  const stateRoot = `${root}-state`;
  context.after(async () => {
    await fs.rm(stateRoot, { recursive: true, force: true });
    await fs.rm(root, { recursive: true, force: true });
  });
  const stagingDir = path.join(root, 'config-staging');
  await fs.mkdir(stagingDir, { mode: 0o700 });
  return {
    root,
    socketPath: path.join(root, 'config-pull.sock'),
    stateRoot,
    queueDir: path.join(stateRoot, 'queue'),
    stateDir: path.join(stateRoot, 'state'),
    publicStatusFile: path.join(stateRoot, 'public-status.json'),
    stagedConfigFile: path.join(stagingDir, 'production.toml.staged'),
    stagedMetadataFile: path.join(stagingDir, 'production.toml.staged.json'),
    requestTimeoutMs: 500,
    commandTimeoutMs: 1_000,
    outputLimitBytes: 4_096,
  };
}

function metadataOverridingFsApi(targetPath, metadata) {
  return new Proxy(fs, {
    get(target, property) {
      if (property !== 'lstat') return target[property];
      return async (candidate) => {
        const stat = await target.lstat(candidate);
        if (candidate !== targetPath) return stat;
        return new Proxy(stat, {
          get(statTarget, statProperty) {
            if (Object.hasOwn(metadata, statProperty)) return metadata[statProperty];
            const value = Reflect.get(statTarget, statProperty, statTarget);
            return typeof value === 'function' ? value.bind(statTarget) : value;
          },
        });
      };
    },
  });
}

async function assertPrivateStorageDoesNotExist(layout) {
  await Promise.all([
    assert.rejects(fs.stat(layout.queueDir), { code: 'ENOENT' }),
    assert.rejects(fs.stat(layout.stateDir), { code: 'ENOENT' }),
  ]);
}

function unitDirectiveValues(unit, directive) {
  return unit
    .split('\n')
    .filter((line) => line.startsWith(`${directive}=`))
    .map((line) => line.slice(directive.length + 1));
}

function sourceIntegerConstant(source, name) {
  const match = source.match(new RegExp(`^(?:export )?const ${name} = ([0-9_]+);$`, 'm'));
  assert(match, `missing integer constant ${name}`);
  return Number(match[1].replaceAll('_', ''));
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, reject, resolve };
}

async function stagePreparedResult(layout, actionId) {
  await fs.writeFile(layout.stagedConfigFile, STAGED_CONFIG, { mode: 0o600 });
  await fs.writeFile(
    layout.stagedMetadataFile,
    `${JSON.stringify({ ...PREPARED_RESULT, request_id: actionId })}\n`,
    { mode: 0o600 },
  );
}

function durabilityRecordingFsApi(
  layout,
  actionId,
  events,
  { failSyncLabel = null } = {},
) {
  return new Proxy(fs, {
    get(target, property) {
      if (property !== 'open') return target[property];
      return async (file, flags, ...rest) => {
        if (
          flags === 'wx'
          && path.dirname(file) === layout.stateDir
          && path.basename(file).startsWith(`.atomic-${actionId}.json-`)
        ) {
          events.push('state-write');
        }
        const handle = await target.open(file, flags, ...rest);
        let syncLabel = null;
        if (file === layout.stagedConfigFile) syncLabel = 'staged-config-sync';
        if (file === layout.stagedMetadataFile) syncLabel = 'staged-metadata-sync';
        if (file === path.dirname(layout.stagedConfigFile) && flags === 'r') {
          syncLabel = 'staging-directory-sync';
        }
        if (!syncLabel) return handle;
        return new Proxy(handle, {
          get(handleTarget, handleProperty) {
            if (handleProperty === 'sync') {
              return async () => {
                events.push(syncLabel);
                if (syncLabel === failSyncLabel) {
                  const error = new Error(`injected ${syncLabel} failure`);
                  error.code = 'EIO';
                  throw error;
                }
                return handleTarget.sync();
              };
            }
            const value = Reflect.get(handleTarget, handleProperty, handleTarget);
            return typeof value === 'function' ? value.bind(handleTarget) : value;
          },
        });
      };
    },
  });
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

function actionState(actionId, enqueueSequence, status, updatedAt, details = {}) {
  return {
    version: 1,
    action_id: actionId,
    action: 'pull',
    enqueue_sequence: enqueueSequence,
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

function exitedChild(exitCode) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.pid = 4_000_003;
  child.kill = () => {};
  queueMicrotask(() => {
    child.stdout.end();
    child.stderr.end();
    child.emit('close', exitCode, null);
  });
  return child;
}
