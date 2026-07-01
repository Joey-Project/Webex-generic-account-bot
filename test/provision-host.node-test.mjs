import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  ARTIFACTS,
  MANAGED_UNITS,
  buildLockedApplyCommand,
  buildProvisionPlan,
  hasProvisionLock,
  parseArgs,
  parseIdentityDatabases,
  provisionHost,
  readSystemIdentitySnapshot,
  readSystemUnitStates,
  runCli,
  validateIdentityPolicy,
  validateNsswitchPolicy,
} from '../scripts/provision-host.mjs';

const REPO_SYSTEMD_ROOT = fileURLToPath(
  new URL('../deploy/systemd/', import.meta.url),
);
const UID = process.getuid();
const GID = process.getgid();

describe('guarded host provisioner policy', () => {
  it('pins the complete non-secret allowlist and excludes activation permission', () => {
    const plan = buildProvisionPlan();
    assert.equal(ARTIFACTS.length, 15);
    assert.deepEqual(
      ARTIFACTS.reduce((counts, artifact) => ({
        ...counts,
        [artifact.kind]: (counts[artifact.kind] ?? 0) + 1,
      }), {}),
      { sysusers: 4, tmpfiles: 6, unit: 5 },
    );
    assert.equal(plan.artifacts.length, ARTIFACTS.length);
    assert.deepEqual(
      plan.artifacts
        .filter(({ kind }) => kind === 'unit')
        .map(({ sourceName }) => sourceName)
        .sort(),
      [...MANAGED_UNITS].sort(),
    );
    const encoded = JSON.stringify(plan);
    assert.doesNotMatch(encoded, /10-codex-launcher\.conf|service\.d/);
    assert.doesNotMatch(encoded, /access-token|bot\.env|jenkins\.env|id_ed25519/);
    assert.equal(new Set(plan.artifacts.map(({ target }) => target)).size, ARTIFACTS.length);
  });

  it('defaults to dry-run and exposes no path override', () => {
    assert.deepEqual(parseArgs([]), { apply: false, json: false });
    assert.deepEqual(parseArgs(['--dry-run', '--json']), { apply: false, json: true });
    assert.deepEqual(parseArgs(['--apply']), { apply: true, json: false });
    assert.throws(() => parseArgs(['--root', '/tmp/host']), /unknown argument/);
    assert.throws(() => parseArgs(['--source-root', '/tmp/source']), /unknown argument/);
    assert.throws(() => parseArgs(['--apply', '--dry-run']), /cannot be combined/);
    assert.throws(() => parseArgs(['--dry-run', '--apply']), /cannot be combined/);
    assert.throws(() => parseArgs(['--apply', '--apply']), /only once/);
  });

  it('wraps the complete apply in the fixed exclusive flock command', async () => {
    const command = buildLockedApplyCommand({
      argv: ['--apply', '--json'],
      nodePath: '/trusted/node',
      scriptPath: '/trusted/provision-host.mjs',
    });
    assert.deepEqual(command, {
      command: '/usr/bin/flock',
      args: [
        '--exclusive',
        '--nonblock',
        '--no-fork',
        '--conflict-exit-code',
        '75',
        '/run/webex-host-provision.lock',
        '/trusted/node',
        '/trusted/provision-host.mjs',
        '--apply',
        '--json',
      ],
    });
    assert.throws(
      () => buildLockedApplyCommand({ argv: ['--dry-run'] }),
      /requires --apply/,
    );

    const calls = [];
    assert.equal(await runCli({
      argv: ['--apply'],
      lockHeld: false,
      runLockedApply: async (argv) => {
        calls.push([...argv]);
        return 75;
      },
    }), 75);
    assert.deepEqual(calls, [['--apply']]);
    assert.equal(
      hasProvisionLock(
        '7: FLOCK ADVISORY WRITE 123 00:2a:456 0 EOF\n',
        123,
        { dev: 0x2a, ino: 456 },
      ),
      true,
    );
    assert.equal(
      hasProvisionLock(
        '7: FLOCK ADVISORY WRITE 124 00:2a:456 0 EOF\n',
        123,
        { dev: 0x2a, ino: 456 },
      ),
      false,
    );
    assert.equal(
      hasProvisionLock(
        '7: FLOCK ADVISORY WRITE 123 00:2b:456 0 EOF\n',
        123,
        { dev: 0x2a, ino: 456 },
      ),
      false,
    );
    await assert.rejects(
      runCli({
        argv: ['--apply'],
        lockHeld: true,
        verifyLockedApply: async () => {
          throw new Error('lock ownership is not proven');
        },
      }),
      /lock ownership is not proven/,
    );
  });

  it('rejects static membership and primary-GID drift', () => {
    validateNsswitchPolicy('passwd: files systemd\ngroup: files systemd\n');
    assert.throws(
      () => validateNsswitchPolicy('passwd: files sss\ngroup: files systemd\n'),
      /unsupported NSS policy for passwd/,
    );
    assert.throws(
      () => validateNsswitchPolicy(
        'passwd: files systemd\ngroup: files systemd\ninitgroups: files sss\n',
      ),
      /unsupported NSS policy for initgroups/,
    );
    const clean = expectedIdentitySnapshot();
    validateIdentityPolicy(clean, { requireAccounts: true });

    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        botEffectiveGroups: [2001, 2002],
      })),
      /unexpected static groups.*webex-generic-account-bot/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        workerEffectiveGroups: [2002, 2001],
      })),
      /unexpected static groups.*webex-config-deploy/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        workerEffectiveGroups: [2002, 2003],
      })),
      /unexpected static groups.*webex-config-deploy/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        configPullMembers: ['webex-generic-account-bot'],
      })),
      /managed group has static members: webex-config-pull/,
    );
    assert.throws(
      () => validateIdentityPolicy(parseIdentityDatabases(
        [
          passwdRecord('webex-generic-account-bot', 1001, 2001),
          passwdRecord('webex-config-deploy', 1002, 2002),
          passwdRecord('unexpected', 1003, 2003),
          '',
        ].join('\n'),
        expectedGroupDatabase(),
        {
          'webex-generic-account-bot': [2001],
          'webex-config-deploy': [2002],
        },
      )),
      /static primary group for unexpected: webex-config-pull/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        botEffectiveGroups: [2001, 2999],
      })),
      /unexpected static groups.*webex-generic-account-bot/,
    );
    assert.throws(
      () => validateIdentityPolicy(parseIdentityDatabases(
        [
          passwdRecord('webex-generic-account-bot', 1001, 2001, {
            shell: '/bin/bash',
          }),
          passwdRecord('webex-config-deploy', 1002, 2002),
          '',
        ].join('\n'),
        expectedGroupDatabase(),
        {
          'webex-generic-account-bot': [2001],
          'webex-config-deploy': [2002],
        },
      )),
      /account metadata is unexpected.*webex-generic-account-bot/,
    );
    assert.throws(
      () => validateIdentityPolicy(parseIdentityDatabases(
        [
          passwdRecord('webex-generic-account-bot', 61_184, 2001),
          passwdRecord('webex-config-deploy', 1002, 2002),
          '',
        ].join('\n'),
        expectedGroupDatabase(),
        {
          'webex-generic-account-bot': [2001],
          'webex-config-deploy': [2002],
        },
      )),
      /managed user ID is outside the local range/,
    );
  });

  it('enumerates static identities from files and permits only DynamicUser', async () => {
    const commands = [];
    const snapshot = await readSystemIdentitySnapshot(
      async (command, args) => {
        commands.push([command, [...args]]);
        return {
          command,
          args: [...args],
          code: 0,
          stdout: args.at(-1) === 'passwd'
            ? [
              passwdRecord('webex-generic-account-bot', 1001, 2001),
              passwdRecord('webex-config-deploy', 1002, 2002),
              '',
            ].join('\n')
            : expectedGroupDatabase(),
          stderr: '',
        };
      },
      systemIdentityFs({ dynamicUserProvider: true }),
    );

    assert.deepEqual(commands, [
      ['/usr/bin/getent', ['-s', 'files', 'passwd']],
      ['/usr/bin/getent', ['-s', 'files', 'group']],
    ]);
    validateIdentityPolicy(snapshot, { requireAccounts: true });
  });

  it('rejects unsupported or static systemd userdb records before getent', async () => {
    let commandCalled = false;
    const runCommand = async () => {
      commandCalled = true;
      throw new Error('getent must not run');
    };

    await assert.rejects(
      readSystemIdentitySnapshot(
        runCommand,
        systemIdentityFs({ providerName: 'io.example.Untrusted' }),
      ),
      /unsupported systemd userdb provider/,
    );
    await assert.rejects(
      readSystemIdentitySnapshot(
        runCommand,
        systemIdentityFs({ staticUserdbEntry: '9000.user' }),
      ),
      /static systemd userdb records are not supported/,
    );
    assert.equal(commandCalled, false);
  });
});

describe('guarded host provisioner execution', () => {
  it('dry-runs without writing targets or invoking host commands', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    const report = await provisionHost(
      { apply: false },
      fixture.dependencies({ commands }),
    );

    assert.equal(report.mode, 'dry-run');
    assert.equal(report.artifact_count, 15);
    assert.equal(report.changed_artifact_count, 15);
    assert.deepEqual(commands, []);
    await assert.rejects(fs.stat(path.join(fixture.targetRoot, 'etc')), { code: 'ENOENT' });
  });

  it('preserves stale candidates in dry-run and removes them before apply', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts[0];
    const candidate = path.join(
      path.dirname(artifact.target),
      `.${path.basename(artifact.target)}.provision-00000000-0000-4000-8000-000000000099.tmp`,
    );
    await fs.mkdir(path.dirname(candidate), { recursive: true, mode: 0o755 });
    await fs.writeFile(candidate, 'interrupted candidate\n', { mode: 0o600 });
    await fs.chmod(candidate, 0o600);

    await provisionHost({ apply: false }, fixture.dependencies());
    assert.equal(await fs.readFile(candidate, 'utf8'), 'interrupted candidate\n');

    await provisionHost(
      { apply: true },
      fixture.dependencies({ applied: true }),
    );
    await assert.rejects(fs.stat(candidate), { code: 'ENOENT' });
    assert.equal(await fs.readFile(artifact.target, 'utf8'), await fs.readFile(artifact.source, 'utf8'));
  });

  it('bounds total directory entries before stale-candidate inspection', async (context) => {
    const fixture = await provisionFixture(context);
    const firstDirectory = path.dirname(fixture.plan.artifacts[0].target);
    await fs.mkdir(firstDirectory, { recursive: true, mode: 0o755 });
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'opendir') return target[property];
        return async (directory) => {
          if (directory !== firstDirectory) return target.opendir(directory);
          return {
            async *[Symbol.asyncIterator]() {
              for (let index = 0; index < 4097; index += 1) {
                yield { name: `unrelated-${index}`, isFile: () => true };
              }
            },
            close: async () => {},
          };
        };
      },
    });

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ fsApi, applied: true }),
      ),
      /too many policy directory entries/,
    );
  });

  it('installs the fixed set transactionally and converges without enabling units', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({ commands, applied: true }),
    );

    assert.equal(report.mode, 'applied');
    assert.equal(report.artifact_count, 15);
    assert.equal(report.changed_artifact_count, 15);
    assert.equal(report.installed_artifacts.length, 15);
    assert.deepEqual(commands, [
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
    for (const artifact of fixture.plan.artifacts) {
      assert.equal(
        await fs.readFile(artifact.target, 'utf8'),
        await fs.readFile(artifact.source, 'utf8'),
      );
      const stat = await fs.stat(artifact.target);
      assert.equal(stat.uid, UID, artifact.target);
      assert.equal(stat.gid, GID, artifact.target);
      assert.equal(stat.mode & 0o777, 0o644, artifact.target);
    }
    await assert.rejects(
      fs.stat(path.join(
        fixture.targetRoot,
        'etc/systemd/system/webex-generic-account-bot.service.d/10-codex-launcher.conf',
      )),
      { code: 'ENOENT' },
    );

    const secondCommands = [];
    const loadedStates = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    });
    const second = await provisionHost(
      { apply: true },
      fixture.dependencies({
        commands: secondCommands,
        applied: true,
        identitySequence: [expectedIdentitySnapshot(), expectedIdentitySnapshot()],
        unitStateSequence: [loadedStates, loadedStates],
      }),
    );
    assert.equal(second.changed_artifact_count, 0);
    assert.deepEqual(second.installed_artifacts, []);
    assert.equal(secondCommands.length, 3);
  });

  it('rejects untrusted sources before creating target directories', async (context) => {
    const fixture = await provisionFixture(context);
    await fs.chmod(fixture.plan.artifacts[0].source, 0o664);
    await assert.rejects(
      provisionHost({ apply: true }, fixture.dependencies({ applied: true })),
      /policy file metadata is not trusted/,
    );
    await assert.rejects(fs.stat(path.join(fixture.targetRoot, 'etc')), { code: 'ENOENT' });
  });

  it('rejects active or enabled managed units before writing targets', async (context) => {
    const fixture = await provisionFixture(context);
    const activeStates = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    activeStates.set(MANAGED_UNITS[0], {
      load: 'loaded',
      active: 'active',
      enabled: 'enabled',
    });
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ unitStateSequence: [activeStates] }),
      ),
      /managed unit is not inactive/,
    );
    await assert.rejects(fs.stat(path.join(fixture.targetRoot, 'etc')), { code: 'ENOENT' });
  });

  it('discovers and rejects active launcher template instances', async (context) => {
    const fixture = await provisionFixture(context);
    const instance = 'webex-codex-launcher@test.service';
    const states = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    states.set(instance, { load: 'loaded', active: 'active', enabled: 'static' });
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ unitStateSequence: [states] }),
      ),
      new RegExp(`managed unit is not inactive: ${instance}`),
    );

    const calls = [];
    const discovered = await readSystemUnitStates(MANAGED_UNITS, async (command, args) => {
      calls.push([command, [...args]]);
      if (args[0] === 'list-units') {
        return { stdout: `${instance} loaded active running test\n`, stderr: '', code: 0 };
      }
      if (args[0] === 'list-unit-files') {
        return {
          stdout: 'webex-codex-launcher@.service static -\nwebex-codex-launcher@boot.service enabled -\n',
          stderr: '',
          code: 0,
        };
      }
      const unit = args.at(-1);
      if (args[0] === 'is-active') {
        return { stdout: unit === instance ? 'active\n' : 'inactive\n', stderr: '', code: 0 };
      }
      if (args[0] === 'is-enabled') {
        return {
          stdout: unit === 'webex-codex-launcher@boot.service' ? 'enabled\n' : 'static\n',
          stderr: '',
          code: 0,
        };
      }
      return { stdout: 'loaded\n', stderr: '', code: 0 };
    });
    assert.equal(discovered.get(instance).active, 'active');
    assert.equal(discovered.get('webex-codex-launcher@boot.service').enabled, 'enabled');
    assert.equal(calls.filter(([, args]) => args[0] === 'list-units').length, 1);
    assert.equal(calls.filter(([, args]) => args[0] === 'list-unit-files').length, 1);

    let stateQueries = 0;
    await assert.rejects(
      readSystemUnitStates(MANAGED_UNITS, async (_command, args) => {
        if (args[0] === 'list-units') {
          return {
            stdout: Array.from(
              { length: 129 },
              (_, index) => `webex-codex-launcher@instance-${index}.service loaded inactive dead test`,
            ).join('\n'),
            stderr: '',
            code: 0,
          };
        }
        if (args[0] === 'list-unit-files') {
          return { stdout: '', stderr: '', code: 0 };
        }
        stateQueries += 1;
        return { stdout: '', stderr: '', code: 0 };
      }),
      /too many launcher instances/,
    );
    assert.equal(stateQueries, 0);
  });

  it('rolls back the complete policy set when an atomic rename fails', async (context) => {
    const fixture = await provisionFixture(context);
    const existingArtifacts = fixture.plan.artifacts.slice(0, 2);
    await fs.mkdir(path.dirname(existingArtifacts[0].target), { recursive: true, mode: 0o755 });
    for (const [index, artifact] of existingArtifacts.entries()) {
      await fs.writeFile(artifact.target, `existing policy ${index}\n`, { mode: 0o644 });
      await fs.chmod(artifact.target, 0o644);
    }
    let candidateRenames = 0;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'rename') return target[property];
        return async (source, destination) => {
          if (path.basename(source).includes('.provision-')) {
            candidateRenames += 1;
            if (candidateRenames === 3) throw new Error('injected atomic rename failure');
          }
          return target.rename(source, destination);
        };
      },
    });

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ fsApi, applied: true }),
      ),
      /injected atomic rename failure/,
    );
    for (const [index, artifact] of existingArtifacts.entries()) {
      assert.equal(await fs.readFile(artifact.target, 'utf8'), `existing policy ${index}\n`);
    }
    for (const artifact of fixture.plan.artifacts.slice(2)) {
      await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
    }
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('preserves the journal instead of rolling back over an unknown state', async (context) => {
    const fixture = await provisionFixture(context);
    const unknownTarget = fixture.plan.artifacts[1].target;
    let candidateRenames = 0;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'rename') return target[property];
        return async (source, destination) => {
          if (path.basename(source).includes('.provision-')) {
            candidateRenames += 1;
            if (candidateRenames === 3) {
              await target.writeFile(unknownTarget, 'concurrent administrator state\n', {
                mode: 0o644,
              });
              await target.chmod(unknownTarget, 0o644);
              throw new Error('injected later rename failure');
            }
          }
          return target.rename(source, destination);
        };
      },
    });

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ fsApi, applied: true }),
      ),
      /policy rollback failed.*policy target has unknown state during recovery/,
    );
    assert.equal(await fs.readFile(unknownTarget, 'utf8'), 'concurrent administrator state\n');
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('rolls back a target whose post-rename directory fsync fails', async (context) => {
    const fixture = await provisionFixture(context);
    const firstTarget = fixture.plan.artifacts[0].target;
    const firstTargetDirectory = path.dirname(firstTarget);
    let targetRenamed = false;
    let injected = false;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property === 'rename') {
          return async (source, destination) => {
            const result = await target.rename(source, destination);
            if (destination === firstTarget) targetRenamed = true;
            return result;
          };
        }
        if (property === 'open') {
          return async (...args) => {
            const handle = await target.open(...args);
            if (args[0] !== firstTargetDirectory || !targetRenamed || injected) return handle;
            return new Proxy(handle, {
              get(handleTarget, handleProperty) {
                if (handleProperty === 'sync') {
                  return async () => {
                    injected = true;
                    throw new Error('injected target directory fsync failure');
                  };
                }
                const value = handleTarget[handleProperty];
                return typeof value === 'function' ? value.bind(handleTarget) : value;
              },
            });
          };
        }
        return target[property];
      },
    });

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ fsApi, applied: true }),
      ),
      /injected target directory fsync failure/,
    );
    for (const artifact of fixture.plan.artifacts) {
      await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
    }
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('recovers a crash-interrupted policy transaction before reapplying', async (context) => {
    const fixture = await provisionFixture(context);
    const existingArtifacts = fixture.plan.artifacts.slice(0, 2);
    await fs.mkdir(path.dirname(existingArtifacts[0].target), { recursive: true, mode: 0o755 });
    for (const [index, artifact] of existingArtifacts.entries()) {
      await fs.writeFile(artifact.target, `pre-crash policy ${index}\n`, { mode: 0o644 });
      await fs.chmod(artifact.target, 0o644);
    }

    let candidateRenames = 0;
    const interruptedFs = new Proxy(fs, {
      get(target, property) {
        if (property !== 'rename') return target[property];
        return async (source, destination) => {
          if (path.basename(source).includes('.provision-')) {
            candidateRenames += 1;
            if (candidateRenames === 4) throw new Error('injected commit interruption');
            if (candidateRenames === 5) throw new Error('injected rollback interruption');
          }
          return target.rename(source, destination);
        };
      },
    });
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ fsApi: interruptedFs, applied: true }),
      ),
      /policy rollback failed/,
    );
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);

    await assert.rejects(
      provisionHost({ apply: false }, fixture.dependencies()),
      /recovery is required/,
    );

    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({ applied: true }),
    );
    assert.equal(report.mode, 'applied');
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
    for (const artifact of fixture.plan.artifacts) {
      assert.equal(await fs.readFile(artifact.target, 'utf8'), await fs.readFile(artifact.source, 'utf8'));
    }
  });

  it('resyncs every old-state target directory before removing the journal', async (context) => {
    const fixture = await provisionFixture(context);
    await writeNullTransaction(fixture);
    const firstDirectory = path.dirname(fixture.plan.artifacts[0].target);
    let injected = false;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'open') return target[property];
        return async (...args) => {
          const handle = await target.open(...args);
          if (args[0] !== firstDirectory || injected) return handle;
          return new Proxy(handle, {
            get(handleTarget, handleProperty) {
              if (handleProperty === 'sync') {
                return async () => {
                  injected = true;
                  throw new Error('injected recovery directory fsync failure');
                };
              }
              const value = handleTarget[handleProperty];
              return typeof value === 'function' ? value.bind(handleTarget) : value;
            },
          });
        };
      },
    });

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ fsApi, applied: true }),
      ),
      /injected recovery directory fsync failure/,
    );
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);

    await provisionHost(
      { apply: true },
      fixture.dependencies({ applied: true }),
    );
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('fails closed before recovery when a target directory is replaced', async (context) => {
    const fixture = await provisionFixture(context);
    const outside = path.join(fixture.root, 'outside');
    const sysusersDirectory = path.join(fixture.targetRoot, 'etc/sysusers.d');
    await fs.mkdir(outside, { mode: 0o700 });
    await writeNullTransaction(fixture);
    await fs.rm(sysusersDirectory, { recursive: true });
    await fs.symlink(outside, sysusersDirectory);

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ applied: true }),
      ),
      /policy directory is not trusted/,
    );
    assert.deepEqual(await fs.readdir(outside), []);
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('rejects a malformed recovery journal without changing targets', async (context) => {
    const fixture = await provisionFixture(context);
    const transactionDirectory = path.dirname(fixture.plan.transactionFile);
    await fs.mkdir(transactionDirectory, { recursive: true, mode: 0o755 });
    await fs.writeFile(fixture.plan.transactionFile, '{not-json}\n', { mode: 0o600 });
    await fs.chmod(fixture.plan.transactionFile, 0o600);

    await assert.rejects(
      provisionHost({ apply: false }, fixture.dependencies()),
      /host policy transaction is malformed/,
    );
    assert.equal(await fs.readFile(fixture.plan.transactionFile, 'utf8'), '{not-json}\n');
  });

  it('refuses to overwrite an unknown target state during recovery', async (context) => {
    const fixture = await provisionFixture(context);
    await writeNullTransaction(fixture);
    const target = fixture.plan.artifacts[0].target;
    await fs.writeFile(target, 'administrator repair\n', { mode: 0o644 });
    await fs.chmod(target, 0o644);

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ applied: true }),
      ),
      /policy target has unknown state during recovery/,
    );
    assert.equal(await fs.readFile(target, 'utf8'), 'administrator repair\n');
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('keeps the complete policy set after a post-install convergence failure', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    const dependencies = fixture.dependencies({ commands, applied: true });
    dependencies.runCommand = async (command, args) => {
      commands.push([command, [...args]]);
      throw new Error('injected sysusers failure');
    };

    await assert.rejects(
      provisionHost({ apply: true }, dependencies),
      /policy files are installed but convergence failed.*injected sysusers failure/,
    );
    assert.deepEqual(commands, [
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
    ]);
    for (const artifact of fixture.plan.artifacts) {
      assert.equal(await fs.readFile(artifact.target, 'utf8'), await fs.readFile(artifact.source, 'utf8'));
    }
  });

  it('requires root before apply and keeps help side-effect free', async () => {
    await assert.rejects(
      provisionHost(
        { apply: true },
        {
          processApi: { geteuid: () => 1000 },
        },
      ),
      /--apply requires root/,
    );

    const output = [];
    assert.equal(await runCli({
      argv: ['--help'],
      stdout: { write: (value) => output.push(value) },
    }), 0);
    assert.match(output.join(''), /Dry-run is the default/);
  });
});

async function provisionFixture(context) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-host-provision-test-'));
  context.after(async () => fs.rm(root, { recursive: true, force: true }));
  const sourceRoot = path.join(root, 'source');
  const targetRoot = path.join(root, 'target');
  await fs.mkdir(sourceRoot, { mode: 0o700 });
  await fs.mkdir(targetRoot, { mode: 0o700 });
  for (const artifact of ARTIFACTS) {
    await fs.copyFile(
      path.join(REPO_SYSTEMD_ROOT, artifact.sourceName),
      path.join(sourceRoot, artifact.sourceName),
    );
    await fs.chmod(path.join(sourceRoot, artifact.sourceName), 0o644);
  }
  const plan = buildProvisionPlan({ sourceRoot, targetRoot });
  return {
    root,
    sourceRoot,
    targetRoot,
    plan,
    dependencies({
      commands = [],
      fsApi = fs,
      applied = false,
      identitySequence = null,
      unitStateSequence = null,
    } = {}) {
      const identities = identitySequence ?? (applied
        ? [emptyIdentitySnapshot(), expectedIdentitySnapshot()]
        : [emptyIdentitySnapshot()]);
      const stateSequence = unitStateSequence ?? (applied
        ? [
          unitStates({ load: 'not-found', active: 'inactive', enabled: 'not-found' }),
          unitStates({ load: 'loaded', active: 'inactive', enabled: 'disabled' }),
        ]
        : [unitStates({ load: 'not-found', active: 'inactive', enabled: 'not-found' })]);
      let identityIndex = 0;
      let stateIndex = 0;
      let uuid = 0;
      return {
        plan,
        fsApi,
        allowTestRoot: true,
        requireRoot: false,
        sourceTrustRoot: sourceRoot,
        sourceUid: UID,
        sourceGid: GID,
        targetUid: UID,
        targetGid: GID,
        randomUUID: () => `00000000-0000-4000-8000-${String(uuid += 1).padStart(12, '0')}`,
        readIdentitySnapshot: async () => identities[
          Math.min(identityIndex++, identities.length - 1)
        ],
        readUnitStates: async () => stateSequence[
          Math.min(stateIndex++, stateSequence.length - 1)
        ],
        runCommand: async (command, args) => {
          commands.push([command, [...args]]);
          return { command, args: [...args], code: 0, stdout: '', stderr: '' };
        },
      };
    },
  };
}

async function writeNullTransaction(fixture) {
  for (const directory of new Set(
    fixture.plan.artifacts.map(({ target }) => path.dirname(target)),
  )) {
    await fs.mkdir(directory, { recursive: true, mode: 0o755 });
  }
  const transaction = {
    version: 1,
    artifacts: fixture.plan.artifacts.map(({ target }) => ({
      target,
      desired_sha256: '0'.repeat(64),
      existing: null,
    })),
  };
  await fs.writeFile(
    fixture.plan.transactionFile,
    `${JSON.stringify(transaction)}\n`,
    { mode: 0o600 },
  );
  await fs.chmod(fixture.plan.transactionFile, 0o600);
}

function emptyIdentitySnapshot() {
  return parseIdentityDatabases('', '');
}

function expectedIdentitySnapshot({
  botEffectiveGroups = [2001],
  workerEffectiveGroups = [2002],
  configPullMembers = [],
} = {}) {
  return parseIdentityDatabases(
    [
      passwdRecord('webex-generic-account-bot', 1001, 2001),
      passwdRecord('webex-config-deploy', 1002, 2002),
      '',
    ].join('\n'),
    expectedGroupDatabase(configPullMembers),
    {
      'webex-generic-account-bot': botEffectiveGroups,
      'webex-config-deploy': workerEffectiveGroups,
    },
  );
}

function expectedGroupDatabase(configPullMembers = []) {
  return [
    groupRecord('webex-generic-account-bot', 2001),
    groupRecord('webex-config-deploy', 2002),
    groupRecord('webex-config-pull', 2003, configPullMembers),
    groupRecord('webex-codex-input', 2004),
    groupRecord('webex-codex-launch', 2005),
    '',
  ].join('\n');
}

function passwdRecord(name, uid, gid, {
  home = name === 'webex-generic-account-bot'
    ? '/var/lib/webex-generic-account-bot'
    : '/nonexistent',
  shell = '/usr/sbin/nologin',
} = {}) {
  return `${name}:x:${uid}:${gid}:${name}:${home}:${shell}`;
}

function groupRecord(name, gid, members = []) {
  return `${name}:x:${gid}:${members.join(',')}`;
}

function systemIdentityFs({
  dynamicUserProvider = false,
  providerName = null,
  staticUserdbEntry = null,
} = {}) {
  const nsswitch = Buffer.from('passwd: files systemd\ngroup: files systemd\n');
  const provider = providerName
    ?? (dynamicUserProvider ? 'io.systemd.DynamicUser' : null);
  const directoryEntries = new Map();
  if (provider) {
    directoryEntries.set('/run/systemd/userdb', [directoryEntry(provider, true)]);
  }
  if (staticUserdbEntry) {
    directoryEntries.set('/etc/userdb', [directoryEntry(staticUserdbEntry, false)]);
  }
  const optionalDirectories = new Set([
    '/run/systemd/userdb',
    '/etc/userdb',
    '/run/userdb',
    '/run/host/userdb',
    '/usr/lib/userdb',
  ]);
  const directoryStat = Object.freeze({
    uid: 0,
    gid: 0,
    mode: 0o40755,
    isDirectory: () => true,
    isSymbolicLink: () => false,
  });
  const socketStat = Object.freeze({
    uid: 0,
    gid: 0,
    mode: 0o140666,
    nlink: 1,
    isSocket: () => true,
    isSymbolicLink: () => false,
  });
  const nsswitchStat = Object.freeze({
    uid: 0,
    gid: 0,
    mode: 0o100644,
    nlink: 1,
    size: nsswitch.length,
    dev: 1,
    ino: 1,
    mtimeMs: 1,
    ctimeMs: 1,
    isFile: () => true,
    isSymbolicLink: () => false,
  });
  const missing = () => Object.assign(new Error('missing'), { code: 'ENOENT' });

  return {
    async open(file) {
      if (file !== '/etc/nsswitch.conf') throw missing();
      return {
        stat: async () => nsswitchStat,
        readFile: async () => Buffer.from(nsswitch),
        close: async () => {},
      };
    },
    async lstat(candidate) {
      if (provider && candidate === `/run/systemd/userdb/${provider}`) {
        return socketStat;
      }
      if (optionalDirectories.has(candidate) && !directoryEntries.has(candidate)) {
        throw missing();
      }
      return directoryStat;
    },
    async opendir(directory) {
      const entries = directoryEntries.get(directory);
      if (!entries) throw missing();
      return asyncDirectory(entries);
    },
  };
}

function directoryEntry(name, socket) {
  return Object.freeze({
    name,
    isSocket: () => socket,
  });
}

function asyncDirectory(entries) {
  return {
    async *[Symbol.asyncIterator]() {
      yield* entries;
    },
    close: async () => {},
  };
}

function unitStates(state) {
  return new Map(MANAGED_UNITS.map((unit) => [unit, { ...state }]));
}
