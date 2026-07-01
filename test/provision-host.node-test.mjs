import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  ARTIFACTS,
  MANAGED_UNITS,
  buildProvisionPlan,
  parseArgs,
  parseIdentityDatabases,
  provisionHost,
  runCli,
  validateIdentityPolicy,
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

  it('rejects static membership and primary-GID drift', () => {
    const clean = expectedIdentitySnapshot();
    validateIdentityPolicy(clean, { requireAccounts: true });

    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        botEffectiveGroups: [2001, 2002],
      })),
      /forbidden static group.*webex-config-deploy/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        workerEffectiveGroups: [2002, 2001],
      })),
      /forbidden static group.*webex-generic-account-bot/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        workerEffectiveGroups: [2002, 2003],
      })),
      /forbidden static group.*webex-config-pull/,
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
      )),
      /static primary group for unexpected: webex-config-pull/,
    );
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

  it('installs the fixed set atomically and converges without enabling units', async (context) => {
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
    artifacts: fixture.plan.artifacts.map(({ target }) => ({ target, existing: null })),
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

function passwdRecord(name, uid, gid) {
  return `${name}:x:${uid}:${gid}:${name}:/nonexistent:/usr/sbin/nologin`;
}

function groupRecord(name, gid, members = []) {
  return `${name}:x:${gid}:${members.join(',')}`;
}

function unitStates(state) {
  return new Map(MANAGED_UNITS.map((unit) => [unit, { ...state }]));
}
