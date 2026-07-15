import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  DEFAULTS,
  SECRET_FILES,
  SECRET_ROOTS,
  inspectActivationBoundary,
  inspectDeploymentSecrets,
  parseArgs,
  prepareHostDeployment,
  runJsonCommand,
  usage,
} from '../scripts/prepare-host-deployment.mjs';

const REVISION = 'a'.repeat(40);
const MANIFEST_SHA256 = 'b'.repeat(64);
const DIGEST = 'c'.repeat(64);

describe('host deployment preparation', () => {
  it('accepts only fixed modes and approval evidence', () => {
    assert.deepEqual(parseArgs([]), {
      apply: false,
      json: false,
      requireSecrets: false,
      through: null,
    });
    assert.deepEqual(parseArgs([
      '--apply',
      '--through',
      'preactivation-ready',
      '--json',
      '--require-secrets',
      '--expected-bot-revision',
      REVISION,
      '--expected-manifest-sha256',
      MANIFEST_SHA256,
    ]), {
      apply: true,
      json: true,
      requireSecrets: true,
      through: 'preactivation-ready',
      expectedBotRevision: REVISION,
      expectedManifestSha256: MANIFEST_SHA256,
    });
    assert.throws(
      () => parseArgs(['--apply', '--dry-run']),
      /select exactly one deployment mode/,
    );
    assert.throws(() => parseArgs(['--root', '/tmp/host']), /unknown argument/);
    assert.throws(
      () => parseArgs(['--through', 'activated']),
      /deployment target must be provisioned or preactivation-ready/,
    );
    assert.match(usage(), /never installs secrets, enables services, or activates the runner/);
  });

  it('keeps dry-run read-only and invokes only reviewed fixed entrypoints', async () => {
    const calls = [];
    const report = await prepareHostDeployment(options(), {
      euid: 0,
      runJson: async (command, args, label) => {
        calls.push({ command, args, label });
        if (command === DEFAULTS.releaseInstaller) return releaseReport();
        if (command === DEFAULTS.provisioner) return provisionReport('dry-run');
        if (command === DEFAULTS.node) return runtimeInspectionReport();
        assert.fail(`unexpected command: ${command}`);
      },
      inspectSecrets: async () => secretReport('missing'),
      inspectBoundary: async () => activationBoundary(true),
    });

    assert.deepEqual(calls, [
      {
        command: DEFAULTS.releaseInstaller,
        args: [
          '--dry-run',
          '--json',
          '--expected-bot-revision',
          REVISION,
          '--expected-manifest-sha256',
          MANIFEST_SHA256,
        ],
        label: 'host release verification',
      },
      {
        command: DEFAULTS.provisioner,
        args: ['--dry-run', '--json'],
        label: 'host policy provisioning',
      },
      {
        command: DEFAULTS.node,
        args: [DEFAULTS.runtimeBuilder, '--dry-run', '--json'],
        label: 'runtime source inspection',
      },
    ]);
    assert.equal(report.mode, 'dry-run');
    assert.equal(report.runtime.status, 'inspected');
    assert.equal(report.secrets.contents_inspected, false);
    assert.equal(report.service_state, 'unchanged');
    assert.equal(report.activation_state, 'not_attempted');
  });

  it('applies policy and prepares the immutable runtime without service activation', async () => {
    const calls = [];
    let lockCalls = 0;
    const report = await prepareHostDeployment(options({
      apply: true,
      through: 'preactivation-ready',
    }), {
      euid: 0,
      runJson: async (command, args, label) => {
        calls.push({ command, args, label });
        if (command === DEFAULTS.releaseInstaller) return releaseReport();
        if (command === DEFAULTS.provisioner) {
          return provisionReport(args[0] === '--apply' ? 'applied' : 'dry-run', 0);
        }
        if (args.at(-1) === '--write-source-manifest') return sourceManifestReport();
        return runtimeReport();
      },
      inspectSecrets: async () => secretReport('ready'),
      inspectBoundary: async () => activationBoundary(true),
      withLock: async (operation) => {
        lockCalls += 1;
        return operation();
      },
    });

    assert.deepEqual(calls.slice(1), [
      {
        command: DEFAULTS.provisioner,
        args: ['--apply', '--json'],
        label: 'host policy provisioning',
      },
      {
        command: DEFAULTS.provisioner,
        args: ['--dry-run', '--json'],
        label: 'locked host policy revalidation',
      },
      {
        command: DEFAULTS.node,
        args: [DEFAULTS.runtimeBuilder, '--write-source-manifest'],
        label: 'runtime source manifest creation',
      },
      {
        command: DEFAULTS.node,
        args: [DEFAULTS.runtimeBuilder, '--first-deployment'],
        label: 'runtime image creation',
      },
    ]);
    assert.equal(report.runtime.status, 'prepared');
    assert.equal(lockCalls, 1);
    assert.equal(report.runtime.image_sha256, DIGEST);
    assert.equal(report.secrets.ready, true);
    assert.equal(report.service_state, 'unchanged');
    assert.equal(report.activation_state, 'not_attempted');
  });

  it('requires root, exact release evidence, and explicit secret readiness', async () => {
    await assert.rejects(
      prepareHostDeployment(options({ apply: true }), { euid: 0 }),
      /--apply requires an explicit --through target/,
    );
    await assert.rejects(
      prepareHostDeployment(options(), { euid: 1000 }),
      /requires root/,
    );
    await assert.rejects(
      prepareHostDeployment(options({ expectedBotRevision: 'A'.repeat(40) }), { euid: 0 }),
      /lowercase 40-character Git SHA/,
    );
    await assert.rejects(
      prepareHostDeployment(options({ requireSecrets: true }), {
        euid: 0,
        runJson: async (command) => (
          command === DEFAULTS.releaseInstaller ? releaseReport() : provisionReport('dry-run')
        ),
        inspectSecrets: async () => secretReport('missing'),
        inspectBoundary: async () => activationBoundary(true),
      }),
      /deployment secrets are not ready: webex_access_token/,
    );
    await assert.rejects(
      prepareHostDeployment(options(), {
        euid: 0,
        runJson: async (command) => (
          command === DEFAULTS.releaseInstaller
            ? { ...releaseReport(), status: 'recoverable_candidate' }
            : provisionReport('dry-run')
        ),
        inspectBoundary: async () => activationBoundary(true),
      }),
      /does not match the approved installed release/,
    );
  });

  it('can stop after converging host policy without crossing the runtime boundary', async () => {
    const calls = [];
    const report = await prepareHostDeployment(options({
      apply: true,
      through: 'provisioned',
    }), {
      euid: 0,
      runJson: async (command, args) => {
        calls.push({ command, args });
        return command === DEFAULTS.releaseInstaller
          ? releaseReport()
          : provisionReport('applied');
      },
      inspectSecrets: async () => secretReport('missing'),
      inspectBoundary: async () => activationBoundary(false),
      withLock: async () => assert.fail('provision-only apply must not acquire the runtime lock'),
    });
    assert.equal(report.requested_state, 'provisioned');
    assert.deepEqual(report.runtime, { status: 'not_requested' });
    assert.equal(report.activation_boundary.clean, false);
    assert.equal(calls.length, 2);
  });

  it('rejects a dirty activation boundary before runtime mutation', async () => {
    let runtimeCommandReached = false;
    await assert.rejects(
      prepareHostDeployment(options({
        apply: true,
        through: 'preactivation-ready',
      }), {
        euid: 0,
        runJson: async (command, args) => {
          if (command === DEFAULTS.releaseInstaller) return releaseReport();
          if (command === DEFAULTS.provisioner) {
            return args[0] === '--apply'
              ? provisionReport('applied')
              : provisionReport('dry-run', 0);
          }
          runtimeCommandReached = true;
          return runtimeReport();
        },
        inspectSecrets: async () => secretReport('ready'),
        inspectBoundary: async () => activationBoundary(false),
        withLock: async (operation) => operation(),
      }),
      /activation boundary is not clean/,
    );
    assert.equal(runtimeCommandReached, false);
  });

  it('rejects host policy drift after acquiring the runtime lock', async () => {
    let runtimeCommandReached = false;
    await assert.rejects(
      prepareHostDeployment(options({
        apply: true,
        through: 'preactivation-ready',
      }), {
        euid: 0,
        runJson: async (command, args) => {
          if (command === DEFAULTS.releaseInstaller) return releaseReport();
          if (command === DEFAULTS.provisioner) {
            return args[0] === '--apply'
              ? provisionReport('applied')
              : provisionReport('dry-run', 1);
          }
          runtimeCommandReached = true;
          return runtimeReport();
        },
        inspectSecrets: async () => secretReport('ready'),
        inspectBoundary: async () => activationBoundary(true),
        withLock: async (operation) => operation(),
      }),
      /host policy changed before runtime preparation/,
    );
    assert.equal(runtimeCommandReached, false);
  });

  it('rejects activation boundary drift after the runtime build', async () => {
    let boundaryInspections = 0;
    let runtimeCommands = 0;
    await assert.rejects(
      prepareHostDeployment(options({
        apply: true,
        through: 'preactivation-ready',
      }), {
        euid: 0,
        runJson: async (command, args) => {
          if (command === DEFAULTS.releaseInstaller) return releaseReport();
          if (command === DEFAULTS.provisioner) {
            return args[0] === '--apply'
              ? provisionReport('applied')
              : provisionReport('dry-run', 0);
          }
          runtimeCommands += 1;
          return args.at(-1) === '--write-source-manifest'
            ? sourceManifestReport()
            : runtimeReport();
        },
        inspectSecrets: async () => secretReport('ready'),
        inspectBoundary: async () => {
          boundaryInspections += 1;
          return activationBoundary(boundaryInspections === 1);
        },
        withLock: async (operation) => operation(),
      }),
      /activation boundary changed while preparing the runtime/,
    );
    assert.equal(runtimeCommands, 2);
    assert.equal(boundaryInspections, 2);
  });

  it('reports an existing upgrade runtime as a read-only conflict', async () => {
    const report = await prepareHostDeployment(options(), {
      euid: 0,
      runJson: async (command) => {
        if (command === DEFAULTS.releaseInstaller) return releaseReport();
        if (command === DEFAULTS.provisioner) return provisionReport('dry-run');
        return runtimeInspectionReport('conflict');
      },
      inspectSecrets: async () => secretReport('ready'),
      inspectBoundary: async () => activationBoundary(true),
    });
    assert.equal(report.runtime.active_runtime, 'conflict');
    assert.equal(report.runtime.writes_performed, 0);
  });

  it('reports only absence or presence for activation boundary artifacts', async () => {
    const report = await inspectActivationBoundary({
      fsApi: {
        async lstat(file) {
          if (file.includes('receipt')) return { isFile: () => true };
          throw Object.assign(new Error('missing'), { code: 'ENOENT' });
        },
      },
    });
    assert.equal(report.clean, false);
    assert.deepEqual(report.entries, [
      { name: 'activation_receipt', status: 'present' },
      { name: 'runner_permission', status: 'absent' },
      { name: 'reboot_challenge', status: 'absent' },
    ]);
  });

  it('checks secret metadata without opening or reading secret contents', async () => {
    const groupIds = new Map([
      ['webex-generic-account-bot', 4100],
      ['webex-config-deploy', 4101],
    ]);
    const metadata = new Map();
    for (const root of SECRET_ROOTS) {
      metadata.set(root.path, directoryMetadata(groupIds.get(root.group), root.mode));
    }
    for (const file of SECRET_FILES) {
      metadata.set(
        file.path,
        fileMetadata(file.group === null ? 0 : groupIds.get(file.group), file.modes[0]),
      );
    }
    const calls = [];
    const aclCalls = [];
    const report = await inspectDeploymentSecrets({
      resolveGroup: async (name) => groupIds.get(name) ?? null,
      verifyNoAcl: async (file) => aclCalls.push(file),
      fsApi: {
        async lstat(file) {
          calls.push(file);
          const value = metadata.get(file);
          if (value === undefined) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
          return value;
        },
        async readFile() {
          assert.fail('secret contents must not be read');
        },
        async open() {
          assert.fail('secret files must not be opened');
        },
      },
    });
    assert.equal(report.ready, true);
    assert.equal(report.contents_inspected, false);
    assert.deepEqual(report.files.map(({ status }) => status), Array(SECRET_FILES.length).fill('ready'));
    assert.equal(calls.length, SECRET_ROOTS.length + SECRET_FILES.length);
    assert.deepEqual(aclCalls, calls);
  });

  it('reports missing identities, unsafe roots, links, modes, and sizes without details', async () => {
    const botGid = 4100;
    const deployGid = 4101;
    const metadata = new Map();
    for (const root of SECRET_ROOTS) {
      metadata.set(
        root.path,
        directoryMetadata(root.group === 'webex-config-deploy' ? deployGid : botGid, root.mode),
      );
    }
    metadata.set(SECRET_ROOTS[1].path, directoryMetadata(botGid, 0o770));
    metadata.set(SECRET_FILES[1].path, fileMetadata(botGid, 0o666));
    metadata.set(SECRET_FILES[2].path, fileMetadata(botGid, 0o440, { nlink: 2 }));
    metadata.set(SECRET_FILES[3].path, fileMetadata(0, 0o400, { symbolicLink: true }));
    metadata.set(SECRET_FILES[4].path, fileMetadata(deployGid, 0o440, { size: 0 }));

    const report = await inspectDeploymentSecrets({
      resolveGroup: async (name) => (
        name === 'webex-generic-account-bot' ? botGid : deployGid
      ),
      fsApi: {
        async lstat(file) {
          const value = metadata.get(file);
          if (value === undefined) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
          return value;
        },
      },
      verifyNoAcl: async () => {},
    });
    assert.deepEqual(report.files, [
      { name: 'webex_access_token', status: 'invalid' },
      { name: 'bot_environment', status: 'invalid' },
      { name: 'jenkins_environment', status: 'invalid' },
      { name: 'codex_auth', status: 'invalid' },
      { name: 'config_deploy_key', status: 'invalid' },
    ]);
    assert.equal(report.ready, false);

    const pending = await inspectDeploymentSecrets({
      resolveGroup: async () => null,
      fsApi: { lstat: async () => assert.fail('identity-pending roots must not be inspected') },
      verifyNoAcl: async () => assert.fail('identity-pending roots must not inspect ACLs'),
    });
    assert.ok(pending.files.every(({ status }) => status === 'identity_pending'));
  });

  it('scrubs child environments and never includes child output in failures', async () => {
    const calls = [];
    const parsed = await runJsonCommand('/fixed/tool', ['--json'], 'fixed command', {
      run: async (command, args, options_) => {
        calls.push({ command, args, options: options_ });
        return { stdout: '{"ok":true}', stderr: '' };
      },
    });
    assert.deepEqual(parsed, { ok: true });
    assert.deepEqual(calls[0].options.env, {
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    });
    assert.equal(calls[0].options.cwd, '/');

    await assert.rejects(
      runJsonCommand('/fixed/tool', [], 'fixed command', {
        run: async () => {
          throw Object.assign(new Error('token=do-not-report'), {
            code: 9,
            stdout: 'access_token=do-not-report',
            stderr: 'password=do-not-report',
          });
        },
      }),
      (error) => error.message === 'fixed command failed (exit 9)',
    );
  });
});

function options(overrides = {}) {
  return {
    apply: false,
    json: false,
    requireSecrets: false,
    through: null,
    expectedBotRevision: REVISION,
    expectedManifestSha256: MANIFEST_SHA256,
    ...overrides,
  };
}

function runtimeInspectionReport(activeRuntime = 'absent') {
  return {
    version: 1,
    status: 'inspected',
    codex_version: '0.142.3',
    codex_target: 'x86_64-unknown-linux-musl',
    source_file_count: 7,
    source_manifest_sha256: DIGEST,
    active_runtime: activeRuntime,
    writes_performed: 0,
  };
}

function activationBoundary(clean) {
  const entries = ['activation_receipt', 'runner_permission', 'reboot_challenge']
    .map((name, index) => ({
      name,
      status: clean || index > 0 ? 'absent' : 'present',
    }));
  return { clean, entries };
}

function releaseReport() {
  return {
    status: 'already_installed',
    bot_revision: REVISION,
    codex_version: '0.142.3',
    file_count: 42,
    install_root: DEFAULTS.installRoot,
  };
}

function provisionReport(mode, changed = mode === 'applied' ? 0 : 16) {
  return {
    version: 1,
    mode,
    artifact_count: 16,
    changed_artifact_count: changed,
    installed_artifacts: mode === 'applied' ? ['/fixed/policy'] : [],
    command_count: mode === 'applied' ? 3 : 0,
    units_started: 0,
    units_enabled: 0,
  };
}

function sourceManifestReport() {
  return {
    version: 1,
    codex_version: '0.142.3',
    files: [{ source: '/fixed/source' }],
    symlinks: [],
  };
}

function runtimeReport() {
  return {
    version: 1,
    codex_version: '0.142.3',
    source_manifest_sha256: DIGEST,
    image_sha256: DIGEST,
    mksquashfs_sha256: DIGEST,
    image_size: 1024,
  };
}

function secretReport(status) {
  const files = SECRET_FILES.map(({ name }, index) => ({
    name,
    status: index === 0 ? status : 'ready',
  }));
  return {
    ready: files.every((entry) => entry.status === 'ready'),
    contents_inspected: false,
    files,
  };
}

function directoryMetadata(gid, mode) {
  return {
    uid: 0,
    gid,
    mode,
    isDirectory: () => true,
    isSymbolicLink: () => false,
  };
}

function fileMetadata(gid, mode, overrides = {}) {
  return {
    uid: 0,
    gid,
    mode,
    nlink: overrides.nlink ?? 1,
    size: overrides.size ?? 128,
    isFile: () => true,
    isSymbolicLink: () => overrides.symbolicLink ?? false,
  };
}
