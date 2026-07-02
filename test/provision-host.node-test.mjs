import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  buildDeployPlan,
  parseArgs as parseDeployArgs,
} from '../scripts/deploy-config.mjs';
import {
  ARTIFACTS,
  MANAGED_UNITS,
  assertCanonicalVarRunLink,
  assertInitialPidNamespace,
  assertManagedRuntimeAncestorsTraversable,
  assertNoExtendedPosixAcl,
  assertSameMountNamespace,
  buildLockedApplyCommand,
  buildProvisionPlan,
  ensureProvisionLockFile,
  executeIdentityRecovery,
  findOpenFileDescriptor,
  executeLockedApply,
  hasIdentityLock,
  hasProvisionLock,
  parseArgs,
  parseIdentityDatabases,
  provisionHost,
  readBoundedProcFile,
  readSystemIdentitySnapshot,
  readSystemBootPolicyCatalogs,
  readSystemUnitStates as readSystemUnitStatesImpl,
  restoreInterruptedIdentityDatabases,
  runFixedCommand,
  runCli,
  runIdentityRecoveryChild,
  validateIdentityPolicy,
  validateNsswitchPolicy,
  validateProvisionLockMetadata,
  verifyManagedTmpfilesState,
} from '../scripts/provision-host.mjs';

const REPO_SYSTEMD_ROOT = fileURLToPath(
  new URL('../deploy/systemd/', import.meta.url),
);
const UID = process.getuid();
const GID = process.getgid();
const PROVISION_CANDIDATE_PREFIX = '.webex-host-policy.provision-';
const SYSTEMD_MANAGER_UNIT_PATH = [
  '/etc/systemd/system.control',
  '/run/systemd/system.control',
  '/run/systemd/transient',
  '/run/systemd/generator.early',
  '/etc/systemd/system',
  '/etc/systemd/system.attached',
  '/run/systemd/system',
  '/run/systemd/system.attached',
  '/run/systemd/generator',
  '/usr/local/lib/systemd/system',
  '/usr/lib/systemd/system',
  '/run/systemd/generator.late',
].join(' ');
const SPLIT_USR_SYSTEMD_MANAGER_UNIT_PATH = SYSTEMD_MANAGER_UNIT_PATH.replace(
  '/usr/lib/systemd/system',
  '/lib/systemd/system',
);
const SAFE_MOUNT_INFO = [
  '1 0 0:1 / / rw - overlay overlay rw',
  '2 1 0:2 / /run rw - tmpfs tmpfs rw',
  '3 1 8:1 / /var/lib rw - ext4 /dev/root rw',
  '5 2 0:4 net:[4026532613] /run/docker/netns/test rw - nsfs nsfs rw',
  '',
].join('\n');

function readSystemUnitStates(units, runCommand, fsApi, identitySnapshot = null) {
  return readSystemUnitStatesImpl(
    units,
    async (command, args, allowedExitCodes) => {
      if (args.join('\0') === 'show\0--property=UnitPath\0--value') {
        return { stdout: `${SYSTEMD_MANAGER_UNIT_PATH}\n`, stderr: '', code: 0 };
      }
      const result = await runCommand(command, args, allowedExitCodes);
      if (args[0] === 'is-active' && result.code === 0 && result.stdout === 'inactive\n') {
        return { ...result, code: 3 };
      }
      return result;
    },
    fsApi,
    identitySnapshot,
  );
}

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

  it('requires the provisioner to share PID 1 mount namespace identity', async () => {
    const namespaceFs = (managerInode) => ({
      async open(file, flags) {
        assert.equal(flags, fsConstants.O_RDONLY);
        return {
          stat: async () => ({
            dev: 7,
            ino: file === '/proc/self/ns/mnt' ? 41 : managerInode,
          }),
          close: async () => {},
        };
      },
    });
    await assert.doesNotReject(assertSameMountNamespace(namespaceFs(41)));
    await assert.rejects(
      assertSameMountNamespace(namespaceFs(42)),
      /not in PID 1 mount namespace/,
    );
    await assert.doesNotReject(assertSameMountNamespace(namespaceFs(42), {
      expectPrivate: true,
      readMountInfo: async () => SAFE_MOUNT_INFO,
    }));
    await assert.rejects(
      assertSameMountNamespace(namespaceFs(41), {
        expectPrivate: true,
        readMountInfo: async () => SAFE_MOUNT_INFO,
      }),
      /apply is not in a private mount namespace/,
    );
    await assert.rejects(
      assertSameMountNamespace(namespaceFs(42), {
        expectPrivate: true,
        readMountInfo: async () => SAFE_MOUNT_INFO.replace(' / rw - ', ' / rw shared:1 - '),
      }),
      /mount propagation is not private/,
    );
  });

  it('requires the canonical root-owned /var/run compatibility link', async () => {
    await assertCanonicalVarRunLink(systemdUnitPathFs(
      new Map(),
      { symlinksByPath: new Map([['/var/run', '../run']]) },
    ));
    await assertCanonicalVarRunLink(systemdUnitPathFs(
      new Map(),
      { symlinksByPath: new Map([['/var/run', '/run']]) },
    ));
    await assert.rejects(
      assertCanonicalVarRunLink(systemdUnitPathFs(
        new Map(),
        { symlinksByPath: new Map([['/var/run', '/etc']]) },
      )),
      /not the canonical symlink to \/run/,
    );
    await assert.rejects(
      assertCanonicalVarRunLink(systemdUnitPathFs()),
      /not the canonical root-owned symlink/,
    );
  });

  it('requires the initial PID namespace through the fixed lsns probe', async () => {
    const calls = [];
    const hostProcContents = new Map([
      ['/proc/1/comm', 'systemd\n'],
      ['/proc/1/cgroup', '0::/init.scope\n'],
      ['/proc/self/uid_map', '0 0 4294967295\n'],
      ['/proc/self/gid_map', '0 0 4294967295\n'],
    ]);
    const initialUserNamespace = new Map([
      ['/proc/self/ns/user', { dev: 4, ino: 5 }],
      ['/proc/1/ns/user', { dev: 4, ino: 5 }],
    ]);
    const hostProcFs = boundedProcFileSystem(hostProcContents, initialUserNamespace);
    const runCommand = async (command, args) => {
      calls.push([command, args]);
      return { code: 0, stdout: '0\n', stderr: '' };
    };
    await assertInitialPidNamespace(runCommand, { pid: 1234 }, hostProcFs);
    assert.deepEqual(calls, [[
      '/usr/bin/lsns',
      ['--noheadings', '--output', 'PNS', '--type', 'pid', '--task', '1234'],
    ]]);
    await assert.rejects(
      assertInitialPidNamespace(
        async () => ({ code: 0, stdout: '4026531836\n', stderr: '' }),
        { pid: 2 },
        hostProcFs,
      ),
      /not in the initial PID namespace/,
    );
    await assert.rejects(
      assertInitialPidNamespace(
        runCommand,
        { pid: 2 },
        boundedProcFileSystem(hostProcContents, new Map([
          ['/proc/self/ns/user', { dev: 4, ino: 6 }],
          ['/proc/1/ns/user', { dev: 4, ino: 5 }],
        ])),
      ),
      /not in the initial user namespace/,
    );
    await assert.rejects(
      assertInitialPidNamespace(
        runCommand,
        { pid: 2 },
        boundedProcFileSystem(new Map([
          ['/proc/1/comm', 'bwrap\n'],
          ['/proc/1/cgroup', '0::/\n'],
          ['/proc/self/uid_map', '1002 0 1\n'],
          ['/proc/self/gid_map', '1002 0 1\n'],
        ])),
      ),
      /not running under the host systemd manager/,
    );
    await assert.rejects(
      assertInitialPidNamespace(
        runCommand,
        { pid: 2 },
        boundedProcFileSystem(new Map([
          ['/proc/1/comm', 'systemd\n'],
          ['/proc/1/cgroup', '0::/init.scope\n'],
          ['/proc/self/uid_map', '1002 0 1\n'],
          ['/proc/self/gid_map', '1002 0 1\n'],
        ])),
      ),
      /not in the initial user namespace/,
    );
  });

  it('wraps the complete apply in the fixed exclusive flock command', async () => {
    const fdBootstrap = [
      'const { readFileSync } = await import("node:fs");',
      'const source = readFileSync(5).toString("base64");',
      'const { runCli } = await import("data:text/javascript;base64," + source);',
      'process.exitCode = await runCli({ argv: process.argv.slice(1) });',
    ].join(' ');
    const command = buildLockedApplyCommand({
      argv: ['--apply', '--json'],
      nodePath: '/trusted/node',
    });
    assert.deepEqual(command, {
      command: '/usr/bin/flock',
      args: [
        '--exclusive',
        '--nonblock',
        '--no-fork',
        '--conflict-exit-code',
        '75',
        '/run/webex-config-deploy/deploy-config.lock',
        '/usr/bin/unshare',
        '--mount',
        '--propagation',
        'private',
        '--',
        '/trusted/node',
        '--input-type=module',
        '--eval',
        fdBootstrap,
        '--',
        '--apply',
        '--json',
      ],
    });
    assert.equal(
      command.args[5],
      buildDeployPlan(parseDeployArgs(['--apply'])).lockDir,
    );
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
      hasIdentityLock(
        '8: POSIX ADVISORY WRITE 321 00:2a:654 0 EOF\n',
        321,
        { dev: 0x2a, ino: 654 },
      ),
      true,
    );
    assert.equal(
      hasIdentityLock(
        '8: POSIX ADVISORY WRITE 322 00:2a:654 0 EOF\n',
        321,
        { dev: 0x2a, ino: 654 },
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
        privateMountNamespace: true,
        verifyLockedApply: async () => {
          throw new Error('lock ownership is not proven');
        },
      }),
      /lock ownership is not proven/,
    );
    await assert.rejects(
      runCli({
        argv: ['--apply'],
        lockHeld: true,
        privateMountNamespace: false,
        verifyLockedApply: async () => {},
      }),
      /requires a private mount namespace/,
    );

    const entrypoints = [];
    let ensureLockCalls = 0;
    await assert.rejects(
      executeLockedApply(['--apply'], {
        nodePath: '/trusted/node',
        scriptPath: '/untrusted/provision-host.mjs',
        verifyReexecFile: async (file) => {
          entrypoints.push(file);
          if (file === '/untrusted/provision-host.mjs') {
            throw new Error('provisioner script is not trusted');
          }
        },
        ensureLock: async () => {
          ensureLockCalls += 1;
        },
      }),
      /provisioner script is not trusted/,
    );
    assert.deepEqual(entrypoints, ['/trusted/node', '/untrusted/provision-host.mjs']);
    assert.equal(ensureLockCalls, 0);

    const ordering = [];
    await assert.rejects(
      executeLockedApply(['--apply'], {
        nodePath: '/trusted/node',
        scriptPath: '/trusted/provision-host.mjs',
        verifyReexecFile: async (file) => ordering.push(`verify:${file}`),
        preflightHost: async () => {
          ordering.push('preflight');
          throw new Error('host policy preflight failed');
        },
        ensureLock: async () => ordering.push('ensure-lock'),
      }),
      /host policy preflight failed/,
    );
    assert.deepEqual(ordering, [
      'verify:/trusted/node',
      'verify:/trusted/provision-host.mjs',
      'verify:/usr/bin/flock',
      'verify:/usr/bin/unshare',
      'verify:/opt/webex-generic-account-bot/bin/webex-host-identity-lock',
      'preflight',
    ]);

    const opened = [];
    const closed = [];
    let spawned = null;
    const openReexecFile = async (file) => {
      const fd = 31 + opened.length;
      opened.push(file);
      return { fd, close: async () => closed.push(file) };
    };
    const exitCode = await executeLockedApply(['--apply'], {
      nodePath: '/trusted/node',
      scriptPath: '/trusted/provision-host.mjs',
      verifyReexecFile: async () => {},
      preflightHost: async () => {},
      ensureLock: async () => {},
      openExecutable: openReexecFile,
      openScript: openReexecFile,
      spawnProcess: (command, args, options) => {
        spawned = { command, args, options };
        return {
          once(event, callback) {
            if (event === 'exit') queueMicrotask(() => callback(0, null));
            return this;
          },
        };
      },
    });
    assert.equal(exitCode, 0);
    assert.deepEqual(opened, [
      '/usr/bin/flock',
      '/usr/bin/unshare',
      '/trusted/node',
      '/trusted/provision-host.mjs',
    ]);
    assert.deepEqual(closed, opened);
    assert.equal(spawned.command, '/proc/self/fd/31');
    assert.equal(spawned.options.argv0, '/usr/bin/flock');
    assert.deepEqual(spawned.options.stdio.slice(3), [32, 33, 34]);
    assert.equal(spawned.options.env.WEBEX_HOST_PROVISION_SOURCE_ROOT, '/deploy/systemd');
    assert.deepEqual(spawned.args.slice(6, 17), [
      '/proc/self/fd/3',
      '--mount',
      '--propagation',
      'private',
      '--',
      '/proc/self/fd/4',
      '--input-type=module',
      '--eval',
      fdBootstrap,
      '--',
      '--apply',
    ]);

    let identitySpawn = null;
    const identityClosed = [];
    await executeIdentityRecovery({
      allowTestInvocation: true,
      resolveProvisionLock: async () => ({ fd: 46 }),
      processApi: { pid: 4321 },
      openExecutable: async (file) => {
        assert.equal(
          file,
          '/opt/webex-generic-account-bot/bin/webex-host-identity-lock',
        );
        return { fd: 44, close: async () => identityClosed.push(file) };
      },
      spawnProcess: (command, args, options) => {
        identitySpawn = { command, args, options };
        return {
          once(event, callback) {
            if (event === 'exit') queueMicrotask(() => callback(0, null));
            return this;
          },
        };
      },
    });
    assert.equal(identitySpawn.command, '/proc/self/fd/44');
    assert.deepEqual(identitySpawn.args, []);
    assert.equal(
      identitySpawn.options.argv0,
      '/opt/webex-generic-account-bot/bin/webex-host-identity-lock',
    );
    assert.deepEqual(identitySpawn.options.stdio, [
      'inherit',
      'inherit',
      'inherit',
      4,
      'ignore',
      5,
      46,
    ]);
    assert.deepEqual(Object.keys(identitySpawn.options.env).sort(), [
      'LANG',
      'LC_ALL',
      'PATH',
      'WEBEX_HOST_IDENTITY_LOCK_PARENT_PID',
    ]);
    assert.equal(identitySpawn.options.env.WEBEX_HOST_IDENTITY_LOCK_PARENT_PID, '4321');
    assert.deepEqual(identityClosed, [
      '/opt/webex-generic-account-bot/bin/webex-host-identity-lock',
    ]);

    const descriptorFile = path.join(
      await fs.mkdtemp(path.join(os.tmpdir(), 'webex-provision-fd-test-')),
      'lock',
    );
    await fs.writeFile(descriptorFile, '');
    const descriptorHandle = await fs.open(descriptorFile, fsConstants.O_RDONLY);
    try {
      assert.equal(
        await findOpenFileDescriptor(await descriptorHandle.stat()),
        descriptorHandle.fd,
      );
      const duplicateHandle = await fs.open(descriptorFile, fsConstants.O_RDONLY);
      try {
        await assert.rejects(
          findOpenFileDescriptor(await descriptorHandle.stat()),
          /descriptor is missing or ambiguous/,
        );
      } finally {
        await duplicateHandle.close();
      }
    } finally {
      await descriptorHandle.close();
      await fs.rm(path.dirname(descriptorFile), { recursive: true, force: true });
    }

    const provisionScript = fileURLToPath(
      new URL('../scripts/provision-host.mjs', import.meta.url),
    );
    const scriptHandle = await fs.open(provisionScript, fsConstants.O_RDONLY);
    try {
      const result = spawnSync(
        process.execPath,
        [
          '--input-type=module',
          '--eval',
          fdBootstrap,
          '--',
          '--help',
        ],
        {
          env: {
            PATH: '/usr/bin:/bin',
            LANG: 'C.UTF-8',
            LC_ALL: 'C.UTF-8',
            WEBEX_HOST_PROVISION_LOCKED: '1',
            WEBEX_HOST_PROVISION_PRIVATE_MOUNT_NS: '1',
            WEBEX_HOST_PROVISION_SOURCE_ROOT: REPO_SYSTEMD_ROOT,
          },
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe', 'ignore', 'ignore', scriptHandle.fd],
        },
      );
      assert.equal(result.error, undefined);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /Dry-run is the default/);
      assert.equal(result.stderr, '');
    } finally {
      await scriptHandle.close();
    }

    const launcherPath = fileURLToPath(new URL('../scripts/provision-host', import.meta.url));
    const launcher = await fs.readFile(launcherPath, 'utf8');
    assert.equal((await fs.stat(launcherPath)).mode & 0o777, 0o755);
    assert.equal(launcher, [
      '#!/usr/bin/env -S -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 /usr/bin/node',
      '',
      "const process = require('node:process');",
      '',
      "import('./provision-host.mjs')",
      '  .then(({ runCli }) => runCli())',
      '  .then((code) => {',
      '    process.exitCode = code;',
      '  })',
      '  .catch((error) => {',
      '    process.stderr.write(`${error.message}\\n`);',
      '    process.exitCode = 1;',
      '  });',
      '',
    ].join('\n'));
    const cleanLaunch = spawnSync(
      '/usr/bin/env',
      [
        '-S',
        `-i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 ${process.execPath}`,
        launcherPath,
        '--help',
      ],
      {
        env: { NODE_OPTIONS: '--definitely-invalid' },
        encoding: 'utf8',
      },
    );
    assert.equal(cleanLaunch.status, 0, cleanLaunch.stderr);
    assert.match(cleanLaunch.stdout, /Dry-run is the default/);
    assert.equal(cleanLaunch.stderr, '');
    const readme = await fs.readFile(
      fileURLToPath(new URL('../README.md', import.meta.url)),
      'utf8',
    );
    assert.match(readme, /sudoers rule must name that absolute launcher path/);
    assert.match(readme, /must use\n`NOSETENV` with the normal `env_reset` policy/);
    assert.match(readme, /granting `SETENV`.*dynamic-loader variables/s);
  });

  it('accepts bootstrap, deployed, or interrupted shared lock migration metadata', () => {
    const directoryStat = (gid, mode) => ({
      uid: 0,
      gid,
      mode: 0o40000 | mode,
      isDirectory: () => true,
      isSymbolicLink: () => false,
    });
    const lockStat = (gid, mode) => ({
      uid: 0,
      gid,
      mode: 0o100000 | mode,
      nlink: 1,
      isFile: () => true,
      isSymbolicLink: () => false,
    });

    assert.deepEqual(
      validateProvisionLockMetadata(directoryStat(0, 0o755), lockStat(0, 0o600), null),
      { state: 'bootstrap', gid: 0, mode: 0o600, parentMode: 0o755 },
    );
    for (const interruptedMode of [0o000, 0o055, 0o500, 0o700, 0o710, 0o750]) {
      assert.deepEqual(
        validateProvisionLockMetadata(
          directoryStat(0, interruptedMode),
          lockStat(0, 0o600),
          null,
        ),
        { state: 'bootstrap', gid: 0, mode: 0o600, parentMode: 0o755 },
      );
    }
    assert.deepEqual(
      validateProvisionLockMetadata(directoryStat(2003, 0o750), lockStat(2003, 0o660), 2003),
      { state: 'deployed', gid: 2003, mode: 0o660, parentMode: 0o750 },
    );
    assert.deepEqual(
      validateProvisionLockMetadata(directoryStat(2003, 0o750), lockStat(0, 0o600), 2003),
      { state: 'deployed', gid: 2003, mode: 0o660, parentMode: 0o750 },
    );
    assert.deepEqual(
      validateProvisionLockMetadata(
        directoryStat(2003, 0o755),
        lockStat(0, 0o600),
        2003,
      ),
      { state: 'deployed', gid: 2003, mode: 0o660, parentMode: 0o750 },
    );
    assert.throws(
      () => validateProvisionLockMetadata(
        directoryStat(2003, 0o750),
        lockStat(0, 0o600),
        2003,
        { allowInterruptedMigration: false },
      ),
      /provision lock file is not trusted/,
    );
    assert.throws(
      () => validateProvisionLockMetadata(
        directoryStat(2003, 0o755),
        lockStat(0, 0o600),
        2003,
        { allowInterruptedMigration: false },
      ),
      /provision lock parent is not trusted/,
    );
    assert.throws(
      () => validateProvisionLockMetadata(
        directoryStat(2004, 0o750),
        lockStat(2004, 0o660),
        2003,
      ),
      /provision lock parent is not trusted/,
    );
    assert.throws(
      () => validateProvisionLockMetadata(
        directoryStat(2003, 0o750),
        lockStat(2003, 0o600),
        2003,
      ),
      /provision lock file is not trusted/,
    );
  });

  it('recovers safe umask and tmpfiles lock migration interruptions', async () => {
    const state = {
      parentGid: 2003,
      parentMode: 0o755,
      lockGid: 0,
      lockMode: 0o000,
    };
    const directoryStat = (gid = 0, mode = 0o755) => Object.freeze({
      uid: 0,
      gid,
      mode: 0o40000 | mode,
      isDirectory: () => true,
      isSymbolicLink: () => false,
    });
    const lockStat = () => Object.freeze({
      uid: 0,
      gid: state.lockGid,
      mode: 0o100000 | state.lockMode,
      nlink: 1,
      isFile: () => true,
      isSymbolicLink: () => false,
    });
    const fsApi = {
      lstat: async (candidate) => (
        candidate === '/run/webex-config-deploy'
          ? directoryStat(state.parentGid, state.parentMode)
          : directoryStat()
      ),
      chmod: async (candidate, mode) => {
        assert.equal(candidate, '/run/webex-config-deploy');
        state.parentMode = mode;
      },
      open: async (candidate, flags) => {
        if (candidate === '/etc/group') {
          const contents = Buffer.from(expectedGroupDatabase());
          const stat = Object.freeze({
            ...lockStat(),
            mode: 0o100644,
            size: contents.length,
            dev: 1,
            ino: 1,
            mtimeMs: 1,
            ctimeMs: 1,
          });
          return {
            stat: async () => stat,
            readFile: async () => contents,
            close: async () => {},
          };
        }
        if (candidate === '/run' || candidate === '/run/webex-config-deploy') {
          return { sync: async () => {}, close: async () => {} };
        }
        if (flags & fsConstants.O_EXCL) {
          throw Object.assign(new Error('exists'), { code: 'EEXIST' });
        }
        assert.equal(candidate, '/run/webex-config-deploy/deploy-config.lock');
        return {
          stat: async () => lockStat(),
          chown: async (uid, gid) => {
            assert.equal(uid, 0);
            state.lockGid = gid;
          },
          chmod: async (mode) => { state.lockMode = mode; },
          sync: async () => {},
          close: async () => {},
        };
      },
    };

    const namespaceBoundaries = [];
    await ensureProvisionLockFile(
      fsApi,
      async (boundary) => namespaceBoundaries.push(boundary),
    );
    assert.deepEqual(state, {
      parentGid: 2003,
      parentMode: 0o750,
      lockGid: 2003,
      lockMode: 0o660,
    });
    assert.ok(namespaceBoundaries.includes('provision-lock-parent-chmod'));
    assert.ok(namespaceBoundaries.includes('provision-lock-existing-chown'));
    assert.ok(namespaceBoundaries.includes('provision-lock-existing-chmod'));
  });

  it('rejects static membership and primary-GID drift', () => {
    validateNsswitchPolicy([
      'passwd: files systemd',
      'group: files systemd',
      'shadow: files',
      'gshadow: files',
      '',
    ].join('\n'));
    assert.throws(
      () => validateNsswitchPolicy([
        'passwd: files sss',
        'group: files systemd',
        'shadow: files',
        'gshadow: files',
        '',
      ].join('\n')),
      /unsupported NSS policy for passwd/,
    );
    assert.throws(
      () => validateNsswitchPolicy([
        'passwd: files systemd',
        'group: files systemd',
        'shadow: files',
        'gshadow: files',
        'initgroups: files sss',
        '',
      ].join('\n')),
      /unsupported NSS policy for initgroups/,
    );
    assert.throws(
      () => validateNsswitchPolicy([
        'passwd: files systemd',
        'group: files systemd',
        'shadow: files sss',
        'gshadow: files',
        '',
      ].join('\n')),
      /unsupported NSS policy for shadow/,
    );
    const clean = expectedIdentitySnapshot();
    validateIdentityPolicy(clean, { requireAccounts: true });
    assert.throws(
      () => validateIdentityPolicy(parseIdentityDatabases(
        '',
        `${groupRecord('external-operators', 27, ['webex-config-deploy'])}\n`,
      )),
      /managed user has static group privileges: webex-config-deploy \(external-operators\)/,
    );
    assert.throws(
      () => validateIdentityPolicy(parseIdentityDatabases(
        `${passwdRecord('external-user', 1500, 2002)}\n`,
        `${groupRecord('external-group', 1500)}\n`,
      )),
      /static user primary GID has no group: external-user \(2002\)/,
    );

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
        expectedGshadowDatabase(),
        expectedShadowDatabase(),
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
        expectedGshadowDatabase(),
        expectedShadowDatabase(),
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
        expectedGshadowDatabase(),
        expectedShadowDatabase(),
      )),
      /managed user ID is outside the local range/,
    );
    assert.throws(
      () => validateIdentityPolicy(parseIdentityDatabases(
        [
          passwdRecord('webex-generic-account-bot', 0, 2001),
          passwdRecord('webex-config-deploy', 1002, 2002),
          '',
        ].join('\n'),
        expectedGroupDatabase(),
        {
          'webex-generic-account-bot': [2001],
          'webex-config-deploy': [2002],
        },
        expectedGshadowDatabase(),
        expectedShadowDatabase(),
      ), { requireAccounts: true }),
      /managed user ID is outside the local range/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        groupDatabase: expectedGroupDatabase().replace(
          'webex-codex-launch:x:2005:',
          'webex-codex-launch:x:0:',
        ),
      })),
      /managed group ID is outside the local range/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        groupDatabase: expectedGroupDatabase().replace(
          'webex-codex-launch:x:',
          'webex-codex-launch:$6$usable:',
        ),
      })),
      /managed group password is not locked: webex-codex-launch/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        gshadowDatabase: expectedGshadowDatabase().replace(
          'webex-config-deploy:!::\n',
          '',
        ),
      })),
      /managed group shadow credential is missing: webex-config-deploy/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        gshadowDatabase: expectedGshadowDatabase().replace(
          'webex-config-pull:!::',
          'webex-config-pull:$6$usable::',
        ),
      })),
      /managed group shadow password is not locked: webex-config-pull/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        gshadowDatabase: expectedGshadowDatabase().replace(
          'webex-codex-input:!::',
          'webex-codex-input:!:administrator:',
        ),
      })),
      /managed group has shadow administrators or members: webex-codex-input/,
    );
    assert.throws(
      () => validateIdentityPolicy(parseIdentityDatabases(
        '',
        '',
        {},
        'webex-codex-launch:$6$usable:administrator:member\n',
      )),
      /managed group has an orphan shadow credential: webex-codex-launch/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        gshadowDatabase: `${expectedGshadowDatabase()}docker:!:administrator:webex-generic-account-bot\n`,
      })),
      /managed user has shadow-group privileges: webex-generic-account-bot \(docker\)/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        shadowDatabase: expectedShadowDatabase().replace(
          `${shadowRecord('webex-config-deploy')}\n`,
          `${shadowRecord('webex-config-deploy', '$6$usable')}\n`,
        ),
      })),
      /managed user shadow password is not locked: webex-config-deploy/,
    );
    assert.throws(
      () => validateIdentityPolicy(expectedIdentitySnapshot({
        shadowDatabase: expectedShadowDatabase().replace(
          `${shadowRecord('webex-generic-account-bot')}\n`,
          '',
        ),
      })),
      /managed user shadow credential is missing: webex-generic-account-bot/,
    );
    assert.throws(
      () => validateIdentityPolicy(parseIdentityDatabases(
        '',
        '',
        {},
        '',
        `${shadowRecord('webex-config-deploy')}\n`,
      )),
      /managed user has an orphan shadow credential: webex-config-deploy/,
    );
  });

  it('reads complete stable files identities and permits only DynamicUser', async () => {
    const lookups = [];
    const snapshot = await readSystemIdentitySnapshot(
      systemIdentityFs({ dynamicUserProvider: true }),
      emptySystemdIdentityLookup(lookups),
    );

    validateIdentityPolicy(snapshot, { requireAccounts: true });
    assert.equal(lookups.length, 7);
    assert.deepEqual(lookups[0], [
      '/usr/bin/getent',
      ['-s', 'systemd', 'passwd', 'webex-generic-account-bot'],
      [0, 2],
    ]);
  });

  it('rejects managed identities claimed by DynamicUser', async () => {
    await assert.rejects(
      readSystemIdentitySnapshot(
        systemIdentityFs({ dynamicUserProvider: true }),
        async (_command, args) => (
          args.at(-1) === 'webex-config-deploy'
            ? {
              code: 0,
              stdout: 'webex-config-deploy:x:61184:61184:Dynamic User:/:/usr/sbin/nologin\n',
              stderr: '',
            }
            : { code: 2, stdout: '', stderr: '' }
        ),
      ),
      /managed identity is claimed by systemd userdb: webex-config-deploy/,
    );
  });

  it('rejects unsupported or static systemd userdb records', async () => {
    await assert.rejects(
      readSystemIdentitySnapshot(
        systemIdentityFs({ providerName: 'io.example.Untrusted' }),
        emptySystemdIdentityLookup(),
      ),
      /unsupported systemd userdb provider/,
    );
    await assert.rejects(
      readSystemIdentitySnapshot(
        systemIdentityFs({ staticUserdbEntry: '9000.user' }),
        emptySystemdIdentityLookup(),
      ),
      /static systemd userdb records are not supported/,
    );
    await assert.rejects(
      readSystemIdentitySnapshot(
        systemIdentityFs({
          staticUserdbDirectory: '/usr/local/lib/userdb',
          staticUserdbEntry: '9001.user',
        }),
        emptySystemdIdentityLookup(),
      ),
      /static systemd userdb records are not supported/,
    );
  });

  it('rejects writable or unstable files identity databases', async () => {
    await readSystemIdentitySnapshot(
      systemIdentityFs({ shadowMode: 0o000, gshadowMode: 0o000 }),
      emptySystemdIdentityLookup(),
    );
    await assert.rejects(
      readSystemIdentitySnapshot(
        systemIdentityFs({ groupMode: 0o666 }),
        emptySystemdIdentityLookup(),
      ),
      /policy file metadata is not trusted: \/etc\/group/,
    );
    await assert.rejects(
      readSystemIdentitySnapshot(
        systemIdentityFs({ mutateGroupIdentity: true }),
        emptySystemdIdentityLookup(),
      ),
      /policy file changed while reading: \/etc\/group/,
    );
    await assert.rejects(
      readSystemIdentitySnapshot(
        systemIdentityFs({ shadowMode: 0o644 }),
        emptySystemdIdentityLookup(),
      ),
      /identity file metadata is not trusted: \/etc\/shadow/,
    );
  });

  it('restores an interrupted sysusers commit from transaction-bound backups', async (context) => {
    const targetRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-identity-recovery-'));
    context.after(async () => fs.rm(targetRoot, { recursive: true, force: true }));
    const original = new Map([
      ['/etc/group', Buffer.from(`${groupRecord('shadow', 42)}\n`)],
      ['/etc/gshadow', Buffer.from('shadow:!::\n')],
      ['/etc/passwd', Buffer.alloc(0)],
      ['/etc/shadow', Buffer.alloc(0)],
    ]);
    const modes = new Map([
      ['/etc/group', 0o644],
      ['/etc/gshadow', 0o600],
      ['/etc/passwd', 0o644],
      ['/etc/shadow', 0o600],
    ]);
    const committed = new Map([
      ['/etc/group', Buffer.from(expectedGroupDatabase())],
      ['/etc/gshadow', Buffer.from(expectedGshadowDatabase())],
      ['/etc/passwd', Buffer.from([
        passwdRecord('webex-generic-account-bot', 1001, 2001),
        passwdRecord('webex-config-deploy', 1002, 2002),
        '',
      ].join('\n'))],
      ['/etc/shadow', Buffer.from(expectedShadowDatabase())],
    ]);
    const identityFiles = [...modes].map(([file, mode]) => Object.freeze({
      path: file,
      sha256: createHash('sha256').update(original.get(file)).digest('hex'),
      uid: UID,
      gid: GID,
      mode,
    }));
    const transaction = Object.freeze({ identityFiles: Object.freeze(identityFiles) });
    const phaseRoots = [];
    for (let committedCount = 1; committedCount < 4; committedCount += 1) {
      const phaseRoot = path.join(targetRoot, `phase-${committedCount}`);
      phaseRoots.push(phaseRoot);
      await fs.mkdir(path.join(phaseRoot, 'etc'), { recursive: true, mode: 0o755 });
      const current = new Map();
      for (const [index, file] of [
        '/etc/group',
        '/etc/gshadow',
        '/etc/passwd',
        '/etc/shadow',
      ].entries()) {
        const contents = index < committedCount ? committed.get(file) : original.get(file);
        current.set(file, contents);
        const target = path.join(phaseRoot, file.slice(1));
        const mode = modes.get(file);
        await fs.writeFile(target, contents, { mode });
        await fs.chmod(target, mode);
        await fs.writeFile(`${target}-`, original.get(file), { mode });
        await fs.chmod(`${target}-`, mode);
      }
      const effectiveGroups = committedCount >= 3
        ? {
          'webex-generic-account-bot': [2001],
          'webex-config-deploy': [2002],
        }
        : {};
      const snapshot = parseIdentityDatabases(
        current.get('/etc/passwd').toString('utf8'),
        current.get('/etc/group').toString('utf8'),
        effectiveGroups,
        current.get('/etc/gshadow').toString('utf8'),
        current.get('/etc/shadow').toString('utf8'),
      );
      const options = {
        fsApi: fs,
        targetRoot: phaseRoot,
        verifyIdentityLock: async () => {},
        verifyMountNamespace: async () => {},
        readMountInfo: async () => SAFE_MOUNT_INFO,
      };
      if (committedCount === 1) {
        const legacySnapshot = Object.freeze({
          ...snapshot,
          identityFiles: Object.freeze(identityFiles.map((entry) => Object.freeze({
            ...entry,
            sha256: createHash('sha256').update(current.get(entry.path)).digest('hex'),
          }))),
        });
        const legacyTransaction = Object.freeze({ identityFiles: null });
        await assert.rejects(
          restoreInterruptedIdentityDatabases(
            legacyTransaction,
            legacySnapshot,
            options,
          ),
          /legacy identity recovery requires explicit manual repair/,
        );
      }
      await restoreInterruptedIdentityDatabases(transaction, snapshot, options);
      assert.deepEqual(
        await fs.readFile(path.join(phaseRoot, 'etc/group')),
        current.get('/etc/group'),
      );
      if (committedCount === 3) {
        let renames = 0;
        const interruptedFs = new Proxy(fs, {
          get(target, property) {
            if (property !== 'rename') return target[property];
            return async (...args) => {
              renames += 1;
              if (renames === 2) throw new Error('injected identity recovery interruption');
              return target.rename(...args);
            };
          },
        });
        await assert.rejects(
          restoreInterruptedIdentityDatabases(transaction, snapshot, {
            ...options,
            apply: true,
            fsApi: interruptedFs,
          }),
          /injected identity recovery interruption/,
        );
      }
      await restoreInterruptedIdentityDatabases(transaction, snapshot, {
        ...options,
        apply: true,
      });
      for (const [file, contents] of original) {
        const target = path.join(phaseRoot, file.slice(1));
        assert.deepEqual(await fs.readFile(target), contents);
        assert.deepEqual(await fs.readFile(`${target}-`), contents);
      }
    }

    const driftRoot = phaseRoots[0];
    const driftGroup = path.join(driftRoot, 'etc/group');
    await fs.writeFile(
      driftGroup,
      Buffer.concat([committed.get('/etc/group'), Buffer.from('external:x:3000:\n')]),
      { mode: 0o644 },
    );
    await fs.writeFile(`${driftGroup}-`, original.get('/etc/group'), { mode: 0o644 });
    await assert.rejects(
      restoreInterruptedIdentityDatabases(
        transaction,
        parseIdentityDatabases('', committed.get('/etc/group').toString('utf8')),
        {
          fsApi: fs,
          targetRoot: driftRoot,
          verifyMountNamespace: async () => {},
          readMountInfo: async () => SAFE_MOUNT_INFO,
        },
      ),
      /unmanaged identity records changed during recovery/,
    );

    const passwdDriftRoot = phaseRoots[1];
    const driftPasswd = path.join(passwdDriftRoot, 'etc/passwd');
    const groupNamedUser = Buffer.from(
      `${passwdRecord('webex-config-pull', 3000, 42)}\n`,
    );
    await fs.writeFile(driftPasswd, groupNamedUser, { mode: 0o644 });
    await fs.writeFile(`${driftPasswd}-`, original.get('/etc/passwd'), { mode: 0o644 });
    await assert.rejects(
      restoreInterruptedIdentityDatabases(
        transaction,
        parseIdentityDatabases(
          groupNamedUser.toString('utf8'),
          original.get('/etc/group').toString('utf8'),
        ),
        {
          fsApi: fs,
          targetRoot: passwdDriftRoot,
          verifyMountNamespace: async () => {},
          readMountInfo: async () => SAFE_MOUNT_INFO,
        },
      ),
      /unmanaged identity records changed during recovery: \/etc\/passwd/,
    );
  });

  it('rechecks dormant units under the identity lock before recovery mutation', async (context) => {
    const fixture = await provisionFixture(context);
    await writeIdentityRecoveryTransaction(fixture);
    const partialIdentity = expectedIdentitySnapshot({ shadowDatabase: '' });
    const activeStates = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    activeStates.set(MANAGED_UNITS[0], {
      load: 'loaded',
      active: 'active',
      enabled: 'disabled',
      fragment: fixture.plan.units.find(
        (candidate) => path.basename(candidate) === MANAGED_UNITS[0],
      ),
      dropIns: '',
    });
    const recoveryModes = [];

    await assert.rejects(
      runIdentityRecoveryChild({
        allowTestInvocation: true,
        dependencies: fixture.dependencies({
          identitySequence: [partialIdentity],
          unitStateSequence: [activeStates],
        }),
        restoreIdentityDatabases: async (_transaction, _snapshot, options) => {
          recoveryModes.push(options.apply);
        },
      }),
      /managed unit is not inactive/,
    );
    assert.deepEqual(recoveryModes, [false]);
  });

  it('rejects restrictive unmanaged runtime ancestors before mutation', async (context) => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-runtime-ancestor-test-'));
    context.after(async () => fs.rm(root, { recursive: true, force: true }));
    await fs.chmod(root, 0o755);
    await fs.mkdir(path.join(root, 'var'), { mode: 0o755 });
    await fs.mkdir(path.join(root, 'var/lib'), { mode: 0o700 });
    const plan = { targetRoot: root };
    const inspected = {
      artifacts: [{
        kind: 'tmpfiles',
        source: { contents: Buffer.from('d /var/lib/webex-example 0755 root root -\n') },
      }],
    };

    await assert.rejects(
      assertManagedRuntimeAncestorsTraversable(plan, inspected, {
        fsApi: fs,
        targetUid: UID,
        targetGid: GID,
        verifyNoExtendedPosixAcl: async () => {},
      }),
      /managed runtime ancestor is not traversable/,
    );

    const fixture = await provisionFixture(context);
    const allowlistInspection = {
      artifacts: await Promise.all(fixture.plan.artifacts.map(async (artifact) => ({
        ...artifact,
        source: { contents: await fs.readFile(artifact.source) },
      }))),
    };
    const trustedDirectory = Object.freeze({
      uid: UID,
      gid: GID,
      mode: 0o40755,
      nlink: 1,
      isDirectory: () => true,
      isFile: () => true,
      isSymbolicLink: () => false,
    });
    await assertManagedRuntimeAncestorsTraversable(
      fixture.plan,
      allowlistInspection,
      {
        fsApi: { lstat: async () => trustedDirectory },
        targetUid: UID,
        targetGid: GID,
        verifyNoExtendedPosixAcl: async () => {},
      },
    );

    const managedLock = path.join(
      fixture.targetRoot,
      'run/webex-config-deploy/deploy-config.lock',
    );
    await assert.rejects(
      assertManagedRuntimeAncestorsTraversable(
        fixture.plan,
        allowlistInspection,
        {
          fsApi: { lstat: async () => trustedDirectory },
          targetUid: UID,
          targetGid: GID,
          verifyNoExtendedPosixAcl: async (candidate) => {
            if (candidate === managedLock) {
              throw new Error(`managed runtime path has an extended POSIX ACL: ${candidate}`);
            }
          },
        },
      ),
      /managed runtime path has an extended POSIX ACL/,
    );

    const hardLinkTarget = `${root}/var/lib/webex-example.lock`;
    const hardLinkInspection = {
      artifacts: [{
        kind: 'tmpfiles',
        source: { contents: Buffer.from('f /var/lib/webex-example.lock 0660 root root -\n') },
      }],
    };
    const hardLinkStat = Object.freeze({
      uid: UID,
      gid: GID,
      mode: 0o100660,
      nlink: 2,
      isDirectory: () => false,
      isFile: () => true,
      isSymbolicLink: () => false,
    });
    await assert.rejects(
      assertManagedRuntimeAncestorsTraversable(plan, hardLinkInspection, {
        fsApi: {
          lstat: async (candidate) => candidate === hardLinkTarget
            ? hardLinkStat
            : trustedDirectory,
        },
        targetUid: UID,
        targetGid: GID,
        verifyNoExtendedPosixAcl: async () => {},
      }),
      /managed runtime path is not safe to mutate/,
    );
  });

  it('verifies exact managed tmpfiles ownership and mode after creation', async () => {
    const root = '/test-root';
    const plan = { targetRoot: root };
    const target = `${root}/run/webex-example`;
    const inspected = {
      artifacts: [{
        kind: 'tmpfiles',
        source: {
          contents: Buffer.from(
            'd /run/webex-example 0750 webex-config-deploy webex-config-pull -\n',
          ),
        },
      }],
    };
    const directoryStat = (uid, gid, mode) => Object.freeze({
      uid,
      gid,
      mode: 0o40000 | mode,
      isDirectory: () => true,
      isFile: () => false,
      isSymbolicLink: () => false,
    });
    const records = new Map([
      [root, directoryStat(0, 0, 0o755)],
      [`${root}/run`, directoryStat(0, 0, 0o755)],
      [target, directoryStat(1002, 2003, 0o700)],
    ]);
    const fsApi = {
      lstat: async (candidate) => records.get(candidate)
        ?? Promise.reject(Object.assign(new Error('missing'), { code: 'ENOENT' })),
    };

    await assert.rejects(
      verifyManagedTmpfilesState(
        plan,
        inspected,
        expectedIdentitySnapshot(),
        {
          fsApi,
          targetUid: 0,
          targetGid: 0,
          verifyNoExtendedPosixAcl: async () => {},
        },
      ),
      /managed runtime path metadata is not converged/,
    );
    records.set(target, directoryStat(1002, 2003, 0o750));
    const aclChecks = [];
    await verifyManagedTmpfilesState(
      plan,
      inspected,
      expectedIdentitySnapshot(),
      {
        fsApi,
        targetUid: 0,
        targetGid: 0,
        verifyNoExtendedPosixAcl: async (candidate) => aclChecks.push(candidate),
      },
    );
    assert.deepEqual(aclChecks, [root, `${root}/run`, target, target]);
    await assert.rejects(
      verifyManagedTmpfilesState(
        plan,
        inspected,
        expectedIdentitySnapshot(),
        {
          fsApi,
          targetUid: 0,
          targetGid: 0,
          verifyNoExtendedPosixAcl: async () => {
            throw new Error(`managed runtime path has an extended POSIX ACL: ${target}`);
          },
        },
      ),
      /managed runtime path has an extended POSIX ACL/,
    );
    await assert.rejects(
      verifyManagedTmpfilesState(
        plan,
        inspected,
        expectedIdentitySnapshot(),
        {
          fsApi,
          targetUid: 0,
          targetGid: 0,
          verifyNoExtendedPosixAcl: async (candidate) => {
            if (candidate === target) {
              records.set(target, directoryStat(1002, 2003, 0o700));
            }
          },
        },
      ),
      /managed runtime path changed during ACL inspection/,
    );
  });

  it('uses a fixed read-only getfacl command for runtime ACL convergence', async () => {
    const calls = [];
    await assertNoExtendedPosixAcl('/run/webex-example', async (command, args) => {
      calls.push([command, args]);
      return { code: 0, stdout: '', stderr: '' };
    });
    assert.deepEqual(calls, [[
      '/usr/bin/getfacl',
      [
        '--absolute-names',
        '--numeric',
        '--omit-header',
        '--skip-base',
        '--physical',
        '--',
        '/run/webex-example',
      ],
    ]]);
    await assert.rejects(
      assertNoExtendedPosixAcl(
        '/run/webex-example',
        async () => ({ code: 0, stdout: 'user:1000:rwx\n', stderr: '' }),
      ),
      /managed runtime path has an extended POSIX ACL/,
    );
  });

  it('executes fixed host commands through a verified open file descriptor', async () => {
    const directoryStat = Object.freeze({
      uid: 0,
      gid: 0,
      mode: 0o40755,
      isDirectory: () => true,
      isSymbolicLink: () => false,
    });
    const executableStat = Object.freeze({
      uid: 0,
      gid: 0,
      mode: 0o100755,
      nlink: 1,
      dev: 8,
      ino: 42,
      size: 4096,
      mtimeMs: 1,
      ctimeMs: 1,
      isFile: () => true,
      isSymbolicLink: () => false,
    });
    const execCalls = [];
    const result = await runFixedCommand(
      '/usr/bin/getfacl',
      ['--version'],
      [0],
      {
        fsApi: {
          lstat: async () => directoryStat,
          open: async (candidate, flags) => {
            assert.equal(candidate, '/usr/bin/getfacl');
            assert.equal(
              flags,
              fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
            );
            return {
              fd: 17,
              stat: async () => executableStat,
              close: async () => {},
            };
          },
        },
        readMountInfo: async () => SAFE_MOUNT_INFO,
        execFileCommand: async (command, args, options) => {
          execCalls.push([command, args, options]);
          return { stdout: 'getfacl 2.3.2\n', stderr: '' };
        },
      },
    );
    assert.equal(result.code, 0);
    assert.equal(result.command, '/usr/bin/getfacl');
    assert.equal(execCalls.length, 1);
    assert.equal(execCalls[0][0], '/proc/self/fd/17');
    assert.deepEqual(execCalls[0][1], ['--version']);
    assert.equal(execCalls[0][2].argv0, '/usr/bin/getfacl');
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

  it('rechecks mount namespace identity immediately before apply mutation', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    let namespaceChecks = 0;
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          commands,
          verifyMountNamespace: async () => {
            namespaceChecks += 1;
            if (namespaceChecks === 2) {
              throw new Error('host provisioner is not in PID 1 mount namespace');
            }
          },
        }),
      ),
      /not in PID 1 mount namespace/,
    );
    assert.equal(namespaceChecks, 2);
    assert.deepEqual(commands, []);
    await assert.rejects(fs.stat(path.join(fixture.targetRoot, 'etc')), { code: 'ENOENT' });
  });

  it('guards each policy and host-command mutation boundary with mount namespace identity', async (context) => {
    for (const failureBoundary of [
      'candidate-write',
      'candidate-chown',
      'candidate-chmod',
      'policy-install-rename',
      'systemd-sysusers',
      'systemd-tmpfiles',
      'daemon-reload-final',
    ]) {
      const fixture = await provisionFixture(context);
      const commands = [];
      const checkedBoundaries = [];
      let injected = false;
      await assert.rejects(
        provisionHost(
          { apply: true },
          fixture.dependencies({
            applied: true,
            commands,
            verifyMountNamespace: async (boundary) => {
              checkedBoundaries.push(boundary);
              if (!injected && boundary === failureBoundary) {
                injected = true;
                throw new Error(`mount namespace changed before ${boundary}`);
              }
            },
          }),
        ),
        new RegExp(`mount namespace changed before ${failureBoundary}`),
        failureBoundary,
      );
      assert.equal(injected, true, failureBoundary);
      assert.ok(checkedBoundaries.includes(failureBoundary), failureBoundary);
      if (failureBoundary === 'policy-install-rename') {
        assert.equal(commands.some(([command]) => command.endsWith('systemd-sysusers')), false);
      }
      if (failureBoundary === 'systemd-sysusers') {
        assert.equal(commands.some(([command]) => command.endsWith('systemd-sysusers')), false);
      }
      if (failureBoundary === 'systemd-tmpfiles') {
        assert.equal(commands.some(([command]) => command.endsWith('systemd-tmpfiles')), false);
      }
    }
  });

  it('guards policy recovery mutations with mount namespace identity', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    const checkedBoundaries = [];
    const before = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    const unsafe = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    }, fixture.plan);
    unsafe.set(MANAGED_UNITS[0], {
      ...unsafe.get(MANAGED_UNITS[0]),
      active: 'active',
    });
    const dependencies = fixture.dependencies({
      applied: true,
      commands,
      unitStateSequence: [before, unsafe],
      verifyMountNamespace: async (boundary) => {
        checkedBoundaries.push(boundary);
        if (boundary === 'policy-recovery-remove') {
          throw new Error(`mount namespace changed before ${boundary}`);
        }
      },
    });

    await assert.rejects(
      provisionHost({ apply: true }, dependencies),
      /mount namespace changed before policy-recovery-remove/,
    );
    assert.ok(checkedBoundaries.includes('policy-recovery-remove'));
    assert.equal(commands.filter(([, args]) => args[0] === 'daemon-reload').length, 1);
  });

  it('rejects unexpected mounts overlapping managed tmpfiles paths', async (context) => {
    const fixture = await provisionFixture(context);
    for (const [root, mountPoint, device, expectedError] of [
      ['/etc/shadow', '/run/webex-config-deploy/deploy-config.lock'],
      ['/spoofed-shadow', '/etc/shadow'],
      ['/spoofed-command', '/usr/bin/getfacl'],
      ['/etc', '/mnt/identity-alias', '0:1', /unexpected mount aliases protected host path/],
      ['/sensitive-state', '/var/lib/webex-generic-account-bot'],
      ['/redirected-var-lib', '/var/lib'],
      ['/', '/etc'],
      ['/', '/', '0:1', /mountinfo must contain exactly one root mount/],
      ['/', '/var/lib/webex-generic-account-bot/state/nested'],
    ]) {
      const commands = [];
      await assert.rejects(
        provisionHost(
          { apply: false },
          fixture.dependencies({
            commands,
            mountInfoSequence: [mountInfoWith(root, mountPoint, device)],
          }),
        ),
        expectedError ?? /unexpected mount (?:overlaps|aliases) protected host path/,
      );
      assert.deepEqual(commands, []);
    }
  });

  it('reads complete proc mount data across short reads and preserves the byte bound', async (context) => {
    const fixture = await provisionFixture(context);
    const mountInfo = mountInfoWith(
      '/sensitive-state',
      '/var/lib/webex-generic-account-bot/state/nested',
    );
    const dependencies = fixture.dependencies();
    dependencies.readMountInfo = () => readBoundedProcFile(
      '/proc/self/mountinfo',
      Buffer.byteLength(mountInfo),
      shortReadFileSystem(mountInfo, 17),
    );

    await assert.rejects(
      provisionHost({ apply: false }, dependencies),
      /unexpected mount overlaps protected host path/,
    );
    await assert.rejects(
      readBoundedProcFile(
        '/proc/self/mountinfo',
        Buffer.byteLength(mountInfo) - 1,
        shortReadFileSystem(mountInfo, 11),
      ),
      /proc file is too large/,
    );
    await assert.rejects(
      readBoundedProcFile('/proc/self/mountinfo', 128, {
        open: async () => ({
          stat: async () => ({ isFile: () => false }),
          close: async () => {},
        }),
      }),
      /proc file metadata is not trusted/,
    );
  });

  it('requires a single root mount in the proc mount snapshot', async (context) => {
    const fixture = await provisionFixture(context);
    for (const mountInfo of [
      '',
      `${SAFE_MOUNT_INFO}4 0 0:4 / / rw - tmpfs tmpfs rw\n`,
    ]) {
      const commands = [];
      await assert.rejects(
        provisionHost(
          { apply: false },
          fixture.dependencies({ commands, mountInfoSequence: [mountInfo] }),
        ),
        /mountinfo must contain exactly one root mount/,
      );
      assert.deepEqual(commands, []);
    }
  });

  it('rejects protected mount snapshot drift across tmpfiles execution', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    const changedRunMount = SAFE_MOUNT_INFO.replace('2 1 0:2', '2 1 0:22');
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          applied: true,
          commands,
          mountInfoSequence: [
            SAFE_MOUNT_INFO,
            SAFE_MOUNT_INFO,
            SAFE_MOUNT_INFO,
            SAFE_MOUNT_INFO,
            changedRunMount,
          ],
        }),
      ),
      /protected host mount snapshot changed during command execution/,
    );
    assert.deepEqual(commands.slice(0, 2), [
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
    ]);
  });

  it('rejects unmanaged boot policy that can cross the Webex boundary', async (context) => {
    for (const [kind, policy] of [
      ['sysusers', 'm webex-generic-account-bot sudo'],
      ['sysusers', 'm \\x77ebex-generic-account-bot sudo'],
      ['sysusers', 'u external /var/lib/webex-generic-account-bot/state -'],
      ['sysusers', 'u external-user 999 -'],
      ['sysusers', 'u external-user -:998 -'],
      ['sysusers', 'g external-group 997 -'],
      ['sysusers', 'r - 61184-65519'],
      ['tmpfiles', 'd /run/webex-codex-canary 0777 root root -'],
      ['tmpfiles', 'd /run/\\x77ebex-config-deploy 0777 root root -'],
      ['tmpfiles', 'R /run/* - - - -'],
      ['tmpfiles', 'R /run/ - - - -'],
      ['tmpfiles', 'R /var/run/ - - - -'],
      ['tmpfiles', 'R /var/*/../etc/passwd - - - -'],
      ['tmpfiles', 'R /var/r?n/../etc/passwd - - - -'],
      ['tmpfiles', 'R /var/[r]un/../etc/passwd - - - -'],
      ['tmpfiles', 'R /var/r?n/systemd/system/* - - - -'],
      ['tmpfiles', 'L /var/run - - - - ../run/child/..'],
      ['tmpfiles', 'L /var/run/external - - - - ../etc/passwd'],
      ['tmpfiles', 'L /var/lib/innocent - - - - ../run/../etc/passwd'],
      [
        'tmpfiles',
        'C /tmp/leak 0644 root root - /pivot /../var/lib/webex-headless-access/access-token',
      ],
      [
        'tmpfiles',
        'L /tmp/leak - - - - /pivot /../var/lib/webex-headless-access/access-token',
      ],
      ['tmpfiles', 'Z /var/lib 0777 root root -'],
      ['tmpfiles', 'Z /etc 0755 root root -'],
      ['tmpfiles', 'R /run/%H - - - -'],
      ['tmpfiles', 'd %t/\\x77ebex-config-deploy 0777 root root -'],
      ['tmpfiles', 'f /tmp/untrusted 0600 :webex-config-deploy root -'],
      ['tmpfiles', 'f /tmp/untrusted 0600 1001 root -'],
      ['tmpfiles', 'f /tmp/untrusted 0600 root :02001 -'],
      ['tmpfiles', 'f+! /etc/shadow 0600 root root - replacement'],
      ['tmpfiles', 'f+ /var/run/../etc/passwd 0600 root root - replacement'],
      ['tmpfiles', 'f+ /usr/bin/getfacl 0755 root root - replacement'],
      ['tmpfiles', 'f+ /etc/userdb/1002.user 0600 root root - {}'],
      ['tmpfiles', 'f /etc/credstore/userdb.user.injected 0600 root root - {}'],
      ['tmpfiles', 'f /run/credstore/* 0600 root root - payload'],
      ['tmpfiles', 'f /run/credentials/@system/sysusers.extra 0600 root root - payload'],
      ['tmpfiles', 'f /var//run/credentials/@system/sysusers.extra 0600 root root - payload'],
      ['tmpfiles', 'f /var/./run/credentials/@system/tmpfiles.extra 0600 root root - payload'],
      ['tmpfiles', 'd+ /run/credstore 0700 root root -'],
      ['tmpfiles', 'L+ /dev/host-creds - - - - /run/credentials/@system'],
      ['tmpfiles', 'L+ /run/systemd/userdb/untrusted - - - - /tmp/provider'],
      ['tmpfiles', 'L /tmp/untrusted - - - - %t/systemd/userdb'],
      ['tmpfiles', 'f+ /var/run/systemd/system/external.service 0644 root root - payload'],
      ['tmpfiles', 'R /var/run/systemd/system/* - - - -'],
      ['tmpfiles', 'L+ /var/run/userdb/untrusted - - - - /tmp/provider'],
      ['tmpfiles', 'A+! /opt/private-tree - - - - user:webex-generic-account-bot:r-X'],
      ['tmpfiles', 'A+! /opt/private-tree - - - - group:02001:r-X'],
      [
        'tmpfiles',
        'L+ /etc/systemd/system/external.service - - - - webex-generic-account-bot.service',
      ],
      [
        'tmpfiles',
        'L+ /etc/systemd/system/multi-user.target.wants/external.service - - - - ../external.service',
      ],
      [
        'tmpfiles',
        'L /tmp/managed-alias - - - - /etc/systemd/system/webex-generic-account-bot.service',
      ],
      ['tmpfiles', 'R /etc/systemd/system/* - - - -'],
      ['tmpfiles', 'R /etc/sysusers.d/* - - - -'],
      ['tmpfiles', 'R /etc/tmpfiles.d/* - - - -'],
      ['tmpfiles', 'f+ /etc/sysusers.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'f+ /run/sysusers.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'f+ /usr/local/lib/sysusers.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'f+ /usr/lib/sysusers.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'f+ /lib/sysusers.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'f+ /etc/tmpfiles.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'f+ /run/tmpfiles.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'f+ /usr/local/lib/tmpfiles.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'f+ /usr/lib/tmpfiles.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'f+ /lib/tmpfiles.d/rogue.conf 0644 root root - payload'],
      ['tmpfiles', 'z /var/lib 0777 root root -'],
      ['tmpfiles', 'C+ /var/lib - - - - /usr/share/factory/var/lib'],
      ['tmpfiles', 'L+ /var/lib - - - - /tmp'],
      ['tmpfiles', 'd /var/lib 0755 root root 0'],
      ['tmpfiles', 'R / - - - -'],
      ['tmpfiles', 'd / 0777 root root -'],
      ['tmpfiles', 'd /var/lib 0700 root root -'],
      ['tmpfiles', 'd / 0000 root root -'],
      ['tmpfiles', 'd= /var/lib 0755 root root -'],
      ['tmpfiles', 'z+ /etc/systemd 0755 root root -'],
      ['tmpfiles', 'R /var/lib/../lib/[w]ebex-generic-account-bot - - - -'],
      ['tmpfiles', 'C /tmp/copied-state - - - - /var/lib/[w]ebex-generic-account-bot'],
      ['tmpfiles', ['R \\', '# ignored continuation comment', '/etc/systemd/system/* - - - -'].join('\n')],
    ]) {
      const fixture = await provisionFixture(context);
      await assert.rejects(
        provisionHost(
          { apply: false },
          fixture.dependencies({
            bootPolicySequence: [{
              ...fixture.bootPolicyCatalogs,
              [kind]: `${fixture.bootPolicyCatalogs[kind]}\n${policy}\n`,
            }],
          }),
        ),
        new RegExp(`unmanaged ${kind} policy touches the Webex boundary`),
      );
    }
  });

  it('accepts materialised external sysusers numeric IDs', async (context) => {
    const fixture = await provisionFixture(context);
    const identity = parseIdentityDatabases(
      `${passwdRecord('external-user', 999, 999)}\n`,
      [
        groupRecord('external-user', 999),
        groupRecord('external-primary', 998),
        groupRecord('external-group', 997),
        '',
      ].join('\n'),
    );
    const report = await provisionHost(
      { apply: false },
      fixture.dependencies({
        identitySequence: [identity],
        bootPolicySequence: [{
          ...fixture.bootPolicyCatalogs,
          sysusers: [
            fixture.bootPolicyCatalogs.sysusers,
            'u external-user 999 -',
            'u deferred-user -:998 -',
            'g external-primary 998 -',
            'g external-group 997 -',
          ].join('\n'),
        }],
      }),
    );

    assert.equal(report.mode, 'dry-run');
  });

  it('accepts non-writable root maintenance for protected-path ancestors', async (context) => {
    const fixture = await provisionFixture(context);
    const report = await provisionHost(
      { apply: false },
      fixture.dependencies({
        bootPolicySequence: [{
          ...fixture.bootPolicyCatalogs,
          tmpfiles: [
            fixture.bootPolicyCatalogs.tmpfiles,
            'q /var 0755 - - -',
            'd / 0755 root root -',
            'd /var/lib 0755 root root -',
            'd /var/lib 0711 root root -',
            'z /etc/systemd 0755 :root :root -',
            'L /var/run - - - - ../run',
            'd /run/credstore 0700 root root -',
            '',
          ].join('\n'),
        }],
      }),
    );
    assert.equal(report.mode, 'dry-run');
  });

  it('rechecks numeric tmpfiles ownership after allocating managed IDs', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          applied: true,
          commands,
          bootPolicySequence: [
            fixture.bootPolicyCatalogs,
            {
              ...fixture.bootPolicyCatalogs,
              tmpfiles: [
                fixture.bootPolicyCatalogs.tmpfiles,
                'f /tmp/untrusted 0600 :1002 root -',
                '',
              ].join('\n'),
            },
          ],
        }),
      ),
      /unmanaged tmpfiles policy touches the Webex boundary/,
    );
    assert.deepEqual(commands, [
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
    ]);
  });

  it('reads the merged boot policy through fixed read-only commands', async () => {
    const commands = [];
    const sourceFiles = new Map([
      ['/usr/lib/sysusers.d/example.conf', Buffer.from('g example - -\n')],
      ['/usr/lib/tmpfiles.d/example.conf', Buffer.from('d /run/example 0755 root root -\n')],
    ]);
    const catalogs = await readSystemBootPolicyCatalogs(async (command, args) => {
      commands.push([command, [...args]]);
      if (command.endsWith('systemd-creds')) {
        return { stdout: '', stderr: 'No credentials passed to system.\n', code: 1 };
      }
      const kind = command.endsWith('sysusers') ? 'sysusers' : 'tmpfiles';
      const source = `/usr/lib/${kind}.d/example.conf`;
      return {
        stdout: `# ${source}\n${sourceFiles.get(source).toString('utf8')}`,
        stderr: '',
        code: 0,
      };
    }, systemdUnitPathFs(new Map(), { filesByPath: sourceFiles }));
    assert.deepEqual(commands, [
      ['/usr/bin/systemd-sysusers', ['--cat-config', '--tldr', '--no-pager']],
      ['/usr/bin/systemd-tmpfiles', ['--cat-config', '--tldr', '--no-pager']],
      ['/usr/bin/systemd-creds', ['--system', '--no-legend', '--no-pager', 'list']],
    ]);
    assert.match(catalogs.sysusers, /g example/);
    assert.match(catalogs.tmpfiles, /d \/run\/example/);
    assert.deepEqual(catalogs.sources, {
      sysusers: ['/usr/lib/sysusers.d/example.conf'],
      tmpfiles: ['/usr/lib/tmpfiles.d/example.conf'],
    });

    for (const [label, fsApi] of [
      [
        'writable empty search directory',
        systemdUnitPathFs(new Map(), {
          filesByPath: sourceFiles,
          directoryModesByPath: new Map([['/run/tmpfiles.d', 0o777]]),
        }),
      ],
      [
        'search directory symlink',
        systemdUnitPathFs(new Map(), {
          filesByPath: sourceFiles,
          symlinksByPath: new Map([['/run/sysusers.d', '/opt/untrusted/sysusers.d']]),
        }),
      ],
    ]) {
      let commandCalls = 0;
      await assert.rejects(
        readSystemBootPolicyCatalogs(
          async () => {
            commandCalls += 1;
            throw new Error('boot policy command reached');
          },
          fsApi,
        ),
        /policy directory is not trusted/,
        label,
      );
      assert.equal(commandCalls, 0, label);
    }

    const injectedPolicy = '/run/tmpfiles.d/injected.conf';
    let commandCalls = 0;
    await assert.rejects(
      readSystemBootPolicyCatalogs(
        async () => {
          commandCalls += 1;
          throw new Error('boot policy command reached');
        },
        systemdUnitPathFs(
          new Map([['/run/tmpfiles.d', [{ name: 'injected.conf' }]]]),
          {
            filesByPath: sourceFiles,
            specialStatsByPath: new Map([[injectedPolicy, Object.freeze({
              uid: 0,
              gid: 0,
              mode: 0o010644,
              nlink: 1,
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => false,
            })]]),
          },
        ),
      ),
      /boot policy search entry is not trusted: \/run\/tmpfiles\.d\/injected\.conf/,
    );
    assert.equal(commandCalls, 0);

    for (const [kind, result] of [
      ['sysusers', { stdout: '', stderr: '', code: 0 }],
      ['tmpfiles', { stdout: 'catalog\n', stderr: 'warning\n', code: 0 }],
      ['sysusers', { stdout: 'catalog\n', stderr: '', code: 1 }],
    ]) {
      await assert.rejects(
        readSystemBootPolicyCatalogs(
          async (command) => {
            if (command.endsWith('systemd-creds')) {
              return { stdout: 'No credentials passed to system.\n', stderr: '', code: 0 };
            }
            const commandKind = command.endsWith('sysusers') ? 'sysusers' : 'tmpfiles';
            if (commandKind === kind) return result;
            const source = `/usr/lib/${commandKind}.d/example.conf`;
            return {
              stdout: `# ${source}\n${sourceFiles.get(source).toString('utf8')}`,
              stderr: '',
              code: 0,
            };
          },
          systemdUnitPathFs(new Map(), { filesByPath: sourceFiles }),
        ),
        new RegExp(`${kind} catalog listing is incomplete`),
      );
    }

    await assert.rejects(
      readSystemBootPolicyCatalogs(
        async (command) => {
          if (command.endsWith('systemd-creds')) {
            return { stdout: 'No credentials passed to system.\n', stderr: '', code: 0 };
          }
          const kind = command.endsWith('sysusers') ? 'sysusers' : 'tmpfiles';
          const source = `/usr/lib/${kind}.d/example.conf`;
          return { stdout: `# ${source}\npolicy\n`, stderr: '', code: 0 };
        },
        systemdUnitPathFs(new Map(), {
          filesByPath: sourceFiles,
          fileModesByPath: new Map([['/usr/lib/tmpfiles.d/example.conf', 0o664]]),
        }),
      ),
      /policy file metadata is not trusted: \/usr\/lib\/tmpfiles\.d\/example\.conf/,
    );

    for (const credential of [
      'sysusers.extra',
      'passwd.hashed-password.webex-generic-account-bot',
      'passwd.plaintext-password.webex-config-deploy',
      'passwd.shell.webex-generic-account-bot',
      'userdb.transient.user.webex-generic-account-bot',
      'userdb.transient.group.webex-codex-launch',
      'userdb.user.webex-generic-account-bot',
      'userdb.group.webex-codex-launch',
    ]) {
      await assert.rejects(
        readSystemBootPolicyCatalogs(
          async (command) => {
            if (command.endsWith('systemd-creds')) {
              return { stdout: `${credential} insecure 42B\n`, stderr: '', code: 0 };
            }
            const kind = command.endsWith('sysusers') ? 'sysusers' : 'tmpfiles';
            const source = `/usr/lib/${kind}.d/example.conf`;
            return {
              stdout: `# ${source}\n${sourceFiles.get(source).toString('utf8')}`,
              stderr: '',
              code: 0,
            };
          },
          systemdUnitPathFs(new Map(), { filesByPath: sourceFiles }),
        ),
        new RegExp(`system credential can inject host policy: ${credential.replaceAll('.', '\\.')}`),
      );
    }

    for (const credential of [
      'tmpfiles.extra',
      'passwd.hashed-password.webex-generic-account-bot',
      'passwd.plaintext-password.webex-config-deploy',
      'passwd.shell.webex-generic-account-bot',
      'userdb.transient.user.injected',
      'userdb.transient.group.injected',
      'userdb.user.injected',
      'userdb.group.injected',
    ]) {
      await assert.rejects(
        readSystemBootPolicyCatalogs(
          async (command) => {
            if (command.endsWith('systemd-creds')) {
              return { stdout: 'No credentials passed to system.\n', stderr: '', code: 0 };
            }
            const kind = command.endsWith('sysusers') ? 'sysusers' : 'tmpfiles';
            const source = `/usr/lib/${kind}.d/example.conf`;
            return {
              stdout: `# ${source}\n${sourceFiles.get(source).toString('utf8')}`,
              stderr: '',
              code: 0,
            };
          },
          systemdUnitPathFs(
            new Map([['/etc/credstore', [directoryEntry(credential, false)]]]),
            { filesByPath: sourceFiles },
          ),
        ),
        new RegExp(`credential store can inject host policy: /etc/credstore/${credential.replaceAll('.', '\\.')}`),
      );
    }
  });

  it('upgrades source-associated managed boot policy from its trusted old contents', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts.find(
      ({ sourceName }) => sourceName === 'webex-generic-account-bot.tmpfiles.conf',
    );
    const desired = await fs.readFile(artifact.source, 'utf8');
    const existing = desired.replace(
      'd /var/lib/webex-generic-account-bot/state 0700',
      'd /var/lib/webex-generic-account-bot/state 0750',
    );
    assert.notEqual(existing, desired);
    await fs.mkdir(path.dirname(artifact.target), { recursive: true, mode: 0o755 });
    await fs.writeFile(artifact.target, existing, { mode: 0o644 });
    await fs.chmod(artifact.target, 0o644);
    const existingCatalogs = await sourceAssociatedBootPolicyCatalogs(
      fixture.plan,
      new Map([[artifact.targetPath, existing]]),
    );
    const desiredCatalogs = await sourceAssociatedBootPolicyCatalogs(fixture.plan);

    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({
        applied: true,
        bootPolicySequence: [existingCatalogs, desiredCatalogs],
      }),
    );

    assert.equal(report.mode, 'applied');
    assert.equal(await fs.readFile(artifact.target, 'utf8'), desired);
  });

  it('preserves stale candidates in dry-run and removes them before apply', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts[0];
    const candidate = path.join(
      path.dirname(artifact.target),
      `${PROVISION_CANDIDATE_PREFIX}00000000-0000-4000-8000-000000000099.tmp`,
    );
    await fs.mkdir(path.dirname(candidate), { recursive: true, mode: 0o755 });
    await fs.writeFile(candidate, 'interrupted candidate\n', { mode: 0o600 });
    await fs.chmod(candidate, 0o600);
    const umaskCandidate = path.join(
      path.dirname(artifact.target),
      `${PROVISION_CANDIDATE_PREFIX}00000000-0000-4000-8000-000000000098.tmp`,
    );
    await fs.writeFile(umaskCandidate, 'interrupted before chmod\n', { mode: 0o600 });
    await fs.chmod(umaskCandidate, 0o000);
    const unitArtifact = fixture.plan.artifacts.find(({ kind }) => kind === 'unit');
    const unitCandidate = path.join(
      path.dirname(unitArtifact.target),
      `${PROVISION_CANDIDATE_PREFIX}00000000-0000-4000-8000-000000000097.tmp`,
    );
    await fs.mkdir(path.dirname(unitCandidate), { recursive: true, mode: 0o755 });
    await fs.writeFile(unitCandidate, 'interrupted unit candidate\n', { mode: 0o600 });

    await provisionHost({ apply: false }, fixture.dependencies());
    assert.equal(await fs.readFile(candidate, 'utf8'), 'interrupted candidate\n');
    assert.equal((await fs.stat(umaskCandidate)).mode & 0o777, 0o000);
    assert.equal(await fs.readFile(unitCandidate, 'utf8'), 'interrupted unit candidate\n');

    await provisionHost(
      { apply: true },
      fixture.dependencies({ applied: true }),
    );
    await assert.rejects(fs.stat(candidate), { code: 'ENOENT' });
    await assert.rejects(fs.stat(umaskCandidate), { code: 'ENOENT' });
    await assert.rejects(fs.stat(unitCandidate), { code: 'ENOENT' });
    assert.equal(await fs.readFile(artifact.target, 'utf8'), await fs.readFile(artifact.source, 'utf8'));
    assert.equal(
      await fs.readFile(unitArtifact.target, 'utf8'),
      await fs.readFile(unitArtifact.source, 'utf8'),
    );
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

  it('validates every stale candidate before deleting any candidate', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts[0];
    const directory = path.dirname(artifact.target);
    const prefix = PROVISION_CANDIDATE_PREFIX;
    const validName = `${prefix}00000000-0000-4000-8000-000000000099.tmp`;
    const malformedName = `${prefix}not-a-uuid.tmp`;
    const valid = path.join(directory, validName);
    await fs.mkdir(directory, { recursive: true, mode: 0o755 });
    await fs.writeFile(valid, 'valid stale candidate\n', { mode: 0o600 });
    await fs.writeFile(path.join(directory, malformedName), 'malformed candidate\n', { mode: 0o600 });
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'opendir') return target[property];
        return async (candidate) => {
          if (candidate !== directory) return target.opendir(candidate);
          return asyncDirectory([
            directoryEntry(validName, false),
            directoryEntry(malformedName, false),
          ]);
        };
      },
    });

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ fsApi, applied: true }),
      ),
      /stale policy candidate name is malformed/,
    );
    assert.equal(await fs.readFile(valid, 'utf8'), 'valid stale candidate\n');
  });

  it('installs the fixed set transactionally and converges without enabling units', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    let lockConvergenceChecks = 0;
    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({
        commands,
        applied: true,
        verifyProvisionLockConverged: async () => {
          lockConvergenceChecks += 1;
        },
      }),
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
    assert.equal(lockConvergenceChecks, 2);
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
    }, fixture.plan);
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

    const staleManagerStates = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
      needDaemonReload: true,
    }, fixture.plan);
    await assert.rejects(
      provisionHost(
        { apply: false },
        fixture.dependencies({
          identitySequence: [expectedIdentitySnapshot()],
          unitStateSequence: [staleManagerStates],
        }),
      ),
      /managed unit requires daemon-reload/,
    );
    const preflightCommands = [];
    const preflight = await provisionHost(
      { apply: false, recoveryPreflight: true },
      fixture.dependencies({
        commands: preflightCommands,
        identitySequence: [expectedIdentitySnapshot()],
        unitStateSequence: [staleManagerStates],
      }),
    );
    assert.equal(preflight.mode, 'dry-run');
    assert.deepEqual(preflightCommands, []);
    const recoveredCommands = [];
    const recovered = await provisionHost(
      { apply: true },
      fixture.dependencies({
        commands: recoveredCommands,
        applied: true,
        identitySequence: [expectedIdentitySnapshot(), expectedIdentitySnapshot()],
        unitStateSequence: [staleManagerStates, loadedStates, loadedStates],
      }),
    );
    assert.equal(recovered.changed_artifact_count, 0);
    assert.deepEqual(recoveredCommands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
  });

  it('rechecks host identity after the final manager reload', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    const unsafeIdentity = expectedIdentitySnapshot({
      shadowDatabase: expectedShadowDatabase().replace(
        `${shadowRecord('webex-generic-account-bot')}\n`,
        `${shadowRecord('webex-generic-account-bot', '$6$usable')}\n`,
      ),
    });
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          applied: true,
          commands,
          identitySequence: [
            emptyIdentitySnapshot(),
            expectedIdentitySnapshot(),
            unsafeIdentity,
          ],
        }),
      ),
      /host policy files are installed but convergence failed.*managed user shadow password is not locked/,
    );
    assert.deepEqual(commands, [
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
  });

  it('rebinds managed runtime ownership to the final identity snapshot', async (context) => {
    const fixture = await provisionFixture(context);
    let runtimeChecks = 0;
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          applied: true,
          identitySequence: [
            emptyIdentitySnapshot(),
            expectedIdentitySnapshot(),
            renumberedIdentitySnapshot(),
          ],
          verifyManagedRuntimeState: async (_inspected, snapshot) => {
            runtimeChecks += 1;
            if (snapshot.users.get('webex-generic-account-bot').uid !== 1001) {
              throw new Error('managed runtime ownership follows stale identity');
            }
          },
        }),
      ),
      /host policy files are installed but convergence failed.*managed runtime ownership follows stale identity/,
    );
    assert.equal(runtimeChecks, 2);
  });

  it('rejects untrusted sources before creating target directories', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts[0];
    const candidate = path.join(
      path.dirname(artifact.target),
      `${PROVISION_CANDIDATE_PREFIX}00000000-0000-4000-8000-000000000099.tmp`,
    );
    await fs.mkdir(path.dirname(candidate), { recursive: true, mode: 0o755 });
    await fs.writeFile(candidate, 'preserved before preflight\n', { mode: 0o600 });
    await fs.chmod(fixture.plan.artifacts[0].source, 0o664);
    await assert.rejects(
      provisionHost({ apply: true }, fixture.dependencies({ applied: true })),
      /policy file metadata is not trusted/,
    );
    assert.equal(await fs.readFile(candidate, 'utf8'), 'preserved before preflight\n');
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

  it('rejects a source FIFO through non-blocking metadata inspection', async (context) => {
    const fixture = await provisionFixture(context);
    const source = fixture.plan.artifacts[0].source;
    await fs.rm(source);
    const mkfifo = spawnSync('/usr/bin/mkfifo', [source]);
    assert.equal(mkfifo.status, 0, mkfifo.error?.message ?? mkfifo.stderr.toString('utf8'));
    await fs.chmod(source, 0o644);

    await assert.rejects(
      provisionHost({ apply: false }, fixture.dependencies()),
      /policy file metadata is not trusted/,
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
        if (args.some((arg) => arg.startsWith('--state='))) {
          return { stdout: '', stderr: '', code: 0 };
        }
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
      const fragmentUnit = LAUNCHER_INSTANCE_PATTERN_FOR_TEST.test(unit)
        ? 'webex-codex-launcher@.service'
        : unit;
      return {
        stdout: [
          'Job=',
          'LoadState=loaded',
          `UnitFileState=${unit === 'webex-codex-launcher@boot.service' ? 'enabled' : 'static'}`,
          `FragmentPath=/etc/systemd/system/${fragmentUnit}`,
          'DropInPaths=',
          'NeedDaemonReload=no',
          'RequiredBy=',
          'WantedBy=',
          'UpheldBy=',
          'BoundBy=',
          'TriggeredBy=',
          'OnFailureOf=',
          'OnSuccessOf=',
          '',
        ].join('\n'),
        stderr: '',
        code: 0,
      };
    }, systemdUnitPathFs(new Map(), { usrMerged: true }));
    assert.equal(discovered.get(instance).active, 'active');
    assert.equal(discovered.get('webex-codex-launcher@boot.service').enabled, 'enabled');
    assert.equal(calls.filter(([, args]) => args[0] === 'list-units').length, 1);
    assert.equal(calls.filter(([, args]) => args[0] === 'list-unit-files').length, 1);
    assert.equal(calls.filter(([, args]) => args[0] === 'is-enabled').length, 0);

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
      }, systemdUnitPathFs()),
      /too many launcher instances/,
    );
    assert.equal(stateQueries, 0);
  });

  it('rejects next-boot managed-unit references directly from disk policy', async () => {
    const externalUnit = '/etc/systemd/system/external-boot.service';
    const encodedReference = Buffer.from(
      '[Unit]\nOnFailure=webex-codex-activation\\x2drenew.service\n',
    );
    let commandCalls = 0;
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => {
          commandCalls += 1;
          return { stdout: '', stderr: '', code: 0 };
        },
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external-boot.service',
              isFile: () => true,
              isDirectory: () => false,
              isSymbolicLink: () => false,
            }]],
          ]),
          { filesByPath: new Map([[externalUnit, encodedReference]]) },
        ),
      ),
      /external systemd policy references a managed unit/,
    );
    assert.equal(commandCalls, 0);

    const launcherUnit = '/etc/systemd/system/external-launcher.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external-launcher.service',
              isFile: () => true,
              isDirectory: () => false,
              isSymbolicLink: () => false,
            }]],
          ]),
          {
            filesByPath: new Map([[
              launcherUnit,
              Buffer.from('[Unit]\nWants=webex-codex-launcher@%i.service\n'),
            ]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    const specifierUnit = '/etc/systemd/system/webex-generic@.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'webex-generic@.service',
              isFile: () => true,
              isDirectory: () => false,
              isSymbolicLink: () => false,
            }]],
          ]),
          {
            filesByPath: new Map([[
              specifierUnit,
              Buffer.from('[Unit]\nWants=%p-account-bot.service\n'),
            ]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    const identityUnit = '/etc/systemd/system/external-dynamic.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external-dynamic.service',
              isFile: () => true,
              isDirectory: () => false,
              isSymbolicLink: () => false,
            }]],
          ]),
          {
            filesByPath: new Map([[
              identityUnit,
              Buffer.from('[Service]\nDynamicUser=yes\nUser=webex-config-deploy\n'),
            ]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    const numericIdentityUnit = '/etc/systemd/system/external@2003.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{ name: 'external@2003.service' }]],
          ]),
          {
            filesByPath: new Map([[
              numericIdentityUnit,
              Buffer.from('[Service]\nGroup="%i"\n'),
            ]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    const unresolvedIdentityTemplate = '/etc/systemd/system/external@.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{ name: 'external@.service' }]],
          ]),
          {
            filesByPath: new Map([[
              unresolvedIdentityTemplate,
              Buffer.from('[Service]\nGroup=%i\n'),
            ]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    for (const [name, policy] of [
      ['external-host-identity.service', '[Service]\nUser=%H\n'],
      ['external-host-unit.service', '[Unit]\nWants=%H.service\n'],
      [
        'external-composed@.service',
        '[Unit]\nWants=webex-codex-%i@prod.service\n',
      ],
      [
        'external-empty-specifier.service',
        '[Unit]\nWants=webex-codex-activation-renew%W.service\n',
      ],
    ]) {
      const target = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name }]]]),
            { filesByPath: new Map([[target, Buffer.from(policy)]]) },
          ),
        ),
        /external systemd policy references a managed unit/,
      );
    }

    const dashPrefixDropInDirectory =
      '/etc/systemd/system/external-.service.d';
    const dashPrefixDropIn = path.join(dashPrefixDropInDirectory, '50-identity.conf');
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external-.service.d',
              isFile: () => false,
              isDirectory: () => true,
              isSymbolicLink: () => false,
            }]],
            [dashPrefixDropInDirectory, [{ name: '50-identity.conf' }]],
          ]),
          {
            filesByPath: new Map([[
              dashPrefixDropIn,
              Buffer.from('[Service]\nUser=%J\n'),
            ]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    const sharedDropInDirectory = '/etc/systemd/system/external-.service.d';
    const sharedDropIn = path.join(sharedDropInDirectory, '50-identity.conf');
    const sharedDropInTarget = '/usr/lib/systemd/system/benign.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external-.service.d',
              isFile: () => false,
              isDirectory: () => true,
              isSymbolicLink: () => false,
            }]],
            [sharedDropInDirectory, [{
              name: '50-identity.conf',
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          {
            filesByPath: new Map([[
              sharedDropInTarget,
              Buffer.from('[Service]\nUser=%N\n'),
            ]]),
            symlinksByPath: new Map([[sharedDropIn, sharedDropInTarget]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    const credentialDropInDirectory =
      '/etc/systemd/system/external.service.d';
    const credentialDropIn = path.join(credentialDropInDirectory, '50-extra-policy.conf');
    for (const policy of [
      'LoadCredential=sysusers.extra:/root/policy',
      'LoadCredential=passwd.hashed-password.webex-generic-account-bot:/root/password',
      'SetCredential=passwd.plaintext-password.webex-config-deploy:secret',
      'ImportCredential=passwd.shell.*',
      'ImportCredential=payload.*:passwd.shell.',
      'SetCredential=userdb.user.injected:{}',
      'ImportCredential=payload:sysusers.extra',
      'ImportCredential=payload.*:sysusers.',
      'ImportCredential=payload.*:tmpfiles.',
      'ImportCredential=userdb.user.*',
      'ImportCredential=payload.*:userdb.group.',
      'ImportCredential=userdb.transient.user.*',
      'ImportCredential=sysusers.?xtra',
      'ImportCredential=sysusers.[e]xtra',
      'ImportCredential=sysusers.[[:alpha:]]xtra',
    ]) {
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([
              ['/etc/systemd/system', [{
                name: 'external.service.d',
                isFile: () => false,
                isDirectory: () => true,
                isSymbolicLink: () => false,
              }]],
              [credentialDropInDirectory, [{ name: '50-extra-policy.conf' }]],
            ]),
            {
              filesByPath: new Map([[
                credentialDropIn,
                Buffer.from(`[Service]\n${policy}\n`),
              ]]),
            },
          ),
        ),
        /external systemd policy injects a host policy credential/,
      );
    }

    const sysusersDropInDirectory =
      '/etc/systemd/system/systemd-sysusers.service.d';
    const sysusersExecDropIn = path.join(sysusersDropInDirectory, '50-exec.conf');
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'systemd-sysusers.service.d',
              isFile: () => false,
              isDirectory: () => true,
              isSymbolicLink: () => false,
            }]],
            [sysusersDropInDirectory, [{ name: '50-exec.conf' }]],
          ]),
          {
            filesByPath: new Map([[
              sysusersExecDropIn,
              Buffer.from(
                '[Service]\nExecStartPost=/usr/bin/systemd-sysusers /etc/rogue.conf\n',
              ),
            ]]),
          },
        ),
      ),
      /boot policy systemd consumer/,
    );

    const overriddenSysusers = '/etc/systemd/system/systemd-sysusers.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([['/etc/systemd/system', [{ name: 'systemd-sysusers.service' }]]]),
          {
            filesByPath: new Map([[
              overriddenSysusers,
              Buffer.from('[Service]\nExecStart=/usr/bin/systemd-sysusers /etc/rogue.conf\n'),
            ]]),
          },
        ),
      ),
      /boot policy systemd consumer is not trusted/,
    );

    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(new Map([['/etc/systemd/system', [{
          name: 'systemd-sysusers.service',
          isFile: () => false,
          isDirectory: () => true,
          isSymbolicLink: () => false,
        }]]])),
      ),
      /boot policy systemd consumer is not trusted/,
    );

    for (const directoryName of [
      'service.d',
      'systemd-.service.d',
      'systemd-sysusers.service.wants',
    ]) {
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(new Map([['/etc/systemd/system', [{
            name: directoryName,
            isFile: () => false,
            isDirectory: () => true,
            isSymbolicLink: () => false,
          }]]])),
        ),
        /boot policy systemd consumer policy directory is not trusted/,
      );
    }

    for (const [name, target, missingPaths] of [
      ['systemd-tmpfiles-clean.service', '/dev/null', new Set()],
      [
        'systemd-sysusers.service',
        '/usr/lib/systemd/system/missing-systemd-sysusers.service',
        new Set(['/usr/lib/systemd/system/missing-systemd-sysusers.service']),
      ],
      ['systemd-userdb-load-credentials.service', '/opt/systemd/non-regular', new Set()],
    ]) {
      const candidate = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{
              name,
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]]]),
            {
              missingPaths,
              symlinksByPath: new Map([[candidate, target]]),
            },
          ),
        ),
        /boot policy systemd consumer symlink target is not trusted/,
      );
    }

    for (const [name, policy] of [
      [
        'external-tmpfiles.service',
        '[Service]\nExecStart=/usr/bin/systemd-tmpfiles --create /etc/rogue.conf\n',
      ],
      [
        'external-sysusers.service',
        '[Service]\nExecStart=/bin/sh -c "/usr/bin/systemd-sysusers /etc/rogue.conf"\n',
      ],
      [
        'external-userdb.service',
        '[Service]\nExecStart=/usr/lib/systemd/systemd-userdbd --load-credentials\n',
      ],
    ]) {
      const target = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name }]]]),
            { filesByPath: new Map([[target, Buffer.from(policy)]]) },
          ),
        ),
        /external systemd policy invokes a boot policy tool/,
      );
    }

    for (const [name, policy] of [
      [
        'external-tmpfiles.service',
        '[Service]\nExecStart=|/usr/bin/systemd-%j --create /etc/rogue.conf\n',
      ],
      [
        'external-sysusers.service',
        '[Service]\nExecStart=/usr/bin/systemd-%j /etc/rogue.conf\n',
      ],
      [
        'external-userdb.service',
        '[Service]\nExecStart=/usr/lib/systemd/systemd-%jd --load-credentials\n',
      ],
    ]) {
      const target = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name }]]]),
            { filesByPath: new Map([[target, Buffer.from(policy)]]) },
          ),
        ),
        /external systemd policy invokes a boot policy tool/,
      );
    }

    for (const [instance, executable, arguments_] of [
      ['tmpfiles', 'systemd-%i', '--create /etc/rogue.conf'],
      ['sysusers', 'systemd-%I', '/etc/rogue.conf'],
      ['userdbd', 'systemd-%i', '--load-credentials'],
      ['--load-credentials', 'systemd-userdbd', '%i'],
    ]) {
      const template = '/etc/systemd/system/external@.service';
      const activator = '/etc/systemd/system/external-trigger.service';
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [
              { name: 'external@.service' },
              { name: 'external-trigger.service' },
            ]]]),
            {
              filesByPath: new Map([
                [
                  template,
                  Buffer.from(`[Service]\nExecStart=/usr/bin/${executable} ${arguments_}\n`),
                ],
                [
                  activator,
                  Buffer.from(`[Unit]\nWants=external@${instance}.service\n`),
                ],
              ]),
            },
          ),
        ),
        /external systemd policy invokes a boot policy tool/,
      );
    }

    for (const [instance, target] of [
      ['generic-account-bot', 'webex-%i.service'],
      ['generic-account-bot', '/etc/systemd/system/webex-%i.service'],
      ['smoke', 'webex-codex-launcher@%I.service'],
      ['smoke', 'webex-codex-launcher@%I.socket'],
      ['smoke', 'webex-codex-launcher@*.t?mer'],
      ['literal', 'webex-codex-activation-renew'],
      ['literal', 'webex-codex-activation-renew.timer'],
      ['glob-activator', 'webex-codex-activation-renew.[t]imer'],
      ['glob-activator', 'webex-codex-activation-renew.t?mer'],
      ['glob', 'webex-*'],
    ]) {
      const template = '/etc/systemd/system/external@.service';
      const activator = '/etc/systemd/system/external-trigger.service';
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [
              { name: 'external@.service' },
              { name: 'external-trigger.service' },
            ]]]),
            {
              filesByPath: new Map([
                [
                  template,
                  Buffer.from(`[Service]\nExecStart=/usr/bin/systemctl start ${target}\n`),
                ],
                [
                  activator,
                  Buffer.from(`[Unit]\nWants=external@${instance}.service\n`),
                ],
              ]),
            },
          ),
        ),
        /external systemd policy (?:references a managed unit|uses environment expansion)/,
      );
    }

    for (const name of [
      'webex-codex-activation-renew.timer',
      'webex-codex-activation-renew.path',
      'webex-codex-launcher@smoke.socket',
    ]) {
      const target = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name }]]]),
            { filesByPath: new Map([[target, Buffer.from('[Unit]\nDescription=implicit\n')]]) },
          ),
        ),
        /external systemd policy references a managed unit/,
      );
    }

    for (const [name, policy, fsOptions = {}] of [
      [
        'run-webex\\x2dcodex\\x2dcanary.mount',
        '[Mount]\nWhat=tmpfs\n',
      ],
      [
        'var-lib-webex\\x2dcodex\\x2druntime\\x2dinputs.automount',
        '[Automount]\nTimeoutIdleSec=60\n',
      ],
      [
        'external-protected.mount',
        '[Mount]\nWhere=/var/lib/webex-generic-account-bot/state\n',
      ],
      [
        'etc-sysusers.d.mount',
        '[Mount]\nWhere=/etc/sysusers.d\nBefore=systemd-sysusers.service\n',
      ],
      [
        'srv-etc.mount',
        '[Mount]\nWhat=/etc\nWhere=/srv/etc\n',
      ],
      [
        'srv-cache.mount',
        '[Mount]\nWhat=/srv/cache\nWhere=/srv/cache-copy\nOptions=bind\n',
      ],
      [
        'usr-bin-getfacl.mount',
        '[Mount]\nWhat=/srv/getfacl\nWhere=/usr/bin/getfacl\n',
      ],
      [
        'srv-alias-bin.mount',
        '[Mount]\nWhat=/dev/vdb1\nWhere=/srv/alias/bin\n',
        { symlinksByPath: new Map([['/srv/alias', '/usr']]) },
      ],
      [
        'external-mount-alias.service',
        '[Install]\nAlias=run-webex\\\\x2dconfig\\\\x2ddeploy.mount\n',
      ],
    ]) {
      const target = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name }]]]),
            { ...fsOptions, filesByPath: new Map([[target, Buffer.from(policy)]]) },
          ),
        ),
        /external systemd policy mounts a protected directory/,
        name,
      );
    }

    const writableParentMount = '/etc/systemd/system/external-writable-parent.mount';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([['/etc/systemd/system', [{
            name: 'external-writable-parent.mount',
          }]]]),
          {
            filesByPath: new Map([[
              writableParentMount,
              Buffer.from('[Mount]\nWhat=tmpfs\nWhere=/srv/user/alias/system\n'),
            ]]),
            directoryModesByPath: new Map([['/srv/user', 0o777]]),
            symlinksByPath: new Map([['/srv/user/alias', '/srv/safe']]),
          },
        ),
      ),
      /policy directory is not trusted: \/srv\/user/,
    );

    const redirectedVarRunMount = '/etc/systemd/system/external-var-run.mount';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([['/etc/systemd/system', [{ name: 'external-var-run.mount' }]]]),
          {
            filesByPath: new Map([[
              redirectedVarRunMount,
              Buffer.from('[Mount]\nWhat=tmpfs\nWhere=/var/run/bin\n'),
            ]]),
            symlinksByPath: new Map([['/var/run', '/usr']]),
          },
        ),
      ),
      /external systemd policy mounts a protected directory/,
    );

    const protectedMountWants = '/etc/systemd/system/external.target.wants';
    const protectedMountName = 'run-webex\\x2dcodex\\x2dcanary.mount';
    const protectedMountLink = `${protectedMountWants}/${protectedMountName}`;
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external.target.wants',
              isFile: () => false,
              isDirectory: () => true,
              isSymbolicLink: () => false,
            }]],
            [protectedMountWants, [{
              name: protectedMountName,
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          {
            symlinksByPath: new Map([[
              protectedMountLink,
              '/usr/lib/systemd/system/external-protected.mount',
            ]]),
          },
        ),
      ),
      /external systemd policy mounts a protected directory/,
    );

    for (const [index, command] of [
      'systemctl --preset-mode=enable-only preset-all',
      'systemctl daemon-reload',
      'systemctl --marked reload-or-restart',
      'systemctl --mark reload-or-restart',
      'systemctl enable /opt/benign.service',
      'systemctl enable %t-foreign.socket',
      'systemctl edit --full --stdin benign.service',
    ].entries()) {
      const name = `external-global-systemctl-${index}.service`;
      const target = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name }]]]),
            {
              filesByPath: new Map([[
                target,
                Buffer.from(`[Service]\nExecStart=/usr/bin/${command}\n`),
              ]]),
            },
          ),
        ),
        /external systemd policy references a managed unit/,
      );
    }

    const markedSpecifierUnit = '/etc/systemd/system/external@k.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([['/etc/systemd/system', [{ name: 'external@k.service' }]]]),
          {
            filesByPath: new Map([[
              markedSpecifierUnit,
              Buffer.from(
                '[Service]\nExecStart=/usr/bin/systemctl --mar%ied reload-or-restart\n',
              ),
            ]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    const splitEnvUnit = '/etc/systemd/system/external-env-split.service';
    for (const option of [
      '"--split-string=/usr/bin/echo safe"',
      '"--split-s=/usr/bin/echo safe"',
      '"--s=/usr/bin/echo safe"',
      '"--spl=/usr/bin/echo safe"',
      '"-iS /usr/bin/echo safe"',
    ]) {
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name: 'external-env-split.service' }]]]),
            {
              filesByPath: new Map([[
                splitEnvUnit,
                Buffer.from(`[Service]\nExecStart=/usr/bin/env ${option}\n`),
              ]]),
            },
          ),
        ),
        /external systemd policy reinterprets command arguments/,
      );
    }

    for (const [name, option] of [
      ['external@it-str.service', '"--spl%iing=/usr/bin/echo safe"'],
      ['external@S.service', '"-i%i/usr/bin/echo safe"'],
    ]) {
      const target = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name }]]]),
            {
              filesByPath: new Map([[
                target,
                Buffer.from(`[Service]\nExecStart=/usr/bin/env ${option}\n`),
              ]]),
            },
          ),
        ),
        /external systemd policy reinterprets command arguments/,
      );
    }

    const environmentUnit = '/etc/systemd/system/external-environment.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([['/etc/systemd/system', [{ name: 'external-environment.service' }]]]),
          {
            filesByPath: new Map([[
              environmentUnit,
              Buffer.from([
                '[Service]',
                'Environment=HELPER=/usr/bin/systemd-sysusers',
                'ExecStart=/usr/bin/env ${HELPER} /etc/rogue.conf',
                '',
              ].join('\n')),
            ]]),
          },
        ),
      ),
      /external systemd policy uses environment expansion/,
    );

    const specifierEnvironmentUnit = '/etc/systemd/system/external@.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([['/etc/systemd/system', [{ name: 'external@.service' }]]]),
          {
            filesByPath: new Map([[
              specifierEnvironmentUnit,
              Buffer.from('[Service]\nExecStart=/usr/bin/echo --target=%I\n'),
            ]]),
          },
        ),
      ),
      /external systemd policy uses environment expansion/,
    );

    for (const [name, commandLine] of [
      [
        'set-credential-inline',
        'set-credential passwd.plaintext-password.root=secret',
      ],
      [
        'set-credential-path',
        'set-credential sysusers.extra /tmp/sysusers.extra',
      ],
      [
        'set-credential-encrypted-path',
        'set-credential-encrypted tmpfiles.extra /tmp/tmpfiles.extra',
      ],
      [
        'set-credential-option-value',
        'set-credential --property Description sysusers.extra /tmp/sysusers.extra',
      ],
      [
        'set-credential-template',
        'set-credenti%ial sysusers.extra /tmp/sysusers.extra',
      ],
      [
        'set-credential-name-template',
        'set-credential userdb.us%i.webex-generic-account-bot /tmp/userdb.json',
      ],
    ]) {
      const unitName = name.includes('template')
        ? 'external@.service'
        : `external-${name}.service`;
      const credentialUnit = `/etc/systemd/system/${unitName}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name: unitName }]]]),
            {
              filesByPath: new Map([[
                credentialUnit,
                Buffer.from(
                  `[Service]\nExecStart=/usr/bin/systemctl ${commandLine}\n`,
                ),
              ]]),
            },
          ),
        ),
        /external systemd policy injects a host policy credential/,
      );
    }

    for (const [name, policy] of [
      [
        'external-state.service',
        '[Service]\nStateDirectory=webex-headless-access\n',
      ],
      [
        'external-state-alias.service',
        '[Service]\nStateDirectory=external:webex-headless-access\n',
      ],
      [
        'external-runtime.service',
        '[Service]\nRuntimeDirectory=webex-config-deploy\n',
      ],
      [
        'external-sysusers-runtime.service',
        '[Service]\nRuntimeDirectory=sysusers.d\n',
      ],
      [
        'external-config.service',
        '[Service]\nConfigurationDirectory=webex-generic-account-bot\n',
      ],
      [
        'external-state@.service',
        '[Service]\nStateDirectory=%i\n',
      ],
    ]) {
      const target = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{ name }]]]),
            { filesByPath: new Map([[target, Buffer.from(policy)]]) },
          ),
        ),
        /external systemd policy claims a protected directory/,
      );
    }

    for (const [name, policy, activatorPolicy] of [
      [
        'external-shell.service',
        "[Service]\nExecStart=/bin/sh -c '/usr/bin/systemd-\"sysusers\" /etc/rogue.conf'\n",
        null,
      ],
      [
        'external-shell-prefix.service',
        '[Service]\nExecStart=|/usr/bin/echo safe\n',
        null,
      ],
      [
        'external-second-shell-prefix.service',
        '[Service]\nExecStart=/usr/bin/true ; |/usr/bin/echo safe\n',
        null,
      ],
      [
        'external-executable-specifier@.service',
        '[Service]\nExecStart=/run/%i/helper\n',
        null,
      ],
      [
        'external-second-executable-specifier@.service',
        '[Service]\nExecStart=/usr/bin/true ; /usr/bin/helper-%i.bin\n',
        null,
      ],
      ['external-ash.service', "[Service]\nExecStart=/bin/ash -c 'echo safe'\n", null],
      ['external-mksh.service', "[Service]\nExecStart=/bin/mksh -c 'echo safe'\n", null],
      [
        'external-shell@.service',
        "[Service]\nExecStart=/usr/bin/mk%i -c 'echo safe'\n",
        '[Unit]\nWants=external-shell@sh.service\n',
      ],
      [
        'external-env-shell@.service',
        "[Service]\nExecStart=/usr/bin/env pw%i -c 'echo safe'\n",
        '[Unit]\nWants=external-env-shell@sh.service\n',
      ],
    ]) {
      const shellUnit = `/etc/systemd/system/${name}`;
      const activator = '/etc/systemd/system/external-shell-trigger.service';
      const entries = [{ name }];
      const files = [[shellUnit, Buffer.from(policy)]];
      if (activatorPolicy !== null) {
        entries.push({ name: 'external-shell-trigger.service' });
        files.push([activator, Buffer.from(activatorPolicy)]);
      }
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', entries]]),
            { filesByPath: new Map(files) },
          ),
        ),
        /external systemd policy invokes a shell/,
      );
    }

    const helperWants = '/etc/systemd/system/external.target.wants';
    const helperLink = `${helperWants}/external-helper.service`;
    const helperTarget = '/usr/lib/systemd/system/external-helper.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external.target.wants',
              isFile: () => false,
              isDirectory: () => true,
              isSymbolicLink: () => false,
            }]],
            [helperWants, [{
              name: 'external-helper.service',
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          {
            filesByPath: new Map([[
              helperTarget,
              Buffer.from(
                '[Service]\nExecStart=/usr/bin/systemd-sysusers /etc/rogue.conf\n',
              ),
            ]]),
            symlinksByPath: new Map([[helperLink, helperTarget]]),
          },
        ),
      ),
      /external systemd policy invokes a boot policy tool/,
    );

    let vendorImportCommandCalls = 0;
    const sysinitWants = '/usr/lib/systemd/system/sysinit.target.wants';
    const linkedSysusers = `${sysinitWants}/systemd-sysusers.service`;
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => {
          vendorImportCommandCalls += 1;
          throw new Error('systemctl reached after vendor credential import audit');
        },
        systemdUnitPathFs(
          new Map([
            ['/usr/lib/systemd/system', [
              { name: 'systemd-sysusers.service' },
              { name: 'systemd-userdb-load-credentials.service' },
              { name: 'systemd-tmpfiles-setup.service' },
              { name: 'systemd-pcrfs@.service' },
              { name: 'user@.service' },
              { name: 'vendor-shell.service' },
              {
                name: 'sysinit.target.wants',
                isFile: () => false,
                isDirectory: () => true,
                isSymbolicLink: () => false,
              },
            ]],
            [sysinitWants, [{
              name: 'systemd-sysusers.service',
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          {
            filesByPath: new Map([
              [
                '/usr/lib/systemd/system/systemd-sysusers.service',
                Buffer.from([
                  '[Service]',
                  'ImportCredential=passwd.hashed-password.root',
                  'ImportCredential=passwd.plaintext-password.root',
                  'ImportCredential=passwd.shell.root',
                  'ImportCredential=sysusers.*',
                  '',
                ].join('\n')),
              ],
              [
                '/usr/lib/systemd/system/systemd-userdb-load-credentials.service',
                Buffer.from([
                  '[Service]',
                  'ImportCredential=userdb.user.*',
                  'ImportCredential=userdb.group.*',
                  'ImportCredential=userdb.transient.user.*',
                  'ImportCredential=userdb.transient.group.*',
                  '',
                ].join('\n')),
              ],
              [
                '/usr/lib/systemd/system/systemd-tmpfiles-setup.service',
                Buffer.from('[Service]\nImportCredential=tmpfiles.*\n'),
              ],
              [
                '/usr/lib/systemd/system/systemd-pcrfs@.service',
                Buffer.from('[Unit]\nBindsTo=%i.mount\n'),
              ],
              [
                '/usr/lib/systemd/system/user@.service',
                Buffer.from([
                  '[Unit]',
                  'After=user-runtime-dir@%i.service',
                  '[Service]',
                  'User=%i',
                  'Slice=user-%i.slice',
                  '',
                ].join('\n')),
              ],
              [
                '/usr/lib/systemd/system/vendor-shell.service',
                Buffer.from("[Service]\nExecStart=/bin/sh -c 'echo safe'\n"),
              ],
            ]),
            symlinksByPath: new Map([[
              linkedSysusers,
              '../systemd-sysusers.service',
            ]]),
          },
        ),
      ),
      /systemctl reached after vendor credential import audit/,
    );
    assert.equal(vendorImportCommandCalls, 2);

    const intermediatePolicyLink = '/usr/lib/systemd/system/link';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/usr/lib/systemd/system', [{
              name: 'sysinit.target.wants',
              isFile: () => false,
              isDirectory: () => true,
              isSymbolicLink: () => false,
            }]],
            [sysinitWants, [{
              name: 'systemd-sysusers.service',
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          {
            filesByPath: new Map([[
              '/usr/lib/systemd/system/systemd-sysusers.service',
              Buffer.from('[Service]\nImportCredential=sysusers.*\n'),
            ]]),
            symlinksByPath: new Map([
              [
                linkedSysusers,
                '/usr/lib/systemd/system/link/../systemd-sysusers.service',
              ],
              [intermediatePolicyLink, '/opt/untrusted/systemd'],
            ]),
          },
        ),
      ),
      /systemd policy symlink target has unsafe parent traversal/,
    );

    const unresolvedDependencyTemplate =
      '/etc/systemd/system/external-dependency@.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([[
            '/etc/systemd/system',
            [{ name: 'external-dependency@.service' }],
          ]]),
          {
            filesByPath: new Map([[
              unresolvedDependencyTemplate,
              Buffer.from('[Unit]\nWants=%i.service\n'),
            ]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    for (const [name, target, contents, expected] of [
      [
        'external@.service',
        '/usr/lib/systemd/system/user@.service',
        '[Service]\nUser=%i\n',
        /external systemd policy references a managed unit/,
      ],
      [
        'external-sysusers.service',
        '/usr/lib/systemd/system/systemd-sysusers.service',
        '[Service]\nImportCredential=sysusers.*\n',
        /boot policy systemd consumer is not trusted/,
      ],
      [
        'systemd-sysusers.service',
        '/usr/lib/systemd/system/systemd-sysusers.service',
        '[Service]\nImportCredential=sysusers.*\n',
        /boot policy systemd consumer is not trusted/,
      ],
      [
        'external-userdb.service',
        '/usr/lib/systemd/system/systemd-userdb-load-credentials.service',
        '[Service]\nImportCredential=userdb.user.*\n',
        /boot policy systemd consumer is not trusted/,
      ],
    ]) {
      const alias = `/etc/systemd/system/${name}`;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => ({ stdout: '', stderr: '', code: 0 }),
          systemdUnitPathFs(
            new Map([['/etc/systemd/system', [{
              name,
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]]]),
            {
              filesByPath: new Map([[target, Buffer.from(contents)]]),
              symlinksByPath: new Map([[alias, target]]),
            },
          ),
        ),
        expected,
      );
    }

    const externalWants = '/etc/systemd/system/external.target.wants';
    const chainedSysusers = `${externalWants}/systemd-sysusers.service`;
    const intermediateSysusers = '/opt/systemd/systemd-sysusers.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external.target.wants',
              isFile: () => false,
              isDirectory: () => true,
              isSymbolicLink: () => false,
            }]],
            [externalWants, [{
              name: 'systemd-sysusers.service',
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          {
            filesByPath: new Map([[
              '/usr/lib/systemd/system/systemd-sysusers.service',
              Buffer.from('[Service]\nImportCredential=sysusers.*\n'),
            ]]),
            symlinksByPath: new Map([
              [chainedSysusers, intermediateSysusers],
              [intermediateSysusers, '/usr/lib/systemd/system/systemd-sysusers.service'],
            ]),
          },
        ),
      ),
      /boot policy systemd consumer is not trusted/,
    );

    const fakeVendorUnit =
      '/usr/lib/systemd/system/systemd-tmpfiles-unreviewed.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([[
            '/usr/lib/systemd/system',
            [{ name: 'systemd-tmpfiles-unreviewed.service' }],
          ]]),
          {
            filesByPath: new Map([[
              fakeVendorUnit,
              Buffer.from('[Service]\nImportCredential=tmpfiles.*\n'),
            ]]),
          },
        ),
      ),
      /external systemd policy injects a host policy credential/,
    );

    const implicitDynamicUserUnit = '/etc/systemd/system/webex-config-deploy.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{ name: 'webex-config-deploy.service' }]],
          ]),
          {
            filesByPath: new Map([[
              implicitDynamicUserUnit,
              Buffer.from('[Service]\nDynamicUser=yes\n'),
            ]]),
          },
        ),
        expectedIdentitySnapshot(),
      ),
      /external systemd policy references a managed unit/,
    );

    const linkedUnit = '/etc/systemd/system/external-linked.service';
    const linkedTarget = '/opt/systemd/external-linked.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external-linked.service',
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          {
            filesByPath: new Map([[
              linkedTarget,
              Buffer.from('[Unit]\nWants=webex-generic-account-bot.service\n'),
            ]]),
            symlinksByPath: new Map([[linkedUnit, linkedTarget]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    const linkedDropIn = '/etc/systemd/system/external.service.d';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external.service.d',
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          {
            symlinksByPath: new Map([[
              linkedDropIn,
              '/opt/systemd/external.service.d',
            ]]),
          },
        ),
      ),
      /systemd policy symlink target is not a regular file/,
    );

    const danglingUnit = '/etc/systemd/system/external-dangling.service';
    const danglingTarget = '/usr/lib/systemd/system/missing-external.service';
    let danglingCommandCalls = 0;
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => {
          danglingCommandCalls += 1;
          throw new Error('systemctl reached after dangling alias audit');
        },
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external-dangling.service',
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          {
            missingPaths: new Set([danglingTarget]),
            symlinksByPath: new Map([[danglingUnit, danglingTarget]]),
          },
        ),
      ),
      /systemctl reached after dangling alias audit/,
    );
    assert.equal(danglingCommandCalls, 2);

    const wantsDirectory = '/etc/systemd/system/multi-user.target.wants';
    const managedLink = path.join(wantsDirectory, 'webex-generic-account-bot.service');
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'multi-user.target.wants',
              isFile: () => false,
              isDirectory: () => true,
              isSymbolicLink: () => false,
            }]],
            [wantsDirectory, [{
              name: 'webex-generic-account-bot.service',
              isFile: () => false,
              isDirectory: () => false,
              isSymbolicLink: () => true,
            }]],
          ]),
          { symlinksByPath: new Map([[managedLink, '../webex-generic-account-bot.service']]) },
        ),
      ),
      /external systemd policy references a managed unit/,
    );

    const escapedWantsDirectory =
      '/etc/systemd/system/external.target.wants';
    const escapedLauncherInstance =
      'webex-codex-launcher@foo\\x20bar.service';
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => ({ stdout: '', stderr: '', code: 0 }),
        systemdUnitPathFs(
          new Map([
            ['/etc/systemd/system', [{
              name: 'external.target.wants',
              isFile: () => false,
              isDirectory: () => true,
              isSymbolicLink: () => false,
            }]],
            [escapedWantsDirectory, [{ name: escapedLauncherInstance }]],
          ]),
          {
            filesByPath: new Map([[
              path.join(escapedWantsDirectory, escapedLauncherInstance),
              Buffer.from(''),
            ]]),
          },
        ),
      ),
      /external systemd policy references a managed unit/,
    );
  });

  it('rejects unloaded managed-unit policy before querying systemd', async () => {
    for (const policyName of [
      'webex-codex-launcher@unloaded.service',
      'webex-codex-launcher@unloaded.service.d',
      'webex-codex-launcher@unloaded.service.wants',
      'webex-codex-launcher@unloaded.service.requires',
      'webex-codex-launcher@.service.wants',
      'webex-codex-launcher@.service.upholds',
      'webex-generic-account-bot.service.d',
      'webex-generic-account-bot.service.wants',
      'webex-config-pull-worker.service.requires',
      'webex-config-pull-worker.service.upholds',
      'service.d',
      'socket.d',
      'webex-.service.d',
      'webex-codex-.service.d',
    ]) {
      let commandCalls = 0;
      await assert.rejects(
        readSystemUnitStates(
          MANAGED_UNITS,
          async () => {
            commandCalls += 1;
            return { stdout: '', stderr: '', code: 0 };
          },
          systemdUnitPathFs(new Map([
            ['/etc/systemd/system', [
              { name: policyName },
            ]],
          ])),
        ),
        policyName === 'service.d'
          ? /boot policy systemd consumer policy directory is not trusted/
          : new RegExp(`unexpected managed unit policy.*${policyName.replaceAll('.', '\\.')}`),
      );
      assert.equal(commandCalls, 0);
    }

    let commandCalls = 0;
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => {
          commandCalls += 1;
          return { stdout: '', stderr: '', code: 0 };
        },
        systemdUnitPathFs(new Map([
          ['/usr/lib/systemd/system', [{ name: 'webex-generic-account-bot.service' }]],
        ])),
      ),
      /unexpected managed unit policy.*\/usr\/lib\/systemd\/system\/webex-generic-account-bot\.service/,
    );
    assert.equal(commandCalls, 0);
  });

  it('bounds systemd unit-path scanning before querying systemd', async () => {
    let commandCalls = 0;
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => {
          commandCalls += 1;
          return { stdout: '', stderr: '', code: 0 };
        },
        systemdUnitPathFs(new Map([
          ['/etc/systemd/system', Array.from(
            { length: 4097 },
            (_, index) => ({ name: `unrelated-${index}.service` }),
          )],
        ])),
      ),
      /too many entries in trusted directory/,
    );
    assert.equal(commandCalls, 0);
  });

  it('rejects a noncanonical usr-merge lib link before querying systemd', async () => {
    let commandCalls = 0;
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => {
          commandCalls += 1;
          return { stdout: '', stderr: '', code: 0 };
        },
        systemdUnitPathFs(new Map(), { usrMerged: true, usrMergeTarget: 'tmp/lib' }),
      ),
      /usr-merge \/lib link is not trusted/,
    );
    assert.equal(commandCalls, 0);
  });

  it('binds disk policy scanning to the manager unit path', async () => {
    const candidateName =
      `${PROVISION_CANDIDATE_PREFIX}00000000-0000-4000-8000-000000000099.tmp`;
    const fsApi = systemdUnitPathFs(new Map([
      ['/etc/systemd/system', [{
        name: candidateName,
        isFile: () => true,
        isDirectory: () => false,
        isSymbolicLink: () => false,
      }]],
    ]));
    let commandCalls = 0;
    await assert.rejects(
      readSystemUnitStatesImpl(
        MANAGED_UNITS,
        async (_command, args) => {
          commandCalls += 1;
          assert.deepEqual(args, ['show', '--property=UnitPath', '--value']);
          return {
            stdout: `${SYSTEMD_MANAGER_UNIT_PATH} /opt/unreviewed/systemd/system\n`,
            stderr: '',
            code: 0,
          };
        },
        fsApi,
      ),
      /systemd manager unit path is not the reviewed fixed path/,
    );
    assert.equal(commandCalls, 1);

    let listingCalls = 0;
    await assert.rejects(
      readSystemUnitStates(
        MANAGED_UNITS,
        async () => {
          listingCalls += 1;
          throw new Error('systemctl listing reached after candidate audit');
        },
        fsApi,
      ),
      /systemctl listing reached after candidate audit/,
    );
    assert.equal(listingCalls, 2);

    const splitStates = await readSystemUnitStatesImpl(
      MANAGED_UNITS,
      async (_command, args) => {
        if (args.join('\0') === 'show\0--property=UnitPath\0--value') {
          return {
            stdout: `${SPLIT_USR_SYSTEMD_MANAGER_UNIT_PATH}\n`,
            stderr: '',
            code: 0,
          };
        }
        if (args[0] === 'list-units' || args[0] === 'list-unit-files') {
          return { stdout: '', stderr: '', code: 0 };
        }
        if (args[0] === 'is-active') {
          return { stdout: 'inactive\n', stderr: '', code: 3 };
        }
        return { stdout: systemdUnitMetadata('not-found'), stderr: '', code: 0 };
      },
      systemdUnitPathFs(new Map(), { usrMerged: false }),
    );
    assert.equal(splitStates.size, MANAGED_UNITS.length);
  });

  it('rejects malformed or load-inconsistent systemctl state queries', async () => {
    const cases = [
      [
        'empty active output',
        { stdout: '', stderr: '', code: 3 },
        systemdUnitMetadata('not-found'),
        /managed unit active state query is malformed/,
      ],
      [
        'active query diagnostics',
        { stdout: 'inactive\n', stderr: 'Failed to connect to bus\n', code: 3 },
        systemdUnitMetadata('not-found'),
        /managed unit active state query is malformed/,
      ],
      [
        'loaded metadata with missing state queries',
        { stdout: 'inactive\n', stderr: '', code: 4 },
        systemdUnitMetadata('loaded', '/etc/systemd/system/webex-generic-account-bot.service'),
        /managed unit query state disagrees with load state/,
      ],
      [
        'blank load state',
        { stdout: 'inactive\n', stderr: '', code: 3 },
        systemdUnitMetadata(''),
        /managed unit load state is malformed/,
      ],
      [
        'loaded unit missing file state',
        { stdout: 'inactive\n', stderr: '', code: 3 },
        systemdUnitMetadata(
          'loaded',
          '/etc/systemd/system/webex-generic-account-bot.service',
          '',
        ),
        /managed unit file state is malformed/,
      ],
      [
        'missing unit with installed file state',
        { stdout: 'inactive\n', stderr: '', code: 3 },
        systemdUnitMetadata('not-found', '', 'disabled'),
        /managed unit file state disagrees with load state/,
      ],
      [
        'inactive unit with a queued job',
        { stdout: 'inactive\n', stderr: '', code: 3 },
        systemdUnitMetadata('not-found').replace('Job=\n', 'Job=42\n'),
        /managed unit has a pending job/,
      ],
    ];
    for (const [label, active, metadata, expected] of cases) {
      await assert.rejects(
        readSystemUnitStatesImpl(
          MANAGED_UNITS,
          async (_command, args) => {
            if (args.join('\0') === 'show\0--property=UnitPath\0--value') {
              return { stdout: `${SYSTEMD_MANAGER_UNIT_PATH}\n`, stderr: '', code: 0 };
            }
            if (args[0] === 'list-units' || args[0] === 'list-unit-files') {
              return { stdout: '', stderr: '', code: 0 };
            }
            if (args[0] === 'is-active') return active;
            return { stdout: metadata, stderr: '', code: 0 };
          },
          systemdUnitPathFs(),
        ),
        expected,
        label,
      );
    }
  });

  it('rejects loaded policy, stale manager state, and reverse activators', async (context) => {
    const cases = [
      [
        'fragment',
        (state) => ({ ...state, fragment: '/run/systemd/system/webex-generic-account-bot.service' }),
        /managed unit loaded an unexpected fragment/,
      ],
      [
        'drop-in',
        (state) => ({ ...state, dropIns: '/etc/systemd/system/service.d/90-untrusted.conf' }),
        /managed unit loaded unexpected drop-ins/,
      ],
      [
        'daemon-reload',
        (state) => ({ ...state, needDaemonReload: true }),
        /managed unit requires daemon-reload/,
      ],
      [
        'reverse-activator',
        (state) => ({ ...state, reverseActivators: ['external-boot.service'] }),
        /managed unit has an external reverse activator/,
      ],
    ];
    for (const [label, mutate, expected] of cases) {
      const fixture = await provisionFixture(context);
      const before = unitStates({
        load: 'not-found',
        active: 'inactive',
        enabled: 'not-found',
      });
      const after = unitStates({
        load: 'loaded',
        active: 'inactive',
        enabled: 'disabled',
      }, fixture.plan);
      const unit = MANAGED_UNITS[0];
      after.set(unit, mutate(after.get(unit)));
      const commands = [];

      await assert.rejects(
        provisionHost(
          { apply: true },
          fixture.dependencies({
            applied: true,
            commands,
            unitStateSequence: [before, after, before],
          }),
        ),
        expected,
        label,
      );
      assert.deepEqual(commands, [
        ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
        ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
        ['/usr/bin/systemctl', ['daemon-reload']],
        ['/usr/bin/systemctl', ['daemon-reload']],
      ], label);
      for (const artifact of fixture.plan.artifacts) {
        await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
      }
      await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
    }
  });

  it('retains the journal when a safety rollback reload cannot be proven', async (context) => {
    const fixture = await provisionFixture(context);
    const before = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    const unsafe = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    }, fixture.plan);
    unsafe.set(MANAGED_UNITS[0], {
      ...unsafe.get(MANAGED_UNITS[0]),
      dropIns: '/run/systemd/system/service.d/90-untrusted.conf',
    });
    const commands = [];
    const dependencies = fixture.dependencies({
      applied: true,
      unitStateSequence: [before, unsafe],
    });
    let reloads = 0;
    dependencies.runCommand = async (command, args) => {
      commands.push([command, [...args]]);
      if (command === '/usr/bin/systemctl') {
        reloads += 1;
        if (reloads === 2) throw new Error('injected safety rollback reload failure');
      }
      return { command, args: [...args], code: 0, stdout: '', stderr: '' };
    };

    await assert.rejects(
      provisionHost({ apply: true }, dependencies),
      /safety rollback failed: injected safety rollback reload failure/,
    );
    assert.deepEqual(commands, [
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
    for (const artifact of fixture.plan.artifacts) {
      await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
    }
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('uses the current install transaction after recovering an older revision', async (context) => {
    const fixture = await provisionFixture(context);
    const unitArtifact = fixture.plan.artifacts.find(({ kind }) => kind === 'unit');
    const oldPolicy = Buffer.from('[Unit]\nDescription=old policy\n');
    const interruptedPolicy = Buffer.from('[Unit]\nDescription=interrupted policy\n');
    const currentPolicy = Buffer.from('[Unit]\nDescription=current policy\n');
    await writeRecoveryTransaction(
      fixture,
      unitArtifact,
      interruptedPolicy,
      oldPolicy,
    );
    await fs.writeFile(unitArtifact.source, currentPolicy, { mode: 0o644 });
    await fs.chmod(unitArtifact.source, 0o644);

    const before = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    const unsafe = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    }, fixture.plan);
    unsafe.set(MANAGED_UNITS[0], {
      ...unsafe.get(MANAGED_UNITS[0]),
      fragment: '/run/systemd/system/webex-generic-account-bot.service',
    });
    const commands = [];

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          applied: true,
          commands,
          unitStateSequence: [before, before, before, unsafe, before],
        }),
      ),
      /host policy safety validation failed and the old policy set was restored/,
    );
    assert.equal(await fs.readFile(unitArtifact.target, 'utf8'), oldPolicy.toString('utf8'));
    for (const artifact of fixture.plan.artifacts) {
      if (artifact.target === unitArtifact.target) continue;
      await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
    }
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
    assert.deepEqual(commands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
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
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('keeps the desired set when transaction unlink durability is uncertain', async (context) => {
    const fixture = await provisionFixture(context);
    const transactionDirectory = path.dirname(fixture.plan.transactionFile);
    let transactionRemoved = false;
    let injected = false;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property === 'rm') {
          return async (...args) => {
            const result = await target.rm(...args);
            if (args[0] === fixture.plan.transactionFile) transactionRemoved = true;
            return result;
          };
        }
        if (property !== 'open') return target[property];
        return async (...args) => {
          const handle = await target.open(...args);
          if (args[0] !== transactionDirectory || !transactionRemoved || injected) return handle;
          return new Proxy(handle, {
            get(handleTarget, handleProperty) {
              if (handleProperty === 'sync') {
                return async () => {
                  injected = true;
                  throw new Error('injected transaction unlink fsync failure');
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
      /host policy files are installed but convergence failed.*unlink fsync failure/,
    );
    for (const artifact of fixture.plan.artifacts) {
      assert.equal(await fs.readFile(artifact.target, 'utf8'), await fs.readFile(artifact.source, 'utf8'));
    }
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('reloads stale manager state after an installation rollback before reapplying', async (context) => {
    const fixture = await provisionFixture(context);
    let candidateRenames = 0;
    const interruptedFs = new Proxy(fs, {
      get(target, property) {
        if (property !== 'rename') return target[property];
        return async (source, destination) => {
          if (path.basename(source).includes('.provision-')) {
            candidateRenames += 1;
            if (candidateRenames === 13) throw new Error('injected unit rename failure');
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
      /injected unit rename failure/,
    );
    for (const artifact of fixture.plan.artifacts) {
      await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
    }
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);

    const staleManagerStates = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
      needDaemonReload: true,
    });
    const unloadedStates = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    const loadedStates = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    }, fixture.plan);
    const commands = [];
    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({
        applied: true,
        commands,
        unitStateSequence: [
          staleManagerStates,
          unloadedStates,
          unloadedStates,
          loadedStates,
        ],
      }),
    );

    assert.equal(report.mode, 'applied');
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
    assert.deepEqual(commands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
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
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('preflights transaction recovery without mutating policy', async (context) => {
    const fixture = await provisionFixture(context);
    await writeNullTransaction(fixture);
    const transactionBefore = await fs.readFile(fixture.plan.transactionFile);
    const commands = [];
    let runtimePreflights = 0;

    const report = await provisionHost(
      { apply: false, recoveryPreflight: true },
      fixture.dependencies({
        commands,
        verifyRuntimeAncestors: async () => {
          runtimePreflights += 1;
        },
      }),
    );

    assert.equal(report.mode, 'dry-run');
    assert.equal(runtimePreflights, 1);
    assert.deepEqual(commands, []);
    assert.deepEqual(
      await fs.readFile(fixture.plan.transactionFile),
      transactionBefore,
    );
    for (const artifact of fixture.plan.artifacts) {
      await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
    }

    const changedTarget = fixture.plan.artifacts[0].target;
    await fs.writeFile(changedTarget, 'unknown administrator state\n', { mode: 0o644 });
    await fs.chmod(changedTarget, 0o644);
    await assert.rejects(
      provisionHost(
        { apply: false, recoveryPreflight: true },
        fixture.dependencies(),
      ),
      /policy target has unknown state during recovery/,
    );
    assert.equal(
      await fs.readFile(changedTarget, 'utf8'),
      'unknown administrator state\n',
    );
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

    const commands = [];
    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({ applied: true, commands }),
    );
    assert.equal(report.mode, 'applied');
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
    for (const artifact of fixture.plan.artifacts) {
      assert.equal(await fs.readFile(artifact.target, 'utf8'), await fs.readFile(artifact.source, 'utf8'));
    }
    assert.deepEqual(commands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
  });

  it('does not recover policy while a managed unit is active', async (context) => {
    const fixture = await provisionFixture(context);
    await writeNullTransaction(fixture);
    const activeStates = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    activeStates.set(MANAGED_UNITS[0], {
      load: 'loaded',
      active: 'active',
      enabled: 'disabled',
      fragment: fixture.plan.units.find(
        (candidate) => path.basename(candidate) === MANAGED_UNITS[0],
      ),
      dropIns: '',
    });

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ unitStateSequence: [activeStates] }),
      ),
      /managed unit is not inactive/,
    );
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
    for (const artifact of fixture.plan.artifacts) {
      await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
    }
  });

  it('does not recover policy before source trust preflight succeeds', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts[0];
    const desired = Buffer.from('interrupted desired policy\n');
    const existing = Buffer.from('recorded old policy\n');
    await writeRecoveryTransaction(fixture, artifact, desired, existing);
    await fs.chmod(artifact.source, 0o664);
    const commands = [];

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({ applied: true, commands }),
      ),
      /policy file metadata is not trusted/,
    );
    assert.equal(await fs.readFile(artifact.target, 'utf8'), desired.toString('utf8'));
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
    assert.deepEqual(commands, []);
  });

  it('retains the recovery journal when the immediate manager reload fails', async (context) => {
    const fixture = await provisionFixture(context);
    await writeNullTransaction(fixture);
    const commands = [];
    const dependencies = fixture.dependencies({ commands, applied: true });
    dependencies.runCommand = async (command, args) => {
      commands.push([command, [...args]]);
      throw new Error('injected recovery daemon-reload failure');
    };

    await assert.rejects(
      provisionHost({ apply: true }, dependencies),
      /host policy recovery finalisation failed.*daemon-reload failure/,
    );
    assert.deepEqual(commands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('refuses a target change while preparing its recovery candidate', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts[0];
    const desired = Buffer.from('interrupted desired policy\n');
    const existing = Buffer.from('recorded old policy\n');
    await writeRecoveryTransaction(fixture, artifact, desired, existing);
    const candidatePrefix = path.join(
      path.dirname(artifact.target),
      PROVISION_CANDIDATE_PREFIX,
    );
    let injected = false;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'open') return target[property];
        return async (...args) => {
          const handle = await target.open(...args);
          if (!String(args[0]).startsWith(candidatePrefix) || injected) return handle;
          return new Proxy(handle, {
            get(handleTarget, handleProperty) {
              if (handleProperty === 'close') {
                return async () => {
                  await handleTarget.close();
                  injected = true;
                  const replacement = `${artifact.target}.administrator`;
                  await target.writeFile(replacement, 'concurrent administrator state\n', {
                    mode: 0o644,
                  });
                  await target.rename(replacement, artifact.target);
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
      /policy target changed during installation/,
    );
    assert.equal(await fs.readFile(artifact.target, 'utf8'), 'concurrent administrator state\n');
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('keeps the journal when a removed target is recreated before recovery commits', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts[0];
    const desired = Buffer.from('interrupted desired policy\n');
    await writeRecoveryTransaction(fixture, artifact, desired, null);
    const directory = path.dirname(artifact.target);
    let removed = false;
    let injected = false;
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property === 'rm') {
          return async (...args) => {
            const result = await target.rm(...args);
            if (args[0] === artifact.target) removed = true;
            return result;
          };
        }
        if (property !== 'open') return target[property];
        return async (...args) => {
          const handle = await target.open(...args);
          if (args[0] !== directory || !removed || injected) return handle;
          return new Proxy(handle, {
            get(handleTarget, handleProperty) {
              if (handleProperty === 'sync') {
                return async () => {
                  await handleTarget.sync();
                  injected = true;
                  await target.writeFile(
                    artifact.target,
                    'concurrent administrator state\n',
                    { mode: 0o644 },
                  );
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
      /policy target changed after recovery/,
    );
    assert.equal(await fs.readFile(artifact.target, 'utf8'), 'concurrent administrator state\n');
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
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
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);

    const failedRetryCommands = [];
    const failedRetryDependencies = fixture.dependencies({ applied: true });
    failedRetryDependencies.runCommand = async (command, args) => {
      failedRetryCommands.push([command, [...args]]);
      if (command === '/usr/bin/systemd-sysusers') {
        throw new Error('injected resumed sysusers failure');
      }
      return { command, args: [...args], code: 0, stdout: '', stderr: '' };
    };
    await assert.rejects(
      provisionHost({ apply: true }, failedRetryDependencies),
      /policy files are installed but convergence failed.*resumed sysusers failure/,
    );
    assert.deepEqual(failedRetryCommands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
    ]);
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);

    const retryCommands = [];
    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({ applied: true, commands: retryCommands }),
    );
    assert.equal(report.changed_artifact_count, 0);
    assert.deepEqual(report.installed_artifacts, []);
    assert.deepEqual(retryCommands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('rolls back a complete desired recovery when manager safety validation fails', async (context) => {
    const fixture = await provisionFixture(context);
    const failedInstall = fixture.dependencies({ applied: true });
    failedInstall.runCommand = async () => {
      throw new Error('injected initial sysusers failure');
    };
    await assert.rejects(
      provisionHost({ apply: true }, failedInstall),
      /injected initial sysusers failure/,
    );

    const before = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    const unsafe = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    }, fixture.plan);
    const unit = MANAGED_UNITS[0];
    unsafe.set(unit, {
      ...unsafe.get(unit),
      reverseActivators: ['external-boot.service'],
    });
    const commands = [];

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          applied: true,
          commands,
          unitStateSequence: [before, unsafe, before],
        }),
      ),
      /host policy safety validation failed and the old policy set was restored.*external reverse activator/,
    );
    assert.deepEqual(commands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
    for (const artifact of fixture.plan.artifacts) {
      await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
    }
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('retries sysusers after a recoverable credential-database partial commit', async (context) => {
    const fixture = await provisionFixture(context);
    const failedInstall = fixture.dependencies({ applied: true });
    failedInstall.runCommand = async () => {
      throw new Error('injected sysusers partial commit');
    };
    await assert.rejects(
      provisionHost({ apply: true }, failedInstall),
      /injected sysusers partial commit/,
    );

    const partialIdentity = expectedIdentitySnapshot({ shadowDatabase: '' });
    const recoveryModes = [];
    const recoverIdentityDatabases = async (_transaction, _snapshot, options) => {
      recoveryModes.push(options.apply);
    };
    await assert.rejects(
      provisionHost(
        { apply: false, recoveryPreflight: true },
        fixture.dependencies({
          identitySequence: [expectedIdentitySnapshot({
            configPullMembers: ['unexpected-user'],
          })],
        }),
      ),
      /managed group has static members: webex-config-pull/,
    );
    const preflightCommands = [];
    const preflight = await provisionHost(
      { apply: false, recoveryPreflight: true },
      fixture.dependencies({
        commands: preflightCommands,
        identitySequence: [partialIdentity],
        recoverIdentityDatabases,
      }),
    );
    assert.equal(preflight.mode, 'dry-run');
    assert.deepEqual(preflightCommands, []);

    const commands = [];
    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({
        applied: true,
        commands,
        identitySequence: [
          partialIdentity,
          emptyIdentitySnapshot(),
          expectedIdentitySnapshot(),
        ],
        recoverIdentityDatabases,
      }),
    );

    assert.equal(report.mode, 'applied');
    assert.deepEqual(recoveryModes, [false, false, true]);
    assert.deepEqual(report.installed_artifacts, []);
    assert.deepEqual(commands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('rejects counterpart drift for an unmarked old-state transaction', async (context) => {
    const fixture = await provisionFixture(context);
    await writeNullTransaction(fixture);
    const partialIdentity = expectedIdentitySnapshot({
      shadowDatabase: `${shadowRecord('webex-config-deploy')}\n`,
    });

    await assert.rejects(
      provisionHost(
        { apply: false, recoveryPreflight: true },
        fixture.dependencies({ identitySequence: [partialIdentity] }),
      ),
      /managed user shadow credential is missing: webex-generic-account-bot/,
    );
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('clears recovery after a safe partial credential commit and policy rollback', async (context) => {
    const fixture = await provisionFixture(context);
    const failedInstall = fixture.dependencies({ applied: true });
    failedInstall.runCommand = async () => {
      throw new Error('injected sysusers partial commit');
    };
    await assert.rejects(
      provisionHost({ apply: true }, failedInstall),
      /injected sysusers partial commit/,
    );

    const partialIdentity = recoverableSysusersPartialIdentitySnapshot();
    const absent = unitStates({
      load: 'not-found',
      active: 'inactive',
      enabled: 'not-found',
    });
    const unsafe = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    }, fixture.plan);
    unsafe.set(MANAGED_UNITS[0], {
      ...unsafe.get(MANAGED_UNITS[0]),
      reverseActivators: ['external-boot.service'],
    });
    const rollbackCommands = [];

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          commands: rollbackCommands,
          identitySequence: [partialIdentity],
          unitStateSequence: [absent, unsafe, absent],
        }),
      ),
      /host policy safety validation failed and the old policy set was restored/,
    );
    assert.deepEqual(rollbackCommands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
    for (const artifact of fixture.plan.artifacts) {
      await assert.rejects(fs.stat(artifact.target), { code: 'ENOENT' });
    }
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('carries a safe partial identity state into a newer interrupted policy transaction', async (context) => {
    const fixture = await provisionFixture(context);
    const failedInstall = fixture.dependencies({ applied: true });
    failedInstall.runCommand = async () => {
      throw new Error('injected sysusers partial commit');
    };
    await assert.rejects(
      provisionHost({ apply: true }, failedInstall),
      /injected sysusers partial commit/,
    );

    const partialIdentity = recoverableSysusersPartialIdentitySnapshot();
    const unitArtifact = fixture.plan.artifacts.find(({ kind }) => kind === 'unit');
    await fs.writeFile(unitArtifact.source, '[Unit]\nDescription=new revision\n', {
      mode: 0o644,
    });
    await fs.chmod(unitArtifact.source, 0o644);
    const fsApi = new Proxy(fs, {
      get(target, property) {
        if (property !== 'rename') return target[property];
        return async (source, destination) => {
          if (destination === unitArtifact.target) {
            throw new Error('injected newer policy install interruption');
          }
          return target.rename(source, destination);
        };
      },
    });
    const loaded = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    }, fixture.plan);

    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          fsApi,
          identitySequence: [partialIdentity],
          unitStateSequence: [loaded, loaded, loaded],
        }),
      ),
      /injected newer policy install interruption/,
    );
    const interrupted = JSON.parse(await fs.readFile(fixture.plan.transactionFile, 'utf8'));
    assert.equal(interrupted.version, 3);
    assert.equal(interrupted.identity_recovery_required, false);

    const preflight = await provisionHost(
      { apply: false, recoveryPreflight: true },
      fixture.dependencies({
        identitySequence: [partialIdentity],
        unitStateSequence: [loaded],
      }),
    );
    assert.equal(preflight.mode, 'dry-run');
  });

  it('journals a zero-policy-change sysusers partial commit for recovery', async (context) => {
    const fixture = await provisionFixture(context);
    for (const artifact of fixture.plan.artifacts) {
      await fs.mkdir(path.dirname(artifact.target), { recursive: true, mode: 0o755 });
      await fs.copyFile(artifact.source, artifact.target);
      await fs.chmod(artifact.target, 0o644);
    }
    const loaded = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    }, fixture.plan);
    const failedCommands = [];
    const failedInstall = fixture.dependencies({
      commands: failedCommands,
      identitySequence: [emptyIdentitySnapshot()],
      unitStateSequence: [loaded],
    });
    failedInstall.runCommand = async (command, args) => {
      failedCommands.push([command, [...args]]);
      throw new Error('injected zero-change sysusers partial commit');
    };

    await assert.rejects(
      provisionHost({ apply: true }, failedInstall),
      /injected zero-change sysusers partial commit/,
    );
    assert.deepEqual(failedCommands, [
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
    ]);
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);

    const partialIdentity = recoverableSysusersPartialIdentitySnapshot();
    const retryCommands = [];
    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({
        commands: retryCommands,
        identitySequence: [partialIdentity, expectedIdentitySnapshot()],
        unitStateSequence: [loaded, loaded, loaded, loaded],
      }),
    );

    assert.equal(report.mode, 'applied');
    assert.deepEqual(report.installed_artifacts, []);
    assert.deepEqual(retryCommands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('clears an old recovery transaction after the source policy is reverted', async (context) => {
    const fixture = await provisionFixture(context);
    const selected = fixture.plan.artifacts.find(({ kind }) => kind === 'unit');
    const interrupted = Buffer.from('[Unit]\nDescription=interrupted policy\n');
    const snapshots = new Map();
    for (const artifact of fixture.plan.artifacts) {
      const contents = await fs.readFile(artifact.source);
      snapshots.set(artifact.target, contents);
      await fs.mkdir(path.dirname(artifact.target), { recursive: true, mode: 0o755 });
      await fs.copyFile(artifact.source, artifact.target);
      await fs.chmod(artifact.target, 0o644);
    }
    await fs.mkdir(path.dirname(fixture.plan.transactionFile), {
      recursive: true,
      mode: 0o755,
    });
    const transaction = {
      version: 1,
      artifacts: fixture.plan.artifacts.map((artifact) => {
        const existing = snapshots.get(artifact.target);
        const desired = artifact.target === selected.target ? interrupted : existing;
        return {
          target: artifact.target,
          desired_sha256: createHash('sha256').update(desired).digest('hex'),
          existing: {
            contents_base64: existing.toString('base64'),
            sha256: createHash('sha256').update(existing).digest('hex'),
          },
        };
      }),
    };
    await fs.writeFile(
      fixture.plan.transactionFile,
      `${JSON.stringify(transaction)}\n`,
      { mode: 0o600 },
    );
    await fs.chmod(fixture.plan.transactionFile, 0o600);
    const loaded = unitStates({
      load: 'loaded',
      active: 'inactive',
      enabled: 'disabled',
    }, fixture.plan);
    const commands = [];

    const report = await provisionHost(
      { apply: true },
      fixture.dependencies({
        applied: true,
        commands,
        unitStateSequence: [loaded, loaded, loaded, loaded],
      }),
    );

    assert.equal(report.mode, 'applied');
    assert.deepEqual(report.installed_artifacts, []);
    assert.deepEqual(commands, [
      ['/usr/bin/systemctl', ['daemon-reload']],
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
      ['/usr/bin/systemctl', ['daemon-reload']],
    ]);
    await assert.rejects(fs.stat(fixture.plan.transactionFile), { code: 'ENOENT' });
  });

  it('does not reload systemd until the held lock metadata has converged', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    let runtimeVerified = false;
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          commands,
          applied: true,
          verifyManagedRuntimeState: async () => {
            assert.deepEqual(commands.at(-1), [
              '/usr/bin/systemd-tmpfiles',
              ['--create', ...fixture.plan.tmpfiles],
            ]);
            runtimeVerified = true;
          },
          verifyProvisionLockConverged: async () => {
            throw new Error('held lock metadata is still transitional');
          },
        }),
      ),
      /policy files are installed but convergence failed.*held lock metadata is still transitional/,
    );
    assert.deepEqual(commands, [
      ['/usr/bin/systemd-sysusers', fixture.plan.sysusers],
      ['/usr/bin/systemd-tmpfiles', ['--create', ...fixture.plan.tmpfiles]],
    ]);
    assert.equal(runtimeVerified, true);
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
  });

  it('checks PID 1 policy files and mount topology around daemon-reload', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    let managerArtifactChecks = 0;
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          applied: true,
          commands,
          managerMountInfoSequence: [
            SAFE_MOUNT_INFO,
            mountInfoWith('/shadow-systemd', '/etc/systemd/system'),
          ],
          verifyManagerInstalledArtifacts: async () => {
            managerArtifactChecks += 1;
          },
        }),
      ),
      /unexpected mount (?:overlaps|aliases) protected host path/,
    );
    assert.equal(managerArtifactChecks, 1);
    assert.deepEqual(commands.at(-1), ['/usr/bin/systemctl', ['daemon-reload']]);

    const blockedFixture = await provisionFixture(context);
    const blockedCommands = [];
    await assert.rejects(
      provisionHost(
        { apply: true },
        blockedFixture.dependencies({
          applied: true,
          commands: blockedCommands,
          verifyManagerInstalledArtifacts: async () => {
            throw new Error('PID 1 policy digest mismatch: injected');
          },
        }),
      ),
      /PID 1 policy digest mismatch: injected/,
    );
    assert.equal(
      blockedCommands.some(([, args]) => args[0] === 'daemon-reload'),
      false,
    );
  });

  it('requires root for both modes and keeps help side-effect free', async () => {
    await assert.rejects(
      provisionHost(
        { apply: true },
        {
          processApi: { geteuid: () => 1000 },
        },
      ),
      /host provisioning requires root/,
    );
    await assert.rejects(
      provisionHost(
        { apply: false },
        {
          processApi: { geteuid: () => 1000 },
        },
      ),
      /host provisioning requires root/,
    );

    const output = [];
    assert.equal(await runCli({
      argv: ['--help'],
      stdout: { write: (value) => output.push(value) },
    }), 0);
    assert.match(output.join(''), /Dry-run is the default/);
  });
});

function mountInfoWith(root, mountPoint, device = '8:1') {
  return `${SAFE_MOUNT_INFO}4 1 ${device} ${root} ${mountPoint} rw - ext4 /dev/root rw\n`;
}

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
  const bootPolicyCatalogs = {
    sysusers: (await Promise.all(plan.artifacts
      .filter(({ kind }) => kind === 'sysusers')
      .map(({ source }) => fs.readFile(source, 'utf8')))).join('\n'),
    tmpfiles: (await Promise.all(plan.artifacts
      .filter(({ kind }) => kind === 'tmpfiles')
      .map(({ source }) => fs.readFile(source, 'utf8')))).join('\n'),
  };
  return {
    root,
    sourceRoot,
    targetRoot,
    plan,
    bootPolicyCatalogs,
    dependencies({
      commands = [],
      fsApi = fs,
      applied = false,
      identitySequence = null,
      unitStateSequence = null,
      bootPolicySequence = null,
      mountInfoSequence = null,
      managerMountInfoSequence = null,
      verifyProvisionLockConverged = async () => {},
      verifyManagerInstalledArtifacts = async () => {},
      readIdentityFileState = async () => testIdentityFileState(),
      recoverIdentityDatabases = async (_transaction, snapshot) => {
        validateIdentityPolicy(snapshot);
      },
      verifyIdentityLock = async () => {},
      verifyLegacyPaths = async () => {},
      verifyPidNamespace = async () => {},
      verifyMountNamespace = async () => {},
      verifyRuntimeAncestors = async () => {},
      verifyManagedRuntimeState = async () => {},
    } = {}) {
      const identities = identitySequence ?? (applied
        ? [emptyIdentitySnapshot(), expectedIdentitySnapshot()]
        : [emptyIdentitySnapshot()]);
      const stateSequence = unitStateSequence ?? (applied
        ? [
          unitStates({ load: 'not-found', active: 'inactive', enabled: 'not-found' }),
          unitStates({ load: 'loaded', active: 'inactive', enabled: 'disabled' }, plan),
        ]
        : [unitStates({ load: 'not-found', active: 'inactive', enabled: 'not-found' })]);
      let identityIndex = 0;
      let stateIndex = 0;
      let bootPolicyIndex = 0;
      let mountInfoIndex = 0;
      let managerMountInfoIndex = 0;
      let uuid = 0;
      const bootPolicies = bootPolicySequence ?? [bootPolicyCatalogs];
      const mountInfos = mountInfoSequence ?? [SAFE_MOUNT_INFO];
      const managerMountInfos = managerMountInfoSequence ?? [SAFE_MOUNT_INFO];
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
        readBootPolicyCatalogs: async () => bootPolicies[
          Math.min(bootPolicyIndex++, bootPolicies.length - 1)
        ],
        readMountInfo: async () => mountInfos[
          Math.min(mountInfoIndex++, mountInfos.length - 1)
        ],
        readManagerMountInfo: async () => managerMountInfos[
          Math.min(managerMountInfoIndex++, managerMountInfos.length - 1)
        ],
        verifyManagerInstalledArtifacts,
        readIdentityFileState,
        recoverIdentityDatabases,
        verifyIdentityLock,
        verifyLegacyPaths,
        verifyPidNamespace,
        verifyMountNamespace,
        readUnitStates: async () => stateSequence[
          Math.min(stateIndex++, stateSequence.length - 1)
        ],
        verifyProvisionLockConverged,
        verifyRuntimeAncestors,
        verifyManagedRuntimeState,
        runCommand: async (command, args) => {
          commands.push([command, [...args]]);
          return { command, args: [...args], code: 0, stdout: '', stderr: '' };
        },
      };
    },
  };
}

async function sourceAssociatedBootPolicyCatalogs(plan, overrides = new Map()) {
  const catalogs = { sysusers: [], tmpfiles: [] };
  for (const artifact of plan.artifacts) {
    if (!Object.hasOwn(catalogs, artifact.kind)) continue;
    const contents = overrides.get(artifact.targetPath)
      ?? await fs.readFile(artifact.source, 'utf8');
    catalogs[artifact.kind].push(`# ${artifact.targetPath}\n${contents}`);
  }
  return {
    sysusers: catalogs.sysusers.join('\n'),
    tmpfiles: catalogs.tmpfiles.join('\n'),
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

async function writeIdentityRecoveryTransaction(fixture) {
  for (const directory of new Set(
    fixture.plan.artifacts.map(({ target }) => path.dirname(target)),
  )) {
    await fs.mkdir(directory, { recursive: true, mode: 0o755 });
  }
  const transaction = {
    version: 3,
    identity_recovery_required: true,
    identity_files: testIdentityFileState().map((entry) => ({
      path: entry.path,
      sha256: entry.sha256,
      uid: entry.uid,
      gid: entry.gid,
      mode: entry.mode,
    })),
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

async function writeRecoveryTransaction(fixture, selected, desired, existing) {
  for (const directory of new Set(
    fixture.plan.artifacts.map(({ target }) => path.dirname(target)),
  )) {
    await fs.mkdir(directory, { recursive: true, mode: 0o755 });
  }
  await fs.writeFile(selected.target, desired, { mode: 0o644 });
  await fs.chmod(selected.target, 0o644);
  const transaction = {
    version: 1,
    artifacts: fixture.plan.artifacts.map(({ target }) => ({
      target,
      desired_sha256: target === selected.target
        ? createHash('sha256').update(desired).digest('hex')
        : '0'.repeat(64),
      existing: target === selected.target && existing
        ? {
          contents_base64: existing.toString('base64'),
          sha256: createHash('sha256').update(existing).digest('hex'),
        }
        : null,
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

function testIdentityFileState() {
  return [
    ['/etc/group', 0o644],
    ['/etc/gshadow', 0o640],
    ['/etc/passwd', 0o644],
    ['/etc/shadow', 0o640],
  ].map(([file, mode], index) => Object.freeze({
    path: file,
    sha256: String(index + 1).repeat(64),
    uid: 0,
    gid: file.includes('shadow') ? 42 : 0,
    mode,
  }));
}

function recoverableSysusersPartialIdentitySnapshot() {
  return parseIdentityDatabases(
    '',
    expectedGroupDatabase(),
    {},
    expectedGshadowDatabase(),
    '',
  );
}

function expectedIdentitySnapshot({
  botEffectiveGroups = [2001],
  workerEffectiveGroups = [2002],
  configPullMembers = [],
  groupDatabase = expectedGroupDatabase(configPullMembers),
  gshadowDatabase = expectedGshadowDatabase(),
  shadowDatabase = expectedShadowDatabase(),
} = {}) {
  return parseIdentityDatabases(
    [
      passwdRecord('webex-generic-account-bot', 1001, 2001),
      passwdRecord('webex-config-deploy', 1002, 2002),
      '',
    ].join('\n'),
    groupDatabase,
    {
      'webex-generic-account-bot': botEffectiveGroups,
      'webex-config-deploy': workerEffectiveGroups,
    },
    gshadowDatabase,
    shadowDatabase,
  );
}

function renumberedIdentitySnapshot() {
  return parseIdentityDatabases(
    [
      passwdRecord('webex-generic-account-bot', 1101, 2101),
      passwdRecord('webex-config-deploy', 1102, 2102),
      '',
    ].join('\n'),
    [
      groupRecord('shadow', 42),
      groupRecord('webex-generic-account-bot', 2101),
      groupRecord('webex-config-deploy', 2102),
      groupRecord('webex-config-pull', 2103),
      groupRecord('webex-codex-input', 2104),
      groupRecord('webex-codex-launch', 2105),
      '',
    ].join('\n'),
    {
      'webex-generic-account-bot': [2101],
      'webex-config-deploy': [2102],
    },
    expectedGshadowDatabase(),
    expectedShadowDatabase(),
  );
}

function expectedGroupDatabase(configPullMembers = []) {
  return [
    groupRecord('shadow', 42),
    groupRecord('webex-generic-account-bot', 2001),
    groupRecord('webex-config-deploy', 2002),
    groupRecord('webex-config-pull', 2003, configPullMembers),
    groupRecord('webex-codex-input', 2004),
    groupRecord('webex-codex-launch', 2005),
    '',
  ].join('\n');
}

function expectedGshadowDatabase() {
  return [
    'shadow:!::',
    'webex-generic-account-bot:!::',
    'webex-config-deploy:!::',
    'webex-config-pull:!::',
    'webex-codex-input:!::',
    'webex-codex-launch:!::',
    '',
  ].join('\n');
}

function expectedShadowDatabase() {
  return [
    shadowRecord('webex-generic-account-bot'),
    shadowRecord('webex-config-deploy'),
    '',
  ].join('\n');
}

function shadowRecord(name, password = '!') {
  return [name, password, '', '', '', '', '', '', ''].join(':');
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

function emptySystemdIdentityLookup(calls = []) {
  return async (command, args, allowedExitCodes) => {
    calls.push([command, [...args], [...allowedExitCodes]]);
    return { code: 2, stdout: '', stderr: '' };
  };
}

function systemIdentityFs({
  dynamicUserProvider = false,
  providerName = null,
  staticUserdbDirectory = '/etc/userdb',
  staticUserdbEntry = null,
  groupMode = 0o644,
  shadowMode = 0o640,
  gshadowMode = 0o640,
  mutateGroupIdentity = false,
} = {}) {
  const identityFiles = new Map([
    ['/etc/nsswitch.conf', {
      contents: Buffer.from([
        'passwd: files systemd',
        'group: files systemd',
        'shadow: files',
        'gshadow: files',
        '',
      ].join('\n')),
      gid: 0,
      mode: 0o644,
    }],
    ['/etc/passwd', {
      contents: Buffer.from([
        passwdRecord('webex-generic-account-bot', 1001, 2001),
        passwdRecord('webex-config-deploy', 1002, 2002),
        '',
      ].join('\n')),
      gid: 0,
      mode: 0o644,
    }],
    ['/etc/group', {
      contents: Buffer.from(expectedGroupDatabase()),
      gid: 0,
      mode: groupMode,
    }],
    ['/etc/shadow', {
      contents: Buffer.from(expectedShadowDatabase()),
      gid: 42,
      mode: shadowMode,
    }],
    ['/etc/gshadow', {
      contents: Buffer.from(expectedGshadowDatabase()),
      gid: 42,
      mode: gshadowMode,
    }],
  ]);
  const provider = providerName
    ?? (dynamicUserProvider ? 'io.systemd.DynamicUser' : null);
  const directoryEntries = new Map();
  if (provider) {
    directoryEntries.set('/run/systemd/userdb', [directoryEntry(provider, true)]);
  }
  if (staticUserdbEntry) {
    directoryEntries.set(staticUserdbDirectory, [directoryEntry(staticUserdbEntry, false)]);
  }
  const optionalDirectories = new Set([
    '/run/systemd/userdb',
    '/etc/userdb',
    '/run/userdb',
    '/run/host/userdb',
    '/usr/local/lib/userdb',
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
  const missing = () => Object.assign(new Error('missing'), { code: 'ENOENT' });

  return {
    async open(file) {
      const record = identityFiles.get(file);
      if (!record) throw missing();
      let statCalls = 0;
      return {
        stat: async () => {
          statCalls += 1;
          return Object.freeze({
            uid: 0,
            gid: record.gid,
            mode: 0o100000 | record.mode,
            nlink: 1,
            size: record.contents.length,
            dev: 1,
            ino: mutateGroupIdentity && file === '/etc/group' && statCalls > 1 ? 99 : 1,
            mtimeMs: 1,
            ctimeMs: 1,
            isFile: () => true,
            isSymbolicLink: () => false,
          });
        },
        readFile: async () => Buffer.from(record.contents),
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

function shortReadFileSystem(contents, maxChunkBytes) {
  const payload = Buffer.from(contents);
  return {
    async open(file, flags) {
      assert.equal(file, '/proc/self/mountinfo');
      assert.equal(
        flags,
        fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
      );
      let cursor = 0;
      return {
        stat: async () => ({ isFile: () => true }),
        async read(buffer, offset, length, position) {
          assert.equal(position, null);
          const bytesRead = Math.min(maxChunkBytes, length, payload.length - cursor);
          if (bytesRead > 0) {
            payload.copy(buffer, offset, cursor, cursor + bytesRead);
            cursor += bytesRead;
          }
          return { bytesRead, buffer };
        },
        close: async () => {},
      };
    },
  };
}

function boundedProcFileSystem(contentsByPath, namespaceIdentities = new Map([
  ['/proc/self/ns/user', { dev: 4, ino: 5 }],
  ['/proc/1/ns/user', { dev: 4, ino: 5 }],
])) {
  return {
    async open(file, flags) {
      const expectedFlags = namespaceIdentities.has(file)
        ? fsConstants.O_RDONLY
        : fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW;
      assert.equal(flags, expectedFlags);
      const payload = Buffer.from(contentsByPath.get(file) ?? '');
      let cursor = 0;
      return {
        stat: async () => ({
          isFile: () => true,
          ...(namespaceIdentities.get(file) ?? {}),
        }),
        async read(buffer, offset, length, position) {
          assert.equal(position, null);
          const bytesRead = Math.min(length, payload.length - cursor);
          if (bytesRead > 0) {
            payload.copy(buffer, offset, cursor, cursor + bytesRead);
            cursor += bytesRead;
          }
          return { bytesRead, buffer };
        },
        close: async () => {},
      };
    },
  };
}

function systemdUnitPathFs(
  entriesByDirectory = new Map(),
  {
    usrMerged = true,
    usrMergeTarget = 'usr/lib',
    filesByPath = new Map(),
    fileModesByPath = new Map(),
    directoryModesByPath = new Map(),
    missingPaths = new Set(),
    specialStatsByPath = new Map(),
    symlinksByPath = new Map(),
  } = {},
) {
  const directoryStat = (candidate) => Object.freeze({
    uid: 0,
    gid: 0,
    mode: 0o40000 | (directoryModesByPath.get(candidate) ?? 0o755),
    isFile: () => false,
    isDirectory: () => true,
    isSymbolicLink: () => false,
  });
  const usrMergeStat = Object.freeze({
    uid: 0,
    gid: 0,
    mode: 0o120777,
    nlink: 1,
    dev: 1,
    ino: 2,
    size: 7,
    mtimeMs: 1,
    ctimeMs: 1,
    isDirectory: () => false,
    isSymbolicLink: () => true,
  });
  const fileStat = (contents, mode = 0o644) => Object.freeze({
    uid: 0,
    gid: 0,
    mode: 0o100000 | mode,
    nlink: 1,
    dev: 1,
    ino: 3,
    size: contents.length,
    mtimeMs: 1,
    ctimeMs: 1,
    isFile: () => true,
    isDirectory: () => false,
    isSymbolicLink: () => false,
  });
  const symlinkStat = Object.freeze({
    uid: 0,
    gid: 0,
    mode: 0o120777,
    nlink: 1,
    dev: 1,
    ino: 4,
    size: 1,
    mtimeMs: 1,
    ctimeMs: 1,
    isFile: () => false,
    isDirectory: () => false,
    isSymbolicLink: () => true,
  });
  return {
    lstat: async (candidate) => {
      if (usrMerged && candidate === '/lib') return usrMergeStat;
      if (missingPaths.has(candidate)) {
        throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      }
      if (specialStatsByPath.has(candidate)) return specialStatsByPath.get(candidate);
      if (filesByPath.has(candidate)) {
        return fileStat(filesByPath.get(candidate), fileModesByPath.get(candidate));
      }
      if (symlinksByPath.has(candidate)) return symlinkStat;
      return directoryStat(candidate);
    },
    readlink: async (candidate) => {
      if (symlinksByPath.has(candidate)) return symlinksByPath.get(candidate);
      assert.equal(candidate, '/lib');
      return usrMergeTarget;
    },
    opendir: async (directory) => asyncDirectory(entriesByDirectory.get(directory) ?? []),
    open: async (candidate) => {
      const contents = filesByPath.get(candidate);
      if (!contents) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      return {
        stat: async () => fileStat(contents, fileModesByPath.get(candidate)),
        readFile: async () => Buffer.from(contents),
        close: async () => {},
      };
    },
  };
}

const LAUNCHER_INSTANCE_PATTERN_FOR_TEST = /^webex-codex-launcher@[^@/\s]+\.service$/;

function systemdUnitMetadata(
  loadState,
  fragmentPath = '',
  unitFileState = loadState === 'not-found' ? '' : 'disabled',
) {
  return [
    'Job=',
    `LoadState=${loadState}`,
    `UnitFileState=${unitFileState}`,
    `FragmentPath=${fragmentPath}`,
    'DropInPaths=',
    'NeedDaemonReload=no',
    'RequiredBy=',
    'WantedBy=',
    'UpheldBy=',
    'BoundBy=',
    'TriggeredBy=',
    'OnFailureOf=',
    'OnSuccessOf=',
    '',
  ].join('\n');
}

function unitStates(state, plan = null) {
  return new Map(MANAGED_UNITS.map((unit) => [unit, {
    ...state,
    fragment: state.fragment ?? (
      state.load === 'loaded' && plan
        ? plan.units.find((candidate) => path.basename(candidate) === unit)
        : ''
    ),
    dropIns: state.dropIns ?? '',
    needDaemonReload: state.needDaemonReload ?? false,
    reverseActivators: state.reverseActivators ?? [],
  }]));
}
