import assert from 'node:assert/strict';
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
  buildLockedApplyCommand,
  buildProvisionPlan,
  ensureProvisionLockFile,
  executeLockedApply,
  hasProvisionLock,
  parseArgs,
  parseIdentityDatabases,
  provisionHost,
  readSystemIdentitySnapshot,
  readSystemBootPolicyCatalogs,
  readSystemUnitStates,
  runCli,
  validateIdentityPolicy,
  validateNsswitchPolicy,
  validateProvisionLockMetadata,
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
        '/run/webex-config-deploy/deploy-config.lock',
        '/trusted/node',
        '/trusted/provision-host.mjs',
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

    await ensureProvisionLockFile(fsApi);
    assert.deepEqual(state, {
      parentGid: 2003,
      parentMode: 0o750,
      lockGid: 2003,
      lockMode: 0o660,
    });
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

  it('rejects unmanaged boot policy that can cross the Webex boundary', async (context) => {
    for (const [kind, policy] of [
      ['sysusers', 'm webex-generic-account-bot sudo'],
      ['sysusers', 'm \\x77ebex-generic-account-bot sudo'],
      ['sysusers', 'u external /var/lib/webex-generic-account-bot/state -'],
      ['sysusers', 'r - 61184-65519'],
      ['tmpfiles', 'd /run/webex-codex-canary 0777 root root -'],
      ['tmpfiles', 'd /run/\\x77ebex-config-deploy 0777 root root -'],
      ['tmpfiles', 'R /run/* - - - -'],
      ['tmpfiles', 'R /run/ - - - -'],
      ['tmpfiles', 'R /var/run/ - - - -'],
      ['tmpfiles', 'R /var/r?n/systemd/system/* - - - -'],
      ['tmpfiles', 'L /var/run - - - - ../run/child/..'],
      ['tmpfiles', 'Z /var/lib 0777 root root -'],
      ['tmpfiles', 'R /run/%H - - - -'],
      ['tmpfiles', 'd %t/\\x77ebex-config-deploy 0777 root root -'],
      ['tmpfiles', 'f /tmp/untrusted 0600 :webex-config-deploy root -'],
      ['tmpfiles', 'f /tmp/untrusted 0600 1001 root -'],
      ['tmpfiles', 'f /tmp/untrusted 0600 root :02001 -'],
      ['tmpfiles', 'f+! /etc/shadow 0600 root root - replacement'],
      ['tmpfiles', 'f+ /etc/userdb/1002.user 0600 root root - {}'],
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

    await assert.rejects(
      readSystemBootPolicyCatalogs(
        async (command) => {
          if (command.endsWith('systemd-creds')) {
            return { stdout: 'sysusers.extra insecure 42B\n', stderr: '', code: 0 };
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
      /system credential can inject boot policy: sysusers\.extra/,
    );

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
          new Map([['/etc/credstore', [directoryEntry('tmpfiles.extra', false)]]]),
          { filesByPath: sourceFiles },
        ),
      ),
      /credential store can inject boot policy: \/etc\/credstore\/tmpfiles\.extra/,
    );
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
      `.${path.basename(artifact.target)}.provision-00000000-0000-4000-8000-000000000099.tmp`,
    );
    await fs.mkdir(path.dirname(candidate), { recursive: true, mode: 0o755 });
    await fs.writeFile(candidate, 'interrupted candidate\n', { mode: 0o600 });
    await fs.chmod(candidate, 0o600);
    const umaskCandidate = path.join(
      path.dirname(artifact.target),
      `.${path.basename(artifact.target)}.provision-00000000-0000-4000-8000-000000000098.tmp`,
    );
    await fs.writeFile(umaskCandidate, 'interrupted before chmod\n', { mode: 0o600 });
    await fs.chmod(umaskCandidate, 0o000);

    await provisionHost({ apply: false }, fixture.dependencies());
    assert.equal(await fs.readFile(candidate, 'utf8'), 'interrupted candidate\n');
    assert.equal((await fs.stat(umaskCandidate)).mode & 0o777, 0o000);

    await provisionHost(
      { apply: true },
      fixture.dependencies({ applied: true }),
    );
    await assert.rejects(fs.stat(candidate), { code: 'ENOENT' });
    await assert.rejects(fs.stat(umaskCandidate), { code: 'ENOENT' });
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

  it('validates every stale candidate before deleting any candidate', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts[0];
    const directory = path.dirname(artifact.target);
    const prefix = `.${path.basename(artifact.target)}.provision-`;
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
    assert.equal(lockConvergenceChecks, 1);
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

  it('rejects untrusted sources before creating target directories', async (context) => {
    const fixture = await provisionFixture(context);
    const artifact = fixture.plan.artifacts[0];
    const candidate = path.join(
      path.dirname(artifact.target),
      `.${path.basename(artifact.target)}.provision-00000000-0000-4000-8000-000000000099.tmp`,
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
      if (args[0] === 'is-enabled') {
        return {
          stdout: unit === 'webex-codex-launcher@boot.service' ? 'enabled\n' : 'static\n',
          stderr: '',
          code: 0,
        };
      }
      const fragmentUnit = LAUNCHER_INSTANCE_PATTERN_FOR_TEST.test(unit)
        ? 'webex-codex-launcher@.service'
        : unit;
      return {
        stdout: [
          'LoadState=loaded',
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

    const sysusersDropInDirectory =
      '/etc/systemd/system/systemd-sysusers.service.d';
    const sysusersDropIn = path.join(sysusersDropInDirectory, '50-extra-policy.conf');
    for (const policy of [
      'LoadCredential=sysusers.extra:/root/policy',
      'ImportCredential=payload:sysusers.extra',
      'ImportCredential=payload.*:sysusers.',
      'ImportCredential=payload.*:tmpfiles.',
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
                name: 'systemd-sysusers.service.d',
                isFile: () => false,
                isDirectory: () => true,
                isSymbolicLink: () => false,
              }]],
              [sysusersDropInDirectory, [{ name: '50-extra-policy.conf' }]],
            ]),
            {
              filesByPath: new Map([[
                sysusersDropIn,
                Buffer.from(`[Service]\n${policy}\n`),
              ]]),
            },
          ),
        ),
        /external systemd policy injects a boot policy credential/,
      );
    }

    let vendorImportCommandCalls = 0;
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
              { name: 'systemd-tmpfiles-setup.service' },
              { name: 'systemd-pcrfs@.service' },
              { name: 'user@.service' },
            ]],
          ]),
          {
            filesByPath: new Map([
              [
                '/usr/lib/systemd/system/systemd-sysusers.service',
                Buffer.from('[Service]\nImportCredential=sysusers.*\n'),
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
            ]),
          },
        ),
      ),
      /systemctl reached after vendor credential import audit/,
    );
    assert.equal(vendorImportCommandCalls, 2);

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
        /external systemd policy injects a boot policy credential/,
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
      /external systemd policy injects a boot policy credential/,
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
        new RegExp(`unexpected managed unit policy.*${policyName.replaceAll('.', '\\.')}`),
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

      await assert.rejects(
        provisionHost(
          { apply: true },
          fixture.dependencies({
            applied: true,
            unitStateSequence: [before, after],
          }),
        ),
        expected,
        label,
      );
    }
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
      `.${path.basename(artifact.target)}.provision-`,
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

  it('does not reload systemd until the held lock metadata has converged', async (context) => {
    const fixture = await provisionFixture(context);
    const commands = [];
    await assert.rejects(
      provisionHost(
        { apply: true },
        fixture.dependencies({
          commands,
          applied: true,
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
    assert.equal((await fs.stat(fixture.plan.transactionFile)).mode & 0o777, 0o600);
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
      verifyProvisionLockConverged = async () => {},
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
      let uuid = 0;
      const bootPolicies = bootPolicySequence ?? [bootPolicyCatalogs];
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
        readUnitStates: async () => stateSequence[
          Math.min(stateIndex++, stateSequence.length - 1)
        ],
        verifyProvisionLockConverged,
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
      mode: 0o640,
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

function systemdUnitPathFs(
  entriesByDirectory = new Map(),
  {
    usrMerged = false,
    usrMergeTarget = 'usr/lib',
    filesByPath = new Map(),
    fileModesByPath = new Map(),
    missingPaths = new Set(),
    symlinksByPath = new Map(),
  } = {},
) {
  const directoryStat = Object.freeze({
    uid: 0,
    gid: 0,
    mode: 0o40755,
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
      if (filesByPath.has(candidate)) {
        return fileStat(filesByPath.get(candidate), fileModesByPath.get(candidate));
      }
      if (symlinksByPath.has(candidate)) return symlinkStat;
      return directoryStat;
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
