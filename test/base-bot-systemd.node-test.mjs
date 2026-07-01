import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const SYSTEMD_ROOT = fileURLToPath(new URL('../deploy/systemd/', import.meta.url));
const SERVICE_PATH = path.join(SYSTEMD_ROOT, 'webex-generic-account-bot.service');
const SYSUSERS_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-generic-account-bot.sysusers.conf',
);
const TMPFILES_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-generic-account-bot.tmpfiles.conf',
);
const CONFIG_PULL_TMPFILES_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-config-pull-worker.tmpfiles.conf',
);
const CONFIG_PULL_SERVICE_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-config-pull-worker.service',
);
const CONFIG_PULL_SYSUSERS_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-config-pull-worker.sysusers.conf',
);

describe('base bot systemd contract', () => {
  it('passes the real systemd unit parser in an isolated root', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-base-unit-verify-'));
    const unitDirectory = path.join(root, 'etc', 'systemd', 'system');
    const binaryDirectory = path.join(root, 'opt', 'webex-generic-account-bot', 'bin');
    const systemBinaryDirectory = path.join(root, 'usr', 'bin');
    try {
      await fs.mkdir(unitDirectory, { recursive: true });
      await fs.mkdir(binaryDirectory, { recursive: true });
      await fs.mkdir(systemBinaryDirectory, { recursive: true });
      await Promise.all([
        fs.copyFile(SERVICE_PATH, path.join(unitDirectory, path.basename(SERVICE_PATH))),
        fs.copyFile(
          CONFIG_PULL_SERVICE_PATH,
          path.join(unitDirectory, path.basename(CONFIG_PULL_SERVICE_PATH)),
        ),
      ]);
      const placeholderBinary = path.join(binaryDirectory, 'webex-generic-account-bot');
      const placeholderNode = path.join(systemBinaryDirectory, 'node');
      await Promise.all([
        fs.copyFile('/usr/bin/true', placeholderBinary),
        fs.copyFile('/usr/bin/true', placeholderNode),
      ]);
      await Promise.all([
        fs.chmod(placeholderBinary, 0o755),
        fs.chmod(placeholderNode, 0o755),
      ]);

      const { stderr } = await execFileAsync('/usr/bin/systemd-analyze', [
        'verify',
        '--recursive-errors=no',
        `--root=${root}`,
        '--man=no',
        path.basename(SERVICE_PATH),
        path.basename(CONFIG_PULL_SERVICE_PATH),
      ]);
      assert.equal(stderr, '');
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('uses a stable non-login identity without privileged group membership', async () => {
    const sysusers = await fs.readFile(SYSUSERS_PATH, 'utf8');

    assert.equal(
      sysusers,
      'u webex-generic-account-bot - "Webex generic account bot" /var/lib/webex-generic-account-bot /usr/sbin/nologin\n',
    );
    assert.doesNotMatch(sysusers, /^m /m);
    assert.doesNotMatch(
      sysusers,
      /webex-codex-(?:launch|input)|webex-config-(?:pull|deploy)/,
    );
  });

  it('passes the real sysusers and tmpfiles parsers without host mutation', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-base-layout-verify-'));
    const sysusersDirectory = path.join(root, 'etc', 'sysusers.d');
    const tmpfilesDirectory = path.join(root, 'etc', 'tmpfiles.d');
    try {
      await fs.mkdir(sysusersDirectory, { recursive: true });
      await fs.mkdir(tmpfilesDirectory, { recursive: true });
      const sysusersTarget = path.join(sysusersDirectory, 'webex-generic-account-bot.conf');
      const workerSysusersTarget = path.join(
        sysusersDirectory,
        'webex-config-pull-worker.conf',
      );
      await fs.copyFile(SYSUSERS_PATH, sysusersTarget);
      await fs.copyFile(CONFIG_PULL_SYSUSERS_PATH, workerSysusersTarget);
      await execFileAsync('/usr/bin/systemd-sysusers', [
        '--dry-run',
        `--root=${root}`,
        sysusersTarget,
        workerSysusersTarget,
      ]);

      const tmpfiles = await fs.readFile(TMPFILES_PATH, 'utf8');
      const parserFixture = tmpfiles
        .split('\n')
        .map((line) => {
          if (!line) return line;
          const fields = line.split(/\s+/);
          fields[3] = '-';
          fields[4] = '-';
          return fields.join(' ');
        })
        .join('\n');
      const tmpfilesTarget = path.join(tmpfilesDirectory, 'webex-generic-account-bot.conf');
      await fs.writeFile(tmpfilesTarget, parserFixture, { mode: 0o644 });
      await execFileAsync('/usr/bin/systemd-tmpfiles', [
        '--create',
        `--root=${root}`,
        tmpfilesTarget,
      ]);

      const expectedModes = new Map([
        ['/etc/webex-generic-account-bot', 0o750],
        ['/var/lib/webex-headless-access', 0o750],
        ['/var/lib/webex-generic-account-bot', 0o755],
        ['/var/lib/webex-generic-account-bot/rendered', 0o755],
        ['/var/lib/webex-generic-account-bot/state', 0o700],
        ['/var/lib/webex-generic-account-bot/codex-home', 0o700],
        ['/var/lib/webex-generic-account-bot/codex-workspace', 0o700],
        ['/var/lib/webex-generic-account-bot/deploy', 0o750],
        ['/var/lib/webex-generic-account-bot/config-checkout', 0o700],
      ]);
      for (const [entry, expectedMode] of expectedModes) {
        const stat = await fs.lstat(path.join(root, entry));
        assert.equal(stat.isDirectory(), true, entry);
        assert.equal(stat.mode & 0o777, expectedMode, entry);
      }
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('applies the exact production ownership when passwordless sudo is available', async (context) => {
    try {
      await execFileAsync('/usr/bin/sudo', ['-n', '/usr/bin/true']);
    } catch {
      context.skip('passwordless sudo is unavailable');
      return;
    }

    const root = await fs.mkdtemp(
      path.join(os.tmpdir(), 'webex-base-layout-root-verify-'),
    );
    const sysusersDirectory = path.join(root, 'etc', 'sysusers.d');
    const tmpfilesDirectory = path.join(root, 'etc', 'tmpfiles.d');
    try {
      await fs.mkdir(sysusersDirectory, { recursive: true });
      await fs.mkdir(tmpfilesDirectory, { recursive: true });
      const sysusersTarget = path.join(
        sysusersDirectory,
        'webex-generic-account-bot.conf',
      );
      const workerSysusersTarget = path.join(
        sysusersDirectory,
        'webex-config-pull-worker.conf',
      );
      const tmpfilesTarget = path.join(
        tmpfilesDirectory,
        'webex-generic-account-bot.conf',
      );
      await Promise.all([
        fs.copyFile(SYSUSERS_PATH, sysusersTarget),
        fs.copyFile(CONFIG_PULL_SYSUSERS_PATH, workerSysusersTarget),
        fs.copyFile(TMPFILES_PATH, tmpfilesTarget),
      ]);

      await execFileAsync('/usr/bin/sudo', [
        '-n',
        '/usr/bin/chown',
        '0:0',
        root,
      ]);
      await execFileAsync('/usr/bin/sudo', [
        '-n',
        '/usr/bin/chmod',
        '0755',
        root,
      ]);

      await execFileAsync('/usr/bin/sudo', [
        '-n',
        '/usr/bin/systemd-sysusers',
        `--root=${root}`,
        sysusersTarget,
        workerSysusersTarget,
      ]);
      await execFileAsync('/usr/bin/sudo', [
        '-n',
        '/usr/bin/systemd-tmpfiles',
        '--create',
        `--root=${root}`,
        tmpfilesTarget,
      ]);

      const [passwd, group] = await Promise.all([
        fs.readFile(path.join(root, 'etc', 'passwd'), 'utf8'),
        fs.readFile(path.join(root, 'etc', 'group'), 'utf8'),
      ]);
      const botUid = accountId(passwd, 'webex-generic-account-bot');
      const botGid = accountId(group, 'webex-generic-account-bot');
      accountId(passwd, 'webex-config-deploy');
      const deployGid = accountId(group, 'webex-config-deploy');
      accountId(group, 'webex-config-pull');
      const expectedLayout = [
        ['/etc/webex-generic-account-bot', 0, botGid, 0o750],
        ['/var/lib/webex-headless-access', 0, botGid, 0o750],
        ['/var/lib/webex-generic-account-bot', 0, 0, 0o755],
        ['/var/lib/webex-generic-account-bot/rendered', 0, 0, 0o755],
        ['/var/lib/webex-generic-account-bot/state', botUid, botGid, 0o700],
        ['/var/lib/webex-generic-account-bot/codex-home', botUid, botGid, 0o700],
        ['/var/lib/webex-generic-account-bot/codex-workspace', botUid, botGid, 0o700],
        [
          '/var/lib/webex-generic-account-bot/deploy',
          0,
          deployGid,
          0o750,
        ],
        ['/var/lib/webex-generic-account-bot/config-checkout', 0, 0, 0o700],
      ];
      for (const [entry, expectedUid, expectedGid, expectedMode] of expectedLayout) {
        const stat = await fs.lstat(path.join(root, entry));
        assert.equal(stat.isDirectory(), true, entry);
        assert.equal(stat.uid, expectedUid, `${entry} uid`);
        assert.equal(stat.gid, expectedGid, `${entry} gid`);
        assert.equal(stat.mode & 0o777, expectedMode, `${entry} mode`);
      }
    } finally {
      await execFileAsync('/usr/bin/sudo', [
        '-n',
        '/usr/bin/chown',
        '-R',
        `${process.getuid()}:${process.getgid()}`,
        root,
      ]);
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('separates root-managed inputs from bot-owned mutable state', async () => {
    const [tmpfiles, workerTmpfiles, workerSysusers] = await Promise.all([
      fs.readFile(TMPFILES_PATH, 'utf8'),
      fs.readFile(CONFIG_PULL_TMPFILES_PATH, 'utf8'),
      fs.readFile(CONFIG_PULL_SYSUSERS_PATH, 'utf8'),
    ]);

    assert.equal(
      tmpfiles,
      [
        'd /etc/webex-generic-account-bot 0750 root webex-generic-account-bot -',
        'd /var/lib/webex-headless-access 0750 root webex-generic-account-bot -',
        'd /var/lib/webex-generic-account-bot 0755 root root -',
        'd /var/lib/webex-generic-account-bot/rendered 0755 root root -',
        'd /var/lib/webex-generic-account-bot/state 0700 webex-generic-account-bot webex-generic-account-bot -',
        'd /var/lib/webex-generic-account-bot/codex-home 0700 webex-generic-account-bot webex-generic-account-bot -',
        'd /var/lib/webex-generic-account-bot/codex-workspace 0700 webex-generic-account-bot webex-generic-account-bot -',
        'd /var/lib/webex-generic-account-bot/deploy 0750 root webex-config-deploy -',
        'd /var/lib/webex-generic-account-bot/config-checkout 0700 root root -',
        '',
      ].join('\n'),
    );
    assert.doesNotMatch(tmpfiles, /access-token|bot\.env|jenkins\.env/);
    assert.doesNotMatch(tmpfiles, /codex-input-staging|webex-codex-runtime-inputs/);
    assert.match(
      workerTmpfiles,
      /^d \/var\/lib\/webex-generic-account-bot 0755 root root -$/m,
    );
    assert.match(
      workerSysusers,
      /^u webex-config-deploy - "Webex config deployment worker" \/nonexistent \/usr\/sbin\/nologin$/m,
    );
    assert.match(workerSysusers, /^g webex-config-deploy -$/m);
    assert.match(workerSysusers, /^g webex-config-pull -$/m);
    assert.doesNotMatch(workerSysusers, /^m /m);
    assert.match(
      tmpfiles,
      /^d \/var\/lib\/webex-generic-account-bot\/deploy 0750 root webex-config-deploy -$/m,
    );
  });

  it('starts only the fixed bot binary with fixed root-managed inputs', async () => {
    const service = await fs.readFile(SERVICE_PATH, 'utf8');

    assert.deepEqual(directiveValues(service, 'Wants'), ['network-online.target']);
    assert.deepEqual(directiveValues(service, 'After'), [
      'network-online.target systemd-tmpfiles-setup.service',
    ]);
    assert.deepEqual(directiveValues(service, 'ConditionPathExists'), [
      '/sys/fs/cgroup/cgroup.controllers',
    ]);
    assert.deepEqual(directiveValues(service, 'ConditionFileIsExecutable'), [
      '/opt/webex-generic-account-bot/bin/webex-generic-account-bot',
    ]);
    assert.deepEqual(directiveValues(service, 'ConditionFileNotEmpty'), [
      '/var/lib/webex-generic-account-bot/rendered/production.toml',
      '/var/lib/webex-headless-access/access-token',
    ]);
    assert.deepEqual(directiveValues(service, 'User'), ['webex-generic-account-bot']);
    assert.deepEqual(directiveValues(service, 'Group'), ['webex-generic-account-bot']);
    assert.deepEqual(directiveValues(service, 'WorkingDirectory'), [
      '/var/lib/webex-generic-account-bot/codex-workspace',
    ]);
    assert.deepEqual(directiveValues(service, 'Environment'), [
      'PATH=/usr/local/bin:/usr/bin',
    ]);
    assert.deepEqual(directiveValues(service, 'EnvironmentFile'), [
      '/etc/webex-generic-account-bot/bot.env',
    ]);
    assert.deepEqual(directiveValues(service, 'ExecStart'), [
      '/opt/webex-generic-account-bot/bin/webex-generic-account-bot --config /var/lib/webex-generic-account-bot/rendered/production.toml',
    ]);
    assert.deepEqual(directiveValues(service, 'SupplementaryGroups'), ['']);
    assert.deepEqual(directiveValues(service, 'WantedBy'), ['multi-user.target']);
    assert.doesNotMatch(service, /^ExecStart=.*(?:\/bin\/(?:ba)?sh|[%$])/m);
    assert.doesNotMatch(
      service,
      /webex-codex-(?:launch|input)|webex-config-(?:pull|deploy)/,
    );
  });

  it('keeps the writable surface narrow and the service fail closed', async () => {
    const service = await fs.readFile(SERVICE_PATH, 'utf8');

    assert.deepEqual(directiveValues(service, 'ReadOnlyPaths'), [
      '/proc',
      '/run/systemd',
      '/var/lib/webex-generic-account-bot/rendered',
      '/var/lib/webex-headless-access',
      '/etc/webex-generic-account-bot',
    ]);
    assert.deepEqual(directiveValues(service, 'ReadWritePaths'), [
      '/var/lib/webex-generic-account-bot/state',
      '/var/lib/webex-generic-account-bot/codex-home',
      '/var/lib/webex-generic-account-bot/codex-workspace',
    ]);
    for (const directive of [
      'RuntimeDirectory',
      'StateDirectory',
      'CacheDirectory',
      'LogsDirectory',
      'ConfigurationDirectory',
    ]) {
      assert.deepEqual(directiveValues(service, directive), [], directive);
    }
    const requiredHardening = {
      NoNewPrivileges: 'true',
      ProtectSystem: 'strict',
      ProtectHome: 'true',
      PrivateTmp: 'true',
      PrivateDevices: 'true',
      PrivateIPC: 'true',
      RemoveIPC: 'true',
      PrivateNetwork: 'false',
      ProtectClock: 'true',
      ProtectControlGroups: 'true',
      ProtectHostname: 'true',
      ProtectKernelLogs: 'true',
      ProtectKernelModules: 'true',
      ProtectKernelTunables: 'true',
      ProtectProc: 'invisible',
      ProcSubset: 'all',
      RestrictAddressFamilies: 'AF_UNIX AF_INET AF_INET6',
      RestrictNamespaces: 'true',
      RestrictRealtime: 'true',
      RestrictSUIDSGID: 'true',
      LockPersonality: 'true',
      MemoryDenyWriteExecute: 'false',
      CapabilityBoundingSet: '',
      AmbientCapabilities: '',
      SystemCallArchitectures: 'native',
      KeyringMode: 'private',
    };
    for (const [directive, value] of Object.entries(requiredHardening)) {
      assert.deepEqual(directiveValues(service, directive), [value], directive);
    }
  });

  it('bounds lifecycle and resource usage without hiding network readiness', async () => {
    const service = await fs.readFile(SERVICE_PATH, 'utf8');

    assert.deepEqual(directiveValues(service, 'Restart'), ['on-failure']);
    assert.deepEqual(directiveValues(service, 'RestartSec'), ['5s']);
    assert.deepEqual(directiveValues(service, 'TimeoutStartSec'), ['60s']);
    assert.deepEqual(directiveValues(service, 'TimeoutStopSec'), ['120s']);
    assert.deepEqual(directiveValues(service, 'KillMode'), ['control-group']);
    assert.deepEqual(directiveValues(service, 'OOMPolicy'), ['kill']);
    assert.deepEqual(directiveValues(service, 'UMask'), ['0077']);
    assert.deepEqual(directiveValues(service, 'StandardInput'), ['null']);
    assert.deepEqual(directiveValues(service, 'StandardOutput'), ['journal']);
    assert.deepEqual(directiveValues(service, 'StandardError'), ['journal']);
    assert.deepEqual(directiveValues(service, 'TasksMax'), ['256']);
    assert.deepEqual(directiveValues(service, 'CPUQuota'), ['200%']);
    assert.deepEqual(directiveValues(service, 'LimitNOFILE'), ['1024']);
    assert.deepEqual(directiveValues(service, 'LimitNPROC'), ['256']);
    assert.deepEqual(directiveValues(service, 'LimitFSIZE'), ['2304M']);
    assert.deepEqual(directiveValues(service, 'LimitCORE'), ['0']);
    assert.deepEqual(directiveValues(service, 'MemoryMax'), ['2G']);
    assert.deepEqual(directiveValues(service, 'MemorySwapMax'), ['0']);
    assert.deepEqual(directiveValues(service, 'IPAddressDeny'), []);
    assert.deepEqual(directiveValues(service, 'IPAddressAllow'), []);
  });
});

function directiveValues(unit, directive) {
  const prefix = `${directive}=`;
  return unit
    .split('\n')
    .filter((line) => line.startsWith(prefix))
    .map((line) => line.slice(prefix.length));
}

function accountId(database, name) {
  const fields = database
    .split('\n')
    .find((line) => line.startsWith(`${name}:`))
    ?.split(':');
  assert.ok(fields, `missing account ${name}`);
  const id = Number(fields[2]);
  assert.equal(Number.isSafeInteger(id), true, `${name} id`);
  return id;
}
