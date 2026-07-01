import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const SYSTEMD_ROOT = fileURLToPath(new URL('../deploy/systemd/', import.meta.url));
const SOCKET_PATH = path.join(SYSTEMD_ROOT, 'webex-codex-launcher.socket');
const SERVICE_PATH = path.join(SYSTEMD_ROOT, 'webex-codex-launcher@.service');
const BOT_DROP_IN_ROOT = path.join(
  SYSTEMD_ROOT,
  'webex-generic-account-bot.service.d',
);
const BOT_DROP_IN_PATH = path.join(BOT_DROP_IN_ROOT, '10-codex-launcher.conf');
const SYSUSERS_PATH = path.join(SYSTEMD_ROOT, 'webex-codex-launcher.sysusers.conf');
const CONFIG_PULL_SYSUSERS_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-config-pull-worker.sysusers.conf',
);
const TMPFILES_PATH = path.join(SYSTEMD_ROOT, 'webex-codex-launcher.tmpfiles.conf');
const ACTIVATION_TMPFILES_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-codex-activation.tmpfiles.conf',
);
const ACTIVATION_RENEW_SERVICE_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-codex-activation-renew.service',
);
const INPUT_STAGING_TMPFILES_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-codex-input-staging.tmpfiles.conf',
);
const RUNTIME_SYSUSERS_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-codex-runtime.sysusers.conf',
);
const RUNTIME_TMPFILES_PATH = path.join(
  SYSTEMD_ROOT,
  'webex-codex-runtime.tmpfiles.conf',
);
const LAUNCHER_SOURCE_PATH = fileURLToPath(
  new URL('../src/bin/webex-codex-launcher.rs', import.meta.url),
);
const LAUNCHER_MODULE_PATH = fileURLToPath(
  new URL('../src/codex_launcher.rs', import.meta.url),
);
const ISOLATED_EXECUTION_PATH = fileURLToPath(
  new URL('../src/isolated_execution.rs', import.meta.url),
);
const INPUT_SEALER_PATH = fileURLToPath(
  new URL('../src/input_sealer.rs', import.meta.url),
);
const RUNNER_INPUT_PATH = fileURLToPath(
  new URL('../src/runner_input.rs', import.meta.url),
);
const WORK_BUDGET_PATH = fileURLToPath(
  new URL('../src/work_budget.rs', import.meta.url),
);
const RUNTIME_SOURCE_PATH = fileURLToPath(
  new URL('../src/bin/webex-codex-runtime.rs', import.meta.url),
);
const LAUNCHER_PROTOCOL_PATH = fileURLToPath(
  new URL('../src/launcher_protocol.rs', import.meta.url),
);
const CARGO_TOML_PATH = fileURLToPath(new URL('../Cargo.toml', import.meta.url));

describe('Codex launcher systemd boundary', () => {
  it('keeps the bot as the default Cargo run target', async () => {
    const cargoToml = await fs.readFile(CARGO_TOML_PATH, 'utf8');

    assert.match(cargoToml, /^default-run = "webex-generic-account-bot"$/m);
  });

  it('provisions only a root-owned group-gated accepted socket', async () => {
    const [socket, sysusers, tmpfiles, protocol] = await Promise.all([
      fs.readFile(SOCKET_PATH, 'utf8'),
      fs.readFile(SYSUSERS_PATH, 'utf8'),
      fs.readFile(TMPFILES_PATH, 'utf8'),
      fs.readFile(LAUNCHER_PROTOCOL_PATH, 'utf8'),
    ]);

    assert.deepEqual(directiveValues(socket, 'ListenSequentialPacket'), [
      '/run/webex-codex-launcher/launcher.sock',
    ]);
    assert.deepEqual(directiveValues(socket, 'ListenStream'), []);
    assert.deepEqual(directiveValues(socket, 'Accept'), ['yes']);
    assert.deepEqual(directiveValues(socket, 'PassCredentials'), ['yes']);
    assert.deepEqual(directiveValues(socket, 'SocketUser'), ['root']);
    assert.deepEqual(directiveValues(socket, 'SocketGroup'), ['webex-codex-launch']);
    assert.deepEqual(directiveValues(socket, 'SocketMode'), ['0660']);
    assert.deepEqual(directiveValues(socket, 'DirectoryMode'), ['0750']);
    assert.deepEqual(directiveValues(socket, 'RemoveOnStop'), ['yes']);
    assert.deepEqual(directiveValues(socket, 'TriggerLimitIntervalSec'), ['10s']);
    const triggerBurst = protocol.match(
      /pub const LAUNCHER_TRIGGER_LIMIT_BURST: usize = ([\d_]+);/,
    );
    assert.ok(triggerBurst);
    const triggerBurstValue = triggerBurst[1].replaceAll('_', '');
    assert.deepEqual(directiveValues(socket, 'TriggerLimitBurst'), [triggerBurstValue]);
    assert.deepEqual(directiveValues(socket, 'PollLimitIntervalSec'), ['2s']);
    assert.deepEqual(directiveValues(socket, 'PollLimitBurst'), [triggerBurstValue]);
    assert.deepEqual(directiveValues(socket, 'Backlog'), ['16']);
    assert.deepEqual(directiveValues(socket, 'MaxConnections'), ['4']);
    assert.match(protocol, /pub const LAUNCHER_MAX_CONNECTIONS: usize = 4;/);
    assert.deepEqual(directiveValues(socket, 'ReceiveBuffer'), ['1M']);
    assert.deepEqual(directiveValues(socket, 'SendBuffer'), ['2M']);
    assert.deepEqual(directiveValues(socket, 'ConditionPathExists'), [
      '/sys/fs/cgroup/cgroup.controllers',
    ]);
    assert.deepEqual(directiveValues(socket, 'WantedBy'), ['sockets.target']);

    assert.equal(sysusers, 'g webex-codex-launch -\n');
    assert.doesNotMatch(sysusers, /^m /m);
    assert.equal(
      tmpfiles,
      'd /run/webex-codex-launcher 0750 root webex-codex-launch -\n',
    );
  });

  it('pairs the accepted socket with a fixed root-owned launcher process', async () => {
    const [socket, service, protocol] = await Promise.all([
      fs.readFile(SOCKET_PATH, 'utf8'),
      fs.readFile(SERVICE_PATH, 'utf8'),
      fs.readFile(LAUNCHER_PROTOCOL_PATH, 'utf8'),
    ]);

    assert.equal(path.basename(SOCKET_PATH), 'webex-codex-launcher.socket');
    assert.equal(path.basename(SERVICE_PATH), 'webex-codex-launcher@.service');
    assert.deepEqual(directiveValues(socket, 'Accept'), ['yes']);
    assert.deepEqual(directiveValues(socket, 'Service'), []);
    assert.deepEqual(directiveValues(service, 'Requires'), ['webex-codex-launcher.socket']);
    assert.deepEqual(directiveValues(service, 'After'), ['webex-codex-launcher.socket']);
    assert.deepEqual(directiveValues(service, 'ConditionPathExists'), [
      '/sys/fs/cgroup/cgroup.controllers',
    ]);
    assert.deepEqual(directiveValues(service, 'CollectMode'), ['inactive-or-failed']);
    assert.deepEqual(directiveValues(service, 'User'), ['root']);
    assert.deepEqual(directiveValues(service, 'Group'), ['root']);
    assert.deepEqual(directiveValues(service, 'Slice'), ['system.slice']);
    assert.deepEqual(directiveValues(service, 'SupplementaryGroups'), [
      'webex-codex-input webex-codex-launch',
    ]);
    assert.deepEqual(directiveValues(service, 'LoadCredential'), [
      'activation-boot-id:/proc/sys/kernel/random/boot_id',
    ]);
    assert.deepEqual(directiveValues(service, 'ExecStart'), [
      '/opt/webex-generic-account-bot/bin/webex-codex-launcher',
    ]);
    assert.deepEqual(directiveValues(service, 'StandardInput'), ['socket']);
    assert.deepEqual(directiveValues(service, 'StandardOutput'), ['socket']);
    assert.deepEqual(directiveValues(service, 'StandardError'), ['journal']);
    assert.deepEqual(directiveValues(service, 'TimeoutStartSec'), ['15s']);
    assert.deepEqual(directiveValues(service, 'TimeoutStopSec'), ['15s']);
    const runtimeMaximum = protocol.match(
      /pub const LAUNCHER_SERVICE_RUNTIME_MAX_SECONDS: u64 = ([\d_]+);/,
    );
    assert.ok(runtimeMaximum);
    assert.deepEqual(directiveValues(service, 'RuntimeMaxSec'), [
      `${Number(runtimeMaximum[1].replaceAll('_', ''))}s`,
    ]);
    assert.deepEqual(directiveValues(service, 'OOMPolicy'), ['kill']);
    assert.doesNotMatch(service, /^EnvironmentFile=/m);
    assert.doesNotMatch(service, /^ExecStart=.*[%$]/m);
    assert.doesNotMatch(service, /^\[Install\]$/m);
  });

  it('provisions a separate input-only group without bot membership', async () => {
    const [sysusers, tmpfiles, stagingTmpfiles] = await Promise.all([
      fs.readFile(RUNTIME_SYSUSERS_PATH, 'utf8'),
      fs.readFile(RUNTIME_TMPFILES_PATH, 'utf8'),
      fs.readFile(INPUT_STAGING_TMPFILES_PATH, 'utf8'),
    ]);

    assert.equal(sysusers, 'g webex-codex-input -\n');
    assert.doesNotMatch(sysusers, /^m /m);
    assert.equal(
      tmpfiles,
      [
        'd /var/lib/webex-codex-runtime-inputs 0550 root webex-codex-input -',
        'd /var/lib/webex-codex-runtime-inputs/ready 1730 root webex-codex-input 1d',
        'd /var/lib/webex-codex-runtime-inputs/consumed 0700 root root 1d',
        '',
      ].join('\n'),
    );
    assert.equal(
      stagingTmpfiles,
      [
        'd /var/lib/webex-generic-account-bot/codex-input-staging 0550 root webex-codex-launch -',
        'd /var/lib/webex-generic-account-bot/codex-input-staging/pending 2730 root webex-codex-launch 1d',
        'd /var/lib/webex-generic-account-bot/codex-input-staging/consumed 0700 root root 1d',
        '',
      ].join('\n'),
    );
  });

  it('provisions only the root-owned activation and canary fixture roots', async () => {
    const tmpfiles = await fs.readFile(ACTIVATION_TMPFILES_PATH, 'utf8');

    assert.equal(
      tmpfiles,
      [
        'd /run/webex-codex-activation 0755 root root -',
        'd /run/webex-codex-canary 0700 root root -',
        'd /var/lib/webex-generic-account-bot/canary-fixtures 0700 root root -',
        '',
      ].join('\n'),
    );
    assert.doesNotMatch(tmpfiles, /receipt\.json/);
  });

  it('keeps activation renewal root-only, bounded, and boot-gated by the bot', async () => {
    const service = await fs.readFile(ACTIVATION_RENEW_SERVICE_PATH, 'utf8');

    assert.deepEqual(directiveValues(service, 'Wants'), ['network-online.target']);
    assert.deepEqual(directiveValues(service, 'Requires'), [
      'webex-codex-launcher.socket webex-config-pull-worker.service',
    ]);
    assert.deepEqual(directiveValues(service, 'After'), [
      'network-online.target systemd-tmpfiles-setup.service webex-codex-launcher.socket webex-config-pull-worker.service',
    ]);
    assert.deepEqual(directiveValues(service, 'Before'), [
      'webex-generic-account-bot.service',
    ]);
    assert.deepEqual(directiveValues(service, 'PartOf'), [
      'webex-generic-account-bot.service',
    ]);
    assert.deepEqual(directiveValues(service, 'ConditionPathExists'), [
      '/sys/fs/cgroup/cgroup.controllers',
    ]);
    assert.deepEqual(directiveValues(service, 'Type'), ['oneshot']);
    assert.deepEqual(directiveValues(service, 'RemainAfterExit'), ['yes']);
    assert.deepEqual(directiveValues(service, 'User'), ['root']);
    assert.deepEqual(directiveValues(service, 'Group'), ['root']);
    assert.deepEqual(directiveValues(service, 'WorkingDirectory'), ['/']);
    assert.deepEqual(directiveValues(service, 'ExecStart'), [
      '/opt/webex-generic-account-bot/bin/webex-codex-activation ensure',
    ]);
    assert.deepEqual(directiveValues(service, 'ExecReload'), [
      '/opt/webex-generic-account-bot/bin/webex-codex-activation ensure',
    ]);
    assert.deepEqual(directiveValues(service, 'Restart'), ['no']);
    assert.deepEqual(directiveValues(service, 'TimeoutStartSec'), ['5400s']);
    assert.deepEqual(directiveValues(service, 'TimeoutStopSec'), ['15s']);
    assert.deepEqual(directiveValues(service, 'RuntimeMaxSec'), []);
    assert.deepEqual(directiveValues(service, 'KillMode'), ['control-group']);
    assert.deepEqual(directiveValues(service, 'OOMPolicy'), ['kill']);
    assert.deepEqual(directiveValues(service, 'UMask'), ['0077']);
    assert.deepEqual(directiveValues(service, 'StandardInput'), ['null']);
    assert.deepEqual(directiveValues(service, 'StandardOutput'), ['journal']);
    assert.deepEqual(directiveValues(service, 'StandardError'), ['journal']);
    assert.deepEqual(directiveValues(service, 'SupplementaryGroups'), [
      'webex-config-pull',
    ]);
    assert.deepEqual(directiveValues(service, 'WantedBy'), []);
    assert.doesNotMatch(service, /^EnvironmentFile=/m);
    assert.doesNotMatch(service, /^ExecStart=.*[%$]/m);
    for (const directive of ['Requires', 'Wants', 'After', 'WantedBy']) {
      assert.equal(
        directiveValues(service, directive).some((value) =>
          value.split(/\s+/).includes('webex-generic-account-bot.service')
        ),
        false,
        `${directive} must not pull in the bot service`,
      );
    }
    assert.doesNotMatch(service, /^WantedBy=.*\.target$/m);
    assert.doesNotMatch(service, /^\[Install\]$/m);
  });

  it('hardens renewal without hiding host canary evidence or manager access', async () => {
    const service = await fs.readFile(ACTIVATION_RENEW_SERVICE_PATH, 'utf8');
    const requiredHardening = {
      NoNewPrivileges: 'true',
      ProtectSystem: 'strict',
      ProtectHome: 'true',
      PrivateTmp: 'true',
      PrivateDevices: 'true',
      PrivateIPC: 'true',
      PrivateNetwork: 'false',
      ProtectClock: 'true',
      ProtectControlGroups: 'true',
      ProtectHostname: 'true',
      ProtectKernelLogs: 'true',
      ProtectKernelModules: 'true',
      ProtectKernelTunables: 'true',
      ProtectProc: 'default',
      ProcSubset: 'all',
      RestrictNamespaces: 'true',
      RestrictRealtime: 'true',
      RestrictSUIDSGID: 'true',
      LockPersonality: 'true',
      MemoryDenyWriteExecute: 'true',
      CapabilityBoundingSet: 'CAP_CHOWN',
      AmbientCapabilities: '',
      SystemCallArchitectures: 'native',
      KeyringMode: 'private',
    };
    for (const [directive, value] of Object.entries(requiredHardening)) {
      assert.deepEqual(directiveValues(service, directive), [value], directive);
    }

    assert.deepEqual(directiveValues(service, 'ReadOnlyPaths'), [
      '/proc',
      '/run/systemd',
    ]);
    assert.deepEqual(directiveValues(service, 'ReadWritePaths'), [
      '/run/webex-codex-activation',
      '/run/webex-codex-canary',
      '/var/lib/webex-generic-account-bot/codex-input-staging',
      '/var/lib/webex-generic-account-bot/canary-fixtures',
      '/var/lib/webex-codex-runtime-inputs',
    ]);
    assert.deepEqual(directiveValues(service, 'BindPaths'), []);
    assert.deepEqual(directiveValues(service, 'BindReadOnlyPaths'), []);
    assert.deepEqual(directiveValues(service, 'RestrictAddressFamilies'), []);
    assert.deepEqual(directiveValues(service, 'IPAddressAllow'), []);
    assert.deepEqual(directiveValues(service, 'IPAddressDeny'), []);
    assert.deepEqual(directiveValues(service, 'NetworkNamespacePath'), []);
    assert.doesNotMatch(service, /^InaccessiblePaths=.*(?:\/proc|\/run\/systemd)/m);
    assert.doesNotMatch(service, /^PrivateUsers=true$/m);
    assert.doesNotMatch(
      service,
      /^(?:RuntimeDirectory|StateDirectory|CacheDirectory|LogsDirectory)=/m,
    );
    assert.deepEqual(directiveValues(service, 'TasksMax'), ['128']);
    assert.deepEqual(directiveValues(service, 'CPUQuota'), ['200%']);
    assert.deepEqual(directiveValues(service, 'LimitNOFILE'), ['256']);
    assert.deepEqual(directiveValues(service, 'LimitNPROC'), ['128']);
    assert.deepEqual(directiveValues(service, 'LimitFSIZE'), ['64M']);
    assert.deepEqual(directiveValues(service, 'MemoryMax'), ['512M']);
    assert.deepEqual(directiveValues(service, 'MemorySwapMax'), ['0']);
  });

  it('keeps systemd and process verification visible without writable host paths', async () => {
    const [service, inputSealer] = await Promise.all([
      fs.readFile(SERVICE_PATH, 'utf8'),
      fs.readFile(INPUT_SEALER_PATH, 'utf8'),
    ]);

    const requiredHardening = {
      NoNewPrivileges: 'true',
      ProtectSystem: 'strict',
      ProtectHome: 'true',
      PrivateTmp: 'true',
      PrivateDevices: 'true',
      PrivateIPC: 'true',
      PrivateNetwork: 'true',
      ProtectClock: 'true',
      ProtectControlGroups: 'true',
      ProtectHostname: 'true',
      ProtectKernelLogs: 'true',
      ProtectKernelModules: 'true',
      ProtectKernelTunables: 'true',
      RestrictAddressFamilies: 'AF_UNIX',
      RestrictNamespaces: 'true',
      RestrictRealtime: 'true',
      RestrictSUIDSGID: 'true',
      LockPersonality: 'true',
      MemoryDenyWriteExecute: 'true',
      CapabilityBoundingSet: 'CAP_SYS_PTRACE CAP_SETPCAP',
      AmbientCapabilities: '',
      SystemCallArchitectures: 'native',
      IPAddressDeny: 'any',
      KeyringMode: 'private',
    };
    for (const [directive, value] of Object.entries(requiredHardening)) {
      assert.deepEqual(directiveValues(service, directive), [value], directive);
    }

    assert.deepEqual(directiveValues(service, 'ProtectProc'), ['ptraceable']);
    assert.deepEqual(directiveValues(service, 'ProcSubset'), ['pid']);
    assert.deepEqual(directiveValues(service, 'ReadOnlyPaths'), [
      '/proc',
      '/run/systemd',
      '-/run/webex-codex-activation',
    ]);
    assert.deepEqual(directiveValues(service, 'ReadWritePaths'), [
      '/var/lib/webex-generic-account-bot/codex-input-staging',
      '/var/lib/webex-codex-runtime-inputs',
    ]);
    assert.deepEqual(directiveValues(service, 'BindPaths'), []);
    assert.deepEqual(directiveValues(service, 'BindReadOnlyPaths'), []);
    for (const directive of [
      'ReadOnlyPaths',
      'ReadWritePaths',
      'BindPaths',
      'BindReadOnlyPaths',
    ]) {
      assert.equal(
        directiveValues(service, directive).some((value) =>
          value.includes('/proc/sys')
        ),
        false,
        `${directive} must not expose /proc/sys directly`,
      );
    }
    assert.doesNotMatch(service, /^InaccessiblePaths=.*(?:\/proc|\/run\/systemd)/m);
    assert.doesNotMatch(service, /^PrivateUsers=true$/m);
    assert.doesNotMatch(
      service,
      /^(?:RuntimeDirectory|StateDirectory|CacheDirectory|LogsDirectory)=/m,
    );
    assert.deepEqual(directiveValues(service, 'CapabilityBoundingSet'), [
      'CAP_SYS_PTRACE CAP_SETPCAP',
    ]);
    assert.deepEqual(directiveValues(service, 'AmbientCapabilities'), ['']);
    assert.deepEqual(directiveValues(service, 'TasksMax'), ['64']);
    assert.deepEqual(directiveValues(service, 'CPUQuota'), ['100%']);
    assert.deepEqual(directiveValues(service, 'LimitNOFILE'), ['128']);
    assert.deepEqual(directiveValues(service, 'LimitNPROC'), ['64']);
    const workspaceMiB = inputSealer.match(
      /^const WORKSPACE_TOTAL_MIB: u64 = ([\d_]+);$/m,
    );
    assert(workspaceMiB, 'workspace MiB limit must remain explicit');
    assert.deepEqual(directiveValues(service, 'LimitFSIZE'), [
      `${Number(workspaceMiB[1].replaceAll('_', ''))}M`,
    ]);
    assert.deepEqual(directiveValues(service, 'MemoryMax'), ['256M']);
    assert.deepEqual(directiveValues(service, 'MemorySwapMax'), ['0']);
  });

  it('grants the bot only reviewed launcher and config-pull access', async () => {
    const [dropIn, launcherFiles, botDropIns] = await Promise.all([
      fs.readFile(BOT_DROP_IN_PATH, 'utf8'),
      Promise.all(
        [
          SOCKET_PATH,
          SERVICE_PATH,
          SYSUSERS_PATH,
          TMPFILES_PATH,
          RUNTIME_SYSUSERS_PATH,
          CONFIG_PULL_SYSUSERS_PATH,
          RUNTIME_TMPFILES_PATH,
          INPUT_STAGING_TMPFILES_PATH,
          ACTIVATION_TMPFILES_PATH,
          ACTIVATION_RENEW_SERVICE_PATH,
        ].map((file) => fs.readFile(file, 'utf8')),
      ),
      readTextFilesRecursively(BOT_DROP_IN_ROOT),
    ]);

    assert.equal(
      dropIn,
      [
        '[Unit]',
        'Requires=webex-codex-activation-renew.service',
        'After=webex-codex-activation-renew.service',
        '',
        '[Service]',
        'SupplementaryGroups=webex-codex-launch webex-config-pull',
        'ReadWritePaths=/var/lib/webex-generic-account-bot/codex-input-staging/pending',
        '',
      ].join('\n'),
    );
    assert.deepEqual(directiveValues(dropIn, 'SupplementaryGroups'), [
      'webex-codex-launch webex-config-pull',
    ]);
    assert.deepEqual(directiveValues(dropIn, 'Requires'), [
      'webex-codex-activation-renew.service',
    ]);
    assert.deepEqual(directiveValues(dropIn, 'After'), [
      'webex-codex-activation-renew.service',
    ]);
    assert.deepEqual(directiveValues(dropIn, 'ReadWritePaths'), [
      '/var/lib/webex-generic-account-bot/codex-input-staging/pending',
    ]);
    assert.doesNotMatch(dropIn, /\bwebex-codex-input\b/);
    assert.doesNotMatch(dropIn, /config[_-]?commands/i);

    for (const { file, contents } of botDropIns) {
      if (file === BOT_DROP_IN_PATH) {
        continue;
      }
      assert.doesNotMatch(
        contents,
        /webex-codex-(?:launch|input)|webex-config-pull|codex-input-staging|webex-codex-activation|webex-codex-launcher|\/run\/credentials/,
        file,
      );
    }

    for (const contents of launcherFiles) {
      assert.doesNotMatch(contents, /\b(?:sudo|pkexec)\b|polkit|PolicyKit/i);
      assert.doesNotMatch(contents, /^m\s+webex-generic-account-bot\s+webex-codex-launch$/m);
      assert.doesNotMatch(contents, /^m\s+webex-codex-launch\s+webex-generic-account-bot$/m);
      assert.doesNotMatch(contents, /^m\s+webex-generic-account-bot\s+webex-codex-input$/m);
      assert.doesNotMatch(contents, /^m\s+webex-generic-account-bot\s+webex-config-pull$/m);
      assert.doesNotMatch(contents, /^m\s+webex-config-pull\s+webex-generic-account-bot$/m);
      assert.doesNotMatch(contents, /^m\s+webex-generic-account-bot\s+webex-config-deploy$/m);
      assert.doesNotMatch(contents, /^m\s+webex-config-deploy\s+webex-generic-account-bot$/m);
    }
  });

  it('keeps transient execution behind fixed launcher and runtime boundaries', async () => {
    const [
      source,
      launcherModule,
      isolatedExecution,
      runtimeSource,
      runnerInput,
      workBudget,
    ] = await Promise.all([
      fs.readFile(LAUNCHER_SOURCE_PATH, 'utf8'),
      fs.readFile(LAUNCHER_MODULE_PATH, 'utf8'),
      fs.readFile(ISOLATED_EXECUTION_PATH, 'utf8'),
      fs.readFile(RUNTIME_SOURCE_PATH, 'utf8'),
      fs.readFile(RUNNER_INPUT_PATH, 'utf8'),
      fs.readFile(WORK_BUDGET_PATH, 'utf8'),
    ]);
    const launcherSources = `${source}\n${launcherModule}`;
    const productionSource = source.split(
      '#[cfg(all(test, target_os = "linux"))]',
      1,
    )[0];
    const productionLauncherModule = launcherModule.split(
      '#[cfg(all(test, target_os = "linux"))]',
      1,
    )[0];
    const productionIsolatedExecution = isolatedExecution.split(
      '#[cfg(all(test, target_os = "linux"))]\nmod tests {',
      1,
    )[0];

    assert.doesNotMatch(
      launcherSources,
      /\b(?:sudo|pkexec)\b|PolicyKit|polkit/i,
    );
    assert.doesNotMatch(
      productionSource,
      /std::process::Command|tokio::process::Command/,
    );
    assert.match(
      launcherModule,
      /const SYSTEMCTL_PATH: &str = "\/usr\/bin\/systemctl";/,
    );
    assert.match(productionLauncherModule, /Command::new\(SYSTEMCTL_PATH\)/);
    assert.equal((productionLauncherModule.match(/Command::new\(/g) ?? []).length, 1);
    assert.doesNotMatch(source, /tokio::io::(?:stdin|stdout)/);
    assert.match(source, /AsyncFd<OwnedFd>/);
    assert.match(source, /libc::SCM_CREDENTIALS/);
    assert.match(launcherModule, /SO_PEERPIDFD/);
    assert.match(launcherModule, /PR_CAPBSET_DROP/);
    assert.match(launcherModule, /capability_bounding_set\(\)\?\.is_empty\(\)/);
    assert.match(source, /#\[tokio::main\(flavor = "current_thread"\)\]/);
    assert.match(source, /tracing_subscriber::fmt\(\)/);
    assert.match(source, /\.with_writer\(std::io::stderr\)/);
    assert.match(source, /log_launcher_error\("preflight unavailable", &error\)/);
    assert.match(source, /log_launcher_error\("execute unavailable", &error\)/);
    assert.match(source, /log_launcher_error\("execute failed", &error\)/);
    assert.match(source, /isolated_execution::preflight_bounded\(&cancellation\)/);
    assert.match(source, /wait_for_client_disconnect\(socket\)/);
    assert.match(source, /ExecutionCancellation::new\(\)/);
    assert.match(source, /cancellation\.cancel\(\)/);
    assert.match(source, /LAUNCHER_CANCELLATION_DRAIN_SECONDS/);
    assert.match(source, /terminate_stuck_launcher/);
    assert.match(source, /IsolatedRunResult::Completed/);
    assert.match(isolatedExecution, /run_blocking_with_process_watchdog/);
    assert.match(
      isolatedExecution,
      /if Instant::now\(\) >= deadline \{\s*discard_captures\(stdout_task, stderr_task\)\.await;\s*return Ok\(IsolatedRunResult::TimedOut\);/,
    );
    assert.match(runnerInput, /run_blocking_with_process_watchdog/);
    assert.match(workBudget, /completion\.recv_timeout\(/);
    assert.match(workBudget, /std::process::exit\(STUCK_WORK_EXIT_CODE\)/);
    assert.match(runnerInput, /const PENDING_ROOT_MODE: u32 = 0o2730;/);
    assert.match(runnerInput, /libc::syncfs\(file\.as_raw_fd\(\)\)/);
    assert.match(
      isolatedExecution,
      /const SYSTEMD_RUN_PATH: &str = "\/usr\/bin\/systemd-run";/,
    );
    assert.match(
      isolatedExecution,
      /const SYSTEMCTL_PATH: &str = "\/usr\/bin\/systemctl";/,
    );
    assert.match(isolatedExecution, /Command::new\(plan\.executable\)/);
    assert.match(isolatedExecution, /Command::new\(SYSTEMCTL_PATH\)/);
    assert.equal(
      (productionIsolatedExecution.match(/Command::new\(plan\.executable\)/g) ?? []).length,
      2,
    );
    assert.equal((productionIsolatedExecution.match(/Command::new\(/g) ?? []).length, 3);
    assert.match(isolatedExecution, /\.stdin\(Stdio::piped\(\)\)/);
    assert.match(isolatedExecution, /\.stdout\(Stdio::piped\(\)\)/);
    assert.match(isolatedExecution, /\.stderr\(Stdio::piped\(\)\)/);
    assert.match(isolatedExecution, /DynamicUser=yes/);
    assert.match(
      isolatedExecution,
      /const CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";/,
    );
    assert.match(
      isolatedExecution,
      /const ACTIVATION_BOOT_ID_CREDENTIAL_NAME: &str = "activation-boot-id";/,
    );
    assert.match(isolatedExecution, /env::var_os\(CREDENTIALS_DIRECTORY_ENV\)/);
    assert.match(workBudget, /tokio::task::spawn_blocking/);
    assert.match(
      isolatedExecution,
      /Duration::from_secs\(LAUNCHER_PREPARATION_WORK_TIMEOUT_SECONDS\)/,
    );
    assert.match(
      isolatedExecution,
      /ActivationPaths::production_for_launcher_with_boot_id\(boot_id\)/,
    );
    assert.match(isolatedExecution, /RootImage=/);
    assert.match(isolatedExecution, /O_PATH/);
    assert.match(isolatedExecution, /O_NOFOLLOW/);
    assert.match(isolatedExecution, /\/proc\/\{\}\/fd\/\{\}/);
    assert.match(isolatedExecution, /failed to consume the verified runtime workspace/);
    assert.match(isolatedExecution, /LoadCredential=codex-auth\.json/);
    assert.match(
      isolatedExecution,
      /InaccessiblePaths=[^"\n]*-\/run\/webex-codex-activation(?:\s|$)/,
    );
    assert.match(
      isolatedExecution,
      /InaccessiblePaths=[^"\n]*-\/run\/webex-config-pull(?:\s|"|$)/,
    );
    assert.doesNotMatch(
      isolatedExecution,
      /SupplementaryGroups=[^"\n]*webex-config-pull/,
    );
    assert.match(isolatedExecution, /CapabilityBoundingSet=/);
    assert.match(
      isolatedExecution,
      /SystemCallFilter=~@debug process_vm_readv process_vm_writev process_madvise kcmp/,
    );
    assert.match(isolatedExecution, /SystemCallErrorNumber=EPERM/);
    assert.match(isolatedExecution, /LimitCORE=0/);
    assert.match(isolatedExecution, /MemoryMax=2G/);
    assert.match(isolatedExecution, /TasksMax=128/);
    assert.doesNotMatch(isolatedExecution, /\b(?:sudo|pkexec)\b|PolicyKit|polkit/i);
    assert.match(runtimeSource, /PR_SET_DUMPABLE/);
    assert.match(runtimeSource, /PR_SET_NO_NEW_PRIVS/);
    assert.match(runtimeSource, /--output-last-message/);
    assert.match(runtimeSource, /FINAL_OUTPUT_PATH/);
    assert.match(runtimeSource, /SYS_close_range/);
    assert.match(runtimeSource, /shell_environment_policy\.inherit=\\"none\\"/);
    assert.match(runtimeSource, /permissions\.webex-isolated\.network\.enabled=false/);
    assert.match(runtimeSource, /\\"\/run\/webex-config-pull\\"=\\"deny\\"/);
    assert.match(runtimeSource, /features\.hooks=false/);
    assert.doesNotMatch(runtimeSource, /systemd-run|sudo|pkexec|PolicyKit|polkit/i);

    const dropCapability = source.indexOf('drop_peer_inspection_capability()?;');
    const readRequest = source.indexOf('receive_request_packet(&socket)');
    assert.notEqual(dropCapability, -1);
    assert.notEqual(readRequest, -1);
    assert.ok(dropCapability < readRequest);
  });
});

function directiveValues(unit, directive) {
  const prefix = `${directive}=`;
  return unit
    .split('\n')
    .filter((line) => line.startsWith(prefix))
    .map((line) => line.slice(prefix.length));
}

async function readTextFilesRecursively(root) {
  let entries;
  try {
    entries = await fs.readdir(root, { withFileTypes: true });
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return [];
    }
    throw error;
  }

  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await readTextFilesRecursively(entryPath)));
      continue;
    }
    assert.equal(
      entry.isFile(),
      true,
      `unexpected bot drop-in entry: ${entryPath}`,
    );
    files.push({ file: entryPath, contents: await fs.readFile(entryPath, 'utf8') });
  }
  return files;
}
