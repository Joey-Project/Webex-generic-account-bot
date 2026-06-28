import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const SYSTEMD_ROOT = fileURLToPath(new URL('../deploy/systemd/', import.meta.url));
const SOCKET_PATH = path.join(SYSTEMD_ROOT, 'webex-codex-launcher.socket');
const SERVICE_PATH = path.join(SYSTEMD_ROOT, 'webex-codex-launcher@.service');
const SYSUSERS_PATH = path.join(SYSTEMD_ROOT, 'webex-codex-launcher.sysusers.conf');
const TMPFILES_PATH = path.join(SYSTEMD_ROOT, 'webex-codex-launcher.tmpfiles.conf');
const LAUNCHER_SOURCE_PATH = fileURLToPath(
  new URL('../src/bin/webex-codex-launcher.rs', import.meta.url),
);

describe('Codex launcher systemd boundary', () => {
  it('provisions only a root-owned group-gated accepted socket', async () => {
    const [socket, sysusers, tmpfiles] = await Promise.all([
      fs.readFile(SOCKET_PATH, 'utf8'),
      fs.readFile(SYSUSERS_PATH, 'utf8'),
      fs.readFile(TMPFILES_PATH, 'utf8'),
    ]);

    assert.deepEqual(directiveValues(socket, 'ListenStream'), [
      '/run/webex-codex-launcher/launcher.sock',
    ]);
    assert.deepEqual(directiveValues(socket, 'Accept'), ['yes']);
    assert.deepEqual(directiveValues(socket, 'SocketUser'), ['root']);
    assert.deepEqual(directiveValues(socket, 'SocketGroup'), ['webex-codex-launch']);
    assert.deepEqual(directiveValues(socket, 'SocketMode'), ['0660']);
    assert.deepEqual(directiveValues(socket, 'DirectoryMode'), ['0750']);
    assert.deepEqual(directiveValues(socket, 'RemoveOnStop'), ['yes']);
    assert.deepEqual(directiveValues(socket, 'WantedBy'), ['sockets.target']);

    assert.equal(sysusers, 'g webex-codex-launch -\n');
    assert.doesNotMatch(sysusers, /^m /m);
    assert.equal(
      tmpfiles,
      'd /run/webex-codex-launcher 0750 root webex-codex-launch -\n',
    );
  });

  it('pairs the accepted socket with a fixed root-owned launcher process', async () => {
    const [socket, service] = await Promise.all([
      fs.readFile(SOCKET_PATH, 'utf8'),
      fs.readFile(SERVICE_PATH, 'utf8'),
    ]);

    assert.equal(path.basename(SOCKET_PATH), 'webex-codex-launcher.socket');
    assert.equal(path.basename(SERVICE_PATH), 'webex-codex-launcher@.service');
    assert.deepEqual(directiveValues(socket, 'Accept'), ['yes']);
    assert.deepEqual(directiveValues(socket, 'Service'), []);
    assert.deepEqual(directiveValues(service, 'Requires'), ['webex-codex-launcher.socket']);
    assert.deepEqual(directiveValues(service, 'After'), ['webex-codex-launcher.socket']);
    assert.deepEqual(directiveValues(service, 'User'), ['root']);
    assert.deepEqual(directiveValues(service, 'Group'), ['root']);
    assert.deepEqual(directiveValues(service, 'ExecStart'), [
      '/opt/webex-generic-account-bot/bin/webex-codex-launcher',
    ]);
    assert.deepEqual(directiveValues(service, 'StandardInput'), ['socket']);
    assert.deepEqual(directiveValues(service, 'StandardOutput'), ['socket']);
    assert.deepEqual(directiveValues(service, 'StandardError'), ['journal']);
    assert.deepEqual(directiveValues(service, 'TimeoutStartSec'), ['15s']);
    assert.deepEqual(directiveValues(service, 'RuntimeMaxSec'), ['20s']);
    assert.deepEqual(directiveValues(service, 'OOMPolicy'), ['kill']);
    assert.doesNotMatch(service, /^EnvironmentFile=/m);
    assert.doesNotMatch(service, /^ExecStart=.*[%$]/m);
    assert.doesNotMatch(service, /^\[Install\]$/m);
  });

  it('keeps systemd and process verification visible without writable host paths', async () => {
    const service = await fs.readFile(SERVICE_PATH, 'utf8');

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
      CapabilityBoundingSet: 'CAP_SYS_PTRACE',
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
    assert.deepEqual(directiveValues(service, 'ReadOnlyPaths'), ['/proc', '/run/systemd']);
    assert.deepEqual(directiveValues(service, 'ReadWritePaths'), []);
    assert.deepEqual(directiveValues(service, 'BindPaths'), []);
    assert.doesNotMatch(service, /^InaccessiblePaths=.*(?:\/proc|\/run\/systemd)/m);
    assert.doesNotMatch(service, /^PrivateUsers=true$/m);
    assert.doesNotMatch(
      service,
      /^(?:RuntimeDirectory|StateDirectory|CacheDirectory|LogsDirectory)=/m,
    );
    assert.deepEqual(directiveValues(service, 'CapabilityBoundingSet'), [
      'CAP_SYS_PTRACE',
    ]);
    assert.deepEqual(directiveValues(service, 'AmbientCapabilities'), ['']);
    assert.deepEqual(directiveValues(service, 'TasksMax'), ['64']);
    assert.deepEqual(directiveValues(service, 'CPUQuota'), ['100%']);
    assert.deepEqual(directiveValues(service, 'LimitNOFILE'), ['128']);
    assert.deepEqual(directiveValues(service, 'LimitNPROC'), ['64']);
    assert.deepEqual(directiveValues(service, 'LimitFSIZE'), ['1M']);
    assert.deepEqual(directiveValues(service, 'MemoryMax'), ['256M']);
    assert.deepEqual(directiveValues(service, 'MemorySwapMax'), ['0']);
  });

  it('does not grant the bot access or delegate execution to policy helpers', async () => {
    const launcherFiles = await Promise.all(
      [SOCKET_PATH, SERVICE_PATH, SYSUSERS_PATH, TMPFILES_PATH].map((file) =>
        fs.readFile(file, 'utf8'),
      ),
    );
    const systemdEntries = await fs.readdir(SYSTEMD_ROOT, { recursive: true });
    const botDropIns = systemdEntries.filter((entry) =>
      entry.startsWith('webex-generic-account-bot.service.d/')
    );

    for (const entry of botDropIns) {
      const contents = await fs.readFile(path.join(SYSTEMD_ROOT, entry), 'utf8');
      assert.doesNotMatch(contents, /webex-codex-launch/, entry);
    }
    for (const contents of launcherFiles) {
      assert.doesNotMatch(contents, /\b(?:systemd-run|sudo|pkexec)\b|polkit|PolicyKit/i);
      assert.doesNotMatch(contents, /^SupplementaryGroups=/m);
      assert.doesNotMatch(contents, /^m\s+webex-generic-account-bot\s+webex-codex-launch$/m);
      assert.doesNotMatch(contents, /^m\s+webex-codex-launch\s+webex-generic-account-bot$/m);
    }
  });

  it('keeps the foundation binary free of transient execution primitives', async () => {
    const source = await fs.readFile(LAUNCHER_SOURCE_PATH, 'utf8');

    assert.doesNotMatch(source, /\b(?:systemd-run|sudo|pkexec)\b|PolicyKit|polkit/i);
    assert.doesNotMatch(source, /std::process::Command|tokio::process::Command/);
    assert.match(source, /ExecutionUnavailable/);
    assert.match(source, /LauncherResponse::ready\(false\)/);
  });
});

function directiveValues(unit, directive) {
  const prefix = `${directive}=`;
  return unit
    .split('\n')
    .filter((line) => line.startsWith(prefix))
    .map((line) => line.slice(prefix.length));
}
