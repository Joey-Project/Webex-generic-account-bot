#!/usr/bin/env node

import { execFile, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants, fstat } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const fstatAsync = promisify(fstat);
const PRIVATE_MOUNT_NAMESPACE_ENV = 'WEBEX_HOST_PROVISION_PRIVATE_MOUNT_NS';
const SOURCE_ROOT_ENV = 'WEBEX_HOST_PROVISION_SOURCE_ROOT';
const IDENTITY_RECOVERY_CHILD_ENV = 'WEBEX_HOST_IDENTITY_RECOVERY_CHILD';
const IDENTITY_LOCK_FD_ENV = 'WEBEX_HOST_IDENTITY_LOCK_FD';
const IDENTITY_LOCK_PID_ENV = 'WEBEX_HOST_IDENTITY_LOCK_PID';
const IDENTITY_LOCK_PARENT_PID_ENV = 'WEBEX_HOST_IDENTITY_LOCK_PARENT_PID';
const FD_REEXEC_SCRIPT_PATH = '/proc/self/fd/5';
const FD_REEXEC_BOOTSTRAP = [
  'const { readFileSync } = await import("node:fs");',
  'const source = readFileSync("/proc/self/fd/5").toString("base64");',
  'const { runCli } = await import("data:text/javascript;base64," + source);',
  'process.exitCode = await runCli({ argv: process.argv.slice(1) });',
].join(' ');

const inheritedSourceRoot = process.env[SOURCE_ROOT_ENV];
if (inheritedSourceRoot && process.env[PRIVATE_MOUNT_NAMESPACE_ENV] !== '1') {
  throw new Error('inherited host provision source root requires private mount re-exec');
}
if (inheritedSourceRoot && !path.isAbsolute(inheritedSourceRoot)) {
  throw new Error('inherited host provision source root is not absolute');
}

const PROVISION_SCRIPT_PATH = inheritedSourceRoot
  ? FD_REEXEC_SCRIPT_PATH
  : fileURLToPath(import.meta.url);
const SYSTEMD_SOURCE_ROOT = inheritedSourceRoot
  ? path.resolve(inheritedSourceRoot)
  : fileURLToPath(new URL('../deploy/systemd/', import.meta.url));
const FILE_MODE = 0o644;
const TRANSACTION_MODE = 0o600;
const DIRECTORY_MODE = 0o755;
const MAX_POLICY_FILE_BYTES = 256 * 1024;
const MAX_TRANSACTION_BYTES = 8 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const MAX_PROC_LOCKS_BYTES = 1024 * 1024;
const MAX_PROC_FD_ENTRIES = 1024;
const MAX_STALE_CANDIDATES = 256;
const MAX_SCANNED_DIRECTORY_ENTRIES = 4096;
const MAX_LAUNCHER_INSTANCES = 128;
const MAX_SYSTEMD_USERDB_ENTRIES = 16;
const MAX_SYSTEMD_UNIT_PATH_ENTRIES = 4096;
const MAX_SYSTEMD_POLICY_TREE_ENTRIES = 32_768;
const MAX_SYSTEMD_POLICY_FILES = 8192;
const MAX_SYSTEMD_POLICY_BYTES = 64 * 1024 * 1024;
const MAX_CREDENTIAL_STORE_ENTRIES = 1024;
const MAX_MOUNTINFO_BYTES = 8 * 1024 * 1024;
const MAX_MOUNTINFO_ENTRIES = 16_384;
const MAX_MANAGED_ID = 59_999;
const MAX_IDENTITY_FILE_BYTES = 8 * 1024 * 1024;
const TRANSACTION_VERSION = 3;
const TRANSACTION_PATH =
  '/etc/systemd/system/.webex-host-provision.transaction.json';
const PROVISION_LOCK_PATH = '/run/webex-config-deploy/deploy-config.lock';
const PROVISION_LOCK_PARENT = path.dirname(PROVISION_LOCK_PATH);
const PROVISION_LOCK_ENV = 'WEBEX_HOST_PROVISION_LOCKED';
const PROVISION_LOCK_CONFLICT_EXIT = 75;
const IDENTITY_LOCK_HELPER_PATH =
  '/opt/webex-generic-account-bot/bin/webex-host-identity-lock';
const IDENTITY_LOCK_PATH = '/etc/.pwd.lock';
const CANDIDATE_UUID_PATTERN =
  '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const PROVISION_CANDIDATE_PREFIX = '.webex-host-policy.provision-';
const LAUNCHER_INSTANCE_PATTERN = /^webex-codex-launcher@[^@/\s]+\.service$/;
const LAUNCHER_REFERENCE_PATTERN = /webex-codex-launcher@[^@/\s]*\.service/;
const SYSTEMD_UNIT_NAME_PATTERN =
  /\.(?:automount|device|mount|path|scope|service|slice|socket|swap|target|timer)$/;
const SYSTEMD_USERDB_DIRECTORY = '/run/systemd/userdb';
const SYSTEMD_SYSTEM_CREDENTIAL_DIRECTORY = '/run/credentials/@system';
const SYSTEMD_DYNAMIC_USER_PROVIDER = 'io.systemd.DynamicUser';
const SYSTEMD_MANAGER_UNIT_PATHS = Object.freeze([
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
]);
const SYSTEMD_PROTECTED_UNIT_PATHS = Object.freeze([
  ...SYSTEMD_MANAGER_UNIT_PATHS,
  '/lib/systemd/system',
]);
const SYSTEMD_MANAGED_DIRECTORY_ROOTS = new Map([
  ['CacheDirectory', '/var/cache'],
  ['ConfigurationDirectory', '/etc'],
  ['LogsDirectory', '/var/log'],
  ['RuntimeDirectory', '/run'],
  ['StateDirectory', '/var/lib'],
]);
const SYSTEMD_PROTECTED_DIRECTORY_PATHS = Object.freeze([
  '/etc/webex-generic-account-bot',
  '/run/webex-codex-activation',
  '/run/webex-codex-canary',
  '/run/webex-codex-launcher',
  '/run/webex-config-deploy',
  '/run/webex-config-pull',
  '/var/lib/webex-codex-runtime-inputs',
  '/var/lib/webex-generic-account-bot',
  '/var/lib/webex-headless-access',
]);
const STATIC_USERDB_DIRECTORIES = Object.freeze([
  '/etc/userdb',
  '/run/userdb',
  '/run/host/userdb',
  '/usr/local/lib/userdb',
  '/usr/lib/userdb',
]);
const MANAGED_ACCOUNTS = Object.freeze({
  bot: Object.freeze({
    name: 'webex-generic-account-bot',
    home: '/var/lib/webex-generic-account-bot',
    shell: '/usr/sbin/nologin',
  }),
  worker: Object.freeze({
    name: 'webex-config-deploy',
    home: '/nonexistent',
    shell: '/usr/sbin/nologin',
  }),
});
const MANAGED_USERS = Object.freeze({
  bot: MANAGED_ACCOUNTS.bot.name,
  worker: MANAGED_ACCOUNTS.worker.name,
});
const MANAGED_GROUPS = Object.freeze({
  bot: 'webex-generic-account-bot',
  configDeploy: 'webex-config-deploy',
  configPull: 'webex-config-pull',
  codexInput: 'webex-codex-input',
  codexLaunch: 'webex-codex-launch',
});
const MANAGED_IDENTITY_NAMES = Object.freeze(
  [...new Set([...Object.values(MANAGED_USERS), ...Object.values(MANAGED_GROUPS)])],
);
const MANAGED_IDENTITY_PATTERNS = Object.freeze(
  MANAGED_IDENTITY_NAMES
    .map((name) => new RegExp(
      `(^|[^A-Za-z0-9_.-])${escapeRegExp(name)}([^A-Za-z0-9_.-]|$)`,
    )),
);
const SYSTEMD_IDENTITY_DIRECTIVES = new Set([
  'Group',
  'SocketGroup',
  'SocketUser',
  'SupplementaryGroups',
  'User',
]);
const SYSTEMD_EXECUTION_ENVIRONMENT_DIRECTIVES = new Set([
  'Environment',
  'EnvironmentFile',
  'ExecSearchPath',
  'PassEnvironment',
  'UnsetEnvironment',
]);
const SYSTEMD_PATH_TRIGGER_DIRECTIVES = new Set([
  'DirectoryNotEmpty',
  'PathChanged',
  'PathExists',
  'PathExistsGlob',
  'PathModified',
]);
const SYSTEMD_SOCKET_PATH_DIRECTIVES = new Set([
  'ListenDatagram',
  'ListenFIFO',
  'ListenSequentialPacket',
  'ListenStream',
  'Symlinks',
]);
const SYSTEMD_UNIT_REFERENCE_DIRECTIVES = new Set([
  'After',
  'Alias',
  'Also',
  'Before',
  'BindsTo',
  'Conflicts',
  'JoinsNamespaceOf',
  'OnFailure',
  'OnSuccess',
  'PartOf',
  'PropagatesReloadTo',
  'PropagatesStopTo',
  'ReloadPropagatedFrom',
  'RequiredBy',
  'Requires',
  'Requisite',
  'Service',
  'Sockets',
  'StopPropagatedFrom',
  'Unit',
  'Upholds',
  'UpheldBy',
  'Wants',
  'WantedBy',
]);
const BOOT_POLICY_DIRECTORIES = Object.freeze({
  sysusers: Object.freeze([
    '/etc/sysusers.d',
    '/run/sysusers.d',
    '/usr/local/lib/sysusers.d',
    '/usr/lib/sysusers.d',
    '/lib/sysusers.d',
  ]),
  tmpfiles: Object.freeze([
    '/etc/tmpfiles.d',
    '/run/tmpfiles.d',
    '/usr/local/lib/tmpfiles.d',
    '/usr/lib/tmpfiles.d',
    '/lib/tmpfiles.d',
  ]),
});
const IDENTITY_POLICY_PATHS = Object.freeze([
  '/etc/nsswitch.conf',
  '/etc/passwd',
  '/etc/shadow',
  '/etc/group',
  '/etc/gshadow',
]);
const IDENTITY_DATABASE_COMMIT_ORDER = Object.freeze([
  '/etc/group',
  '/etc/gshadow',
  '/etc/passwd',
  '/etc/shadow',
]);
const IDENTITY_RECOVERY_CANDIDATE_PATHS = Object.freeze(
  IDENTITY_DATABASE_COMMIT_ORDER.map((file) => (
    path.posix.join(
      path.posix.dirname(file),
      `.webex-host-identity-recovery-${path.posix.basename(file)}.tmp`,
    )
  )),
);
const BOOT_POLICY_CREDENTIAL_NAMES = Object.freeze([
  'fstab.extra',
  'sysusers.extra',
  'tmpfiles.extra',
]);
const BOOT_POLICY_CREDENTIAL_PREFIXES = Object.freeze([
  'passwd.hashed-password.',
  'passwd.plaintext-password.',
  'passwd.shell.',
  'userdb.transient.user.',
  'userdb.transient.group.',
  'userdb.user.',
  'userdb.group.',
  'systemd.extra-unit.',
  'systemd.unit-dropin.',
]);
const CREDENTIAL_STORE_DIRECTORIES = Object.freeze([
  '/etc/credstore',
  '/run/credstore',
  '/usr/lib/credstore',
  '/etc/credstore.encrypted',
  '/run/credstore.encrypted',
  '/usr/lib/credstore.encrypted',
]);
const BOOT_POLICY_CREDENTIAL_PATHS = Object.freeze(
  CREDENTIAL_STORE_DIRECTORIES.flatMap((directory) => (
    BOOT_POLICY_CREDENTIAL_NAMES.map((name) => path.join(directory, name))
  )),
);
const CREDENTIAL_DIRECTIVES = new Set([
  'ImportCredential',
  'LoadCredential',
  'LoadCredentialEncrypted',
  'SetCredential',
  'SetCredentialEncrypted',
]);
const VENDOR_TMPFILES_CREDENTIAL_UNITS = new Set([
  'systemd-tmpfiles-clean.service',
  'systemd-tmpfiles-setup-dev-early.service',
  'systemd-tmpfiles-setup-dev.service',
  'systemd-tmpfiles-setup.service',
]);
const VENDOR_SYSUSERS_CREDENTIAL_IMPORTS = new Set([
  'ImportCredential=passwd.hashed-password.root',
  'ImportCredential=passwd.plaintext-password.root',
  'ImportCredential=passwd.shell.root',
  'ImportCredential=sysusers.*',
]);
const VENDOR_FIRSTBOOT_CREDENTIAL_IMPORTS = new Set([
  'ImportCredential=passwd.hashed-password.root',
  'ImportCredential=passwd.plaintext-password.root',
  'ImportCredential=passwd.shell.root',
]);
const VENDOR_USERDB_CREDENTIAL_IMPORTS = new Set([
  'ImportCredential=userdb.user.*',
  'ImportCredential=userdb.group.*',
  'ImportCredential=userdb.transient.user.*',
  'ImportCredential=userdb.transient.group.*',
]);
const BOOT_POLICY_SYSTEMD_CONSUMER_UNITS = new Set([
  'systemd-sysusers.service',
  'systemd-userdb-load-credentials.service',
  ...VENDOR_TMPFILES_CREDENTIAL_UNITS,
]);
const BOOT_POLICY_SYSTEMD_CONSUMER_POLICY_DIRECTORY_NAMES = new Set(
  [...BOOT_POLICY_SYSTEMD_CONSUMER_UNITS].flatMap((unit) => [
    ...systemdDropInDirectoryNames(unit),
    `${unit}.wants`,
    `${unit}.requires`,
    `${unit}.upholds`,
  ]),
);
const BOOT_POLICY_EXECUTABLES = new Set([
  'systemd-firstboot',
  'systemd-sysusers',
  'systemd-tmpfiles',
]);
const FIXED_HOST_EXECUTABLE_PATHS = Object.freeze([
  IDENTITY_LOCK_HELPER_PATH,
  '/usr/bin/flock',
  '/usr/bin/getent',
  '/usr/bin/getfacl',
  '/usr/bin/lsns',
  '/usr/bin/node',
  '/usr/bin/systemctl',
  '/usr/bin/systemd-creds',
  '/usr/bin/systemd-sysusers',
  '/usr/bin/systemd-tmpfiles',
  '/usr/bin/unshare',
]);
const SYSTEMCTL_UNSCOPED_MUTATION_VERBS = new Set([
  'cancel',
  'daemon-reexec',
  'daemon-reload',
  'default',
  'edit',
  'emergency',
  'exit',
  'halt',
  'hibernate',
  'hybrid-sleep',
  'import-environment',
  'isolate',
  'kexec',
  'log-level',
  'log-target',
  'poweroff',
  'preset-all',
  'reboot',
  'rescue',
  'reset-failed',
  'service-watchdogs',
  'set-default',
  'set-environment',
  'soft-reboot',
  'suspend',
  'suspend-then-hibernate',
  'switch-root',
  'unset-environment',
]);
const SYSTEMD_GLOBAL_CONTROL_EXECUTABLES = new Set([
  'halt',
  'init',
  'poweroff',
  'reboot',
  'shutdown',
  'telinit',
]);
const SYSTEMD_GLOBAL_CONTROL_UNITS = Object.freeze([
  'ctrl-alt-del.target',
  'exit.target',
  'factory-reset.target',
  'halt.target',
  'hibernate.target',
  'hybrid-sleep.target',
  'kexec.target',
  'poweroff.target',
  'reboot.target',
  'runlevel0.target',
  'runlevel6.target',
  'shutdown.target',
  'sleep.target',
  'soft-reboot.target',
  'suspend-then-hibernate.target',
  'suspend.target',
  'systemd-exit.service',
  'systemd-halt.service',
  'systemd-hibernate.service',
  'systemd-hybrid-sleep.service',
  'systemd-kexec.service',
  'systemd-poweroff.service',
  'systemd-reboot.service',
  'systemd-soft-reboot.service',
  'systemd-suspend-then-hibernate.service',
  'systemd-suspend.service',
]);
const SYSTEMD_GLOBAL_ACTIVATION_DIRECTIVES = new Set([
  'Alias',
  'Also',
  'BindsTo',
  'OnFailure',
  'OnSuccess',
  'Requires',
  'Service',
  'Sockets',
  'Unit',
  'Upholds',
  'Wants',
]);
const SYSTEMD_GLOBAL_ACTION_DIRECTIVES = new Set([
  'EmergencyAction',
  'FailureAction',
  'JobTimeoutAction',
  'StartLimitAction',
  'SuccessAction',
]);
const SYSTEMD_GLOBAL_JOB_MODE_DIRECTIVES = new Set([
  'OnFailureJobMode',
  'OnSuccessJobMode',
]);
const SYSTEMCTL_UNIT_FILE_MUTATION_VERBS = new Set([
  'add-requires',
  'add-wants',
  'disable',
  'edit',
  'enable',
  'link',
  'mask',
  'preset',
  'reenable',
  'revert',
  'set-default',
  'unmask',
]);
const SYSTEMCTL_MARKED_OPTION_PREFIXES = Object.freeze(Array.from(
  { length: '--marked'.length - 2 },
  (_, index) => '--marked'.slice(0, index + 3),
));
const SYSTEMCTL_JOB_MODE_OPTION_PREFIXES = Object.freeze(Array.from(
  { length: '--job-mode'.length - 2 },
  (_, index) => '--job-mode'.slice(0, index + 3),
));
const ENV_SPLIT_STRING_OPTION_PREFIXES = Object.freeze(Array.from(
  { length: '--split-string'.length - 2 },
  (_, index) => '--split-string'.slice(0, index + 3),
));
const ENV_ARGV0_OPTION_PREFIXES = Object.freeze(Array.from(
  { length: '--argv0'.length - 2 },
  (_, index) => '--argv0'.slice(0, index + 3),
));
const SYSTEMD_IMPLICIT_SERVICE_ACTIVATOR_SUFFIXES = Object.freeze([
  '.path',
  '.socket',
  '.timer',
]);
const TRUSTED_MANAGED_MOUNT_ANCESTORS = new Set([
  '/',
  '/etc',
  '/proc',
  '/run',
  '/usr',
  '/var',
  '/var/lib',
]);

class PolicySafetyRollbackError extends Error {}

export const MANAGED_UNITS = Object.freeze([
  'webex-generic-account-bot.service',
  'webex-config-pull-worker.service',
  'webex-codex-launcher.socket',
  'webex-codex-launcher@.service',
  'webex-codex-activation-renew.service',
]);
const MANAGED_UNIT_CONTROL_TARGETS = Object.freeze([
  ...new Set(MANAGED_UNITS.flatMap((unit) => (
    unit.endsWith('.service')
      ? [
        unit,
        ...SYSTEMD_IMPLICIT_SERVICE_ACTIVATOR_SUFFIXES.map(
          (suffix) => `${unit.slice(0, -'.service'.length)}${suffix}`,
        ),
      ]
      : [unit]
  ))),
]);
const MANAGED_UNIT_POLICY_DIRECTORY_NAMES = Object.freeze(
  [...new Set(MANAGED_UNITS.flatMap((unit) => [
    ...systemdDropInDirectoryNames(unit),
    `${unit}.wants`,
    `${unit}.requires`,
    `${unit}.upholds`,
  ]))],
);
const REVERSE_ACTIVATION_PROPERTIES = Object.freeze([
  'RequiredBy',
  'WantedBy',
  'UpheldBy',
  'BoundBy',
  'TriggeredBy',
  'OnFailureOf',
  'OnSuccessOf',
]);
const SYSTEMD_UNIT_FILE_STATES = new Set([
  'alias',
  'disabled',
  'enabled',
  'enabled-runtime',
  'generated',
  'indirect',
  'linked',
  'linked-runtime',
  'masked',
  'masked-runtime',
  'static',
  'transient',
]);

export const ARTIFACTS = Object.freeze([
  policyArtifact(
    'sysusers',
    'webex-codex-launcher.sysusers.conf',
    '/etc/sysusers.d/webex-codex-launcher.conf',
  ),
  policyArtifact(
    'sysusers',
    'webex-codex-runtime.sysusers.conf',
    '/etc/sysusers.d/webex-codex-runtime.conf',
  ),
  policyArtifact(
    'sysusers',
    'webex-config-pull-worker.sysusers.conf',
    '/etc/sysusers.d/webex-config-pull-worker.conf',
  ),
  policyArtifact(
    'sysusers',
    'webex-generic-account-bot.sysusers.conf',
    '/etc/sysusers.d/webex-generic-account-bot.conf',
  ),
  policyArtifact(
    'tmpfiles',
    'webex-codex-activation.tmpfiles.conf',
    '/etc/tmpfiles.d/webex-codex-activation.conf',
  ),
  policyArtifact(
    'tmpfiles',
    'webex-codex-input-staging.tmpfiles.conf',
    '/etc/tmpfiles.d/webex-codex-input-staging.conf',
  ),
  policyArtifact(
    'tmpfiles',
    'webex-codex-launcher.tmpfiles.conf',
    '/etc/tmpfiles.d/webex-codex-launcher.conf',
  ),
  policyArtifact(
    'tmpfiles',
    'webex-codex-runtime.tmpfiles.conf',
    '/etc/tmpfiles.d/webex-codex-runtime.conf',
  ),
  policyArtifact(
    'tmpfiles',
    'webex-config-pull-worker.tmpfiles.conf',
    '/etc/tmpfiles.d/webex-config-pull-worker.conf',
  ),
  policyArtifact(
    'tmpfiles',
    'webex-generic-account-bot.tmpfiles.conf',
    '/etc/tmpfiles.d/webex-generic-account-bot.conf',
  ),
  policyArtifact(
    'unit',
    'webex-codex-activation-renew.service',
    '/etc/systemd/system/webex-codex-activation-renew.service',
  ),
  policyArtifact(
    'unit',
    'webex-codex-launcher.socket',
    '/etc/systemd/system/webex-codex-launcher.socket',
  ),
  policyArtifact(
    'unit',
    'webex-codex-launcher@.service',
    '/etc/systemd/system/webex-codex-launcher@.service',
  ),
  policyArtifact(
    'unit',
    'webex-config-pull-worker.service',
    '/etc/systemd/system/webex-config-pull-worker.service',
  ),
  policyArtifact(
    'unit',
    'webex-generic-account-bot.service',
    '/etc/systemd/system/webex-generic-account-bot.service',
  ),
]);

export function parseArgs(argv) {
  const options = { apply: false, json: false };
  let selectedMode = null;
  for (const arg of argv) {
    if (arg === '--apply') {
      if (selectedMode === 'apply') throw new Error('--apply may be specified only once');
      if (selectedMode === 'dry-run') {
        throw new Error('--dry-run cannot be combined with --apply');
      }
      selectedMode = 'apply';
      options.apply = true;
    } else if (arg === '--dry-run') {
      if (selectedMode === 'apply') {
        throw new Error('--dry-run cannot be combined with --apply');
      }
      if (selectedMode === 'dry-run') {
        throw new Error('--dry-run may be specified only once');
      }
      selectedMode = 'dry-run';
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return Object.freeze(options);
}

export function usage() {
  return [
    'Usage: /opt/webex-generic-account-bot/code/scripts/provision-host [--dry-run] [--json]',
    '       /opt/webex-generic-account-bot/code/scripts/provision-host --apply [--json]',
    '',
    'Dry-run is the default. The production source and target paths are fixed.',
  ].join('\n');
}

export function buildProvisionPlan({
  sourceRoot = SYSTEMD_SOURCE_ROOT,
  targetRoot = '/',
} = {}) {
  const resolvedSourceRoot = path.resolve(sourceRoot);
  const resolvedTargetRoot = path.resolve(targetRoot);
  const artifacts = ARTIFACTS.map((artifact) => Object.freeze({
    ...artifact,
    source: path.join(resolvedSourceRoot, artifact.sourceName),
    target: rootedPath(resolvedTargetRoot, artifact.targetPath),
  }));
  return Object.freeze({
    sourceRoot: resolvedSourceRoot,
    targetRoot: resolvedTargetRoot,
    artifacts: Object.freeze(artifacts),
    sysusers: Object.freeze(
      artifacts.filter(({ kind }) => kind === 'sysusers').map(({ target }) => target),
    ),
    tmpfiles: Object.freeze(
      artifacts.filter(({ kind }) => kind === 'tmpfiles').map(({ target }) => target),
    ),
    units: Object.freeze(
      artifacts.filter(({ kind }) => kind === 'unit').map(({ target }) => target),
    ),
    transactionFile: rootedPath(resolvedTargetRoot, TRANSACTION_PATH),
  });
}

export function parseIdentityDatabases(
  passwdText,
  groupText,
  effectiveGroups = {},
  gshadowText = '',
  shadowText = '',
) {
  const users = new Map();
  for (const line of String(passwdText).split('\n').filter(Boolean)) {
    const fields = line.split(':');
    if (fields.length !== 7 || users.has(fields[0])) {
      throw new Error('passwd database is malformed or contains duplicate users');
    }
    const uid = parseDatabaseId(fields[2], 'passwd UID');
    const gid = parseDatabaseId(fields[3], 'passwd GID');
    users.set(fields[0], Object.freeze({
      name: fields[0],
      password: fields[1],
      uid,
      gid,
      home: fields[5],
      shell: fields[6],
    }));
  }

  const shadowUsers = new Map();
  for (const line of String(shadowText).split('\n').filter(Boolean)) {
    const fields = line.split(':');
    if (fields.length !== 9 || shadowUsers.has(fields[0])) {
      throw new Error('shadow database is malformed or contains duplicate users');
    }
    shadowUsers.set(fields[0], Object.freeze({
      name: fields[0],
      password: fields[1],
    }));
  }

  const groups = new Map();
  for (const line of String(groupText).split('\n').filter(Boolean)) {
    const fields = line.split(':');
    if (fields.length !== 4 || groups.has(fields[0])) {
      throw new Error('group database is malformed or contains duplicate groups');
    }
    const gid = parseDatabaseId(fields[2], 'group GID');
    const members = parseGroupMemberList(fields[3], fields[0], 'member');
    groups.set(fields[0], Object.freeze({
      name: fields[0],
      password: fields[1],
      gid,
      members: Object.freeze([...members]),
    }));
  }

  const shadowGroups = new Map();
  for (const line of String(gshadowText).split('\n').filter(Boolean)) {
    const fields = line.split(':');
    if (fields.length !== 4 || shadowGroups.has(fields[0])) {
      throw new Error('gshadow database is malformed or contains duplicate groups');
    }
    const administrators = parseGroupMemberList(fields[2], fields[0], 'administrator');
    const members = parseGroupMemberList(fields[3], fields[0], 'shadow member');
    shadowGroups.set(fields[0], Object.freeze({
      name: fields[0],
      password: fields[1],
      administrators,
      members,
    }));
  }

  const effective = new Map();
  for (const [user, gids] of Object.entries(effectiveGroups)) {
    if (!Array.isArray(gids) || gids.some((gid) => !Number.isSafeInteger(gid) || gid < 0)) {
      throw new Error(`effective group list is invalid: ${user}`);
    }
    effective.set(user, new Set(gids));
  }
  return Object.freeze({
    users,
    shadowUsers,
    groups,
    shadowGroups,
    effectiveGroups: effective,
  });
}

export function validateNsswitchPolicy(contents) {
  const databases = new Map();
  for (const rawLine of String(contents).split('\n')) {
    const line = rawLine.split('#', 1)[0].trim();
    if (line === '') continue;
    const separator = line.indexOf(':');
    if (separator <= 0) throw new Error('nsswitch policy is malformed');
    const database = line.slice(0, separator).trim();
    if (databases.has(database)) throw new Error(`nsswitch database is duplicated: ${database}`);
    databases.set(database, line.slice(separator + 1).trim().split(/\s+/).filter(Boolean));
  }
  for (const database of ['passwd', 'group']) {
    if (JSON.stringify(databases.get(database)) !== JSON.stringify(['files', 'systemd'])) {
      throw new Error(`unsupported NSS policy for ${database}`);
    }
  }
  for (const database of ['shadow', 'gshadow']) {
    const policy = databases.get(database);
    if (
      JSON.stringify(policy) !== JSON.stringify(['files'])
      && JSON.stringify(policy) !== JSON.stringify(['files', 'systemd'])
    ) {
      throw new Error(`unsupported NSS policy for ${database}`);
    }
  }
  if (
    databases.has('initgroups')
    && JSON.stringify(databases.get('initgroups')) !== JSON.stringify(['files', 'systemd'])
  ) {
    throw new Error('unsupported NSS policy for initgroups');
  }
}

export function validateIdentityPolicy(snapshot, { requireAccounts = false } = {}) {
  const bot = snapshot.users.get(MANAGED_USERS.bot);
  const worker = snapshot.users.get(MANAGED_USERS.worker);
  const controlledGroups = Object.values(MANAGED_GROUPS);
  const expectedPrimaryUsers = new Map([
    [MANAGED_GROUPS.bot, new Set([MANAGED_USERS.bot])],
    [MANAGED_GROUPS.configDeploy, new Set([MANAGED_USERS.worker])],
    [MANAGED_GROUPS.configPull, new Set()],
    [MANAGED_GROUPS.codexInput, new Set()],
    [MANAGED_GROUPS.codexLaunch, new Set()],
  ]);

  if (requireAccounts) {
    for (const user of Object.values(MANAGED_USERS)) {
      if (!snapshot.users.has(user)) throw new Error(`managed user is missing: ${user}`);
    }
    for (const group of controlledGroups) {
      if (!snapshot.groups.has(group)) throw new Error(`managed group is missing: ${group}`);
    }
  }

  for (const user of [bot, worker].filter(Boolean)) {
    if (
      user.uid === 0
      || user.gid === 0
      || user.uid > MAX_MANAGED_ID
      || user.gid > MAX_MANAGED_ID
    ) {
      throw new Error(`managed user ID is outside the local range: ${user.name}`);
    }
    const aliases = [...snapshot.users.values()]
      .filter((candidate) => candidate.uid === user.uid)
      .map((candidate) => candidate.name);
    if (aliases.length !== 1) {
      throw new Error(`managed user UID has aliases: ${user.name}`);
    }
    assertManagedUserCredentialLocked(user, snapshot.shadowUsers.get(user.name));
  }
  for (const user of Object.values(MANAGED_USERS)) {
    if (!snapshot.users.has(user) && snapshot.shadowUsers.has(user)) {
      throw new Error(`managed user has an orphan shadow credential: ${user}`);
    }
  }
  for (const user of snapshot.users.values()) {
    if (![...snapshot.groups.values()].some((group) => group.gid === user.gid)) {
      throw new Error(`static user primary GID has no group: ${user.name} (${user.gid})`);
    }
  }
  for (const groupName of controlledGroups) {
    const group = snapshot.groups.get(groupName);
    const shadowGroup = snapshot.shadowGroups.get(groupName);
    if (!group) {
      if (shadowGroup) {
        throw new Error(`managed group has an orphan shadow credential: ${groupName}`);
      }
      continue;
    }
    if (group.gid === 0 || group.gid > MAX_MANAGED_ID) {
      throw new Error(`managed group ID is outside the local range: ${groupName}`);
    }
    const aliases = [...snapshot.groups.values()]
      .filter((candidate) => candidate.gid === group.gid)
      .map((candidate) => candidate.name);
    if (aliases.length !== 1) {
      throw new Error(`managed group GID has aliases: ${groupName}`);
    }
    if (group.members.length !== 0) {
      throw new Error(`managed group has static members: ${groupName}`);
    }
    assertManagedGroupCredentialLocked(group, shadowGroup);
    const primaryUsers = [...snapshot.users.values()]
      .filter((user) => user.gid === group.gid)
      .map((user) => user.name);
    const allowed = expectedPrimaryUsers.get(groupName);
    for (const user of primaryUsers) {
      if (!allowed.has(user)) {
        throw new Error(`managed group is a static primary group for ${user}: ${groupName}`);
      }
    }
  }
  for (const group of snapshot.groups.values()) {
    if (controlledGroups.includes(group.name)) continue;
    for (const user of Object.values(MANAGED_USERS)) {
      if (group.members.includes(user)) {
        throw new Error(`managed user has static group privileges: ${user} (${group.name})`);
      }
    }
  }

  for (const shadowGroup of snapshot.shadowGroups.values()) {
    for (const user of Object.values(MANAGED_USERS)) {
      if (
        shadowGroup.administrators.includes(user)
        || shadowGroup.members.includes(user)
      ) {
        throw new Error(
          `managed user has shadow-group privileges: ${user} (${shadowGroup.name})`,
        );
      }
    }
  }

  if (bot) {
    assertAccountContract(bot, MANAGED_ACCOUNTS.bot);
    assertPrimaryGroup(snapshot, bot, MANAGED_GROUPS.bot);
    assertExactEffectiveGroups(snapshot, bot);
  }
  if (worker) {
    assertAccountContract(worker, MANAGED_ACCOUNTS.worker);
    assertPrimaryGroup(snapshot, worker, MANAGED_GROUPS.configDeploy);
    assertExactEffectiveGroups(snapshot, worker);
  }
}

export async function provisionHost(options, dependencies = {}) {
  const deps = provisionDependencies(dependencies);
  const plan = dependencies.plan ?? buildProvisionPlan();
  if (plan.targetRoot !== '/' && !deps.allowTestRoot) {
    throw new Error('non-production target roots are test-only');
  }
  if (deps.requireRoot && deps.processApi.geteuid?.() !== 0) {
    throw new Error('host provisioning requires root, including dry-run');
  }
  if (
    options.apply
    && deps.requirePrivateMountNamespace
    && deps.processApi.env?.[PRIVATE_MOUNT_NAMESPACE_ENV] !== '1'
  ) {
    throw new Error('host provisioning apply requires the private mount namespace re-exec');
  }
  await deps.verifyPidNamespace();
  await deps.verifyMountNamespace('inspection');
  await deps.verifyLegacyPaths();
  const verifyRuntimeAncestors = dependencies.verifyRuntimeAncestors
    ?? ((runtimeInspected) => assertManagedRuntimeAncestorsTraversable(
      plan,
      runtimeInspected,
      {
        fsApi: deps.fsApi,
        targetUid: deps.targetUid,
        targetGid: deps.targetGid,
        verifyNoExtendedPosixAcl: deps.verifyNoExtendedPosixAcl,
      },
    ));
  const verifyManagedRuntimeState = dependencies.verifyManagedRuntimeState
    ?? ((runtimeInspected, snapshot) => verifyManagedTmpfilesState(
      plan,
      runtimeInspected,
      snapshot,
      {
        fsApi: deps.fsApi,
        targetUid: deps.targetUid,
        targetGid: deps.targetGid,
        verifyNoExtendedPosixAcl: deps.verifyNoExtendedPosixAcl,
      },
    ));

  const transaction = await readProvisionTransaction(plan, deps);
  if (transaction && !options.apply && !options.recoveryPreflight) {
    throw new Error('host policy recovery is required; run --apply');
  }
  const commands = [];
  let identityBefore = null;
  let identityRecoveryRequired = false;
  let recoveryState = null;
  if (transaction) {
    const transactionInspection = await inspectPolicyTransactionRecovery(transaction, plan, deps);
    identityBefore = await deps.readIdentitySnapshot();
    if (transactionInspection.resumeDesiredState || transaction.identityRecoveryRequired) {
      try {
        validateIdentityPolicy(identityBefore);
      } catch {
        await deps.recoverIdentityDatabases(transaction, identityBefore, {
          apply: false,
        });
        identityRecoveryRequired = true;
      }
    } else {
      validateIdentityPolicy(identityBefore);
    }
    const recoveryUnitStates = await deps.readUnitStates(MANAGED_UNITS, identityBefore);
    const recoveryInspected = await inspectArtifacts(plan, deps);
    auditBootPolicyCatalogs(
      await deps.readBootPolicyCatalogs(),
      recoveryInspected,
      identityBefore,
    );
    assertNoUnexpectedManagedMounts(
      plan,
      recoveryInspected,
      await deps.readMountInfo(),
    );
    await verifyRuntimeAncestors(recoveryInspected);
    assertUnitsDormant(recoveryUnitStates, plan, {
      requireLoaded: false,
      allowDaemonReloadRequired: true,
    });
    if (options.recoveryPreflight) {
      return provisionReport('dry-run', plan, recoveryInspected, commands);
    }
    if (identityRecoveryRequired) {
      await deps.recoverIdentityDatabases(transaction, identityBefore, { apply: true });
      identityBefore = await deps.readIdentitySnapshot();
      validateIdentityPolicy(identityBefore);
      identityRecoveryRequired = false;
    }
    recoveryState = await recoverPolicyTransaction(transaction, plan, deps);
    try {
      await deps.verifyMountNamespace('daemon-reload-recovery');
      commands.push(await deps.runCommand('/usr/bin/systemctl', ['daemon-reload']));
      const recoveredUnitStates = await deps.readUnitStates(MANAGED_UNITS, identityBefore);
      assertUnitsDormant(recoveredUnitStates, plan, { requireLoaded: false });
    } catch (error) {
      if (recoveryState === 'desired') {
        await rollbackPolicyAfterSafetyFailure(
          error,
          transaction,
          plan,
          deps,
          commands,
          identityBefore,
          identityRecoveryRequired,
        );
      }
      throw new Error(
        `host policy recovery finalisation failed; rerun --apply after correction: ${error.message}`,
        { cause: error },
      );
    }
  }

  if (identityBefore === null) {
    identityBefore = await deps.readIdentitySnapshot();
    validateIdentityPolicy(identityBefore);
  }
  const unitStatesBefore = await deps.readUnitStates(MANAGED_UNITS, identityBefore);
  const inspected = await inspectArtifacts(plan, deps);
  auditBootPolicyCatalogs(
    await deps.readBootPolicyCatalogs(),
    inspected,
    identityBefore,
  );
  assertNoUnexpectedManagedMounts(plan, inspected, await deps.readMountInfo());
  await verifyRuntimeAncestors(inspected);
  const canRecoverManagerCache = (options.apply || options.recoveryPreflight)
    && inspected.artifacts.every(({ changed }) => !changed);
  assertUnitsDormant(unitStatesBefore, plan, {
    requireLoaded: false,
    allowDaemonReloadRequired: canRecoverManagerCache,
  });
  if (unitStatesNeedDaemonReload(unitStatesBefore)) {
    if (options.recoveryPreflight) {
      return provisionReport('dry-run', plan, inspected, commands);
    }
    await deps.verifyMountNamespace('daemon-reload-cache');
    commands.push(await deps.runCommand('/usr/bin/systemctl', ['daemon-reload']));
    const reloadedUnitStates = await deps.readUnitStates(MANAGED_UNITS, identityBefore);
    assertUnitsDormant(reloadedUnitStates, plan, { requireLoaded: true });
  }
  if (!options.apply) {
    return provisionReport('dry-run', plan, inspected, commands);
  }

  const identityFilesBefore = await deps.readIdentityFileState(identityBefore);
  await cleanupStaleCandidates(plan, deps);
  await ensureTargetDirectories(plan, deps);
  const installed = await installPolicySetAtomically(inspected, plan, deps, {
    identityRecoveryRequired,
    identityFiles: identityFilesBefore,
  });
  const safetyRollbackTransaction = transactionFromInspected(inspected, {
    identityFiles: identityFilesBefore,
  });
  try {
    const mountsBeforeSysusers = assertNoUnexpectedManagedMounts(
      plan,
      inspected,
      await deps.readMountInfo(),
    );
    await deps.verifyMountNamespace('systemd-sysusers');
    commands.push(await deps.runCommand('/usr/bin/systemd-sysusers', plan.sysusers));
    const mountsAfterSysusers = assertNoUnexpectedManagedMounts(
      plan,
      inspected,
      await deps.readMountInfo(),
    );
    assertProtectedMountSnapshotUnchanged(mountsBeforeSysusers, mountsAfterSysusers);
    const identityAfter = await deps.readIdentitySnapshot();
    validateIdentityPolicy(identityAfter, { requireAccounts: true });
    auditBootPolicyCatalogs(
      await deps.readBootPolicyCatalogs(),
      inspected,
      identityAfter,
      { requireManagedPolicy: true },
    );
    const mountsBeforeTmpfiles = assertNoUnexpectedManagedMounts(
      plan,
      inspected,
      await deps.readMountInfo(),
    );
    await deps.verifyMountNamespace('systemd-tmpfiles');
    commands.push(await deps.runCommand('/usr/bin/systemd-tmpfiles', [
      '--create',
      ...plan.tmpfiles,
    ]));
    const mountsAfterTmpfiles = assertNoUnexpectedManagedMounts(
      plan,
      inspected,
      await deps.readMountInfo(),
    );
    assertProtectedMountSnapshotUnchanged(mountsBeforeTmpfiles, mountsAfterTmpfiles);
    await verifyManagedRuntimeState(inspected, identityAfter);
    await deps.verifyProvisionLockConverged();
    const managerMountsBeforeReload = await inspectManagerPolicyView(plan, inspected, deps);
    await deps.verifyMountNamespace('daemon-reload-final');
    commands.push(await deps.runCommand('/usr/bin/systemctl', ['daemon-reload']));
    const managerMountsAfterReload = await inspectManagerPolicyView(plan, inspected, deps);
    assertProtectedMountSnapshotUnchanged(
      managerMountsBeforeReload,
      managerMountsAfterReload,
    );
    await verifyInstalledArtifacts(inspected, deps);
    const identityFinal = await deps.readIdentitySnapshot();
    validateIdentityPolicy(identityFinal, { requireAccounts: true });
    auditBootPolicyCatalogs(
      await deps.readBootPolicyCatalogs(),
      inspected,
      identityFinal,
      { requireManagedPolicy: true },
    );
    assertNoUnexpectedManagedMounts(plan, inspected, await deps.readMountInfo());
    await verifyManagedRuntimeState(inspected, identityFinal);
    await deps.verifyProvisionLockConverged();
    try {
      const unitStatesAfter = await deps.readUnitStates(MANAGED_UNITS, identityFinal);
      assertUnitsDormant(unitStatesAfter, plan, { requireLoaded: true });
    } catch (error) {
      await rollbackPolicyAfterSafetyFailure(
        error,
        safetyRollbackTransaction,
        plan,
        deps,
        commands,
        identityAfter,
        false,
      );
    }
    await removeProvisionTransaction(plan, deps);
  } catch (error) {
    if (error instanceof PolicySafetyRollbackError) throw error;
    throw new Error(
      `host policy files are installed but convergence failed; rerun --apply after correction: ${error.message}`,
      { cause: error },
    );
  }
  return provisionReport('applied', plan, inspected, commands, installed);
}

export async function runCli({
  argv = process.argv.slice(2),
  stdout = process.stdout,
  dependencies = {},
  lockHeld = process.env[PROVISION_LOCK_ENV] === '1',
  privateMountNamespace = process.env[PRIVATE_MOUNT_NAMESPACE_ENV] === '1',
  runLockedApply = executeLockedApply,
  verifyLockedApply = assertProvisionLockHeld,
} = {}) {
  const options = parseArgs(argv);
  if (options.help) {
    stdout.write(`${usage()}\n`);
    return 0;
  }
  if (options.apply && !lockHeld) {
    return runLockedApply(argv);
  }
  if (options.apply && !privateMountNamespace) {
    throw new Error('locked host provisioning apply requires a private mount namespace');
  }
  if (options.apply) await verifyLockedApply();
  const report = await provisionHost(options, dependencies);
  if (options.json) {
    stdout.write(`${JSON.stringify(report)}\n`);
  } else {
    stdout.write(`mode=${report.mode}\n`);
    stdout.write(`artifact_count=${report.artifact_count}\n`);
    stdout.write(`changed_artifact_count=${report.changed_artifact_count}\n`);
    stdout.write('units_started=0\nunits_enabled=0\n');
  }
  return 0;
}

export function buildLockedApplyCommand({
  argv,
  nodePath = process.execPath,
  unsharePath = '/usr/bin/unshare',
} = {}) {
  if (!Array.isArray(argv) || !argv.includes('--apply')) {
    throw new Error('locked provision command requires --apply');
  }
  return Object.freeze({
    command: '/usr/bin/flock',
    args: Object.freeze([
      '--exclusive',
      '--nonblock',
      '--no-fork',
      '--conflict-exit-code',
      String(PROVISION_LOCK_CONFLICT_EXIT),
      PROVISION_LOCK_PATH,
      unsharePath,
      '--mount',
      '--propagation',
      'private',
      '--',
      nodePath,
      '--input-type=module',
      '--eval',
      FD_REEXEC_BOOTSTRAP,
      '--',
      ...argv,
    ]),
  });
}

export function hasProvisionLock(locksText, pid, stat) {
  const expectedPid = String(pid);
  const expectedInode = String(stat.ino);
  const expectedDevice = linuxDeviceNumbers(stat.dev);
  return String(locksText).split('\n').some((line) => {
    const match = line.match(
      /^\d+:\s+FLOCK\s+\S+\s+WRITE\s+(\d+)\s+([0-9a-f]+):([0-9a-f]+):(\d+)\s+\d+\s+EOF$/i,
    );
    return match?.[1] === expectedPid
      && BigInt(`0x${match[2]}`) === expectedDevice.major
      && BigInt(`0x${match[3]}`) === expectedDevice.minor
      && match[4] === expectedInode;
  });
}

export function hasIdentityLock(locksText, pid, stat) {
  const expectedPid = String(pid);
  const expectedInode = String(stat.ino);
  const expectedDevice = linuxDeviceNumbers(stat.dev);
  return String(locksText).split('\n').some((line) => {
    const match = line.match(
      /^\d+:\s+POSIX\s+ADVISORY\s+WRITE\s+(\d+)\s+([0-9a-f]+):([0-9a-f]+):(\d+)\s+0\s+(?:0|EOF)$/i,
    );
    return match?.[1] === expectedPid
      && BigInt(`0x${match[2]}`) === expectedDevice.major
      && BigInt(`0x${match[3]}`) === expectedDevice.minor
      && match[4] === expectedInode;
  });
}

export async function executeLockedApply(argv, {
  fsApi = fs,
  nodePath = process.execPath,
  scriptPath = PROVISION_SCRIPT_PATH,
  verifyReexecFile = assertTrustedReexecFile,
  preflightHost = () => provisionHost({
    apply: false,
    recoveryPreflight: true,
  }),
  ensureLock = ensureProvisionLockFile,
  openExecutable = (file) => openTrustedExecutable(file, fsApi),
  openScript = (file) => openTrustedPolicyScript(file, fsApi),
  spawnProcess = spawn,
} = {}) {
  await verifyReexecFile(nodePath, { executable: true }, fsApi);
  await verifyReexecFile(scriptPath, { mode: FILE_MODE }, fsApi);
  await verifyReexecFile('/usr/bin/flock', { executable: true }, fsApi);
  await verifyReexecFile('/usr/bin/unshare', { executable: true }, fsApi);
  await verifyReexecFile(IDENTITY_LOCK_HELPER_PATH, { executable: true }, fsApi);
  await preflightHost();
  await ensureLock(fsApi, () => assertSameMountNamespace(fsApi));
  const reexecHandles = [];
  try {
    reexecHandles.push(await openExecutable('/usr/bin/flock'));
    reexecHandles.push(await openExecutable('/usr/bin/unshare'));
    reexecHandles.push(await openExecutable(nodePath));
    reexecHandles.push(await openScript(scriptPath));
    const [flockHandle, unshareHandle, nodeHandle, scriptHandle] = reexecHandles;
    const command = buildLockedApplyCommand({
      argv,
      nodePath: '/proc/self/fd/4',
      unsharePath: '/proc/self/fd/3',
    });
    return await new Promise((resolve, reject) => {
      const child = spawnProcess(`/proc/self/fd/${flockHandle.fd}`, command.args, {
        argv0: '/usr/bin/flock',
        cwd: '/',
        env: {
          PATH: '/usr/bin:/bin',
          LANG: 'C.UTF-8',
          LC_ALL: 'C.UTF-8',
          [PROVISION_LOCK_ENV]: '1',
          [PRIVATE_MOUNT_NAMESPACE_ENV]: '1',
          [SOURCE_ROOT_ENV]: path.resolve(path.dirname(scriptPath), '../deploy/systemd'),
        },
        stdio: [
          'inherit',
          'inherit',
          'inherit',
          unshareHandle.fd,
          nodeHandle.fd,
          scriptHandle.fd,
        ],
      });
      child.once('error', reject);
      child.once('exit', (code, signal) => {
        if (signal) {
          reject(new Error(`locked provision command terminated by signal ${signal}`));
          return;
        }
        resolve(code ?? 1);
      });
    });
  } finally {
    await Promise.all(reexecHandles.map((handle) => handle.close()));
  }
}

export async function executeIdentityRecovery({
  fsApi = fs,
  openExecutable = (file) => openTrustedExecutable(file, fsApi),
  processApi = process,
  resolveProvisionLock = (options) => assertProvisionLockHeld({
    ...options,
    fsApi,
    processApi,
  }),
  spawnProcess = spawn,
  allowTestInvocation = false,
} = {}) {
  if (!allowTestInvocation && (
    process.env[PROVISION_LOCK_ENV] !== '1'
    || process.env[PRIVATE_MOUNT_NAMESPACE_ENV] !== '1'
    || PROVISION_SCRIPT_PATH !== FD_REEXEC_SCRIPT_PATH
  )) {
    throw new Error('identity recovery requires the locked private host provisioner');
  }
  const provisionLock = await resolveProvisionLock({
    allowInterruptedMigration: true,
  });
  if (!Number.isInteger(provisionLock?.fd) || provisionLock.fd < 3) {
    throw new Error('identity recovery requires the inherited host provision lock descriptor');
  }
  const helper = await openExecutable(IDENTITY_LOCK_HELPER_PATH);
  try {
    return await new Promise((resolve, reject) => {
      const child = spawnProcess(`/proc/self/fd/${helper.fd}`, [], {
        argv0: IDENTITY_LOCK_HELPER_PATH,
        cwd: '/',
        env: {
          PATH: '/usr/bin:/bin',
          LANG: 'C.UTF-8',
          LC_ALL: 'C.UTF-8',
          [IDENTITY_LOCK_PARENT_PID_ENV]: String(processApi.pid),
        },
        stdio: ['inherit', 'inherit', 'inherit', 4, 'ignore', 5, provisionLock.fd],
      });
      child.once('error', reject);
      child.once('exit', (code, signal) => {
        if (signal) {
          reject(new Error(`identity recovery process terminated by signal ${signal}`));
          return;
        }
        if (code !== 0) {
          reject(new Error(`identity recovery process failed with exit code ${code ?? 1}`));
          return;
        }
        resolve();
      });
    });
  } finally {
    await helper.close();
  }
}

export async function runIdentityRecoveryChild({
  dependencies = {},
  allowTestInvocation = false,
  restoreIdentityDatabases = restoreInterruptedIdentityDatabases,
} = {}) {
  const deps = provisionDependencies(dependencies);
  const plan = dependencies.plan ?? buildProvisionPlan();
  if (!allowTestInvocation && process.env[IDENTITY_RECOVERY_CHILD_ENV] !== '1') {
    throw new Error('identity recovery process invocation is not authorised');
  }
  if (plan.targetRoot !== '/' && !deps.allowTestRoot) {
    throw new Error('non-production target roots are test-only');
  }
  if (deps.requireRoot && deps.processApi.geteuid?.() !== 0) {
    throw new Error('identity recovery process requires root');
  }
  await deps.verifyIdentityLock();
  await deps.verifyPidNamespace();
  await deps.verifyMountNamespace('identity-recovery-inspection');
  await deps.verifyLegacyPaths();
  const transaction = await readProvisionTransaction(plan, deps);
  if (!transaction) throw new Error('identity recovery transaction is missing');
  const transactionInspection = await inspectPolicyTransactionRecovery(transaction, plan, deps);
  if (!transactionInspection.resumeDesiredState && !transaction.identityRecoveryRequired) {
    throw new Error('identity recovery is not permitted for this transaction state');
  }
  const snapshot = await deps.readIdentitySnapshot();
  let recoveryRequired = false;
  try {
    validateIdentityPolicy(snapshot);
  } catch {
    recoveryRequired = true;
    await restoreIdentityDatabases(transaction, snapshot, {
      apply: false,
      fsApi: deps.fsApi,
      verifyMountNamespace: deps.verifyMountNamespace,
      readMountInfo: deps.readMountInfo,
      verifyIdentityLock: deps.verifyIdentityLock,
    });
  }
  if (!recoveryRequired) throw new Error('identity recovery is not required');
  const recoveryUnitStates = await deps.readUnitStates(MANAGED_UNITS, snapshot);
  assertUnitsDormant(recoveryUnitStates, plan, {
    requireLoaded: false,
    allowDaemonReloadRequired: true,
  });
  const recoveryInspected = await inspectArtifacts(plan, deps);
  auditBootPolicyCatalogs(
    await deps.readBootPolicyCatalogs(),
    recoveryInspected,
    snapshot,
  );
  assertNoUnexpectedManagedMounts(plan, recoveryInspected, await deps.readMountInfo());
  await assertManagedRuntimeAncestorsTraversable(plan, recoveryInspected, {
    fsApi: deps.fsApi,
    targetUid: deps.targetUid,
    targetGid: deps.targetGid,
    verifyNoExtendedPosixAcl: deps.verifyNoExtendedPosixAcl,
  });
  const finalRecoveryUnitStates = await deps.readUnitStates(MANAGED_UNITS, snapshot);
  assertUnitsDormant(finalRecoveryUnitStates, plan, {
    requireLoaded: false,
    allowDaemonReloadRequired: true,
  });
  await restoreIdentityDatabases(transaction, snapshot, {
    apply: true,
    fsApi: deps.fsApi,
    verifyMountNamespace: deps.verifyMountNamespace,
    readMountInfo: deps.readMountInfo,
    verifyIdentityLock: deps.verifyIdentityLock,
  });
  validateIdentityPolicy(await deps.readIdentitySnapshot());
  return 0;
}

async function assertProvisionLockHeld({
  allowInterruptedMigration = true,
  fsApi = fs,
  processApi = process,
} = {}) {
  const configPullGid = await readConfigPullGroupGid(fsApi);
  const parentStat = await fsApi.lstat(PROVISION_LOCK_PARENT);
  const lockPolicy = assertTrustedProvisionLockParent(
    parentStat,
    configPullGid,
    { allowInterruptedMigration },
  );
  const lock = await fsApi.open(
    PROVISION_LOCK_PATH,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  let stat;
  try {
    stat = await lock.stat();
    assertTrustedProvisionLock(stat, lockPolicy, { allowInterruptedMigration });
  } finally {
    await lock.close();
  }
  const procLocks = await readBoundedProcFile('/proc/locks', MAX_PROC_LOCKS_BYTES, fsApi);
  if (!hasProvisionLock(procLocks, processApi.pid, stat)) {
    throw new Error('current process does not hold the host provision lock');
  }
  return Object.freeze({
    fd: await findOpenFileDescriptor(stat, { fsApi }),
    stat,
  });
}

export async function findOpenFileDescriptor(
  expected,
  { fsApi = fs, procFdRoot = '/proc/self/fd' } = {},
) {
  const entries = await fsApi.readdir(procFdRoot);
  if (entries.length > MAX_PROC_FD_ENTRIES) {
    throw new Error('process file descriptor table exceeds the audit limit');
  }
  const matches = [];
  for (const entry of entries) {
    if (!/^[0-9]+$/.test(entry)) continue;
    const fd = Number(entry);
    if (!Number.isSafeInteger(fd) || fd < 3) continue;
    let stat;
    try {
      stat = await fsApi.stat(path.join(procFdRoot, entry));
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw error;
    }
    if (stat.dev === expected.dev && stat.ino === expected.ino) matches.push(fd);
  }
  if (matches.length !== 1) {
    throw new Error('host provision lock descriptor is missing or ambiguous');
  }
  return matches[0];
}

export async function assertIdentityLockHeld({
  fsApi = fs,
  processApi = process,
  statFd = fstatAsync,
} = {}) {
  const lockPid = processApi.env?.[IDENTITY_LOCK_PID_ENV];
  if (!/^[1-9][0-9]*$/.test(lockPid ?? '') || String(processApi.pid) !== lockPid) {
    throw new Error('identity recovery process is not the identity lock holder');
  }
  const rawLockFd = processApi.env?.[IDENTITY_LOCK_FD_ENV];
  const lockFd = Number(rawLockFd);
  if (
    !/^[1-9][0-9]*$/.test(rawLockFd ?? '')
    || !Number.isSafeInteger(lockFd)
    || lockFd < 3
    || String(lockFd) !== rawLockFd
  ) {
    throw new Error('identity recovery lock descriptor is invalid');
  }
  await assertTrustedDirectoryChain('/', path.dirname(IDENTITY_LOCK_PATH), 0, 0, fsApi);
  const mountsBeforeInspection = assertNoUnexpectedMountsForPaths(
    new Set([IDENTITY_LOCK_PATH]),
    await readBoundedProcFile('/proc/self/mountinfo', MAX_MOUNTINFO_BYTES, fsApi),
  );
  const pathStat = await fsApi.lstat(IDENTITY_LOCK_PATH);
  const stat = await statFd(lockFd);
  if (
    !pathStat.isFile()
    || pathStat.isSymbolicLink()
    || !stat.isFile()
    || stat.isSymbolicLink()
    || pathStat.nlink !== 1
    || stat.nlink !== 1
    || pathStat.uid !== 0
    || stat.uid !== 0
    || pathStat.gid !== 0
    || stat.gid !== 0
    || ((pathStat.mode & 0o7777) & 0o077) !== 0
    || ((stat.mode & 0o7777) & 0o077) !== 0
    || !sameFileIdentity(pathStat, stat)
  ) {
    throw new Error('system identity database lock file is not trusted');
  }
  if (await findOpenFileDescriptor(stat, { fsApi }) !== lockFd) {
    throw new Error('identity recovery lock descriptor does not match the inherited lock');
  }
  const procLocks = await readBoundedProcFile('/proc/locks', MAX_PROC_LOCKS_BYTES, fsApi);
  if (!hasIdentityLock(procLocks, lockPid, stat)) {
    throw new Error('identity recovery process does not hold the system identity lock');
  }
  const pathAfter = await fsApi.lstat(IDENTITY_LOCK_PATH);
  const statAfter = await statFd(lockFd);
  if (!sameFileIdentity(pathStat, pathAfter) || !sameFileIdentity(stat, statAfter)) {
    throw new Error('system identity database lock file changed during inspection');
  }
  const mountsAfterInspection = assertNoUnexpectedMountsForPaths(
    new Set([IDENTITY_LOCK_PATH]),
    await readBoundedProcFile('/proc/self/mountinfo', MAX_MOUNTINFO_BYTES, fsApi),
  );
  assertProtectedMountSnapshotUnchanged(mountsBeforeInspection, mountsAfterInspection);
}

function linuxDeviceNumbers(device) {
  const value = BigInt(device);
  return Object.freeze({
    major: ((value >> 8n) & 0xfffn) | ((value >> 32n) & 0xfffff000n),
    minor: (value & 0xffn) | ((value >> 12n) & 0xffffff00n),
  });
}

async function inspectArtifacts(plan, deps) {
  await assertTrustedDirectoryChain(
    deps.sourceTrustRoot,
    plan.sourceRoot,
    deps.sourceUid,
    deps.sourceGid,
    deps.fsApi,
  );
  const artifacts = [];
  for (const artifact of plan.artifacts) {
    const source = await readTrustedFile(
      artifact.source,
      deps.sourceUid,
      deps.sourceGid,
      FILE_MODE,
      deps.fsApi,
    );
    await assertTrustedExistingAncestors(
      plan.targetRoot,
      path.dirname(artifact.target),
      deps.targetUid,
      deps.targetGid,
      deps.fsApi,
    );
    const existing = await readOptionalTrustedFile(
      artifact.target,
      deps.targetUid,
      deps.targetGid,
      FILE_MODE,
      deps.fsApi,
    );
    artifacts.push(Object.freeze({
      ...artifact,
      sourcePath: artifact.source,
      source,
      existing,
      changed: existing?.sha256 !== source.sha256,
    }));
  }
  return Object.freeze({ artifacts: Object.freeze(artifacts) });
}

async function ensureTargetDirectories(plan, deps) {
  const directories = new Set(plan.artifacts.map(({ target }) => path.dirname(target)));
  for (const directory of directories) {
    await createTrustedDirectoryChain(
      plan.targetRoot,
      directory,
      deps.targetUid,
      deps.targetGid,
      deps.fsApi,
      deps.verifyMountNamespace,
    );
  }
}

async function cleanupStaleCandidates(plan, deps) {
  const targets = [...plan.artifacts.map(({ target }) => target), plan.transactionFile];
  const targetDirectories = new Set(targets.map((target) => path.dirname(target)));

  let candidateCount = 0;
  let scannedEntryCount = 0;
  const candidates = [];
  for (const directory of targetDirectories) {
    await assertTrustedExistingAncestors(
      plan.targetRoot,
      directory,
      deps.targetUid,
      deps.targetGid,
      deps.fsApi,
    );
    let directoryHandle;
    try {
      directoryHandle = await deps.fsApi.opendir(directory);
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw error;
    }
    try {
      for await (const entry of directoryHandle) {
        scannedEntryCount += 1;
        if (scannedEntryCount > MAX_SCANNED_DIRECTORY_ENTRIES) {
          throw new Error('too many policy directory entries');
        }
        if (!entry.name.startsWith(PROVISION_CANDIDATE_PREFIX)) continue;
        candidateCount += 1;
        if (candidateCount > MAX_STALE_CANDIDATES) {
          throw new Error('too many stale policy candidates');
        }
        const suffix = entry.name.slice(PROVISION_CANDIDATE_PREFIX.length);
        if (!new RegExp(`^${CANDIDATE_UUID_PATTERN}\\.tmp$`).test(suffix)) {
          throw new Error(`stale policy candidate name is malformed: ${entry.name}`);
        }
        const candidate = path.join(directory, entry.name);
        const stat = await deps.fsApi.lstat(candidate);
        const mode = stat.mode & 0o7777;
        assertTrustedFileMetadata(candidate, stat, deps.targetUid, deps.targetGid, null);
        const interruptedCreation = (mode & ~0o600) === 0;
        if (!stat.isFile() || (!interruptedCreation && mode !== FILE_MODE)) {
          throw new Error(`stale policy candidate metadata is not trusted: ${candidate}`);
        }
        candidates.push(Object.freeze({ candidate, directory, stat }));
      }
    } finally {
      try {
        await directoryHandle.close();
      } catch (error) {
        if (error?.code !== 'ERR_DIR_CLOSED') throw error;
      }
    }
  }

  const changedDirectories = new Set();
  for (const { candidate, directory, stat } of candidates) {
    const current = await deps.fsApi.lstat(candidate);
    const mode = current.mode & 0o7777;
    assertTrustedFileMetadata(candidate, current, deps.targetUid, deps.targetGid, null);
    if (
      !sameFileIdentity(stat, current)
      || ((mode & ~0o600) !== 0 && mode !== FILE_MODE)
    ) {
      throw new Error(`stale policy candidate changed before cleanup: ${candidate}`);
    }
    await deps.verifyMountNamespace('stale-candidate-remove');
    await deps.fsApi.rm(candidate);
    changedDirectories.add(directory);
  }
  for (const directory of changedDirectories) {
    await syncDirectory(directory, deps.fsApi);
  }
}

async function installPolicySetAtomically(
  inspected,
  plan,
  deps,
  { identityRecoveryRequired = false, identityFiles } = {},
) {
  const changed = inspected.artifacts.filter(({ changed }) => changed);
  const staged = [];
  const rollbackTransaction = transactionFromInspected(inspected, {
    identityRecoveryRequired,
    identityFiles,
  });
  await writeProvisionTransaction(inspected, plan, deps, {
    identityRecoveryRequired,
    identityFiles,
  });
  if (changed.length === 0) return [];
  try {
    for (const artifact of changed) {
      const temporary = await writeCandidate(
        artifact.target,
        artifact.source.contents,
        deps,
      );
      staged.push({ artifact, temporary });
    }
    for (const entry of staged) {
      await assertTargetUnchanged(entry.artifact, deps.fsApi);
      await deps.verifyMountNamespace('policy-install-rename');
      await deps.fsApi.rename(entry.temporary, entry.artifact.target);
      entry.temporary = null;
      await syncDirectory(path.dirname(entry.artifact.target), deps.fsApi);
    }
    await verifyInstalledArtifacts(inspected, deps);
  } catch (error) {
    try {
      await recoverPolicyTransaction(rollbackTransaction, plan, deps);
    } catch (rollbackError) {
      throw new Error(
        `${error.message}; policy rollback failed: ${rollbackError.message}`,
        { cause: error },
      );
    }
    throw error;
  } finally {
    await Promise.allSettled(staged
      .filter(({ temporary }) => temporary)
      .map(async ({ temporary }) => {
        await deps.verifyMountNamespace('candidate-cleanup');
        await deps.fsApi.rm(temporary, { force: true });
      }));
  }
  return changed.map(({ target }) => target);
}

function transactionFromInspected(
  inspected,
  { identityRecoveryRequired = false, identityFiles } = {},
) {
  if (!Array.isArray(identityFiles)) {
    throw new Error('identity recovery metadata is unavailable');
  }
  return Object.freeze({
    version: TRANSACTION_VERSION,
    identityRecoveryRequired,
    identityFiles: Object.freeze(identityFiles.map((entry) => Object.freeze({ ...entry }))),
    artifacts: Object.freeze(inspected.artifacts.map((artifact) => Object.freeze({
      target: artifact.target,
      desiredSha256: artifact.source.sha256,
      existing: artifact.existing
        ? Object.freeze({ contents: artifact.existing.contents })
        : null,
    }))),
  });
}

async function verifyInstalledArtifacts(inspected, deps) {
  for (const artifact of inspected.artifacts) {
    const installed = await readTrustedFile(
      artifact.target,
      deps.targetUid,
      deps.targetGid,
      FILE_MODE,
      deps.fsApi,
    );
    if (installed.sha256 !== artifact.source.sha256) {
      throw new Error(`installed policy digest mismatch: ${artifact.target}`);
    }
  }
}

async function verifyManagerInstalledArtifacts(inspected, deps) {
  for (const artifact of inspected.artifacts) {
    const managerTarget = `/proc/1/root${artifact.targetPath}`;
    const installed = await readTrustedFile(
      managerTarget,
      deps.targetUid,
      deps.targetGid,
      FILE_MODE,
      deps.fsApi,
    );
    if (installed.sha256 !== artifact.source.sha256) {
      throw new Error(`PID 1 policy digest mismatch: ${artifact.targetPath}`);
    }
  }
}

async function inspectManagerPolicyView(plan, inspected, deps) {
  const mounts = assertNoUnexpectedManagedMounts(
    plan,
    inspected,
    await deps.readManagerMountInfo(),
  );
  await deps.verifyManagerInstalledArtifacts(inspected);
  return mounts;
}

async function writeCandidate(target, contents, deps) {
  return writeCandidateWithMode(target, contents, FILE_MODE, deps);
}

async function writeCandidateWithMode(target, contents, mode, deps) {
  const temporary = path.join(
    path.dirname(target),
    `${PROVISION_CANDIDATE_PREFIX}${deps.randomUUID()}.tmp`,
  );
  let handle;
  try {
    await deps.verifyMountNamespace('candidate-create');
    handle = await deps.fsApi.open(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await deps.verifyMountNamespace('candidate-write');
    await handle.writeFile(contents);
    await deps.verifyMountNamespace('candidate-chown');
    await handle.chown(deps.targetUid, deps.targetGid);
    await deps.verifyMountNamespace('candidate-chmod');
    await handle.chmod(mode);
    await handle.sync();
    await handle.close();
    handle = null;
    return temporary;
  } catch (error) {
    await handle?.close().catch(() => {});
    await deps.verifyMountNamespace('candidate-cleanup');
    await deps.fsApi.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

export async function ensureProvisionLockFile(
  fsApi,
  verifyMountNamespace = () => assertSameMountNamespace(fsApi),
) {
  await assertTrustedDirectoryChain(
    '/',
    path.dirname(PROVISION_LOCK_PARENT),
    0,
    0,
    fsApi,
  );
  const configPullGid = await readConfigPullGroupGid(fsApi);
  let parentStat;
  try {
    parentStat = await fsApi.lstat(PROVISION_LOCK_PARENT);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    await verifyMountNamespace('provision-lock-parent-create');
    await fsApi.mkdir(PROVISION_LOCK_PARENT, { mode: DIRECTORY_MODE });
    await verifyMountNamespace('provision-lock-parent-chown');
    await fsApi.chown(PROVISION_LOCK_PARENT, 0, 0);
    await verifyMountNamespace('provision-lock-parent-chmod');
    await fsApi.chmod(PROVISION_LOCK_PARENT, DIRECTORY_MODE);
    await syncDirectory(path.dirname(PROVISION_LOCK_PARENT), fsApi);
    parentStat = await fsApi.lstat(PROVISION_LOCK_PARENT);
  }
  let lockPolicy = assertTrustedProvisionLockParent(parentStat, configPullGid);
  if ((parentStat.mode & 0o7777) !== lockPolicy.parentMode) {
    await verifyMountNamespace('provision-lock-parent-chmod');
    await fsApi.chmod(PROVISION_LOCK_PARENT, lockPolicy.parentMode);
    await syncDirectory(path.dirname(PROVISION_LOCK_PARENT), fsApi);
    parentStat = await fsApi.lstat(PROVISION_LOCK_PARENT);
    lockPolicy = assertTrustedProvisionLockParent(parentStat, configPullGid);
  }
  let handle;
  try {
    await verifyMountNamespace('provision-lock-create');
    handle = await fsApi.open(
      PROVISION_LOCK_PATH,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await verifyMountNamespace('provision-lock-create-chown');
    await handle.chown(0, lockPolicy.gid);
    await verifyMountNamespace('provision-lock-create-chmod');
    await handle.chmod(lockPolicy.mode);
    await handle.sync();
    await handle.close();
    handle = null;
    await syncDirectory(PROVISION_LOCK_PARENT, fsApi);
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error?.code !== 'EEXIST') throw error;
  }

  const existing = await fsApi.open(
    PROVISION_LOCK_PATH,
    fsConstants.O_RDWR | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    const stat = await existing.stat();
    if (!provisionLockMatchesPolicy(stat, lockPolicy)) {
      assertRecoverableProvisionLock(stat, lockPolicy);
      await verifyMountNamespace('provision-lock-existing-chown');
      await existing.chown(0, lockPolicy.gid);
      await verifyMountNamespace('provision-lock-existing-chmod');
      await existing.chmod(lockPolicy.mode);
      await existing.sync();
    }
    assertTrustedProvisionLock(await existing.stat(), lockPolicy);
  } finally {
    await existing.close();
  }
  await syncDirectory(PROVISION_LOCK_PARENT, fsApi);
}

async function readConfigPullGroupGid(fsApi) {
  const group = await readTrustedFile(
    '/etc/group',
    0,
    0,
    FILE_MODE,
    fsApi,
    MAX_IDENTITY_FILE_BYTES,
  );
  const snapshot = parseIdentityDatabases('', group.contents.toString('utf8'));
  return snapshot.groups.get(MANAGED_GROUPS.configPull)?.gid ?? null;
}

function assertTrustedProvisionLockParent(
  stat,
  configPullGid,
  { allowInterruptedMigration = true } = {},
) {
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.uid !== 0
  ) {
    throw new Error(`provision lock parent is not trusted: ${PROVISION_LOCK_PARENT}`);
  }
  const mode = stat.mode & 0o7777;
  const recoverableBootstrapMode = (mode & 0o7000) === 0 && (mode & 0o022) === 0;
  if (
    stat.gid === 0
    && recoverableBootstrapMode
    && (configPullGid === null || allowInterruptedMigration)
  ) {
    return Object.freeze({
      state: 'bootstrap',
      gid: 0,
      mode: 0o600,
      parentMode: DIRECTORY_MODE,
    });
  }
  if (
    configPullGid !== null
    && stat.gid === configPullGid
    && (mode === 0o750 || (allowInterruptedMigration && mode === DIRECTORY_MODE))
  ) {
    return Object.freeze({
      state: 'deployed',
      gid: configPullGid,
      mode: 0o660,
      parentMode: 0o750,
    });
  }
  throw new Error(`provision lock parent is not trusted: ${PROVISION_LOCK_PARENT}`);
}

function assertTrustedProvisionLock(
  stat,
  policy,
  { allowInterruptedMigration = true } = {},
) {
  const mode = stat.mode & 0o7777;
  const matchesPolicy = stat.gid === policy.gid && mode === policy.mode;
  const isInterruptedMigration = policy.state === 'deployed'
    && stat.gid === 0
    && mode === 0o600;
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1
    || stat.uid !== 0
    || (!matchesPolicy && !(allowInterruptedMigration && isInterruptedMigration))
  ) {
    throw new Error(`provision lock file is not trusted: ${PROVISION_LOCK_PATH}`);
  }
}

function provisionLockMatchesPolicy(stat, policy) {
  return stat.gid === policy.gid && (stat.mode & 0o7777) === policy.mode;
}

function assertRecoverableProvisionLock(stat, policy) {
  const mode = stat.mode & 0o7777;
  const expectedOwner = stat.uid === 0
    && (stat.gid === 0 || stat.gid === policy.gid);
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1
    || !expectedOwner
    || (mode & ~0o600) !== 0
  ) {
    throw new Error(`provision lock file is not trusted: ${PROVISION_LOCK_PATH}`);
  }
}

export function validateProvisionLockMetadata(
  parentStat,
  lockStat,
  configPullGid,
  options = {},
) {
  const policy = assertTrustedProvisionLockParent(parentStat, configPullGid, options);
  assertTrustedProvisionLock(lockStat, policy, options);
  return policy;
}

async function assertTrustedReexecFile(file, policy, fsApi) {
  if (!path.isAbsolute(file)) throw new Error(`re-exec path is not absolute: ${file}`);
  await assertTrustedDirectoryChain('/', path.dirname(file), 0, 0, fsApi);
  const handle = await fsApi.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    const stat = await handle.stat();
    if (policy.mode !== undefined) {
      assertTrustedFileMetadata(file, stat, 0, 0, policy.mode);
      return;
    }
    const mode = stat.mode & 0o7777;
    if (
      !stat.isFile()
      || stat.isSymbolicLink()
      || stat.nlink !== 1
      || stat.uid !== 0
      || stat.gid !== 0
      || (mode & 0o7022) !== 0
      || (mode & 0o100) === 0
      || !policy.executable
    ) {
      throw new Error(`re-exec file metadata is not trusted: ${file}`);
    }
  } finally {
    await handle.close();
  }
}

async function assertTargetUnchanged(artifact, fsApi) {
  try {
    const current = await fsApi.lstat(artifact.target);
    if (!artifact.existing || !sameFileIdentity(current, artifact.existing.stat)) {
      throw new Error(`policy target changed during installation: ${artifact.target}`);
    }
  } catch (error) {
    if (error?.code === 'ENOENT' && !artifact.existing) return;
    throw error;
  }
}

async function readOptionalTrustedFile(
  file,
  uid,
  gid,
  mode,
  fsApi,
  maxBytes = MAX_POLICY_FILE_BYTES,
) {
  try {
    return await readTrustedFile(file, uid, gid, mode, fsApi, maxBytes);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function readTrustedFile(
  file,
  uid,
  gid,
  mode,
  fsApi,
  maxBytes = MAX_POLICY_FILE_BYTES,
) {
  const handle = await fsApi.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat();
    assertTrustedFileMetadata(file, before, uid, gid, mode);
    if (before.size <= 0 || before.size > maxBytes) {
      throw new Error(`policy file size is invalid: ${file}`);
    }
    const contents = await handle.readFile();
    if (contents.length !== before.size) {
      throw new Error(`policy file size is invalid: ${file}`);
    }
    const after = await handle.stat();
    if (!sameFileIdentity(before, after)) {
      throw new Error(`policy file changed while reading: ${file}`);
    }
    return Object.freeze({
      contents,
      sha256: createHash('sha256').update(contents).digest('hex'),
      stat: before,
    });
  } finally {
    await handle.close();
  }
}

async function readTrustedSensitiveIdentityFile(file, allowedGids, allowedModes, fsApi) {
  const handle = await fsApi.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat();
    const mode = before.mode & 0o7777;
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.uid !== 0
      || !allowedGids.has(before.gid)
      || !allowedModes.has(mode)
      || before.size <= 0
      || before.size > MAX_IDENTITY_FILE_BYTES
    ) {
      throw new Error(`identity file metadata is not trusted: ${file}`);
    }
    const contents = await handle.readFile();
    if (contents.length !== before.size) {
      throw new Error(`identity file size is invalid: ${file}`);
    }
    const after = await handle.stat();
    if (!sameFileIdentity(before, after)) {
      throw new Error(`identity file changed while reading: ${file}`);
    }
    return Object.freeze({ contents, stat: before });
  } finally {
    await handle.close();
  }
}

export async function restoreInterruptedIdentityDatabases(
  transaction,
  snapshot,
  {
    apply = false,
    fsApi = fs,
    targetRoot = '/',
    verifyMountNamespace = () => assertSameMountNamespace(fsApi),
    readMountInfo = () => readBoundedProcFile(
      '/proc/self/mountinfo',
      MAX_MOUNTINFO_BYTES,
      fsApi,
    ),
    verifyIdentityLock = assertIdentityLockHeld,
  } = {},
) {
  if (!Array.isArray(transaction.identityFiles)) {
    throw new Error('legacy identity recovery requires explicit manual repair');
  }
  const currentFiles = new Map();
  const originalFiles = new Map();
  const changed = [];
  const protectedPaths = new Set(IDENTITY_DATABASE_COMMIT_ORDER.flatMap((file) => {
    const target = rootedPath(targetRoot, file);
    return [target, `${target}-`, identityRecoveryCandidatePath(target)];
  }));
  const mountsBeforeRecovery = assertNoUnexpectedMountsForPaths(
    protectedPaths,
    await readMountInfo(),
  );
  const identityFiles = transaction.identityFiles;
  assertIdentityRecoveryFileSet(identityFiles);
  for (const expected of identityFiles) {
    const target = rootedPath(targetRoot, expected.path);
    const current = await readTrustedIdentityRecoveryFile(target, expected, fsApi);
    currentFiles.set(expected.path, current);
    if (current.sha256 === expected.sha256) {
      originalFiles.set(expected.path, current);
      continue;
    }
    const backup = await readTrustedIdentityRecoveryFile(`${target}-`, expected, fsApi);
    if (backup.sha256 !== expected.sha256) {
      throw new Error(`identity recovery backup digest mismatch: ${expected.path}`);
    }
    assertUnmanagedIdentityRecordsUnchanged(
      current.contents,
      backup.contents,
      expected.path,
    );
    originalFiles.set(expected.path, backup);
    changed.push(Object.freeze({ expected, target, current, backup }));
  }

  validateIdentityPolicy(identitySnapshotFromFiles(originalFiles));
  validateIdentityPolicyForDesiredRecovery(identitySnapshotFromFiles(
    currentFiles,
    snapshot.effectiveGroups,
  ));
  if (!apply) return;

  await verifyIdentityLock();
  const candidates = new Map();
  try {
    for (const entry of changed) {
      const candidate = await prepareIdentityRecoveryCandidate(
        entry,
        fsApi,
        verifyMountNamespace,
      );
      candidates.set(entry.expected.path, candidate);
    }
    for (const entry of [...changed].reverse()) {
      await verifyIdentityLock();
      const current = await readTrustedIdentityRecoveryFile(
        entry.target,
        entry.expected,
        fsApi,
      );
      const backup = await readTrustedIdentityRecoveryFile(
        `${entry.target}-`,
        entry.expected,
        fsApi,
      );
      const candidate = await readTrustedIdentityRecoveryFile(
        candidates.get(entry.expected.path).path,
        entry.expected,
        fsApi,
      );
      if (
        !sameFileIdentity(current.stat, entry.current.stat)
        || current.sha256 !== entry.current.sha256
        || !sameFileIdentity(backup.stat, entry.backup.stat)
        || backup.sha256 !== entry.expected.sha256
        || !sameFileIdentity(candidate.stat, candidates.get(entry.expected.path).stat)
        || candidate.sha256 !== entry.expected.sha256
      ) {
        throw new Error(`identity database changed during recovery: ${entry.expected.path}`);
      }
      await verifyMountNamespace('identity-recovery-rename');
      await fsApi.rename(candidates.get(entry.expected.path).path, entry.target);
      candidates.delete(entry.expected.path);
      await syncDirectory(path.dirname(entry.target), fsApi);
    }
  } finally {
    await Promise.allSettled([...candidates.values()].map(async ({ path: candidate }) => {
      await verifyMountNamespace('identity-recovery-candidate-cleanup');
      await fsApi.rm(candidate, { force: true });
      await syncDirectory(path.dirname(candidate), fsApi);
    }));
  }

  for (const expected of identityFiles) {
    const restored = await readTrustedIdentityRecoveryFile(
      rootedPath(targetRoot, expected.path),
      expected,
      fsApi,
    );
    if (restored.sha256 !== expected.sha256) {
      throw new Error(`identity database recovery failed: ${expected.path}`);
    }
  }
  const mountsAfterRecovery = assertNoUnexpectedMountsForPaths(
    protectedPaths,
    await readMountInfo(),
  );
  assertProtectedMountSnapshotUnchanged(mountsBeforeRecovery, mountsAfterRecovery);
}

function assertIdentityRecoveryFileSet(identityFiles) {
  if (
    identityFiles.length !== IDENTITY_DATABASE_COMMIT_ORDER.length
    || identityFiles.some((entry, index) => (
      entry.path !== IDENTITY_DATABASE_COMMIT_ORDER[index]
      || typeof entry.sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(entry.sha256)
      || !Number.isSafeInteger(entry.uid)
      || entry.uid < 0
      || !Number.isSafeInteger(entry.gid)
      || entry.gid < 0
      || !Number.isSafeInteger(entry.mode)
      || entry.mode < 0
      || entry.mode > 0o7777
    ))
  ) {
    throw new Error('identity recovery metadata is invalid');
  }
}

function identityRecoveryCandidatePath(target) {
  return path.join(
    path.dirname(target),
    `.webex-host-identity-recovery-${path.basename(target)}.tmp`,
  );
}

async function prepareIdentityRecoveryCandidate(entry, fsApi, verifyMountNamespace) {
  const candidate = identityRecoveryCandidatePath(entry.target);
  await removeInterruptedIdentityRecoveryCandidate(
    candidate,
    entry.expected,
    fsApi,
    verifyMountNamespace,
  );
  let handle;
  try {
    await verifyMountNamespace('identity-recovery-candidate-create');
    handle = await fsApi.open(
      candidate,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(entry.backup.contents);
    await handle.chown(entry.expected.uid, entry.expected.gid);
    await handle.chmod(entry.expected.mode);
    await handle.sync();
    await handle.close();
    handle = null;
    const staged = await readTrustedIdentityRecoveryFile(candidate, entry.expected, fsApi);
    if (staged.sha256 !== entry.expected.sha256) {
      throw new Error(`identity recovery candidate digest mismatch: ${entry.expected.path}`);
    }
    return Object.freeze({ path: candidate, stat: staged.stat });
  } catch (error) {
    await handle?.close().catch(() => {});
    await removeInterruptedIdentityRecoveryCandidate(
      candidate,
      entry.expected,
      fsApi,
      verifyMountNamespace,
    ).catch(() => {});
    throw error;
  }
}

async function removeInterruptedIdentityRecoveryCandidate(
  candidate,
  expected,
  fsApi,
  verifyMountNamespace,
) {
  let stat;
  try {
    stat = await fsApi.lstat(candidate);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  const mode = stat.mode & 0o7777;
  const interruptedCreation = (mode & ~0o600) === 0;
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1
    || stat.uid !== expected.uid
    || !new Set([0, expected.gid]).has(stat.gid)
    || (!interruptedCreation && mode !== expected.mode)
    || stat.size < 0
    || stat.size > MAX_IDENTITY_FILE_BYTES
  ) {
    throw new Error(`identity recovery candidate is not trusted: ${candidate}`);
  }
  await verifyMountNamespace('identity-recovery-candidate-cleanup');
  await fsApi.rm(candidate);
  await syncDirectory(path.dirname(candidate), fsApi);
}

async function readTrustedIdentityRecoveryFile(file, expected, fsApi) {
  const handle = await fsApi.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat();
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.uid !== expected.uid
      || before.gid !== expected.gid
      || (before.mode & 0o7777) !== expected.mode
      || before.size < 0
      || before.size > MAX_IDENTITY_FILE_BYTES
    ) {
      throw new Error(`identity recovery file metadata is not trusted: ${file}`);
    }
    const contents = await handle.readFile();
    if (contents.length !== before.size) {
      throw new Error(`identity recovery file size is invalid: ${file}`);
    }
    const after = await handle.stat();
    if (!sameFileIdentity(before, after)) {
      throw new Error(`identity recovery file changed while reading: ${file}`);
    }
    return Object.freeze({
      contents,
      sha256: createHash('sha256').update(contents).digest('hex'),
      stat: before,
    });
  } finally {
    await handle.close();
  }
}

function identitySnapshotFromFiles(files, effectiveGroups = null) {
  const texts = Object.fromEntries([...files].map(([file, record]) => (
    [file, record.contents.toString('utf8')]
  )));
  let effective = effectiveGroups;
  if (effective === null) {
    const basic = parseIdentityDatabases(texts['/etc/passwd'], texts['/etc/group']);
    effective = Object.fromEntries(Object.values(MANAGED_USERS)
      .filter((user) => basic.users.has(user))
      .map((user) => {
        const record = basic.users.get(user);
        return [user, [
          record.gid,
          ...[...basic.groups.values()]
            .filter((group) => group.members.includes(user))
            .map((group) => group.gid),
        ]];
      }));
  } else if (effective instanceof Map) {
    effective = Object.fromEntries(
      [...effective].map(([user, gids]) => [user, [...gids]]),
    );
  }
  return parseIdentityDatabases(
    texts['/etc/passwd'],
    texts['/etc/group'],
    effective,
    texts['/etc/gshadow'],
    texts['/etc/shadow'],
  );
}

function assertUnmanagedIdentityRecordsUnchanged(current, original, file) {
  const managed = new Set(
    ['/etc/passwd', '/etc/shadow'].includes(file)
      ? Object.values(MANAGED_USERS)
      : Object.values(MANAGED_GROUPS),
  );
  const unmanaged = (contents) => contents.toString('utf8').split('\n')
    .filter((line) => !managed.has(line.split(':', 1)[0]))
    .join('\n');
  if (unmanaged(current) !== unmanaged(original)) {
    throw new Error(`unmanaged identity records changed during recovery: ${file}`);
  }
}

function validateIdentityPolicyForDesiredRecovery(snapshot) {
  const shadowUsers = new Map(snapshot.shadowUsers);
  const shadowGroups = new Map(snapshot.shadowGroups);
  for (const userName of Object.values(MANAGED_USERS)) {
    const user = snapshot.users.get(userName);
    const shadowUser = shadowUsers.get(userName);
    if (user?.password === 'x' && !shadowUser) {
      shadowUsers.set(userName, Object.freeze({ name: userName, password: '!' }));
    } else if (!user && shadowUser) {
      if (!/^[!*]+$/.test(shadowUser.password)) {
        throw new Error(`managed user shadow password is not locked: ${userName}`);
      }
      shadowUsers.delete(userName);
    }
  }
  for (const groupName of Object.values(MANAGED_GROUPS)) {
    const group = snapshot.groups.get(groupName);
    const shadowGroup = shadowGroups.get(groupName);
    if (group?.password === 'x' && !shadowGroup) {
      shadowGroups.set(groupName, Object.freeze({
        name: groupName,
        password: '!',
        administrators: Object.freeze([]),
        members: Object.freeze([]),
      }));
    } else if (!group && shadowGroup) {
      if (
        !/^[!*]+$/.test(shadowGroup.password)
        || shadowGroup.administrators.length !== 0
        || shadowGroup.members.length !== 0
      ) {
        throw new Error(`managed group shadow credential is not recoverable: ${groupName}`);
      }
      shadowGroups.delete(groupName);
    }
  }
  validateIdentityPolicy(Object.freeze({
    ...snapshot,
    shadowUsers,
    shadowGroups,
  }));
}

export async function readBoundedProcFile(file, maxBytes, fsApi) {
  const handle = await fsApi.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error(`proc file metadata is not trusted: ${file}`);
    const buffer = Buffer.alloc(maxBytes + 1);
    let totalBytesRead = 0;
    while (totalBytesRead < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        totalBytesRead,
        buffer.length - totalBytesRead,
        null,
      );
      if (bytesRead === 0) break;
      totalBytesRead += bytesRead;
    }
    if (totalBytesRead > maxBytes) throw new Error(`proc file is too large: ${file}`);
    return buffer.subarray(0, totalBytesRead).toString('utf8');
  } finally {
    await handle.close();
  }
}

export async function assertInitialPidNamespace(
  runCommand = runFixedCommand,
  processApi = process,
  fsApi = fs,
) {
  const [
    managerName,
    managerCgroup,
    uidMap,
    gidMap,
    selfUserNamespace,
    managerUserNamespace,
  ] = await Promise.all([
    readBoundedProcFile('/proc/1/comm', 64, fsApi),
    readBoundedProcFile('/proc/1/cgroup', 4096, fsApi),
    readBoundedProcFile('/proc/self/uid_map', 4096, fsApi),
    readBoundedProcFile('/proc/self/gid_map', 4096, fsApi),
    readNamespaceIdentity('/proc/self/ns/user', fsApi),
    readNamespaceIdentity('/proc/1/ns/user', fsApi),
  ]);
  if (managerName !== 'systemd\n' || managerCgroup !== '0::/init.scope\n') {
    throw new Error('host provisioner is not running under the host systemd manager');
  }
  assertInitialIdNamespaceMap(uidMap, 'UID');
  assertInitialIdNamespaceMap(gidMap, 'GID');
  if (
    selfUserNamespace.dev !== managerUserNamespace.dev
    || selfUserNamespace.ino !== managerUserNamespace.ino
  ) {
    throw new Error('host provisioner is not in the initial user namespace');
  }
  const result = await runCommand('/usr/bin/lsns', [
    '--noheadings',
    '--output',
    'PNS',
    '--type',
    'pid',
    '--task',
    String(processApi.pid),
  ]);
  if (result.code !== 0 || result.stderr !== '' || String(result.stdout).trim() !== '0') {
    throw new Error('host provisioner is not in the initial PID namespace');
  }
}

async function readNamespaceIdentity(file, fsApi) {
  const handle = await fsApi.open(file, fsConstants.O_RDONLY);
  try {
    const stat = await handle.stat();
    return Object.freeze({ dev: stat.dev, ino: stat.ino });
  } finally {
    await handle.close();
  }
}

function assertInitialIdNamespaceMap(contents, label) {
  const lines = String(contents).trim().split('\n');
  const fields = lines.length === 1 ? lines[0].trim().split(/\s+/) : [];
  if (
    fields.length !== 3
    || fields[0] !== '0'
    || fields[1] !== '0'
    || fields[2] !== '4294967295'
  ) {
    throw new Error(`host provisioner is not in the initial user namespace (${label})`);
  }
}

export async function assertSameMountNamespace(
  fsApi = fs,
  {
    expectPrivate = process.env[PRIVATE_MOUNT_NAMESPACE_ENV] === '1',
    readMountInfo = () => readBoundedProcFile(
      '/proc/self/mountinfo',
      MAX_MOUNTINFO_BYTES,
      fsApi,
    ),
  } = {},
) {
  const [selfNamespace, managerNamespace] = await Promise.all([
    readNamespaceIdentity('/proc/self/ns/mnt', fsApi),
    readNamespaceIdentity('/proc/1/ns/mnt', fsApi),
  ]);
  const namespacesMatch = selfNamespace.dev === managerNamespace.dev
    && selfNamespace.ino === managerNamespace.ino;
  if (!expectPrivate && !namespacesMatch) {
    throw new Error('host provisioner is not in PID 1 mount namespace');
  }
  if (expectPrivate) {
    if (namespacesMatch) {
      throw new Error('host provisioner apply is not in a private mount namespace');
    }
    assertMountPropagationIsPrivate(await readMountInfo());
  }
}

export async function assertCanonicalVarRunLink(fsApi = fs) {
  assertTrustedDirectory('/var', await fsApi.lstat('/var'), 0, 0);
  const before = await fsApi.lstat('/var/run');
  if (
    !before.isSymbolicLink()
    || before.uid !== 0
    || before.gid !== 0
    || before.nlink !== 1
  ) {
    throw new Error('/var/run is not the canonical root-owned symlink');
  }
  const target = await fsApi.readlink('/var/run');
  const after = await fsApi.lstat('/var/run');
  if (
    !after.isSymbolicLink()
    || !sameFileIdentity(before, after)
    || !['../run', '/run'].includes(target)
  ) {
    throw new Error('/var/run is not the canonical symlink to /run');
  }
  assertTrustedDirectory('/run', await fsApi.lstat('/run'), 0, 0);
}

function assertMountPropagationIsPrivate(mountInfo) {
  for (const { raw } of parseMountInfo(mountInfo)) {
    const fields = raw.split(' ');
    const separator = fields.indexOf('-');
    if (fields.slice(6, separator).some((field) => (
      field === 'unbindable'
      || field.startsWith('shared:')
      || field.startsWith('master:')
      || field.startsWith('propagate_from:')
    ))) {
      throw new Error('host provisioner apply mount propagation is not private');
    }
  }
}

async function openTrustedExecutable(file, fsApi) {
  if (!path.isAbsolute(file)) throw new Error(`fixed executable path is not absolute: ${file}`);
  await assertTrustedDirectoryChain('/', path.dirname(file), 0, 0, fsApi);
  const mountsBeforeOpen = assertNoUnexpectedMountsForPaths(
    new Set([file]),
    await readBoundedProcFile('/proc/self/mountinfo', MAX_MOUNTINFO_BYTES, fsApi),
  );
  const handle = await fsApi.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    const stat = await handle.stat();
    const mode = stat.mode & 0o7777;
    if (
      !stat.isFile()
      || stat.isSymbolicLink()
      || stat.nlink !== 1
      || stat.uid !== 0
      || stat.gid !== 0
      || (mode & 0o7022) !== 0
      || (mode & 0o100) === 0
    ) {
      throw new Error(`fixed executable is not trusted: ${file}`);
    }
    const mountsAfterOpen = assertNoUnexpectedMountsForPaths(
      new Set([file]),
      await readBoundedProcFile('/proc/self/mountinfo', MAX_MOUNTINFO_BYTES, fsApi),
    );
    assertProtectedMountSnapshotUnchanged(mountsBeforeOpen, mountsAfterOpen);
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function openTrustedPolicyScript(file, fsApi) {
  if (!path.isAbsolute(file)) throw new Error(`policy script path is not absolute: ${file}`);
  await assertTrustedDirectoryChain('/', path.dirname(file), 0, 0, fsApi);
  const mountsBeforeOpen = assertNoUnexpectedMountsForPaths(
    new Set([file]),
    await readBoundedProcFile('/proc/self/mountinfo', MAX_MOUNTINFO_BYTES, fsApi),
  );
  const handle = await fsApi.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    assertTrustedFileMetadata(file, await handle.stat(), 0, 0, FILE_MODE);
    const mountsAfterOpen = assertNoUnexpectedMountsForPaths(
      new Set([file]),
      await readBoundedProcFile('/proc/self/mountinfo', MAX_MOUNTINFO_BYTES, fsApi),
    );
    assertProtectedMountSnapshotUnchanged(mountsBeforeOpen, mountsAfterOpen);
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

function assertTrustedFileMetadata(file, stat, uid, gid, mode) {
  const actualMode = stat.mode & 0o7777;
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1
    || stat.uid !== uid
    || stat.gid !== gid
    || (mode === null ? (actualMode & 0o022) !== 0 : actualMode !== mode)
  ) {
    throw new Error(`policy file metadata is not trusted: ${file}`);
  }
}

async function assertTrustedExistingAncestors(root, directory, uid, gid, fsApi) {
  const candidates = pathComponentsWithin(root, directory);
  let missing = false;
  for (const candidate of candidates) {
    if (missing) continue;
    try {
      const stat = await fsApi.lstat(candidate);
      assertTrustedDirectory(candidate, stat, uid, gid);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      missing = true;
    }
  }
}

async function assertTrustedDirectoryChain(root, directory, uid, gid, fsApi) {
  for (const candidate of pathComponentsWithin(root, directory)) {
    const stat = await fsApi.lstat(candidate);
    assertTrustedDirectory(candidate, stat, uid, gid);
  }
}

async function createTrustedDirectoryChain(
  root,
  directory,
  uid,
  gid,
  fsApi,
  verifyMountNamespace,
) {
  for (const candidate of pathComponentsWithin(root, directory)) {
    try {
      const stat = await fsApi.lstat(candidate);
      assertTrustedDirectory(candidate, stat, uid, gid);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      const parent = path.dirname(candidate);
      await verifyMountNamespace('target-directory-create');
      await fsApi.mkdir(candidate, { mode: DIRECTORY_MODE });
      await verifyMountNamespace('target-directory-chown');
      await fsApi.chown(candidate, uid, gid);
      await verifyMountNamespace('target-directory-chmod');
      await fsApi.chmod(candidate, DIRECTORY_MODE);
      await syncDirectory(parent, fsApi);
      const stat = await fsApi.lstat(candidate);
      assertTrustedDirectory(candidate, stat, uid, gid);
    }
  }
}

function assertTrustedDirectory(directory, stat, uid, gid) {
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.uid !== uid
    || stat.gid !== gid
    || ((stat.mode & 0o7777) & 0o022) !== 0
  ) {
    throw new Error(`policy directory is not trusted: ${directory}`);
  }
}

function pathComponentsWithin(root, candidate) {
  const resolvedRoot = path.resolve(root);
  const resolvedCandidate = path.resolve(candidate);
  const relative = path.relative(resolvedRoot, resolvedCandidate);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`policy path escapes its trusted root: ${candidate}`);
  }
  const components = [resolvedRoot];
  let current = resolvedRoot;
  for (const component of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    components.push(current);
  }
  return components;
}

async function syncDirectory(directory, fsApi) {
  const handle = await fsApi.open(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readProvisionTransaction(plan, deps) {
  await assertTrustedExistingAncestors(
    plan.targetRoot,
    path.dirname(plan.transactionFile),
    deps.targetUid,
    deps.targetGid,
    deps.fsApi,
  );
  const record = await readOptionalTrustedFile(
    plan.transactionFile,
    deps.targetUid,
    deps.targetGid,
    TRANSACTION_MODE,
    deps.fsApi,
    MAX_TRANSACTION_BYTES,
  );
  if (!record) return null;
  let value;
  try {
    value = JSON.parse(record.contents.toString('utf8'));
  } catch {
    throw new Error('host policy transaction is malformed');
  }
  return parseProvisionTransaction(value, plan);
}

function parseProvisionTransaction(value, plan) {
  const legacyV1 = value?.version === 1;
  const legacyV2 = value?.version === 2;
  const expectedKeys = legacyV1
    ? 'artifacts,version'
    : legacyV2
      ? 'artifacts,identity_recovery_required,version'
      : 'artifacts,identity_files,identity_recovery_required,version';
  if (
    !value
    || typeof value !== 'object'
    || Array.isArray(value)
    || (!legacyV1 && !legacyV2 && value.version !== TRANSACTION_VERSION)
    || Object.keys(value).sort().join(',') !== expectedKeys
    || (!legacyV1 && typeof value.identity_recovery_required !== 'boolean')
    || !Array.isArray(value.artifacts)
    || value.artifacts.length !== plan.artifacts.length
  ) {
    throw new Error('host policy transaction schema is invalid');
  }
  const artifacts = value.artifacts.map((entry, index) => {
    const expectedTarget = plan.artifacts[index].target;
    if (
      !entry
      || typeof entry !== 'object'
      || Array.isArray(entry)
      || Object.keys(entry).sort().join(',') !== 'desired_sha256,existing,target'
      || entry.target !== expectedTarget
      || typeof entry.desired_sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(entry.desired_sha256)
    ) {
      throw new Error('host policy transaction target set is invalid');
    }
    if (entry.existing === null) {
      return Object.freeze({
        target: expectedTarget,
        desiredSha256: entry.desired_sha256,
        existing: null,
      });
    }
    if (
      typeof entry.existing !== 'object'
      || Array.isArray(entry.existing)
      || Object.keys(entry.existing).sort().join(',') !== 'contents_base64,sha256'
      || typeof entry.existing.contents_base64 !== 'string'
      || typeof entry.existing.sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(entry.existing.sha256)
    ) {
      throw new Error('host policy transaction snapshot is invalid');
    }
    const contents = Buffer.from(entry.existing.contents_base64, 'base64');
    if (
      contents.length === 0
      || contents.length > MAX_POLICY_FILE_BYTES
      || contents.toString('base64') !== entry.existing.contents_base64
      || createHash('sha256').update(contents).digest('hex') !== entry.existing.sha256
    ) {
      throw new Error('host policy transaction snapshot digest is invalid');
    }
    return Object.freeze({
      target: expectedTarget,
      desiredSha256: entry.desired_sha256,
      existing: Object.freeze({ contents }),
    });
  });
  let identityFiles = null;
  if (!legacyV1 && !legacyV2) {
    if (
      !Array.isArray(value.identity_files)
      || value.identity_files.length !== IDENTITY_DATABASE_COMMIT_ORDER.length
    ) {
      throw new Error('host policy transaction identity snapshot is invalid');
    }
    identityFiles = value.identity_files.map((entry, index) => {
      if (
        !entry
        || typeof entry !== 'object'
        || Array.isArray(entry)
        || Object.keys(entry).sort().join(',') !== 'gid,mode,path,sha256,uid'
        || entry.path !== IDENTITY_DATABASE_COMMIT_ORDER[index]
        || typeof entry.sha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(entry.sha256)
        || !Number.isSafeInteger(entry.uid)
        || entry.uid < 0
        || !Number.isSafeInteger(entry.gid)
        || entry.gid < 0
        || !Number.isSafeInteger(entry.mode)
        || entry.mode < 0
        || entry.mode > 0o7777
      ) {
        throw new Error('host policy transaction identity snapshot is invalid');
      }
      return Object.freeze({
        path: entry.path,
        sha256: entry.sha256,
        uid: entry.uid,
        gid: entry.gid,
        mode: entry.mode,
      });
    });
  }
  return Object.freeze({
    version: TRANSACTION_VERSION,
    identityRecoveryRequired: legacyV1 ? false : value.identity_recovery_required,
    identityFiles: identityFiles && Object.freeze(identityFiles),
    artifacts: Object.freeze(artifacts),
  });
}

async function writeProvisionTransaction(
  inspected,
  plan,
  deps,
  { identityRecoveryRequired = false, identityFiles } = {},
) {
  await writeProvisionTransactionRecord(
    transactionFromInspected(inspected, { identityRecoveryRequired, identityFiles }),
    plan,
    deps,
  );
}

async function writeProvisionTransactionRecord(
  transaction,
  plan,
  deps,
  identityRecoveryRequired = transaction.identityRecoveryRequired,
) {
  if (!transaction.identityFiles) {
    throw new Error('host policy transaction lacks identity recovery metadata');
  }
  const value = {
    version: TRANSACTION_VERSION,
    identity_recovery_required: identityRecoveryRequired,
    identity_files: transaction.identityFiles.map((entry) => ({
      path: entry.path,
      sha256: entry.sha256,
      uid: entry.uid,
      gid: entry.gid,
      mode: entry.mode,
    })),
    artifacts: transaction.artifacts.map((artifact) => ({
      target: artifact.target,
      desired_sha256: artifact.desiredSha256,
      existing: artifact.existing
        ? {
          contents_base64: artifact.existing.contents.toString('base64'),
          sha256: createHash('sha256').update(artifact.existing.contents).digest('hex'),
        }
        : null,
    })),
  };
  const contents = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  if (contents.length > MAX_TRANSACTION_BYTES) {
    throw new Error('host policy transaction is too large');
  }
  const temporary = await writeCandidateWithMode(
    plan.transactionFile,
    contents,
    TRANSACTION_MODE,
    deps,
  );
  try {
    await deps.verifyMountNamespace('transaction-rename');
    await deps.fsApi.rename(temporary, plan.transactionFile);
    await syncDirectory(path.dirname(plan.transactionFile), deps.fsApi);
  } catch (error) {
    await deps.verifyMountNamespace('candidate-cleanup');
    await deps.fsApi.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

async function recoverPolicyTransaction(
  transaction,
  plan,
  deps,
  { forceOld = false } = {},
) {
  const {
    directories,
    recovery,
    resumeDesiredState: inspectedResumeDesiredState,
  } = await inspectPolicyTransactionRecovery(transaction, plan, deps);
  const resumeDesiredState = !forceOld && inspectedResumeDesiredState;
  for (const entry of [...recovery].reverse()) {
    if (resumeDesiredState) break;
    if (!entry.restore) continue;
    const { artifact } = entry;
    if (artifact.existing) {
      const temporary = await writeCandidate(
        artifact.target,
        artifact.existing.contents,
        deps,
      );
      try {
        await assertTargetUnchanged(
          { target: artifact.target, existing: entry.current },
          deps.fsApi,
        );
        await deps.verifyMountNamespace('policy-recovery-rename');
        await deps.fsApi.rename(temporary, artifact.target);
      } catch (error) {
        await deps.verifyMountNamespace('candidate-cleanup');
        await deps.fsApi.rm(temporary, { force: true }).catch(() => {});
        throw error;
      }
    } else {
      await assertTargetUnchanged(
        { target: artifact.target, existing: entry.current },
        deps.fsApi,
      );
      await deps.verifyMountNamespace('policy-recovery-remove');
      await deps.fsApi.rm(artifact.target, { force: true });
    }
    await syncDirectory(path.dirname(artifact.target), deps.fsApi);
  }
  for (const directory of directories) {
    await syncDirectory(directory, deps.fsApi);
  }
  for (const artifact of transaction.artifacts) {
    const current = await readOptionalTrustedFile(
      artifact.target,
      deps.targetUid,
      deps.targetGid,
      FILE_MODE,
      deps.fsApi,
    );
    const matchesExpectedState = resumeDesiredState
      ? current?.sha256 === artifact.desiredSha256
      : artifact.existing
        ? current?.sha256 === createHash('sha256')
          .update(artifact.existing.contents)
          .digest('hex')
        : !current;
    if (!matchesExpectedState) {
      throw new Error(`policy target changed after recovery: ${artifact.target}`);
    }
  }
  return resumeDesiredState ? 'desired' : 'old';
}

async function rollbackPolicyAfterSafetyFailure(
  safetyError,
  transaction,
  plan,
  deps,
  commands,
  identitySnapshot,
  identityRecoveryRequired,
) {
  try {
    if (identityRecoveryRequired) {
      await writeProvisionTransactionRecord(transaction, plan, deps, true);
    }
    const recoveredState = await recoverPolicyTransaction(
      transaction,
      plan,
      deps,
      { forceOld: true },
    );
    if (recoveredState !== 'old') {
      throw new Error('safety rollback did not restore the old policy set');
    }
    await deps.verifyMountNamespace('daemon-reload-rollback');
    commands.push(await deps.runCommand('/usr/bin/systemctl', ['daemon-reload']));
    const recoveredUnitStates = await deps.readUnitStates(MANAGED_UNITS, identitySnapshot);
    assertUnitsDormant(recoveredUnitStates, plan, { requireLoaded: false });
    if (!identityRecoveryRequired) {
      await removeProvisionTransaction(plan, deps);
    }
  } catch (rollbackError) {
    throw new PolicySafetyRollbackError(
      `${safetyError.message}; safety rollback failed: ${rollbackError.message}`,
      { cause: safetyError },
    );
  }
  throw new PolicySafetyRollbackError(
    `host policy safety validation failed and the old policy set was restored: ${safetyError.message}`,
    { cause: safetyError },
  );
}

async function inspectPolicyTransactionRecovery(transaction, plan, deps) {
  const directories = new Set(
    transaction.artifacts.map(({ target }) => path.dirname(target)),
  );
  for (const directory of directories) {
    await assertTrustedDirectoryChain(
      plan.targetRoot,
      directory,
      deps.targetUid,
      deps.targetGid,
      deps.fsApi,
    );
  }
  const recovery = [];
  for (const artifact of transaction.artifacts) {
    const current = await readOptionalTrustedFile(
      artifact.target,
      deps.targetUid,
      deps.targetGid,
      FILE_MODE,
      deps.fsApi,
    );
    const existingSha256 = artifact.existing
      ? createHash('sha256').update(artifact.existing.contents).digest('hex')
      : null;
    const matchesOldState = artifact.existing
      ? current?.sha256 === existingSha256
      : !current;
    const matchesDesiredState = current?.sha256 === artifact.desiredSha256;
    if (!matchesOldState && !matchesDesiredState) {
      throw new Error(`policy target has unknown state during recovery: ${artifact.target}`);
    }
    recovery.push(Object.freeze({
      artifact,
      current,
      restore: matchesDesiredState && !matchesOldState,
    }));
  }
  const resumeDesiredState = recovery.every(
    ({ artifact, current }) => current?.sha256 === artifact.desiredSha256,
  );
  return Object.freeze({
    directories,
    recovery: Object.freeze(recovery),
    resumeDesiredState,
  });
}

async function removeProvisionTransaction(plan, deps) {
  await deps.verifyMountNamespace('transaction-remove');
  await deps.fsApi.rm(plan.transactionFile, { force: true });
  await syncDirectory(path.dirname(plan.transactionFile), deps.fsApi);
}

function assertUnitsDormant(
  states,
  plan,
  { requireLoaded, allowDaemonReloadRequired = false },
) {
  for (const unit of MANAGED_UNITS) {
    const state = states.get(unit);
    if (!state) throw new Error(`unit state is missing: ${unit}`);
    assertUnitDormant(unit, state, {
      requireLoaded,
      allowDaemonReloadRequired,
      expectedFragment: expectedUnitFragment(plan, unit),
    });
  }
  for (const [unit, state] of states) {
    if (!LAUNCHER_INSTANCE_PATTERN.test(unit)) continue;
    assertUnitDormant(unit, state, {
      requireLoaded,
      allowDaemonReloadRequired,
      expectedFragment: expectedUnitFragment(plan, 'webex-codex-launcher@.service'),
    });
  }
}

function assertUnitDormant(
  unit,
  state,
  { requireLoaded, allowDaemonReloadRequired, expectedFragment },
) {
  if (state.active !== 'inactive') {
    throw new Error(`managed unit is not inactive: ${unit} (${state.active})`);
  }
  if (!['disabled', 'indirect', 'not-found', 'static'].includes(state.enabled)) {
    throw new Error(`managed unit is enabled or masked: ${unit} (${state.enabled})`);
  }
  if (requireLoaded && state.load !== 'loaded') {
    throw new Error(`managed unit did not load after installation: ${unit} (${state.load})`);
  }
  if (!['loaded', 'not-found'].includes(state.load)) {
    throw new Error(`managed unit has unexpected load state: ${unit} (${state.load})`);
  }
  if (state.load === 'loaded' && state.fragment !== expectedFragment) {
    throw new Error(`managed unit loaded an unexpected fragment: ${unit} (${state.fragment})`);
  }
  if (state.load === 'not-found' && state.fragment !== '') {
    throw new Error(`unloaded managed unit reported a fragment: ${unit} (${state.fragment})`);
  }
  if (state.dropIns !== '') {
    throw new Error(`managed unit loaded unexpected drop-ins: ${unit} (${state.dropIns})`);
  }
  if (state.needDaemonReload && !allowDaemonReloadRequired) {
    throw new Error(`managed unit requires daemon-reload: ${unit}`);
  }
  for (const activator of state.reverseActivators) {
    if (!MANAGED_UNITS.includes(activator) && !LAUNCHER_INSTANCE_PATTERN.test(activator)) {
      throw new Error(`managed unit has an external reverse activator: ${unit} (${activator})`);
    }
  }
}

function unitStatesNeedDaemonReload(states) {
  return [...states.values()].some(({ needDaemonReload }) => needDaemonReload);
}

function expectedUnitFragment(plan, unit) {
  const target = plan.units.find((candidate) => path.basename(candidate) === unit);
  if (!target) throw new Error(`managed unit has no fixed fragment: ${unit}`);
  return target;
}

async function validateSystemdUserdbBoundary(fsApi, runCommand) {
  const providers = await readTrustedDirectoryEntries(
    SYSTEMD_USERDB_DIRECTORY,
    MAX_SYSTEMD_USERDB_ENTRIES,
    fsApi,
  );
  for (const entry of providers) {
    if (entry.name !== SYSTEMD_DYNAMIC_USER_PROVIDER) {
      throw new Error(`unsupported systemd userdb provider: ${entry.name}`);
    }
    const provider = path.join(SYSTEMD_USERDB_DIRECTORY, entry.name);
    const stat = await fsApi.lstat(provider);
    if (
      !entry.isSocket()
      || !stat.isSocket()
      || stat.isSymbolicLink()
      || stat.nlink !== 1
      || stat.uid !== 0
      || stat.gid !== 0
      || (stat.mode & 0o7777) !== 0o666
    ) {
      throw new Error(`systemd userdb provider is not trusted: ${provider}`);
    }
  }
  for (const directory of STATIC_USERDB_DIRECTORIES) {
    const entries = await readTrustedDirectoryEntries(
      directory,
      MAX_SYSTEMD_USERDB_ENTRIES,
      fsApi,
    );
    if (entries.length !== 0) {
      throw new Error(`static systemd userdb records are not supported: ${directory}`);
    }
  }
  for (const [database, names] of [
    ['passwd', Object.values(MANAGED_USERS)],
    ['group', Object.values(MANAGED_GROUPS)],
  ]) {
    for (const name of names) {
      const result = await runCommand(
        '/usr/bin/getent',
        ['-s', 'systemd', database, name],
        [0, 2],
      );
      if (result.code !== 2 || result.stdout !== '' || result.stderr !== '') {
        throw new Error(`managed identity is claimed by systemd userdb: ${name}`);
      }
    }
  }
}

async function readTrustedDirectoryEntries(directory, maxEntries, fsApi) {
  await assertTrustedExistingAncestors('/', directory, 0, 0, fsApi);
  let handle;
  try {
    handle = await fsApi.opendir(directory);
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  await assertTrustedDirectoryChain('/', directory, 0, 0, fsApi);
  const entries = [];
  try {
    for await (const entry of handle) {
      entries.push(entry);
      if (entries.length > maxEntries) {
        throw new Error(`too many entries in trusted directory: ${directory}`);
      }
    }
  } finally {
    try {
      await handle.close();
    } catch (error) {
      if (error?.code !== 'ERR_DIR_CLOSED') throw error;
    }
  }
  return entries;
}

export async function readSystemIdentitySnapshot(fsApi = fs, runCommand = runFixedCommand) {
  const [nsswitch, passwd, group] = await Promise.all([
    readTrustedFile('/etc/nsswitch.conf', 0, 0, FILE_MODE, fsApi),
    readTrustedFile('/etc/passwd', 0, 0, FILE_MODE, fsApi, MAX_IDENTITY_FILE_BYTES),
    readTrustedFile('/etc/group', 0, 0, FILE_MODE, fsApi, MAX_IDENTITY_FILE_BYTES),
  ]);
  validateNsswitchPolicy(nsswitch.contents.toString('utf8'));
  await validateSystemdUserdbBoundary(fsApi, runCommand);
  const initial = parseIdentityDatabases(
    passwd.contents.toString('utf8'),
    group.contents.toString('utf8'),
  );
  const shadowGid = initial.groups.get('shadow')?.gid ?? 0;
  const [shadow, gshadow] = await Promise.all([
    readTrustedSensitiveIdentityFile(
      '/etc/shadow',
      new Set([0, shadowGid]),
      new Set([0o000, 0o600, 0o640]),
      fsApi,
    ),
    readTrustedSensitiveIdentityFile(
      '/etc/gshadow',
      new Set([0, shadowGid]),
      new Set([0o000, 0o600, 0o640]),
      fsApi,
    ),
  ]);
  const passwdText = passwd.contents.toString('utf8');
  const groupText = group.contents.toString('utf8');
  const shadowText = shadow.contents.toString('utf8');
  const gshadowText = gshadow.contents.toString('utf8');
  const complete = parseIdentityDatabases(passwdText, groupText, {}, gshadowText, shadowText);
  const effectiveGroups = {};
  for (const user of Object.values(MANAGED_USERS)) {
    if (!complete.users.has(user)) continue;
    const record = complete.users.get(user);
    effectiveGroups[user] = [
      record.gid,
      ...[...complete.groups.values()]
        .filter((groupRecord) => groupRecord.members.includes(user))
        .map((groupRecord) => groupRecord.gid),
    ];
  }
  const snapshot = parseIdentityDatabases(
    passwdText,
    groupText,
    effectiveGroups,
    gshadowText,
    shadowText,
  );
  const records = new Map([
    ['/etc/group', group],
    ['/etc/gshadow', gshadow],
    ['/etc/passwd', passwd],
    ['/etc/shadow', shadow],
  ]);
  return Object.freeze({
    ...snapshot,
    identityFiles: Object.freeze(IDENTITY_DATABASE_COMMIT_ORDER.map((file) => {
      const record = records.get(file);
      return Object.freeze({
        path: file,
        sha256: createHash('sha256').update(record.contents).digest('hex'),
        uid: record.stat.uid,
        gid: record.stat.gid,
        mode: record.stat.mode & 0o7777,
      });
    })),
  });
}

export async function readSystemBootPolicyCatalogs(
  runCommand = runFixedCommand,
  fsApi = fs,
) {
  await assertTrustedBootPolicySearchDirectories(fsApi);
  const [sysusers, tmpfiles, systemCredentials] = await Promise.all([
    runCommand('/usr/bin/systemd-sysusers', ['--cat-config', '--tldr', '--no-pager']),
    runCommand('/usr/bin/systemd-tmpfiles', ['--cat-config', '--tldr', '--no-pager']),
    runCommand(
      '/usr/bin/systemd-creds',
      ['--system', '--no-legend', '--no-pager', 'list'],
      [0, 1],
    ),
  ]);
  assertBootPolicyCatalogCommand('sysusers', sysusers);
  assertBootPolicyCatalogCommand('tmpfiles', tmpfiles);
  assertNoBootPolicySystemCredentials(systemCredentials);
  await assertNoBootPolicyCredentialStoreFiles(fsApi);
  const sources = Object.freeze({
    sysusers: await validateBootPolicySources('sysusers', sysusers.stdout, fsApi),
    tmpfiles: await validateBootPolicySources('tmpfiles', tmpfiles.stdout, fsApi),
  });
  await assertTrustedBootPolicySearchDirectories(fsApi);
  return Object.freeze({
    sysusers: sysusers.stdout,
    tmpfiles: tmpfiles.stdout,
    sources,
  });
}

async function assertTrustedBootPolicySearchDirectories(fsApi) {
  const usrMerged = await isUsrMergedLib(fsApi);
  const directories = new Set(Object.values(BOOT_POLICY_DIRECTORIES).flat());
  for (const directory of directories) {
    if (usrMerged && directory.startsWith('/lib/')) continue;
    try {
      await fsApi.lstat(directory);
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw error;
    }
    await assertTrustedDirectoryChain('/', directory, 0, 0, fsApi);
    const entries = await readTrustedDirectoryEntries(
      directory,
      MAX_SCANNED_DIRECTORY_ENTRIES,
      fsApi,
    );
    for (const entry of entries) {
      if (!entry.name.endsWith('.conf')) continue;
      if (path.basename(entry.name) !== entry.name || ['.', '..'].includes(entry.name)) {
        throw new Error(`boot policy search entry is not trusted: ${entry.name}`);
      }
      await assertTrustedBootPolicySearchEntry(path.join(directory, entry.name), fsApi);
    }
  }
}

async function assertTrustedBootPolicySearchEntry(file, fsApi) {
  const before = await fsApi.lstat(file);
  if (before.isSymbolicLink()) {
    const target = await fsApi.readlink(file);
    const after = await fsApi.lstat(file);
    if (
      target !== '/dev/null'
      || before.uid !== 0
      || before.gid !== 0
      || !sameFileIdentity(before, after)
    ) {
      throw new Error(`boot policy search entry is not trusted: ${file}`);
    }
    return;
  }
  if (!before.isFile()) {
    throw new Error(`boot policy search entry is not trusted: ${file}`);
  }
  const handle = await fsApi.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    const opened = await handle.stat();
    assertTrustedFileMetadata(file, opened, 0, 0, null);
    if (opened.size < 0 || opened.size > MAX_POLICY_FILE_BYTES) {
      throw new Error(`policy file size is invalid: ${file}`);
    }
    const contents = await handle.readFile();
    if (contents.length !== opened.size) {
      throw new Error(`policy file size is invalid: ${file}`);
    }
    const after = await handle.stat();
    if (!sameFileIdentity(opened, after)) {
      throw new Error(`policy file changed while reading: ${file}`);
    }
  } finally {
    await handle.close();
  }
}

function assertBootPolicyCatalogCommand(kind, result) {
  if (
    result.code !== 0
    || result.stderr !== ''
    || String(result.stdout).trim() === ''
  ) {
    throw new Error(`${kind} catalog listing is incomplete`);
  }
}

function assertNoBootPolicySystemCredentials(result) {
  if (
    result.code === 1
    && result.stdout === ''
    && result.stderr === 'No credentials passed to system.\n'
  ) {
    return;
  }
  if (result.code !== 0) {
    throw new Error('system credential listing failed');
  }
  if (result.stderr !== '') {
    throw new Error('system credential listing emitted unexpected stderr');
  }
  const output = String(result.stdout).trim();
  if (output === '' || output === 'No credentials passed to system.') return;
  for (const line of output.split('\n')) {
    const [name] = line.trim().split(/\s+/);
    if (credentialNameCanInjectHostPolicy(name)) {
      throw new Error(`system credential can inject host policy: ${name}`);
    }
  }
}

async function assertNoBootPolicyCredentialStoreFiles(fsApi) {
  for (const directory of CREDENTIAL_STORE_DIRECTORIES) {
    const entries = await readTrustedDirectoryEntries(
      directory,
      MAX_CREDENTIAL_STORE_ENTRIES,
      fsApi,
    );
    for (const entry of entries) {
      if (credentialNameCanInjectHostPolicy(entry.name)) {
        throw new Error(`credential store can inject host policy: ${path.join(directory, entry.name)}`);
      }
    }
  }
}

async function assertNoBootPolicySystemCredentialFiles(fsApi) {
  const entries = await readTrustedDirectoryEntries(
    SYSTEMD_SYSTEM_CREDENTIAL_DIRECTORY,
    MAX_CREDENTIAL_STORE_ENTRIES,
    fsApi,
  );
  for (const entry of entries) {
    if (credentialNameCanInjectHostPolicy(entry.name)) {
      throw new Error(`system credential can inject host policy: ${entry.name}`);
    }
  }
}

function credentialNameCanInjectHostPolicy(name) {
  return BOOT_POLICY_CREDENTIAL_NAMES.includes(name)
    || BOOT_POLICY_CREDENTIAL_PREFIXES.some((prefix) => name.startsWith(prefix));
}

async function validateBootPolicySources(kind, catalog, fsApi) {
  const allowedDirectories = BOOT_POLICY_DIRECTORIES[kind];
  const sources = new Set();
  let currentSource = null;
  for (const rawLine of String(catalog).split('\n')) {
    const line = rawLine.trim();
    if (line === '') continue;
    if (line.startsWith('#')) {
      const match = line.match(/^# (\/\S+)$/);
      if (!match) throw new Error(`${kind} catalog source marker is malformed`);
      const source = path.posix.normalize(match[1]);
      if (
        source !== match[1]
        || !allowedDirectories.some((directory) => path.dirname(source) === directory)
      ) {
        throw new Error(`${kind} catalog source is outside trusted policy directories: ${source}`);
      }
      currentSource = source;
      sources.add(source);
      continue;
    }
    if (currentSource === null) {
      throw new Error(`${kind} catalog policy is missing a source marker`);
    }
  }
  for (const source of sources) {
    await assertTrustedDirectoryChain('/', path.dirname(source), 0, 0, fsApi);
    await readTrustedFile(source, 0, 0, null, fsApi);
  }
  return Object.freeze([...sources]);
}

export function auditBootPolicyCatalogs(
  catalogs,
  inspected,
  identitySnapshot,
  { requireManagedPolicy = false } = {},
) {
  const managedNames = new Set([
    ...Object.values(MANAGED_USERS),
    ...Object.values(MANAGED_GROUPS),
  ]);
  const managedIds = new Set();
  for (const user of Object.values(MANAGED_USERS)) {
    const record = identitySnapshot.users.get(user);
    if (record) {
      managedIds.add(String(record.uid));
      managedIds.add(String(record.gid));
    }
  }
  for (const group of Object.values(MANAGED_GROUPS)) {
    const record = identitySnapshot.groups.get(group);
    if (record) managedIds.add(String(record.gid));
  }
  const occupiedIds = Object.freeze({
    users: new Set([...identitySnapshot.users.values()].map(({ uid }) => uid)),
    groups: new Set([...identitySnapshot.groups.values()].map(({ gid }) => gid)),
  });
  const protectedPaths = new Set([
    ...inspected.artifacts
      .filter((artifact) => artifact.kind === 'tmpfiles')
      .flatMap((artifact) => policyCatalogLines(artifact.source.contents))
      .map((line) => parseSystemdFields(line)[1]),
    ...inspected.artifacts.map((artifact) => artifact.targetPath),
    ...inspected.artifacts.map((artifact) => artifact.sourcePath).filter(Boolean),
    ...IDENTITY_POLICY_PATHS,
    ...IDENTITY_DATABASE_COMMIT_ORDER.map((file) => `${file}-`),
    ...IDENTITY_RECOVERY_CANDIDATE_PATHS,
    IDENTITY_LOCK_PATH,
    ...STATIC_USERDB_DIRECTORIES,
    SYSTEMD_USERDB_DIRECTORY,
    SYSTEMD_SYSTEM_CREDENTIAL_DIRECTORY,
    ...SYSTEMD_PROTECTED_UNIT_PATHS,
    ...Object.values(BOOT_POLICY_DIRECTORIES).flat(),
    ...BOOT_POLICY_CREDENTIAL_PATHS,
    ...FIXED_HOST_EXECUTABLE_PATHS,
    process.execPath,
    PROVISION_SCRIPT_PATH,
    TRANSACTION_PATH,
    PROVISION_LOCK_PATH,
  ]);

  for (const kind of ['sysusers', 'tmpfiles']) {
    if (typeof catalogs?.[kind] !== 'string') {
      throw new Error(`boot policy catalog is missing: ${kind}`);
    }
    const managedArtifacts = inspected.artifacts.filter((artifact) => artifact.kind === kind);
    const allowed = new Set(managedArtifacts
      .flatMap((artifact) => policyCatalogLines(artifact.source.contents)));
    const managedSources = new Map(managedArtifacts.map((artifact) => [
      artifact.targetPath,
      new Set([
        ...policyCatalogLines(artifact.source.contents),
        ...(artifact.existing ? policyCatalogLines(artifact.existing.contents) : []),
      ]),
    ]));
    const observed = policyCatalogEntries(catalogs[kind]);
    const sourceAware = observed.some(({ source }) => source !== null);
    if (requireManagedPolicy) {
      for (const artifact of managedArtifacts) {
        for (const line of policyCatalogLines(artifact.source.contents)) {
          if (!observed.some((entry) => (
            entry.line === line
            && (!sourceAware || entry.source === artifact.targetPath)
          ))) {
            throw new Error(`managed ${kind} policy is not active: ${line}`);
          }
        }
      }
    }
    for (const { line, source } of observed) {
      const sourceLines = source === null ? null : managedSources.get(source);
      if ((sourceAware ? sourceLines?.has(line) : allowed.has(line))) continue;
      if (bootPolicyLineTouchesManagedSurface(
        kind,
        line,
        managedNames,
        managedIds,
        occupiedIds,
        protectedPaths,
      )) {
        throw new Error(`unmanaged ${kind} policy touches the Webex boundary: ${line}`);
      }
    }
  }
}

export async function assertManagedRuntimeAncestorsTraversable(
  plan,
  inspected,
  {
    fsApi = fs,
    targetUid = 0,
    targetGid = 0,
    verifyNoExtendedPosixAcl = assertNoExtendedPosixAcl,
  } = {},
) {
  const entries = managedTmpfilesEntries(plan, inspected);
  const managedTargets = new Set(entries.map(({ target }) => target));
  const ancestors = new Set(entries.flatMap(({ target }) => (
    pathComponentsWithin(plan.targetRoot, path.dirname(target))
  )));
  for (const ancestor of [...ancestors].sort()) {
    if (managedTargets.has(ancestor)) continue;
    let stat;
    try {
      stat = await fsApi.lstat(ancestor);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        throw new Error(`managed runtime ancestor is missing: ${ancestor}`);
      }
      throw error;
    }
    assertTrustedDirectory(ancestor, stat, targetUid, targetGid);
    if (((stat.mode & 0o7777) & 0o001) === 0) {
      throw new Error(`managed runtime ancestor is not traversable: ${ancestor}`);
    }
    await verifyNoExtendedPosixAcl(ancestor);
    const after = await fsApi.lstat(ancestor);
    if (
      !sameFileIdentity(stat, after)
      || !after.isDirectory()
      || after.isSymbolicLink()
      || after.uid !== targetUid
      || after.gid !== targetGid
      || ((after.mode & 0o7777) & 0o022) !== 0
      || ((after.mode & 0o7777) & 0o001) === 0
    ) {
      throw new Error(`managed runtime ancestor changed during ACL inspection: ${ancestor}`);
    }
  }
  for (const entry of entries) {
    let stat;
    try {
      stat = await fsApi.lstat(entry.target);
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw error;
    }
    const correctType = entry.type === 'd' ? stat.isDirectory() : stat.isFile();
    if (
      !correctType
      || stat.isSymbolicLink()
      || (entry.type === 'f' && stat.nlink !== 1)
    ) {
      throw new Error(`managed runtime path is not safe to mutate: ${entry.target}`);
    }
    await verifyNoExtendedPosixAcl(entry.target);
    const after = await fsApi.lstat(entry.target);
    const afterCorrectType = entry.type === 'd' ? after.isDirectory() : after.isFile();
    if (
      !sameFileIdentity(stat, after)
      || !afterCorrectType
      || after.isSymbolicLink()
      || (entry.type === 'f' && after.nlink !== 1)
      || after.uid !== stat.uid
      || after.gid !== stat.gid
      || (after.mode & 0o7777) !== (stat.mode & 0o7777)
    ) {
      throw new Error(`managed runtime path changed during ACL inspection: ${entry.target}`);
    }
  }
}

export async function verifyManagedTmpfilesState(
  plan,
  inspected,
  identitySnapshot,
  {
    fsApi = fs,
    targetUid = 0,
    targetGid = 0,
    verifyNoExtendedPosixAcl = assertNoExtendedPosixAcl,
  } = {},
) {
  await assertManagedRuntimeAncestorsTraversable(plan, inspected, {
    fsApi,
    targetUid,
    targetGid,
    verifyNoExtendedPosixAcl,
  });
  for (const entry of managedTmpfilesEntries(plan, inspected, identitySnapshot)) {
    let stat;
    try {
      stat = await fsApi.lstat(entry.target);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        throw new Error(`managed runtime path is missing: ${entry.target}`);
      }
      throw error;
    }
    const correctType = entry.type === 'd' ? stat.isDirectory() : stat.isFile();
    if (
      !correctType
      || stat.isSymbolicLink()
      || (entry.type === 'f' && stat.nlink !== 1)
      || stat.uid !== entry.uid
      || stat.gid !== entry.gid
      || (stat.mode & 0o7777) !== entry.mode
    ) {
      throw new Error(`managed runtime path metadata is not converged: ${entry.target}`);
    }
    await verifyNoExtendedPosixAcl(entry.target);
    const after = await fsApi.lstat(entry.target);
    const afterCorrectType = entry.type === 'd' ? after.isDirectory() : after.isFile();
    if (
      !sameFileIdentity(stat, after)
      || !afterCorrectType
      || after.isSymbolicLink()
      || (entry.type === 'f' && after.nlink !== 1)
      || after.uid !== entry.uid
      || after.gid !== entry.gid
      || (after.mode & 0o7777) !== entry.mode
    ) {
      throw new Error(`managed runtime path changed during ACL inspection: ${entry.target}`);
    }
  }
}

export async function assertNoExtendedPosixAcl(file, runCommand = runFixedCommand) {
  const result = await runCommand('/usr/bin/getfacl', [
    '--absolute-names',
    '--numeric',
    '--omit-header',
    '--skip-base',
    '--physical',
    '--',
    file,
  ]);
  if (result.code !== 0 || result.stderr !== '') {
    throw new Error(`managed runtime POSIX ACL inspection failed: ${file}`);
  }
  if (result.stdout !== '') {
    throw new Error(`managed runtime path has an extended POSIX ACL: ${file}`);
  }
}

function managedTmpfilesEntries(plan, inspected, identitySnapshot = null) {
  const entries = new Map();
  for (const artifact of inspected.artifacts.filter(({ kind }) => kind === 'tmpfiles')) {
    for (const line of policyCatalogLines(artifact.source.contents)) {
      const fields = parseSystemdFields(line);
      if (fields.length !== 6) {
        throw new Error(`managed tmpfiles policy line is malformed: ${line}`);
      }
      const [type, rawPath, rawMode, user, group, age] = fields;
      const policyPath = normaliseBootPolicyPath(rawPath);
      if (
        !['d', 'f'].includes(type)
        || !['-', '1d'].includes(age)
        || !path.posix.isAbsolute(rawPath)
        || policyPath !== rawPath
        || !/^[0-7]{3,4}$/.test(rawMode)
      ) {
        throw new Error(`managed tmpfiles policy line is unsupported: ${line}`);
      }
      const target = rootedPath(plan.targetRoot, policyPath);
      const entry = {
        type,
        target,
        mode: Number.parseInt(rawMode, 8),
        user,
        group,
      };
      if (identitySnapshot) {
        entry.uid = resolveTmpfilesIdentity(user, 'user', identitySnapshot);
        entry.gid = resolveTmpfilesIdentity(group, 'group', identitySnapshot);
      }
      const existing = entries.get(target);
      const signature = JSON.stringify([type, entry.mode, user, group]);
      if (existing && existing.signature !== signature) {
        throw new Error(`managed tmpfiles path has conflicting policy: ${policyPath}`);
      }
      entries.set(target, Object.freeze({ ...entry, signature }));
    }
  }
  return Object.freeze([...entries.values()]);
}

function resolveTmpfilesIdentity(name, kind, identitySnapshot) {
  if (name === 'root' || name === '0') return 0;
  const record = kind === 'user'
    ? identitySnapshot.users.get(name)
    : identitySnapshot.groups.get(name);
  if (!record) throw new Error(`managed tmpfiles ${kind} is missing: ${name}`);
  return kind === 'user' ? record.uid : record.gid;
}

function policyCatalogLines(contents) {
  return policyCatalogEntries(contents).map(({ line }) => line);
}

function policyCatalogEntries(contents) {
  const logicalLines = [];
  let pending = '';
  let source = null;
  for (const physicalLine of String(contents).split('\n')) {
    const trimmed = physicalLine.trimStart();
    if (pending === '' && trimmed.startsWith('#')) {
      const match = trimmed.match(/^# (\/\S+)$/);
      if (match) source = path.posix.normalize(match[1]);
      continue;
    }
    if (
      pending !== ''
      && (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith(';'))
    ) {
      continue;
    }
    const line = `${pending}${physicalLine}`;
    if (hasTrailingContinuation(line)) {
      pending = `${line.slice(0, -1)} `;
    } else {
      logicalLines.push(Object.freeze({ line, source }));
      pending = '';
    }
  }
  if (pending !== '') throw new Error('boot policy ends with an unterminated continuation');
  return logicalLines
    .map((entry) => Object.freeze({ ...entry, line: entry.line.trim() }))
    .filter(({ line }) => line !== '' && !line.startsWith('#') && !line.startsWith(';'));
}

function hasTrailingContinuation(line) {
  let backslashes = 0;
  for (let offset = line.length - 1; offset >= 0 && line[offset] === '\\'; offset -= 1) {
    backslashes += 1;
  }
  return backslashes % 2 === 1;
}

function bootPolicyLineTouchesManagedSurface(
  kind,
  line,
  managedNames,
  managedIds,
  occupiedIds,
  protectedPaths,
) {
  const fields = parseSystemdFields(line);
  if (kind === 'sysusers') {
    return sysusersLineTouchesManagedSurface(
      fields,
      managedNames,
      managedIds,
      occupiedIds,
      protectedPaths,
    );
  }
  if (kind === 'tmpfiles') {
    return tmpfilesLineTouchesManagedSurface(fields, managedNames, managedIds, protectedPaths);
  }
  throw new Error(`unsupported boot policy kind: ${kind}`);
}

function sysusersLineTouchesManagedSurface(
  fields,
  managedNames,
  managedIds,
  occupiedIds,
  protectedPaths,
) {
  if (fields.length < 3) throw new Error('sysusers policy line is malformed');
  const [type, name, id] = fields;
  if (managedNames.has(name) || [...managedNames].some((managed) => id === managed)) return true;
  if (name.includes('%') || id.includes('%')) return true;
  if (type === 'm') return managedNames.has(name) || managedNames.has(id);
  if (['u', 'u!', 'g', 'g!'].includes(type)) {
    if (id.startsWith('/')) return true;
    if (sysusersIdClaimsUnmaterialisedLocalId(type, id, occupiedIds)) return true;
    for (const component of id.split(':')) {
      if (managedIds.has(component) || managedNames.has(component)) return true;
    }
    for (const field of fields.slice(3)) {
      if (pathFieldTouchesProtected(field, true, protectedPaths)) return true;
    }
    return false;
  }
  if (type === 'r') {
    return true;
  }
  throw new Error(`unsupported sysusers policy type: ${type}`);
}

function sysusersIdClaimsUnmaterialisedLocalId(type, id, occupiedIds) {
  const components = id.split(':');
  if (components.length > 2) return true;
  const [userOrGroupId, primaryGroupId] = components;
  if (type === 'g' || type === 'g!') {
    return localIdentityIdIsUnmaterialised(userOrGroupId, occupiedIds.groups);
  }
  if (localIdentityIdIsUnmaterialised(userOrGroupId, occupiedIds.users)) return true;
  const groupId = primaryGroupId === undefined ? userOrGroupId : primaryGroupId;
  return localIdentityIdIsUnmaterialised(groupId, occupiedIds.groups);
}

function localIdentityIdIsUnmaterialised(id, occupiedIds) {
  if (!/^[0-9]+$/.test(id)) return false;
  const parsed = Number(id);
  return Number.isSafeInteger(parsed)
    && parsed > 0
    && parsed <= MAX_MANAGED_ID
    && !occupiedIds.has(parsed);
}

function tmpfilesLineTouchesManagedSurface(fields, managedNames, managedIds, protectedPaths) {
  if (fields.length < 2) throw new Error('tmpfiles policy line is malformed');
  const [type, policyPath] = fields;
  const user = normaliseTmpfilesOwner(fields[3] ?? '-');
  const group = normaliseTmpfilesOwner(fields[4] ?? '-');
  if (
    identityTokenTouchesManagedSurface(user, managedNames, managedIds)
    || identityTokenTouchesManagedSurface(group, managedNames, managedIds)
  ) {
    return true;
  }
  const credentialStorePolicy = tmpfilesCredentialStorePathTouchesManagedSurface(fields);
  if (credentialStorePolicy !== null) return credentialStorePolicy;
  const argument = fields.length > 6 ? fields.slice(6).join(' ') : undefined;
  if (type === 'L' && policyPath === '/var/run' && argument !== undefined) {
    if (['../run', '/run'].includes(argument)) return false;
  }
  if (pathFieldTouchesProtected(
    policyPath,
    tmpfilesAncestorPolicyIsSafe(fields),
    protectedPaths,
  )) {
    return true;
  }
  if (argument === undefined || argument === '-') return false;
  if (type.startsWith('C')) {
    return !argument.startsWith('/')
      || pathFieldTouchesProtected(argument, false, protectedPaths);
  }
  if (type.startsWith('L')) {
    if (argument.includes('%')) return true;
    const resolvedTarget = argument.startsWith('/')
      ? normaliseBootPolicyPath(argument)
      : resolveBootPolicyRelativePath(path.posix.dirname(policyPath), argument);
    return pathFieldTouchesProtected(resolvedTarget, false, protectedPaths);
  }
  if (/^[aA]/.test(type)) {
    const acl = fields.slice(6).join(' ');
    if (acl.includes('%')) return true;
    return acl.split(/[^A-Za-z0-9_.+:-]+/)
      .flatMap((entry) => entry.split(':'))
      .some((token) => identityTokenTouchesManagedSurface(
        normaliseTmpfilesOwner(token),
        managedNames,
        managedIds,
      ));
  }
  return false;
}

function tmpfilesCredentialStorePathTouchesManagedSurface(fields) {
  const policyPath = normaliseBootPolicyPath(fields[1]);
  for (const directory of CREDENTIAL_STORE_DIRECTORIES) {
    if (policyPath === directory) {
      return !tmpfilesCredentialStoreDirectoryPolicyIsSafe(fields);
    }
    if (policyPath.startsWith(`${directory}/`)) return true;
  }
  return null;
}

function tmpfilesCredentialStoreDirectoryPolicyIsSafe(fields) {
  const [type, , mode = '-', rawUser = '-', rawGroup = '-', age = '-'] = fields;
  if (!/^[devqQz]$/.test(type ?? '') || age !== '-') return false;
  const user = normaliseTmpfilesOwner(rawUser);
  const group = normaliseTmpfilesOwner(rawGroup);
  if (!['-', 'root', '0'].includes(user) || !['-', 'root', '0'].includes(group)) return false;
  if (mode === '-') return true;
  if (!/^[0-7]{3,4}$/.test(mode)) return false;
  const parsedMode = Number.parseInt(mode, 8);
  return (parsedMode & 0o700) === 0o700 && (parsedMode & 0o022) === 0;
}

function normaliseTmpfilesOwner(owner) {
  return owner.replace(/^[:+]+/, '');
}

function identityTokenTouchesManagedSurface(identity, managedNames, managedIds) {
  if (managedNames.has(identity) || managedIds.has(identity)) return true;
  if (!/^[0-9]+$/.test(identity)) return false;
  const id = Number(identity);
  return Number.isSafeInteger(id) && id > 0 && id <= MAX_MANAGED_ID;
}

function pathFieldTouchesProtected(policyPath, ancestorPolicyIsSafe, protectedPaths) {
  if (!policyPath.startsWith('/')) return policyPath.includes('%');
  if (bootPolicyPatternHasParentTraversal(policyPath)) return true;
  const normalisedPolicyPath = normaliseBootPolicyPath(policyPath);
  if (/(^|\/)webex(?:-|\/|$)/.test(normalisedPolicyPath)) return true;
  const wildcardOffset = normalisedPolicyPath.search(/[%*?[]/);
  const literal = wildcardOffset < 0 ? normalisedPolicyPath : null;
  const staticPrefix = wildcardOffset < 0
    ? literal
    : normalisedPolicyPath.slice(0, wildcardOffset);
  if (
    wildcardOffset >= 0
    && (
      '/var/run'.startsWith(staticPrefix)
      || staticPrefix === '/var/run'
      || staticPrefix.startsWith('/var/run/')
    )
  ) {
    return true;
  }
  for (const protectedPath of protectedPaths) {
    if (literal !== null) {
      if (literal === protectedPath || literal.startsWith(`${protectedPath}/`)) return true;
      const protectsAncestor = literal === '/'
        ? protectedPath.startsWith('/')
        : protectedPath.startsWith(`${literal}/`);
      if (
        protectsAncestor
        && !ancestorPolicyIsSafe
      ) {
        return true;
      }
      continue;
    }
    if (
      protectedPath.startsWith(staticPrefix)
      || staticPrefix === protectedPath
      || staticPrefix.startsWith(`${protectedPath}/`)
    ) {
      return true;
    }
  }
  return false;
}

function bootPolicyPatternHasParentTraversal(policyPath) {
  const components = policyPath.split('/');
  const hasPattern = components.some((component) => /[%*?[\]]/.test(component));
  return hasPattern && components.includes('..');
}

function resolveBootPolicyRelativePath(basePath, relativePath) {
  const normalisedBase = normaliseBootPolicyPath(basePath);
  return normaliseBootPolicyPath(`${normalisedBase}/${relativePath}`);
}

function normaliseBootPolicyPath(policyPath) {
  if (!policyPath.startsWith('/')) return path.posix.normalize(policyPath);
  const components = [];
  for (const component of policyPath.split('/')) {
    if (component === '' || component === '.') continue;
    if (component === '..') {
      components.pop();
      continue;
    }
    components.push(component);
    if (components.length === 2 && components[0] === 'var' && components[1] === 'run') {
      components.splice(0, components.length, 'run');
    }
  }
  return `/${components.join('/')}`;
}

function assertNoUnexpectedManagedMounts(plan, inspected, mountInfo) {
  return assertNoUnexpectedMountsForPaths(
    protectedHostMountPaths(plan, inspected),
    mountInfo,
  );
}

function assertNoUnexpectedMountsForPaths(protectedPaths, mountInfo) {
  const mounts = parseMountInfo(mountInfo);
  const mountIdentityCounts = new Map();
  const mountPointCounts = new Map();
  for (const { device, root, mountPoint } of mounts) {
    const identity = `${device}\0${root}`;
    mountIdentityCounts.set(identity, (mountIdentityCounts.get(identity) ?? 0) + 1);
    mountPointCounts.set(mountPoint, (mountPointCounts.get(mountPoint) ?? 0) + 1);
  }
  const relevantMounts = [];
  for (const mount of mounts) {
    const {
      device,
      root,
      mountPoint,
      raw,
    } = mount;
    if (mountAliasesProtectedPath(mount, mounts, protectedPaths)) {
      throw new Error(`unexpected mount aliases protected host path: ${mountPoint}`);
    }
    for (const protectedPath of protectedPaths) {
      if (!systemdPathsOverlap(mountPoint, protectedPath)) continue;
      relevantMounts.push(raw);
      if (mountPoint === protectedPath || mountPoint.startsWith(`${protectedPath}/`)) {
        throw new Error(`unexpected mount overlaps protected host path: ${mountPoint}`);
      }
      const mountIsAncestor = mountPoint === '/'
        ? protectedPath.startsWith('/')
        : protectedPath.startsWith(`${mountPoint}/`);
      if (!mountIsAncestor) continue;
      const uniqueFilesystemRoot = mountIdentityCounts.get(`${device}\0${root}`) === 1;
      const uniqueMountPoint = mountPointCounts.get(mountPoint) === 1;
      if (
        TRUSTED_MANAGED_MOUNT_ANCESTORS.has(mountPoint)
        && root === '/'
        && uniqueFilesystemRoot
        && uniqueMountPoint
      ) continue;
      throw new Error(`unexpected mount overlaps protected host path: ${mountPoint}`);
    }
  }
  return Object.freeze([...new Set(relevantMounts)].sort());
}

function mountAliasesProtectedPath(mount, mounts, protectedPaths) {
  if (!path.posix.isAbsolute(mount.root)) return false;
  return mounts.some((anchor) => {
    if (anchor.mountId === mount.mountId || anchor.device !== mount.device) return false;
    if (!path.posix.isAbsolute(anchor.root)) return false;
    const rootWithinAnchor = anchor.root === '/'
      ? mount.root.startsWith('/')
      : mount.root === anchor.root || mount.root.startsWith(`${anchor.root}/`);
    if (!rootWithinAnchor) return false;
    const relativeRoot = path.posix.relative(anchor.root, mount.root);
    const sourcePath = normaliseBootPolicyPath(
      path.posix.join(anchor.mountPoint, relativeRoot),
    );
    return [...protectedPaths].some((protectedPath) => (
      systemdPathsOverlap(sourcePath, protectedPath)
    ));
  });
}

function protectedHostMountPaths(plan, inspected) {
  const managedPaths = inspected.artifacts
    .filter(({ kind }) => kind === 'tmpfiles')
    .flatMap(({ source }) => policyCatalogLines(source.contents))
    .map((line) => parseSystemdFields(line)[1])
    .map(normaliseBootPolicyPath);
  return new Set([
    ...protectedSystemdMountPaths(),
    ...managedPaths,
    ...plan.artifacts.flatMap(({ source, target, targetPath }) => [source, target, targetPath]),
    plan.transactionFile,
    process.execPath,
    PROVISION_SCRIPT_PATH,
  ].map((candidate) => path.resolve(candidate)));
}

function assertProtectedMountSnapshotUnchanged(before, after) {
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error('protected host mount snapshot changed during command execution');
  }
}

function parseMountInfo(mountInfo) {
  const contents = Buffer.isBuffer(mountInfo)
    ? mountInfo
    : Buffer.from(String(mountInfo), 'utf8');
  if (contents.length > MAX_MOUNTINFO_BYTES) {
    throw new Error('mountinfo exceeds the safety limit');
  }
  const text = contents.toString('utf8');
  if (text.includes('\uFFFD')) throw new Error('mountinfo is not valid UTF-8');
  const lines = text.split('\n').filter((line) => line !== '');
  if (lines.length > MAX_MOUNTINFO_ENTRIES) {
    throw new Error('mountinfo has too many entries');
  }
  const mounts = lines.map((line) => {
    const fields = line.split(' ');
    const separator = fields.indexOf('-');
    if (separator < 6 || fields.length < separator + 4) {
      throw new Error('mountinfo entry is malformed');
    }
    const root = decodeMountInfoPath(fields[3]);
    const mountPoint = decodeMountInfoPath(fields[4]);
    const device = fields[2];
    const mountId = fields[0];
    const parentId = fields[1];
    if (!/^[1-9][0-9]*$/.test(mountId) || !/^[0-9]+$/.test(parentId)) {
      throw new Error('mountinfo identity is malformed');
    }
    if (!/^[0-9]+:[0-9]+$/.test(device)) {
      throw new Error('mountinfo device is malformed');
    }
    if (!path.posix.isAbsolute(mountPoint)) {
      throw new Error('mountinfo mount point is not absolute');
    }
    if (!path.posix.isAbsolute(root) && !/^[A-Za-z0-9_.-]+:\[[0-9]+\]$/.test(root)) {
      throw new Error('mountinfo root is malformed');
    }
    return Object.freeze({
      mountId,
      parentId,
      device,
      root: path.posix.isAbsolute(root) ? path.posix.normalize(root) : root,
      mountPoint: path.posix.normalize(mountPoint),
      raw: line,
    });
  });
  if (mounts.filter(({ mountPoint }) => mountPoint === '/').length !== 1) {
    throw new Error('mountinfo must contain exactly one root mount');
  }
  return mounts;
}

function decodeMountInfoPath(value) {
  if (/\\(?![0-7]{3})/.test(value)) {
    throw new Error('mountinfo path escape is malformed');
  }
  return value.replace(/\\([0-7]{3})/g, (_match, encoded) => (
    String.fromCodePoint(Number.parseInt(encoded, 8))
  ));
}

function tmpfilesAncestorPolicyIsSafe(fields) {
  const [type, , mode = '-', rawUser = '-', rawGroup = '-', age = '-'] = fields;
  if (!/^[devqQz][!-]*$/.test(type ?? '')) return false;
  if (age !== '-') return false;
  const user = normaliseTmpfilesOwner(rawUser);
  const group = normaliseTmpfilesOwner(rawGroup);
  if (!['-', 'root', '0'].includes(user) || !['-', 'root', '0'].includes(group)) return false;
  if (mode === '-') return true;
  if (!/^[0-7]{3,4}$/.test(mode)) return false;
  const parsedMode = Number.parseInt(mode, 8);
  return (parsedMode & 0o022) === 0 && (parsedMode & 0o111) === 0o111;
}

function parseSystemdFields(line) {
  const fields = [];
  let field = '';
  let quote = null;
  let started = false;
  for (let offset = 0; offset < line.length; offset += 1) {
    const character = line[offset];
    if (quote !== null) {
      if (character === quote) {
        quote = null;
      } else if (character === '\\') {
        const decoded = decodeSystemdEscape(line, offset);
        field += decoded.value;
        offset = decoded.end;
      } else {
        field += character;
      }
      started = true;
      continue;
    }
    if (/\s/.test(character)) {
      if (started) {
        fields.push(field);
        field = '';
        started = false;
      }
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      started = true;
      continue;
    }
    if (character === '\\') {
      const decoded = decodeSystemdEscape(line, offset);
      field += decoded.value;
      offset = decoded.end;
    } else {
      field += character;
    }
    started = true;
  }
  if (quote !== null) throw new Error('systemd policy field has an unterminated quote');
  if (started) fields.push(field);
  return fields;
}

function decodeSystemdEscape(value, offset) {
  const marker = value[offset + 1];
  const simple = new Map([
    ['a', '\x07'], ['b', '\b'], ['e', '\x1b'], ['f', '\f'], ['n', '\n'], ['r', '\r'],
    ['s', ' '], ['t', '\t'], ['v', '\v'], ['\\', '\\'], ['"', '"'], ["'", "'"],
  ]);
  if (simple.has(marker)) return { value: simple.get(marker), end: offset + 1 };
  const formats = marker === 'x'
    ? { digits: 2, radix: 16 }
    : marker === 'u'
      ? { digits: 4, radix: 16 }
      : marker === 'U'
        ? { digits: 8, radix: 16 }
        : /[0-7]/.test(marker ?? '')
          ? { digits: Math.min(3, (value.slice(offset + 1).match(/^[0-7]+/)?.[0].length ?? 0)), radix: 8 }
          : null;
  if (!formats || formats.digits === 0) throw new Error('systemd policy contains an invalid escape');
  const start = marker === 'x' || marker === 'u' || marker === 'U' ? offset + 2 : offset + 1;
  const encoded = value.slice(start, start + formats.digits);
  const pattern = formats.radix === 16 ? /^[0-9A-Fa-f]+$/ : /^[0-7]+$/;
  if (encoded.length !== formats.digits || !pattern.test(encoded)) {
    throw new Error('systemd policy contains an invalid escape');
  }
  const codePoint = Number.parseInt(encoded, formats.radix);
  if (codePoint === 0 || codePoint > 0x10ffff) {
    throw new Error('systemd policy contains an invalid code point');
  }
  return {
    value: String.fromCodePoint(codePoint),
    end: start + formats.digits - 1,
  };
}

export async function readSystemUnitStates(
  units,
  runCommand = runFixedCommand,
  fsApi = fs,
  identitySnapshot = null,
) {
  const unitPaths = await reviewedSystemdManagerUnitPaths(fsApi);
  await assertNoUnexpectedManagedUnitPolicy(
    fsApi,
    managedIdentityIds(identitySnapshot),
    unitPaths,
  );
  await assertSystemdManagerUnitPath(runCommand, unitPaths);
  const [loadedInstances, installedInstances] = await Promise.all([
    runCommand('/usr/bin/systemctl', [
      'list-units',
      '--all',
      '--full',
      '--plain',
      '--no-legend',
      '--no-pager',
      '--type=service',
      'webex-codex-launcher@*.service',
    ]),
    runCommand('/usr/bin/systemctl', [
      'list-unit-files',
      '--full',
      '--no-legend',
      '--no-pager',
      'webex-codex-launcher@*.service',
    ]),
  ]);
  assertSystemctlCommandSucceeded(loadedInstances, 'launcher runtime unit listing');
  assertSystemctlCommandSucceeded(installedInstances, 'launcher installed unit listing');
  const discovered = new Set([
    ...parseLauncherInstanceUnits(loadedInstances.stdout),
    ...parseLauncherInstanceUnits(installedInstances.stdout),
  ]);
  if (discovered.size > MAX_LAUNCHER_INSTANCES) {
    throw new Error('too many launcher instances');
  }
  const states = new Map();
  for (const unit of [...units, ...[...discovered].sort()]) {
    const [active, metadata] = await Promise.all([
      runCommand('/usr/bin/systemctl', ['is-active', unit], [0, 3, 4]),
      runCommand('/usr/bin/systemctl', [
        'show',
        '--property=Job',
        '--property=LoadState',
        '--property=UnitFileState',
        '--property=FragmentPath',
        '--property=DropInPaths',
        '--property=NeedDaemonReload',
        ...REVERSE_ACTIVATION_PROPERTIES.map((property) => `--property=${property}`),
        unit,
      ]),
    ]);
    const activeState = parseSystemctlStateQuery(active, unit, 'active');
    assertSystemctlCommandSucceeded(metadata, `managed unit metadata query: ${unit}`);
    const loadedPolicy = parseSystemUnitMetadata(metadata.stdout, unit);
    const verifiedActiveState = verifySystemctlActiveState(
      unit,
      active,
      activeState,
      loadedPolicy.load,
    );
    states.set(unit, Object.freeze({
      active: verifiedActiveState,
      ...loadedPolicy,
    }));
  }
  return states;
}

async function reviewedSystemdManagerUnitPaths(fsApi) {
  if (await isUsrMergedLib(fsApi)) return SYSTEMD_MANAGER_UNIT_PATHS;
  return Object.freeze(SYSTEMD_MANAGER_UNIT_PATHS.map((directory) => (
    directory === '/usr/lib/systemd/system' ? '/lib/systemd/system' : directory
  )));
}

async function assertSystemdManagerUnitPath(runCommand, unitPaths) {
  const result = await runCommand('/usr/bin/systemctl', [
    'show',
    '--property=UnitPath',
    '--value',
  ]);
  const expected = `${unitPaths.join(' ')}\n`;
  if (result.code !== 0 || result.stderr !== '' || result.stdout !== expected) {
    throw new Error('systemd manager unit path is not the reviewed fixed path');
  }
}

function assertSystemctlCommandSucceeded(result, label) {
  if (result.code !== 0 || result.stderr !== '') {
    throw new Error(`${label} failed`);
  }
}

function parseSystemctlStateQuery(result, unit, kind) {
  const output = String(result.stdout ?? '');
  if (
    !Number.isInteger(result.code)
    || result.stderr !== ''
    || !/^[a-z][a-z-]*\n$/.test(output)
  ) {
    throw new Error(`managed unit ${kind} state query is malformed: ${unit}`);
  }
  return output.slice(0, -1);
}

function verifySystemctlActiveState(
  unit,
  activeResult,
  activeState,
  loadState,
) {
  if (loadState === 'not-found') {
    const missingState = (
      activeResult.code === 3
      && activeState === 'inactive'
    ) || (
      activeResult.code === 4
      && ['inactive', 'unknown'].includes(activeState)
    );
    if (!missingState) {
      throw new Error(`managed unit query state disagrees with load state: ${unit}`);
    }
    return 'inactive';
  }
  if (loadState === 'loaded') {
    const activeCodeMatchesState = (
      activeResult.code === 0
      && ['active', 'activating', 'deactivating', 'maintenance', 'refreshing', 'reloading']
        .includes(activeState)
    ) || (
      activeResult.code === 3
      && ['failed', 'inactive'].includes(activeState)
    );
    if (!activeCodeMatchesState) {
      throw new Error(`managed unit query state disagrees with load state: ${unit}`);
    }
  }
  return activeState;
}

async function assertNoUnexpectedManagedUnitPolicy(fsApi, managedIds, unitPaths) {
  await assertNoBootPolicySystemCredentialFiles(fsApi);
  const budget = { entries: 0, files: 0, bytes: 0 };
  for (const directory of unitPaths) {
    const entries = await readTrustedDirectoryEntries(
      directory,
      Math.min(
        MAX_SYSTEMD_UNIT_PATH_ENTRIES,
        MAX_SYSTEMD_POLICY_TREE_ENTRIES - budget.entries,
      ),
      fsApi,
    );
    budget.entries += entries.length;
    for (const entry of entries) {
      const instanceUnit = /^webex-codex-launcher@[^@/\s]+\.service$/.test(entry.name);
      const policyDirectory =
        /^webex-codex-launcher@(?:[^@/\s]+)?\.service(?:\.d|\.wants|\.requires|\.upholds)$/
          .test(entry.name);
      const managedUnitPolicyDirectory = MANAGED_UNIT_POLICY_DIRECTORY_NAMES.includes(entry.name);
      const bootPolicyConsumerPolicyDirectory =
        BOOT_POLICY_SYSTEMD_CONSUMER_POLICY_DIRECTORY_NAMES.has(entry.name);
      const managedFragmentOutsideTarget = MANAGED_UNITS.includes(entry.name)
        && directory !== '/etc/systemd/system';
      if (bootPolicyConsumerPolicyDirectory) {
        throw new Error(
          `boot policy systemd consumer policy directory is not trusted: ${path.join(directory, entry.name)}`,
        );
      }
      if (
        instanceUnit
        || policyDirectory
        || managedUnitPolicyDirectory
        || managedFragmentOutsideTarget
      ) {
        throw new Error(
          `unexpected managed unit policy in systemd unit path: ${path.join(directory, entry.name)}`,
        );
      }
      if (directory === '/etc/systemd/system' && MANAGED_UNITS.includes(entry.name)) {
        continue;
      }
      await auditSystemdPolicyEntry(
        directory,
        entry,
        budget,
        fsApi,
        managedIds,
        { nested: false },
      );
    }
  }
}

async function auditSystemdPolicyEntry(
  directory,
  entry,
  budget,
  fsApi,
  managedIds,
  { nested },
) {
  const candidate = path.join(directory, entry.name);
  const unitNames = systemdPolicyUnitNames(directory, entry.name);
  const bootPolicyConsumer = [...unitNames].some((unit) => (
    BOOT_POLICY_SYSTEMD_CONSUMER_UNITS.has(unit)
  ));
  assertSystemdPolicyDoesNotReferenceManaged(entry.name, candidate, unitNames, managedIds);
  const unitFile = SYSTEMD_UNIT_NAME_PATTERN.test(entry.name);
  const policyDirectory = /\.(?:d|wants|requires|upholds)$/.test(entry.name);
  if (!nested && !unitFile && !policyDirectory && !entry.isDirectory?.()) return;
  const stat = await fsApi.lstat(candidate);
  if (stat.isSymbolicLink()) {
    await auditSystemdPolicySymlink(
      candidate,
      budget,
      fsApi,
      new Set(),
      unitNames,
      managedIds,
      candidate,
    );
    return;
  }
  if (stat.isFile()) {
    await auditSystemdPolicyFile(candidate, budget, fsApi, unitNames, managedIds, candidate);
    return;
  }
  if (bootPolicyConsumer) {
    throw new Error(`boot policy systemd consumer is not trusted: ${candidate}`);
  }
  if (!stat.isDirectory()) return;
  if (!/\.(?:d|wants|requires|upholds)$/.test(entry.name)) return;
  const nestedEntries = await readTrustedDirectoryEntries(
    candidate,
    MAX_SYSTEMD_POLICY_TREE_ENTRIES - budget.entries,
    fsApi,
  );
  budget.entries += nestedEntries.length;
  for (const child of nestedEntries) {
    const childPath = path.join(candidate, child.name);
    if ((await fsApi.lstat(childPath)).isDirectory()) {
      throw new Error(`nested systemd policy directory is not supported: ${path.join(candidate, child.name)}`);
    }
    await auditSystemdPolicyEntry(
      candidate,
      child,
      budget,
      fsApi,
      managedIds,
      { nested: true },
    );
  }
}

async function auditSystemdPolicySymlink(
  candidate,
  budget,
  fsApi,
  visited,
  unitNames,
  managedIds,
  logicalSource,
) {
  if (visited.has(candidate) || visited.size >= 32) {
    throw new Error(`systemd policy symlink chain is invalid: ${candidate}`);
  }
  visited.add(candidate);
  const before = await fsApi.lstat(candidate);
  const target = await fsApi.readlink(candidate);
  const after = await fsApi.lstat(candidate);
  if (!before.isSymbolicLink() || !sameFileIdentity(before, after)) {
    throw new Error(`systemd policy symlink changed while reading: ${candidate}`);
  }
  assertSystemdPolicyDoesNotReferenceManaged(
    `${path.basename(candidate)} ${target}`,
    candidate,
    unitNames,
    managedIds,
    logicalSource,
    visited.size,
  );
  assertSystemdPolicySymlinkTraversalSafe(candidate, target);
  let resolved = path.resolve(path.dirname(candidate), target);
  if (resolved === '/dev/null') {
    assertBootPolicySystemdConsumerSymlinkTarget(unitNames, logicalSource);
    return;
  }
  if (resolved === '/lib/systemd/system' || resolved.startsWith('/lib/systemd/system/')) {
    if (await isUsrMergedLib(fsApi)) resolved = `/usr${resolved}`;
  }
  await assertTrustedDirectoryChain('/', path.dirname(resolved), 0, 0, fsApi);
  let targetStat;
  try {
    targetStat = await fsApi.lstat(resolved);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      assertBootPolicySystemdConsumerSymlinkTarget(unitNames, logicalSource);
      return;
    }
    throw error;
  }
  if (targetStat.isSymbolicLink()) {
    await auditSystemdPolicySymlink(
      resolved,
      budget,
      fsApi,
      visited,
      mergeSystemdUnitNames(unitNames, path.basename(resolved)),
      managedIds,
      logicalSource,
    );
    return;
  }
  if (!targetStat.isFile()) {
    assertBootPolicySystemdConsumerSymlinkTarget(unitNames, logicalSource);
    throw new Error(`systemd policy symlink target is not a regular file: ${candidate}`);
  }
  await auditSystemdPolicyFile(
    resolved,
    budget,
    fsApi,
    mergeSystemdUnitNames(unitNames, path.basename(resolved)),
    managedIds,
    logicalSource,
    visited.size,
  );
}

function assertSystemdPolicySymlinkTraversalSafe(candidate, target) {
  let enteredDescendant = path.isAbsolute(target);
  for (const component of String(target).split('/')) {
    if (component === '' || component === '.') continue;
    if (component === '..') {
      if (enteredDescendant) {
        throw new Error(`systemd policy symlink target has unsafe parent traversal: ${candidate}`);
      }
      continue;
    }
    enteredDescendant = true;
  }
}

async function auditSystemdPolicyFile(
  candidate,
  budget,
  fsApi,
  unitNames,
  managedIds,
  logicalSource,
  symlinkDepth = 0,
) {
  assertBootPolicySystemdConsumerSource(
    candidate,
    unitNames,
    logicalSource,
    symlinkDepth,
  );
  budget.files += 1;
  if (budget.files > MAX_SYSTEMD_POLICY_FILES) {
    throw new Error('too many systemd policy files');
  }
  const policy = await readTrustedFile(candidate, 0, 0, null, fsApi);
  budget.bytes += policy.contents.length;
  if (budget.bytes > MAX_SYSTEMD_POLICY_BYTES) {
    throw new Error('systemd policy files exceed the aggregate byte limit');
  }
  const lines = policyCatalogLines(policy.contents);
  if (
    systemdPolicyOverridesExecutionEnvironment(lines)
    && await systemdDropInCanOverrideTrustedVendorUnit(logicalSource, unitNames, fsApi)
  ) {
    throw new Error(
      `external systemd policy overrides a trusted vendor execution environment: ${logicalSource}`,
    );
  }
  for (const line of lines) {
    try {
      assertSystemdPolicyDoesNotReferenceManaged(
        line,
        candidate,
        unitNames,
        managedIds,
        logicalSource,
        symlinkDepth,
      );
    } catch (error) {
      if (String(error?.message).includes(candidate)) throw error;
      throw new Error(`${error?.message ?? 'systemd policy audit failed'}: ${candidate}`, {
        cause: error,
      });
    }
  }
  if (!isExpectedGeneratedRootMountPolicy(
    candidate,
    unitNames,
    logicalSource,
    symlinkDepth,
  )) {
    await assertSystemdPathsResolveOutsideProtectedSurface(
      lines,
      unitNames,
      fsApi,
      candidate,
      !isTrustedVendorPathSystemdUnitSource(
        candidate,
        unitNames,
        logicalSource,
        symlinkDepth,
      ),
    );
  }
}

function systemdPolicyOverridesExecutionEnvironment(lines) {
  return lines.some((line) => {
    const separator = line.indexOf('=');
    if (separator <= 0) return false;
    return SYSTEMD_EXECUTION_ENVIRONMENT_DIRECTIVES.has(
      line.slice(0, separator).trim(),
    );
  });
}

async function systemdDropInCanOverrideTrustedVendorUnit(
  logicalSource,
  unitNames,
  fsApi,
) {
  const owner = path.basename(path.dirname(logicalSource));
  if (!owner.endsWith('.d')) return false;
  if (['/usr/lib/systemd/system', '/lib/systemd/system'].includes(
    path.dirname(path.dirname(logicalSource)),
  )) return false;
  if (unitNames.size === 0) return true;
  for (const unitName of unitNames) {
    const candidates = new Set([unitName]);
    const instanceOffset = unitName.indexOf('@');
    const suffixOffset = unitName.lastIndexOf('.');
    if (instanceOffset >= 0 && suffixOffset > instanceOffset + 1) {
      candidates.add(
        `${unitName.slice(0, instanceOffset + 1)}${unitName.slice(suffixOffset)}`,
      );
    }
    for (const candidate of candidates) {
      if (await systemdUnitNameResolvesToTrustedVendorPath(candidate, fsApi)) return true;
    }
  }
  return false;
}

async function systemdUnitNameResolvesToTrustedVendorPath(unitName, fsApi) {
  const unitPaths = await reviewedSystemdManagerUnitPaths(fsApi);
  for (const directory of unitPaths) {
    const candidate = path.join(directory, unitName);
    let stat;
    try {
      stat = await fsApi.lstat(candidate);
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw error;
    }
    if (stat.isSymbolicLink()) {
      return systemdAliasResolvesToTrustedVendorPath(candidate, fsApi);
    }
    if (stat.isFile()) {
      return ['/usr/lib/systemd/system', '/lib/systemd/system'].includes(directory);
    }
  }
  return false;
}

async function systemdAliasResolvesToTrustedVendorPath(candidate, fsApi) {
  const visited = new Set();
  let current = candidate;
  while (true) {
    if (visited.has(current) || visited.size >= 32) {
      throw new Error(`systemd policy symlink chain is invalid: ${candidate}`);
    }
    visited.add(current);
    let before;
    try {
      before = await fsApi.lstat(current);
    } catch (error) {
      if (error?.code === 'ENOENT') return false;
      throw error;
    }
    if (!before.isSymbolicLink()) {
      return before.isFile()
        && ['/usr/lib/systemd/system', '/lib/systemd/system'].includes(
          path.dirname(current),
        )
        && SYSTEMD_UNIT_NAME_PATTERN.test(path.basename(current));
    }
    const target = await fsApi.readlink(current);
    const after = await fsApi.lstat(current);
    if (!after.isSymbolicLink() || !sameFileIdentity(before, after)) {
      throw new Error(`systemd policy symlink changed while reading: ${current}`);
    }
    assertSystemdPolicySymlinkTraversalSafe(current, target);
    current = path.resolve(path.dirname(current), target);
  }
}

async function assertSystemdPathsResolveOutsideProtectedSurface(
  lines,
  unitNames,
  fsApi,
  source,
  inspectActivationPaths,
) {
  for (const line of lines) {
    const decoded = decodeSystemdEscapesForAudit(line);
    const expanded = unitNames.size === 0
      ? [decoded]
      : [...unitNames].map((unitName) => expandSystemdUnitNameSpecifiers(decoded, unitName));
    for (const value of expanded) {
      const separator = value.indexOf('=');
      if (separator <= 0) continue;
      const directive = value.slice(0, separator).trim();
      const protectedPathError = ['What', 'Where'].includes(directive)
        ? 'mounts a protected directory'
        : inspectActivationPaths && SYSTEMD_PATH_TRIGGER_DIRECTIVES.has(directive)
          ? 'watches a protected path'
          : inspectActivationPaths && SYSTEMD_SOCKET_PATH_DIRECTIVES.has(directive)
            ? 'creates a protected socket path'
            : null;
      if (protectedPathError === null) continue;
      for (const field of parseSystemdFields(value.slice(separator + 1))) {
        if (!path.posix.isAbsolute(field) || hasUnresolvedSystemdSpecifier(field)) continue;
        const resolved = await resolveExistingSystemdPath(field, fsApi);
        if (protectedSystemdMountPaths().some((protectedPath) => (
          systemdPathsOverlap(resolved, protectedPath)
        ))) {
          throw new Error(`external systemd policy ${protectedPathError}: ${source}`);
        }
      }
    }
  }
}

async function resolveExistingSystemdPath(value, fsApi) {
  let components = normaliseExistingFilesystemPath(value).split('/').filter(Boolean);
  let current = '/';
  const visited = new Set();
  assertTrustedDirectory('/', await fsApi.lstat('/'), 0, 0);
  while (components.length > 0) {
    const component = components.shift();
    const candidate = path.posix.join(current, component);
    let before;
    try {
      before = await fsApi.lstat(candidate);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return normaliseExistingFilesystemPath(path.posix.join(candidate, ...components));
      }
      throw error;
    }
    if (!before.isSymbolicLink()) {
      if (components.length > 0) {
        assertTrustedDirectory(candidate, before, 0, 0);
      }
      current = candidate;
      continue;
    }
    if (visited.has(candidate) || visited.size >= 32) {
      throw new Error(`systemd mount path symlink chain is invalid: ${value}`);
    }
    visited.add(candidate);
    const target = await fsApi.readlink(candidate);
    const after = await fsApi.lstat(candidate);
    if (!after.isSymbolicLink() || !sameFileIdentity(before, after)) {
      throw new Error(`systemd mount path symlink changed while reading: ${candidate}`);
    }
    const resolvedTarget = path.posix.isAbsolute(target)
      ? normaliseExistingFilesystemPath(target)
      : normaliseExistingFilesystemPath(path.posix.join(path.posix.dirname(candidate), target));
    components = [...resolvedTarget.split('/').filter(Boolean), ...components];
    current = '/';
  }
  return normaliseExistingFilesystemPath(current);
}

function normaliseExistingFilesystemPath(value) {
  return path.posix.normalize(value);
}

function assertSystemdPolicyDoesNotReferenceManaged(
  value,
  source,
  unitNames = new Set(),
  managedIds = new Set(),
  logicalSource = source,
  symlinkDepth = 0,
) {
  const raw = String(value);
  const decoded = decodeSystemdEscapesForAudit(raw);
  if (systemdPolicyInjectsBootPolicyCredential(
    decoded,
    source,
    unitNames,
    logicalSource,
    symlinkDepth,
  )) {
    throw new Error(`external systemd policy injects a host policy credential: ${source}`);
  }
  const representations = new Set([raw, decoded]);
  const expanded = new Set(unitNames.size === 0
    ? representations
    : [...representations].flatMap((representation) => (
      [...unitNames].map((unitName) => (
        expandSystemdUnitNameSpecifiers(representation, unitName)
      ))
    )));
  for (const candidate of expanded) {
    const execCommand = parseSystemdExecCommand(candidate);
    const trustedVendorPathSource = isTrustedVendorPathSystemdUnitSource(
      source,
      unitNames,
      logicalSource,
      symlinkDepth,
    );
    const trustedVendorExecution = execCommand !== null
      && isExpectedVendorSystemdUnitSource(
        source,
        unitNames,
        logicalSource,
        symlinkDepth,
      );
  if (
      !trustedVendorPathSource
      && systemdPolicyInvokesBootPolicyTool(candidate)
    ) {
      throw new Error(`external systemd policy invokes a boot policy tool: ${source}`);
    }
    if (
      !trustedVendorPathSource
      && systemdPolicyInvokesTransientUnitManager(candidate)
    ) {
      throw new Error(`external systemd policy creates a transient unit: ${source}`);
    }
    if (
      !trustedVendorExecution
      && systemdPolicyReinterpretsCommandArguments(candidate)
    ) {
      throw new Error(`external systemd policy reinterprets command arguments: ${source}`);
    }
    if (
      !trustedVendorExecution
      && systemdPolicyUsesEnvironmentExpansion(candidate)
    ) {
      throw new Error(`external systemd policy uses environment expansion: ${source}`);
    }
    if (
      systemdPolicyClaimsProtectedDirectory(candidate)
      && !isExpectedVendorSystemdUnitSource(
        source,
        unitNames,
        logicalSource,
        symlinkDepth,
      )
    ) {
      throw new Error(`external systemd policy claims a protected directory: ${source}`);
    }
    if (
      !trustedVendorPathSource
      && systemdPolicyTriggersProtectedPath(candidate)
    ) {
      throw new Error(`external systemd policy watches a protected path: ${source}`);
    }
    if (
      !trustedVendorPathSource
      && systemdPolicyCreatesProtectedSocketPath(candidate)
    ) {
      throw new Error(`external systemd policy creates a protected socket path: ${source}`);
    }
    if (
      systemdPolicyMountsProtectedDirectory(candidate, unitNames)
      && !isExpectedGeneratedRootMountPolicy(
        source,
        unitNames,
        logicalSource,
        symlinkDepth,
      )
    ) {
      throw new Error(`external systemd policy mounts a protected directory: ${source}`);
    }
    if (
      !trustedVendorPathSource
      && systemdPolicyInjectsSystemCredential(candidate)
    ) {
      throw new Error(`external systemd policy injects a host policy credential: ${source}`);
    }
    if (
      (
        systemdPolicyReferencesGlobalControlUnit(candidate)
        || [...unitNames].some(globalControlUnitFieldCouldMatch)
      )
      && !trustedVendorPathSource
    ) {
      throw new Error(`external systemd policy references a host lifecycle unit: ${source}`);
    }
    if (
      systemdPolicyRequestsGlobalAction(candidate)
      && !trustedVendorPathSource
    ) {
      throw new Error(`external systemd policy requests a host lifecycle action: ${source}`);
    }
    if (
      (!trustedVendorPathSource && (
        MANAGED_UNITS.some((unit) => candidate.includes(unit))
        || LAUNCHER_REFERENCE_PATTERN.test(candidate)
        || systemdPolicyInvokesManagedUnitControl(candidate)
        || MANAGED_IDENTITY_PATTERNS.some((pattern) => pattern.test(candidate))
      ))
      || unresolvedSpecifierCouldReferenceManagedUnit(candidate)
      || [...unitNames].some(systemctlUnitFieldCouldMatch)
      || [...unitNames].some(unitNameClaimsManagedIdentity)
      || systemdIdentityDirectiveUsesManagedId(
        candidate,
        managedIds,
        source,
        unitNames,
        logicalSource,
      )
    ) {
      throw new Error(`external systemd policy references a managed unit: ${source}`);
    }
  }
}

function systemdPolicyInvokesBootPolicyTool(value) {
  const command = parseSystemdExecCommand(value);
  if (!command) return false;
  const names = command.invocations.map(({ name }) => name);
  if (names.some((name) => (
    BOOT_POLICY_EXECUTABLES.has(name)
    || systemdSpecifierFieldCouldMatch(name, [...BOOT_POLICY_EXECUTABLES])
  ))) return true;
  const invokesUserdbLoader = names.some((name) => (
    name === 'systemd-userdbd'
    || systemdSpecifierFieldCouldMatch(name, ['systemd-userdbd'])
  ));
  return invokesUserdbLoader && command.tokens.some((token) => (
    token === '--load-credentials'
    || systemdSpecifierFieldCouldMatch(token, ['--load-credentials'])
  ));
}

function systemdPolicyInvokesTransientUnitManager(value) {
  const command = parseSystemdExecCommand(value);
  return command !== null && command.invocations.some(({ name }) => (
    name === 'systemd-run'
    || systemdSpecifierFieldCouldMatch(name, ['systemd-run'])
  ));
}

function systemdPolicyInvokesManagedUnitControl(value) {
  const command = parseSystemdExecCommand(value);
  if (command === null) return false;
  if (
    command.invocations.some(({ name }) => (
      SYSTEMD_GLOBAL_CONTROL_EXECUTABLES.has(name)
      || systemdSpecifierFieldCouldMatch(
        name,
        [...SYSTEMD_GLOBAL_CONTROL_EXECUTABLES],
      )
    ))
    || command.invocations.some(({ name, argv0 }) => (
      (
        (name === 'systemctl' || systemdSpecifierFieldCouldMatch(name, ['systemctl']))
        && argv0 !== null
        && (
          SYSTEMD_GLOBAL_CONTROL_EXECUTABLES.has(argv0)
          || systemdSpecifierFieldCouldMatch(
            argv0,
            [...SYSTEMD_GLOBAL_CONTROL_EXECUTABLES],
          )
        )
      )
    ))
  ) return true;
  if (!systemdExecInvokes(command, 'systemctl')) return false;
  const unitFileMutation = command.tokens.some((token) => (
    SYSTEMCTL_UNIT_FILE_MUTATION_VERBS.has(token)
    || systemdSpecifierFieldCouldMatch(
      token,
      [...SYSTEMCTL_UNIT_FILE_MUTATION_VERBS],
    )
  ));
  const externalUnitPath = command.tokens.some((token) => (
    (token.includes('/') || hasUnresolvedSystemdSpecifier(token))
    && path.posix.basename(token.replace(/^[-@:+!|]+/, '')) !== 'systemctl'
  ));
  return (
      command.tokens.some(systemctlUnitFieldCouldMatch)
      || command.tokens.some(globalControlUnitFieldCouldMatch)
      || (unitFileMutation && externalUnitPath)
      || command.tokens.some((token) => (
        SYSTEMCTL_UNSCOPED_MUTATION_VERBS.has(token)
        || systemdSpecifierFieldCouldMatch(
          token,
          [...SYSTEMCTL_UNSCOPED_MUTATION_VERBS],
        )
        || systemctlOptionCouldBeMarked(token)
        || systemctlOptionCouldSelectJobMode(token)
      ))
  );
}

function systemctlOptionCouldBeMarked(token) {
  const option = token.slice(0, token.indexOf('=') < 0
    ? token.length
    : token.indexOf('='));
  return SYSTEMCTL_MARKED_OPTION_PREFIXES.includes(option)
    || systemdSpecifierFieldCouldMatch(option, SYSTEMCTL_MARKED_OPTION_PREFIXES);
}

function systemctlOptionCouldSelectJobMode(token) {
  const option = token.slice(0, token.indexOf('=') < 0
    ? token.length
    : token.indexOf('='));
  return SYSTEMCTL_JOB_MODE_OPTION_PREFIXES.includes(option)
    || systemdSpecifierFieldCouldMatch(option, SYSTEMCTL_JOB_MODE_OPTION_PREFIXES);
}

function systemdPolicyReinterpretsCommandArguments(value) {
  const command = parseSystemdExecCommand(value);
  return command !== null
    && systemdExecInvokes(command, 'env')
    && command.envOptions.some((token) => {
      if (envShortOptionSelects(token, 'S') || envShortOptionSelects(token, 'a')) {
        return true;
      }
      const longOption = token.slice(0, token.indexOf('=') < 0
        ? token.length
        : token.indexOf('='));
      return ENV_SPLIT_STRING_OPTION_PREFIXES.includes(longOption)
        || ENV_ARGV0_OPTION_PREFIXES.includes(longOption)
        || systemdSpecifierFieldCouldMatch(
          longOption,
          [...ENV_SPLIT_STRING_OPTION_PREFIXES, ...ENV_ARGV0_OPTION_PREFIXES],
        )
        || systemdSpecifierCouldEnableEnvShortOption(token, 'S')
        || systemdSpecifierCouldEnableEnvShortOption(token, 'a');
    });
}

function systemdPolicyUsesEnvironmentExpansion(value) {
  const command = parseSystemdExecCommand(value);
  return command !== null && command.fields.some((field) => (
    field.includes('$') || systemdSpecifierCanIntroduceEnvironmentExpansion(field)
  ));
}

function systemdSpecifierCanIntroduceEnvironmentExpansion(field) {
  for (let offset = 0; offset < field.length; offset += 1) {
    if (field[offset] !== '%') continue;
    if (field[offset + 1] === '%') {
      offset += 1;
      continue;
    }
    if (['I', 'P', 'J', 'f'].includes(field[offset + 1])) return true;
    if (offset + 1 < field.length) offset += 1;
  }
  return false;
}

function systemdPolicyClaimsProtectedDirectory(value) {
  const separator = value.indexOf('=');
  if (separator <= 0) return false;
  const directive = value.slice(0, separator).trim();
  const root = SYSTEMD_MANAGED_DIRECTORY_ROOTS.get(directive);
  if (!root) return false;
  return parseSystemdFields(value.slice(separator + 1)).some((field) => {
    const [sourceName, destinationName] = field.split(':', 2);
    return [sourceName, destinationName].some((directoryName) => {
      if (!directoryName) return false;
      if (hasUnresolvedSystemdSpecifier(directoryName)) return true;
      const claimedPath = path.resolve(root, directoryName);
      return protectedSystemdMountPaths().some((protectedPath) => (
        systemdPathsOverlap(claimedPath, protectedPath)
      ));
    });
  });
}

function systemdPolicyTriggersProtectedPath(value) {
  return systemdPolicyDirectiveUsesProtectedPath(value, SYSTEMD_PATH_TRIGGER_DIRECTIVES);
}

function systemdPolicyCreatesProtectedSocketPath(value) {
  return systemdPolicyDirectiveUsesProtectedPath(value, SYSTEMD_SOCKET_PATH_DIRECTIVES);
}

function systemdPolicyDirectiveUsesProtectedPath(value, directives) {
  const separator = value.indexOf('=');
  if (separator <= 0) return false;
  const directive = value.slice(0, separator).trim();
  if (!directives.has(directive)) return false;
  return parseSystemdFields(value.slice(separator + 1)).some((field) => {
    if (hasUnresolvedSystemdSpecifier(field)) return true;
    if (
      directive === 'PathExistsGlob'
      && ['*', '?', '[', ']'].some((marker) => field.includes(marker))
    ) return true;
    if (!path.posix.isAbsolute(field)) return false;
    return pathFieldTouchesProtected(field, false, protectedSystemdMountPaths());
  });
}

function systemdPolicyMountsProtectedDirectory(value, unitNames) {
  if ([...unitNames].some(systemdPathUnitOverlapsProtectedDirectory)) return true;
  const separator = value.indexOf('=');
  if (separator <= 0) return false;
  const directive = value.slice(0, separator).trim();
  if (!['Alias', 'Also', 'Options', 'What', 'Where'].includes(directive)) return false;
  const fields = parseSystemdFields(value.slice(separator + 1));
  if (directive === 'Where') {
    return fields.some((field) => {
      if (hasUnresolvedSystemdSpecifier(field) || !path.posix.isAbsolute(field)) return true;
      const mountedPath = normaliseBootPolicyPath(field);
      return protectedSystemdMountPaths().some((protectedPath) => (
        systemdPathsOverlap(mountedPath, protectedPath)
      ));
    });
  }
  if (directive === 'What') {
    return fields.some((field) => {
      if (hasUnresolvedSystemdSpecifier(field)) return true;
      if (!path.posix.isAbsolute(field)) return false;
      const sourcePath = normaliseBootPolicyPath(field);
      return protectedSystemdMountPaths().some((protectedPath) => (
        systemdPathsOverlap(sourcePath, protectedPath)
      ));
    });
  }
  if (directive === 'Options') {
    return fields.some((field) => (
      field.split(',').some((option) => ['bind', 'rbind'].includes(option.trim()))
    ));
  }
  if (!['Alias', 'Also'].includes(directive)) return false;
  return fields.some((field) => (
    systemdPathUnitOverlapsProtectedDirectory(field)
    || systemdSpecifierFieldCouldMatch(field, protectedSystemdPathUnitNames())
  ));
}

function isExpectedGeneratedRootMountPolicy(
  source,
  unitNames,
  logicalSource,
  symlinkDepth,
) {
  if (!systemdUnitNamesEqual(unitNames, '-.mount')) return false;
  const unit = '/run/systemd/generator/-.mount';
  const dependency = '/run/systemd/generator/local-fs.target.requires/-.mount';
  return (
    [0, 1].includes(symlinkDepth)
    && source === logicalSource
    && [unit, dependency].includes(source)
  ) || (
    symlinkDepth === 1
    && source === unit
    && logicalSource === dependency
  );
}

function systemdPathUnitOverlapsProtectedDirectory(unitName) {
  const basename = path.posix.basename(unitName);
  const match = basename.match(/^(.*)\.(?:automount|mount)$/);
  if (!match) return false;
  const mountedPath = match[1] === '-'
    ? '/'
    : normaliseBootPolicyPath(
      `/${decodeSystemdEscapesForAudit(match[1].replaceAll('-', '/'))}`,
    );
  return protectedSystemdMountPaths().some((protectedPath) => (
    systemdPathsOverlap(mountedPath, protectedPath)
  ));
}

function protectedSystemdPathUnitNames() {
  return protectedSystemdMountPaths().flatMap((protectedPath) => {
    const stem = protectedPath
      .slice(1)
      .split('/')
      .map((component) => component.replaceAll('-', '\\x2d'))
      .join('-');
    return [`${stem}.mount`, `${stem}.automount`];
  });
}

function protectedSystemdMountPaths() {
  return [...new Set([
    ...SYSTEMD_PROTECTED_DIRECTORY_PATHS,
    ...IDENTITY_POLICY_PATHS,
    ...IDENTITY_DATABASE_COMMIT_ORDER.map((file) => `${file}-`),
    ...IDENTITY_RECOVERY_CANDIDATE_PATHS,
    IDENTITY_LOCK_PATH,
    ...STATIC_USERDB_DIRECTORIES,
    SYSTEMD_USERDB_DIRECTORY,
    SYSTEMD_SYSTEM_CREDENTIAL_DIRECTORY,
    ...SYSTEMD_PROTECTED_UNIT_PATHS,
    ...Object.values(BOOT_POLICY_DIRECTORIES).flat(),
    ...CREDENTIAL_STORE_DIRECTORIES,
    ...BOOT_POLICY_CREDENTIAL_PATHS,
    ...FIXED_HOST_EXECUTABLE_PATHS,
    '/proc/1/cgroup',
    '/proc/1/comm',
    '/proc/1/mountinfo',
    '/proc/1/ns/mnt',
    '/proc/1/ns/user',
    '/proc/1/root',
    '/proc/locks',
    '/proc/self/mountinfo',
    '/proc/self/ns/mnt',
    '/proc/self/ns/user',
    '/run/systemd/private',
    '/var/run',
    TRANSACTION_PATH,
    PROVISION_LOCK_PATH,
    PROVISION_LOCK_PARENT,
  ])];
}

function systemdPathsOverlap(left, right) {
  return left === right
    || left === '/'
    || right === '/'
    || left.startsWith(`${right}/`)
    || right.startsWith(`${left}/`);
}

function systemdPolicyInjectsSystemCredential(value) {
  const command = parseSystemdExecCommand(value);
  if (
    command === null
    || !systemdExecInvokes(command, 'systemctl')
  ) return false;
  const verbOffset = command.tokens.findIndex((token) => (
    token === 'set-credential'
    || token === 'set-credential-encrypted'
    || systemdSpecifierFieldCouldMatch(
      token,
      ['set-credential', 'set-credential-encrypted'],
    )
  ));
  if (verbOffset < 0) return false;
  return command.tokens.slice(verbOffset + 1).some((token) => {
    const credential = token.slice(0, token.indexOf('=') < 0
      ? token.length
      : token.indexOf('='));
    return hasUnresolvedSystemdSpecifier(credential)
      || credentialNameCanInjectHostPolicy(credential)
      || systemdSpecifierFieldCouldMatch(credential, [
        ...BOOT_POLICY_CREDENTIAL_NAMES,
        ...BOOT_POLICY_CREDENTIAL_PREFIXES.map((prefix) => `${prefix}root`),
      ]);
  });
}

function parseSystemdExecCommand(value) {
  const separator = value.indexOf('=');
  if (separator <= 0) return null;
  const directive = value.slice(0, separator).trim();
  if (!/^Exec[A-Z][A-Za-z]*$/.test(directive)) return null;
  const fields = parseSystemdFields(value.slice(separator + 1));
  const tokens = fields.flatMap((field) => field.split(/[;\s]+/).filter(Boolean));
  const invocations = systemdExecInvocationMetadata(fields);
  return Object.freeze({
    fields,
    tokens,
    invocations: invocations.invocations,
    envOptions: invocations.envOptions,
  });
}

function systemdExecInvokes(command, executable) {
  return command.invocations.some(({ name }) => (
    name === executable
    || systemdSpecifierFieldCouldMatch(name, [executable])
  ));
}

function systemdExecInvocationMetadata(fields) {
  const invocations = [];
  const envOptions = [];
  for (const segment of systemdExecCommandSegments(fields)) {
    let offset = 0;
    let direct = true;
    while (offset < segment.length) {
      const rawExecutable = segment[offset];
      const prefixes = direct ? rawExecutable.match(/^[-@:+!|]+/)?.[0] ?? '' : '';
      const executable = direct
        ? rawExecutable.replace(/^[-@:+!|]+/, '')
        : rawExecutable;
      const name = path.basename(executable);
      offset += 1;
      let argv0 = null;
      if (direct && prefixes.includes('@') && offset < segment.length) {
        argv0 = path.basename(segment[offset]);
        offset += 1;
      }
      invocations.push(Object.freeze({ name, argv0 }));
      direct = false;
      if (name !== 'env') break;
      const env = parseSystemdEnvInvocation(segment, offset);
      envOptions.push(...env.options);
      if (env.commandOffset === null) break;
      offset = env.commandOffset;
    }
  }
  return Object.freeze({
    invocations: Object.freeze(invocations),
    envOptions: Object.freeze(envOptions),
  });
}

function systemdExecCommandSegments(fields) {
  const segments = [[]];
  for (const field of fields) {
    if (field === ';') {
      if (segments.at(-1).length !== 0) segments.push([]);
      continue;
    }
    segments.at(-1).push(field);
  }
  return segments.filter((segment) => segment.length !== 0);
}

function parseSystemdEnvInvocation(segment, start) {
  const options = [];
  let assignmentsStarted = false;
  for (let offset = start; offset < segment.length; offset += 1) {
    const field = segment[offset];
    if (field === '--') {
      return Object.freeze({
        options: Object.freeze(options),
        commandOffset: offset + 1 < segment.length ? offset + 1 : null,
      });
    }
    if (systemdEnvFieldCouldBeAssignment(field)) {
      assignmentsStarted = true;
      continue;
    }
    if (!assignmentsStarted && (field === '-' || field.startsWith('-'))) {
      options.push(field);
      if (envOptionConsumesFollowingField(field)) offset += 1;
      continue;
    }
    return Object.freeze({
      options: Object.freeze(options),
      commandOffset: offset,
    });
  }
  return Object.freeze({ options: Object.freeze(options), commandOffset: null });
}

function systemdEnvFieldCouldBeAssignment(field) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(field)
    || (field.includes('=') && hasUnresolvedSystemdSpecifier(field));
}

function envOptionConsumesFollowingField(field) {
  if (field.startsWith('--')) {
    if (field.includes('=')) return false;
    return [
      '--argv0',
      '--chdir',
      '--split-string',
      '--unset',
    ].some((option) => option.startsWith(field));
  }
  const options = field.slice(1);
  for (const [offset, option] of [...options].entries()) {
    if (!'aCSu'.includes(option)) continue;
    return offset === options.length - 1;
  }
  return false;
}

function envShortOptionSelects(field, expected) {
  if (!/^-[^-]/.test(field)) return false;
  const options = [...field.slice(1)];
  for (const option of options) {
    if (option === expected) return true;
    if ('aCSu'.includes(option)) return false;
  }
  return false;
}

function systemdPolicyReferencesGlobalControlUnit(value) {
  const separator = value.indexOf('=');
  if (separator <= 0) return false;
  const directive = value.slice(0, separator).trim();
  if (!SYSTEMD_GLOBAL_ACTIVATION_DIRECTIVES.has(directive)) return false;
  return parseSystemdFields(value.slice(separator + 1))
    .some(globalControlUnitFieldCouldMatch);
}

function systemdPolicyRequestsGlobalAction(value) {
  const separator = value.indexOf('=');
  if (separator <= 0) return false;
  const directive = value.slice(0, separator).trim();
  if (
    !SYSTEMD_GLOBAL_ACTION_DIRECTIVES.has(directive)
    && !SYSTEMD_GLOBAL_JOB_MODE_DIRECTIVES.has(directive)
  ) return false;
  const fields = parseSystemdFields(value.slice(separator + 1));
  if (fields.length === 0) return false;
  if (fields.length > 1) {
    return SYSTEMD_GLOBAL_ACTION_DIRECTIVES.has(directive)
      || SYSTEMD_GLOBAL_JOB_MODE_DIRECTIVES.has(directive);
  }
  if (SYSTEMD_GLOBAL_ACTION_DIRECTIVES.has(directive)) {
    return fields[0] !== 'none';
  }
  if (SYSTEMD_GLOBAL_JOB_MODE_DIRECTIVES.has(directive)) {
    return !['fail', 'replace', 'replace-irreversibly'].includes(fields[0]);
  }
  return false;
}

function systemctlUnitFieldCouldMatch(field) {
  const basename = path.posix.basename(field);
  return [...new Set([field, basename])]
    .flatMap((candidate) => [candidate, `${candidate}.service`])
    .some((candidate) => {
      const tokens = systemdUnitPatternTokens(candidate);
      const pattern = tokens.map((token) => {
        if (token.literal !== undefined) return escapeRegExp(token.literal);
        return token.repeat ? '[^\\s/]*' : '[^\\s/]';
      }).join('');
      const reference = new RegExp(`^${pattern}$`);
      return MANAGED_UNIT_CONTROL_TARGETS.some((unit) => reference.test(unit))
        || ['.service', ...SYSTEMD_IMPLICIT_SERVICE_ACTIVATOR_SUFFIXES].some(
          (suffix) => systemdTokenPatternsIntersect(
            tokens,
            launcherReferenceTokens(suffix),
          ),
        );
    });
}

function globalControlUnitFieldCouldMatch(field) {
  const basename = path.posix.basename(field);
  return [...new Set([field, basename])].some((candidate) => {
    const tokens = systemdUnitPatternTokens(candidate);
    const pattern = tokens.map((token) => {
      if (token.literal !== undefined) return escapeRegExp(token.literal);
      return token.repeat ? '[^\\s/]*' : '[^\\s/]';
    }).join('');
    const reference = new RegExp(`^${pattern}$`);
    return SYSTEMD_GLOBAL_CONTROL_UNITS.some((unit) => reference.test(unit));
  });
}

function systemdUnitPatternTokens(field) {
  const tokens = [];
  for (let offset = 0; offset < field.length; offset += 1) {
    const character = field[offset];
    if (character === '%' && field[offset + 1] === '%') {
      tokens.push({ literal: '%', repeat: false });
      offset += 1;
      continue;
    }
    if (character === '%') {
      tokens.push({ characterClass: 'unit', repeat: true });
      if (offset + 1 < field.length) offset += 1;
      continue;
    }
    if (character === '*') {
      tokens.push({ characterClass: 'unit', repeat: true });
      continue;
    }
    if (character === '?') {
      tokens.push({ characterClass: 'unit', repeat: false });
      continue;
    }
    if (character === '[') {
      const end = field.indexOf(']', offset + 1);
      tokens.push({ characterClass: 'unit', repeat: false });
      if (end >= 0) offset = end;
      continue;
    }
    tokens.push({ literal: character, repeat: false });
  }
  return tokens;
}

function systemdPolicyInjectsBootPolicyCredential(
  value,
  source,
  unitNames,
  logicalSource,
  symlinkDepth,
) {
  const separator = value.indexOf('=');
  if (separator <= 0) return false;
  const directive = value.slice(0, separator).trim();
  if (!CREDENTIAL_DIRECTIVES.has(directive)) return false;
  if (isExpectedVendorBootPolicyCredentialImport(
    source,
    value.trim(),
    unitNames,
    logicalSource,
    symlinkDepth,
  )) return false;
  const fields = parseSystemdFields(value.slice(separator + 1));
  if (directive === 'ImportCredential') {
    return fields.some(importCredentialSelectorTargetsBootPolicy);
  }
  return fields.some((field) => {
    const separatorOffset = field.indexOf(':');
    const credential = separatorOffset < 0 ? field : field.slice(0, separatorOffset);
    return credential.includes('%') || credentialNameCanInjectHostPolicy(credential);
  });
}

function importCredentialSelectorTargetsBootPolicy(selector) {
  if (
    selector.length > 255
    || selector.includes('%')
    || /[?[\]]/.test(selector)
  ) return true;
  const components = selector.split(':');
  if (components.length > 2) return true;
  const [sourcePattern, renamePrefix] = components;
  if (sourcePattern === '') return true;
  const wildcardOffset = sourcePattern.indexOf('*');
  if (wildcardOffset >= 0 && (
    wildcardOffset !== sourcePattern.length - 1
    || sourcePattern.lastIndexOf('*') !== wildcardOffset
  )) return true;
  if (credentialSelectorCanInjectHostPolicy(sourcePattern, wildcardOffset)) return true;
  if (renamePrefix === undefined) return false;
  if (renamePrefix.includes('*')) return true;
  return wildcardOffset < 0
    ? credentialNameCanInjectHostPolicy(renamePrefix)
    : credentialPrefixCanInjectHostPolicy(renamePrefix);
}

function credentialSelectorCanInjectHostPolicy(selector, wildcardOffset) {
  if (wildcardOffset < 0) return credentialNameCanInjectHostPolicy(selector);
  return credentialPrefixCanInjectHostPolicy(selector.slice(0, -1));
}

function credentialPrefixCanInjectHostPolicy(prefix) {
  return BOOT_POLICY_CREDENTIAL_NAMES.some((name) => name.startsWith(prefix))
    || BOOT_POLICY_CREDENTIAL_PREFIXES.some((managedPrefix) => (
      managedPrefix.startsWith(prefix) || prefix.startsWith(managedPrefix)
    ));
}

function isExpectedVendorBootPolicyCredentialImport(
  source,
  line,
  unitNames,
  logicalSource,
  symlinkDepth,
) {
  const unit = path.basename(source);
  if (
    unit === 'systemd-firstboot.service'
    && VENDOR_FIRSTBOOT_CREDENTIAL_IMPORTS.has(line)
    && isTrustedVendorPathSystemdUnitSource(
      source,
      unitNames,
      logicalSource,
      symlinkDepth,
    )
  ) return true;
  if (!isExpectedVendorBootPolicyConsumerSource(
    source,
    unitNames,
    logicalSource,
    symlinkDepth,
  )) return false;
  return (
    unit === 'systemd-sysusers.service'
    && VENDOR_SYSUSERS_CREDENTIAL_IMPORTS.has(line)
  ) || (
    unit === 'systemd-userdb-load-credentials.service'
    && VENDOR_USERDB_CREDENTIAL_IMPORTS.has(line)
  ) || (
    VENDOR_TMPFILES_CREDENTIAL_UNITS.has(unit)
    && line === 'ImportCredential=tmpfiles.*'
  );
}

function assertBootPolicySystemdConsumerSource(
  source,
  unitNames,
  logicalSource,
  symlinkDepth,
) {
  const consumers = [...unitNames]
    .filter((unit) => BOOT_POLICY_SYSTEMD_CONSUMER_UNITS.has(unit));
  if (consumers.length === 0) return;
  if (
    consumers.length !== 1
    || !isExpectedVendorBootPolicyConsumerSource(
      source,
      unitNames,
      logicalSource,
      symlinkDepth,
    )
  ) {
    throw new Error(`boot policy systemd consumer is not trusted: ${logicalSource}`);
  }
}

function assertBootPolicySystemdConsumerSymlinkTarget(unitNames, logicalSource) {
  if ([...unitNames].some((unit) => BOOT_POLICY_SYSTEMD_CONSUMER_UNITS.has(unit))) {
    throw new Error(
      `boot policy systemd consumer symlink target is not trusted: ${logicalSource}`,
    );
  }
}

function isExpectedVendorBootPolicyConsumerSource(
  source,
  unitNames,
  logicalSource,
  symlinkDepth,
) {
  const directory = path.dirname(source);
  if (!['/usr/lib/systemd/system', '/lib/systemd/system'].includes(directory)) return false;
  const unit = path.basename(source);
  if (!BOOT_POLICY_SYSTEMD_CONSUMER_UNITS.has(unit)) return false;
  return isTrustedVendorPathSystemdUnitSource(
    source,
    unitNames,
    logicalSource,
    symlinkDepth,
  );
}

function isExpectedVendorSystemdUnitSource(
  source,
  unitNames,
  logicalSource,
  symlinkDepth,
) {
  if (isTrustedVendorPathSystemdUnitSource(
    source,
    unitNames,
    logicalSource,
    symlinkDepth,
  )) return true;
  const vendorDirectories = ['/usr/lib/systemd/system', '/lib/systemd/system'];
  if (!vendorDirectories.includes(path.dirname(source))) return false;
  const unit = path.basename(source);
  const logicalUnit = path.basename(logicalSource);
  if (
    !SYSTEMD_UNIT_NAME_PATTERN.test(unit)
    || !SYSTEMD_UNIT_NAME_PATTERN.test(logicalUnit)
    || symlinkDepth !== 1
  ) return false;
  const vendorBackedAlias = (
    SYSTEMD_PROTECTED_UNIT_PATHS.includes(path.dirname(logicalSource))
    && systemdUnitNamesMatch(unitNames, new Set([unit, logicalUnit]))
  );
  const vendorBackedDependencyLink = (
    systemdUnitNamesMatch(unitNames, new Set([unit, logicalUnit]))
    && (logicalUnit === unit || systemdUnitIsInstanceOfTemplate(logicalUnit, unit))
    && /\.(?:wants|requires|upholds)$/.test(path.basename(path.dirname(logicalSource)))
    && SYSTEMD_PROTECTED_UNIT_PATHS.includes(path.dirname(path.dirname(logicalSource)))
  );
  return vendorBackedAlias || vendorBackedDependencyLink;
}

function isTrustedVendorPathSystemdUnitSource(
  source,
  unitNames,
  logicalSource,
  symlinkDepth,
) {
  const directory = path.dirname(source);
  const vendorDirectories = ['/usr/lib/systemd/system', '/lib/systemd/system'];
  if (!vendorDirectories.includes(directory)) return false;
  const unit = path.basename(source);
  if (!SYSTEMD_UNIT_NAME_PATTERN.test(unit)) return false;
  const logicalUnit = path.basename(logicalSource);
  const directVendorFile = (
    symlinkDepth === 0
    && logicalSource === source
    && systemdUnitNamesEqual(unitNames, unit)
  );
  const directVendorAlias = (
    symlinkDepth === 1
    && vendorDirectories.includes(path.dirname(logicalSource))
    && SYSTEMD_UNIT_NAME_PATTERN.test(logicalUnit)
    && systemdUnitNamesMatch(unitNames, new Set([unit, logicalUnit]))
  );
  const directDependencyLink = (
    symlinkDepth === 1
    && systemdUnitNamesMatch(unitNames, new Set([unit, logicalUnit]))
    && (logicalUnit === unit || systemdUnitIsInstanceOfTemplate(logicalUnit, unit))
    && /\.(?:wants|requires|upholds)$/.test(path.basename(path.dirname(logicalSource)))
    && vendorDirectories.includes(path.dirname(path.dirname(logicalSource)))
  );
  return directVendorFile || directVendorAlias || directDependencyLink;
}

function systemdUnitNamesEqual(unitNames, unit) {
  return unitNames.size === 1 && unitNames.has(unit);
}

function systemdUnitNamesMatch(unitNames, expected) {
  return unitNames.size === expected.size
    && [...unitNames].every((unit) => expected.has(unit));
}

function systemdUnitIsInstanceOfTemplate(unit, template) {
  const marker = template.indexOf('@.');
  if (marker < 0) return false;
  const prefix = template.slice(0, marker + 1);
  const suffix = template.slice(marker + 1);
  if (!unit.startsWith(prefix) || !unit.endsWith(suffix)) return false;
  const instance = unit.slice(prefix.length, unit.length - suffix.length);
  return instance !== '' && !/[@/\s]/.test(instance);
}

function unresolvedSpecifierCouldReferenceManagedUnit(value) {
  const separator = value.indexOf('=');
  if (separator <= 0) return false;
  const directive = value.slice(0, separator).trim();
  if (!SYSTEMD_UNIT_REFERENCE_DIRECTIVES.has(directive)) return false;
  return parseSystemdFields(value.slice(separator + 1))
    .some((field) => systemdSpecifierFieldCouldMatch(
      field,
      MANAGED_UNITS,
      { includeLauncherInstances: true },
    ));
}

function systemdSpecifierFieldCouldMatch(
  field,
  candidates,
  {
    includeLauncherInstances = false,
    includeShellFamilies = false,
  } = {},
) {
  const { hasUnresolvedSpecifier, tokens } = systemdSpecifierPatternTokens(field);
  if (!hasUnresolvedSpecifier) return false;
  const pattern = tokens.map((token) => (
    token.literal !== undefined ? escapeRegExp(token.literal) : '[^\\s/]*'
  )).join('');
  const reference = new RegExp(`^${pattern}$`);
  return candidates.some((candidate) => reference.test(candidate))
    || (
      includeLauncherInstances
      && systemdTokenPatternsIntersect(tokens, launcherReferenceTokens())
    )
    || (
      includeShellFamilies
      && systemdTokenPatternsIntersect(tokens, shellFamilyReferenceTokens())
    );
}

function systemdSpecifierPatternTokens(field) {
  let hasUnresolvedSpecifier = false;
  const tokens = [];
  for (let offset = 0; offset < field.length; offset += 1) {
    if (field[offset] !== '%') {
      tokens.push({ literal: field[offset], repeat: false });
      continue;
    }
    if (field[offset + 1] === '%') {
      tokens.push({ literal: '%', repeat: false });
      offset += 1;
      continue;
    }
    hasUnresolvedSpecifier = true;
    tokens.push({ characterClass: 'unit', repeat: true });
    if (offset + 1 < field.length) offset += 1;
  }
  return Object.freeze({ hasUnresolvedSpecifier, tokens: Object.freeze(tokens) });
}

function systemdSpecifierCouldEnableEnvShortOption(field, option) {
  const { hasUnresolvedSpecifier, tokens } = systemdSpecifierPatternTokens(field);
  if (!hasUnresolvedSpecifier) return false;
  return systemdTokenPatternsIntersect(tokens, [
    { literal: '-', repeat: false },
    { characterClass: 'env-short-option', repeat: true },
    { literal: option, repeat: false },
    { characterClass: 'unit', repeat: true },
  ]);
}

function launcherReferenceTokens(suffix = '.service') {
  return [
    ...[...'webex-codex-launcher@'].map((literal) => ({ literal, repeat: false })),
    { characterClass: 'launcher-instance', repeat: false },
    { characterClass: 'launcher-instance', repeat: true },
    ...[...suffix].map((literal) => ({ literal, repeat: false })),
  ];
}

function shellFamilyReferenceTokens() {
  return [
    { characterClass: 'shell-name', repeat: true },
    { literal: 's', repeat: false },
    { literal: 'h', repeat: false },
  ];
}

function systemdTokenPatternsIntersect(left, right) {
  const pending = [[0, 0]];
  const visited = new Set();
  while (pending.length > 0) {
    const [leftOffset, rightOffset] = pending.pop();
    const state = `${leftOffset}:${rightOffset}`;
    if (visited.has(state)) continue;
    visited.add(state);
    if (leftOffset === left.length && rightOffset === right.length) return true;
    const leftToken = left[leftOffset];
    const rightToken = right[rightOffset];
    if (leftToken?.repeat) pending.push([leftOffset + 1, rightOffset]);
    if (rightToken?.repeat) pending.push([leftOffset, rightOffset + 1]);
    if (leftToken && rightToken && systemdTokenCharactersIntersect(leftToken, rightToken)) {
      pending.push([
        leftToken.repeat ? leftOffset : leftOffset + 1,
        rightToken.repeat ? rightOffset : rightOffset + 1,
      ]);
    }
  }
  return false;
}

function systemdTokenCharactersIntersect(left, right) {
  if (left.literal !== undefined && right.literal !== undefined) {
    return left.literal === right.literal;
  }
  if (left.literal !== undefined) return systemdTokenAllows(right, left.literal);
  if (right.literal !== undefined) return systemdTokenAllows(left, right.literal);
  return true;
}

function systemdTokenAllows(token, character) {
  if (/[\s/]/.test(character)) return false;
  if (token.characterClass === 'env-short-option') return character !== '-';
  if (token.characterClass === 'launcher-instance') return character !== '@';
  if (token.characterClass === 'shell-name') return /[A-Za-z0-9_.+-]/.test(character);
  return true;
}

function unitNameClaimsManagedIdentity(unitName) {
  const suffixOffset = unitName.lastIndexOf('.');
  if (suffixOffset <= 0) return false;
  const stem = unitName.slice(0, suffixOffset);
  const implicitIdentity = stem.includes('@') ? stem.slice(0, stem.indexOf('@')) : stem;
  return MANAGED_IDENTITY_NAMES.includes(decodeSystemdEscapesForAudit(implicitIdentity));
}

function systemdIdentityDirectiveUsesManagedId(
  value,
  managedIds,
  source,
  unitNames,
  logicalSource,
) {
  const separator = value.indexOf('=');
  if (separator <= 0) return false;
  const directive = value.slice(0, separator).trim();
  if (!SYSTEMD_IDENTITY_DIRECTIVES.has(directive)) return false;
  const identities = parseSystemdFields(value.slice(separator + 1));
  if (
    identities.some(hasUnresolvedSystemdSpecifier)
    && !isExpectedVendorUserManagerIdentity(
      source,
      value.trim(),
      unitNames,
      logicalSource,
    )
  ) {
    return true;
  }
  return identities.some((identity) => {
    if (managedIds.has(identity)) return true;
    if (!/^[0-9]+$/.test(identity)) return false;
    const id = Number(identity);
    return Number.isSafeInteger(id) && id > 0 && id <= MAX_MANAGED_ID;
  });
}

function hasUnresolvedSystemdSpecifier(value) {
  for (let offset = 0; offset < value.length; offset += 1) {
    if (value[offset] !== '%') continue;
    if (value[offset + 1] === '%') {
      offset += 1;
      continue;
    }
    return true;
  }
  return false;
}

function isExpectedVendorUserManagerIdentity(source, line, unitNames, logicalSource) {
  return (
    source === logicalSource
    && ['/usr/lib/systemd/system', '/lib/systemd/system'].includes(path.dirname(source))
    && path.basename(source) === 'user@.service'
    && systemdUnitNamesEqual(unitNames, 'user@.service')
    && line === 'User=%i'
  );
}

function managedIdentityIds(snapshot) {
  const ids = new Set();
  if (!snapshot) return ids;
  for (const user of Object.values(MANAGED_USERS)) {
    const record = snapshot.users.get(user);
    if (record) {
      ids.add(String(record.uid));
      ids.add(String(record.gid));
    }
  }
  for (const group of Object.values(MANAGED_GROUPS)) {
    const record = snapshot.groups.get(group);
    if (record) ids.add(String(record.gid));
  }
  return ids;
}

function systemdPolicyUnitNames(directory, entryName) {
  const unitNames = new Set();
  if (SYSTEMD_UNIT_NAME_PATTERN.test(entryName)) unitNames.add(entryName);
  const parent = path.basename(directory);
  if (parent.endsWith('.d')) {
    const owner = parent.slice(0, -2);
    const suffixOffset = owner.lastIndexOf('.');
    const sharedDashPrefix = suffixOffset > 0 && owner.slice(0, suffixOffset).endsWith('-');
    if (SYSTEMD_UNIT_NAME_PATTERN.test(owner) && !sharedDashPrefix) unitNames.add(owner);
  }
  return unitNames;
}

function mergeSystemdUnitNames(unitNames, candidate) {
  const merged = new Set(unitNames);
  if (unitNames.size > 0 && SYSTEMD_UNIT_NAME_PATTERN.test(candidate)) {
    merged.add(candidate);
  }
  return merged;
}

function expandSystemdUnitNameSpecifiers(value, unitName) {
  const suffixOffset = unitName.lastIndexOf('.');
  if (suffixOffset <= 0) return value;
  const stem = unitName.slice(0, suffixOffset);
  const atOffset = stem.indexOf('@');
  const prefix = atOffset < 0 ? stem : stem.slice(0, atOffset);
  const instance = atOffset < 0 ? '' : stem.slice(atOffset + 1);
  const unresolvedInstance = atOffset >= 0 && instance === '';
  const finalComponent = prefix.slice(prefix.lastIndexOf('-') + 1);
  const replacements = new Map([
    ['%%', '%%'],
    ['%n', unitName],
    ['%N', stem],
    ['%p', prefix],
    ['%P', decodeSystemdEscapesForAudit(prefix)],
    ['%i', unresolvedInstance ? '%i' : instance],
    ['%I', unresolvedInstance ? '%I' : decodeSystemdEscapesForAudit(instance)],
    ['%j', finalComponent],
    ['%J', decodeSystemdEscapesForAudit(finalComponent)],
  ]);
  return value.replace(/%%|%[nNpPiIjJ]/g, (specifier) => replacements.get(specifier));
}

function decodeSystemdEscapesForAudit(value) {
  let decoded = '';
  for (let offset = 0; offset < value.length; offset += 1) {
    if (value[offset] !== '\\') {
      decoded += value[offset];
      continue;
    }
    if (['a', 'b', 'e', 'f', 'n', 'r', 's', 't', 'v', '\\', '"', "'"]
      .includes(value[offset + 1])) {
      decoded += value.slice(offset, offset + 2);
      offset += 1;
      continue;
    }
    try {
      const escape = decodeSystemdEscape(value, offset);
      decoded += escape.value;
      offset = escape.end;
    } catch {
      if (offset + 1 < value.length) {
        decoded += value[offset + 1];
        offset += 1;
      }
    }
  }
  return decoded;
}

function systemdDropInDirectoryNames(unit) {
  const suffixOffset = unit.lastIndexOf('.');
  if (suffixOffset <= 0) throw new Error(`managed unit name is invalid: ${unit}`);
  const suffix = unit.slice(suffixOffset);
  const unitStem = unit.slice(0, suffixOffset);
  const prefixStem = unitStem.includes('@') ? unitStem.slice(0, unitStem.indexOf('@')) : unitStem;
  const names = new Set([`${unit}.d`, `${suffix.slice(1)}.d`]);
  for (let offset = prefixStem.indexOf('-'); offset >= 0; offset = prefixStem.indexOf('-', offset + 1)) {
    names.add(`${prefixStem.slice(0, offset + 1)}${suffix}.d`);
  }
  return [...names];
}

async function isUsrMergedLib(fsApi) {
  const before = await fsApi.lstat('/lib');
  if (!before.isSymbolicLink()) return false;
  const target = await fsApi.readlink('/lib');
  const after = await fsApi.lstat('/lib');
  if (
    !sameFileIdentity(before, after)
    || before.uid !== 0
    || before.gid !== 0
    || before.nlink !== 1
    || target !== 'usr/lib'
  ) {
    throw new Error('usr-merge /lib link is not trusted');
  }
  return true;
}

function parseSystemUnitMetadata(output, unit) {
  const values = new Map();
  const expected = new Set([
    'Job',
    'LoadState',
    'UnitFileState',
    'FragmentPath',
    'DropInPaths',
    'NeedDaemonReload',
    ...REVERSE_ACTIVATION_PROPERTIES,
  ]);
  for (const line of String(output).split('\n').filter((value) => value !== '')) {
    const separator = line.indexOf('=');
    const key = separator < 0 ? '' : line.slice(0, separator);
    if (!expected.has(key) || values.has(key)) {
      throw new Error(`managed unit metadata is malformed: ${unit}`);
    }
    values.set(key, line.slice(separator + 1));
  }
  if (values.size !== expected.size) {
    throw new Error(`managed unit metadata is incomplete: ${unit}`);
  }
  if (values.get('Job') !== '') {
    throw new Error(`managed unit has a pending job: ${unit}`);
  }
  const needDaemonReload = values.get('NeedDaemonReload');
  if (!['yes', 'no'].includes(needDaemonReload)) {
    throw new Error(`managed unit daemon-reload state is malformed: ${unit}`);
  }
  const loadState = values.get('LoadState');
  if (!/^[a-z][a-z-]*$/.test(loadState)) {
    throw new Error(`managed unit load state is malformed: ${unit}`);
  }
  const unitFileState = values.get('UnitFileState');
  let enabled;
  if (loadState === 'not-found') {
    if (unitFileState !== '') {
      throw new Error(`managed unit file state disagrees with load state: ${unit}`);
    }
    enabled = 'not-found';
  } else {
    if (!SYSTEMD_UNIT_FILE_STATES.has(unitFileState)) {
      throw new Error(`managed unit file state is malformed: ${unit}`);
    }
    enabled = unitFileState;
  }
  const reverseActivators = new Set();
  for (const property of REVERSE_ACTIVATION_PROPERTIES) {
    for (const activator of values.get(property).split(/\s+/).filter(Boolean)) {
      if (!/^[A-Za-z0-9:_.@-]+$/.test(activator)) {
        throw new Error(`managed unit reverse activation state is malformed: ${unit}`);
      }
      reverseActivators.add(activator);
    }
  }
  return Object.freeze({
    load: loadState,
    enabled,
    fragment: values.get('FragmentPath'),
    dropIns: values.get('DropInPaths'),
    needDaemonReload: needDaemonReload === 'yes',
    reverseActivators: Object.freeze([...reverseActivators].sort()),
  });
}

function parseLauncherInstanceUnits(output) {
  const units = [];
  for (const line of String(output).split('\n').map((value) => value.trim()).filter(Boolean)) {
    const [unit] = line.split(/\s+/);
    if (unit === 'webex-codex-launcher@.service') continue;
    if (!LAUNCHER_INSTANCE_PATTERN.test(unit)) {
      throw new Error(`unexpected launcher instance listing: ${unit}`);
    }
    units.push(unit);
  }
  return units;
}

export async function runFixedCommand(
  command,
  args,
  allowedExitCodes = [0],
  {
    fsApi = fs,
    execFileCommand = execFileAsync,
    readMountInfo = () => readBoundedProcFile(
      '/proc/self/mountinfo',
      MAX_MOUNTINFO_BYTES,
      fsApi,
    ),
  } = {},
) {
  await assertTrustedDirectoryChain('/', path.dirname(command), 0, 0, fsApi);
  const mountsBeforeOpen = assertNoUnexpectedMountsForPaths(
    new Set([command]),
    await readMountInfo(),
  );
  const handle = await fsApi.open(
    command,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat();
    const mode = before.mode & 0o7777;
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.uid !== 0
      || before.gid !== 0
      || (mode & 0o7022) !== 0
      || (mode & 0o100) === 0
    ) {
      throw new Error(`fixed command is not trusted: ${command}`);
    }
    const mountsAfterOpen = assertNoUnexpectedMountsForPaths(
      new Set([command]),
      await readMountInfo(),
    );
    assertProtectedMountSnapshotUnchanged(mountsBeforeOpen, mountsAfterOpen);
    let result;
    let executionError = null;
    try {
      result = await execFileCommand(`/proc/self/fd/${handle.fd}`, args, {
        argv0: command,
        cwd: '/',
        env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' },
        encoding: 'utf8',
        maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
        timeout: 120_000,
      });
    } catch (error) {
      executionError = error;
    }
    const after = await handle.stat();
    if (!sameFileIdentity(before, after)) {
      throw new Error(`fixed command changed during execution: ${command}`);
    }
    if (executionError === null) {
      return Object.freeze({ command, args: Object.freeze([...args]), code: 0, ...result });
    }
    if (
      Number.isInteger(executionError.code)
      && allowedExitCodes.includes(executionError.code)
    ) {
      return Object.freeze({
        command,
        args: Object.freeze([...args]),
        code: executionError.code,
        stdout: String(executionError.stdout ?? ''),
        stderr: String(executionError.stderr ?? ''),
      });
    }
    throw executionError;
  } finally {
    await handle.close();
  }
}

function provisionDependencies(dependencies) {
  const runCommand = dependencies.runCommand ?? runFixedCommand;
  const fsApi = dependencies.fsApi ?? fs;
  const processApi = dependencies.processApi ?? process;
  const verifyMountNamespace = dependencies.verifyMountNamespace
    ?? (() => assertSameMountNamespace(fsApi));
  const readMountInfo = dependencies.readMountInfo
    ?? (() => readBoundedProcFile(
      '/proc/self/mountinfo',
      MAX_MOUNTINFO_BYTES,
      fsApi,
    ));
  const verifyIdentityLock = dependencies.verifyIdentityLock
    ?? (() => assertIdentityLockHeld({ fsApi, processApi }));
  return {
    fsApi,
    processApi,
    randomUUID: dependencies.randomUUID ?? randomUUID,
    requireRoot: dependencies.requireRoot ?? true,
    requirePrivateMountNamespace: dependencies.requirePrivateMountNamespace
      ?? (dependencies.requireRoot ?? true),
    allowTestRoot: dependencies.allowTestRoot ?? false,
    sourceTrustRoot: path.resolve(dependencies.sourceTrustRoot ?? '/'),
    sourceUid: dependencies.sourceUid ?? 0,
    sourceGid: dependencies.sourceGid ?? 0,
    targetUid: dependencies.targetUid ?? 0,
    targetGid: dependencies.targetGid ?? 0,
    runCommand,
    readIdentitySnapshot: dependencies.readIdentitySnapshot
      ?? (() => readSystemIdentitySnapshot(fsApi, runCommand)),
    readIdentityFileState: dependencies.readIdentityFileState
      ?? ((snapshot) => {
        if (!Array.isArray(snapshot.identityFiles)) {
          throw new Error('identity recovery metadata is unavailable');
        }
        return snapshot.identityFiles;
      }),
    recoverIdentityDatabases: dependencies.recoverIdentityDatabases
      ?? ((transaction, snapshot, options) => (
        options.apply
          ? executeIdentityRecovery({ fsApi })
          : restoreInterruptedIdentityDatabases(
            transaction,
            snapshot,
            {
              ...options,
              fsApi,
              verifyMountNamespace,
              readMountInfo,
              verifyIdentityLock,
            },
          )
      )),
    readBootPolicyCatalogs: dependencies.readBootPolicyCatalogs
      ?? (() => readSystemBootPolicyCatalogs(runCommand, fsApi)),
    readMountInfo,
    readManagerMountInfo: dependencies.readManagerMountInfo
      ?? (() => readBoundedProcFile(
        '/proc/1/mountinfo',
        MAX_MOUNTINFO_BYTES,
        fsApi,
      )),
    verifyManagerInstalledArtifacts: dependencies.verifyManagerInstalledArtifacts
      ?? ((inspected) => verifyManagerInstalledArtifacts(inspected, {
        fsApi,
        targetUid: dependencies.targetUid ?? 0,
        targetGid: dependencies.targetGid ?? 0,
      })),
    verifyMountNamespace,
    verifyIdentityLock,
    verifyPidNamespace: dependencies.verifyPidNamespace
      ?? (() => assertInitialPidNamespace(runCommand, processApi, fsApi)),
    verifyLegacyPaths: dependencies.verifyLegacyPaths
      ?? (() => assertCanonicalVarRunLink(fsApi)),
    verifyNoExtendedPosixAcl: dependencies.verifyNoExtendedPosixAcl
      ?? ((file) => assertNoExtendedPosixAcl(file, runCommand)),
    readUnitStates: dependencies.readUnitStates
      ?? ((units, identitySnapshot) => readSystemUnitStates(
        units,
        runCommand,
        fsApi,
        identitySnapshot,
      )),
    verifyProvisionLockConverged: dependencies.verifyProvisionLockConverged
      ?? (() => assertProvisionLockHeld({ allowInterruptedMigration: false })),
  };
}

function provisionReport(mode, plan, inspected, commands, installed = []) {
  return Object.freeze({
    version: 1,
    mode,
    artifact_count: plan.artifacts.length,
    changed_artifact_count: inspected.artifacts.filter(({ changed }) => changed).length,
    installed_artifacts: Object.freeze([...installed]),
    command_count: commands.length,
    units_started: 0,
    units_enabled: 0,
  });
}

function assertPrimaryGroup(snapshot, user, groupName) {
  const group = snapshot.groups.get(groupName);
  if (!group || user.gid !== group.gid) {
    throw new Error(`managed user has an unexpected primary group: ${user.name}`);
  }
}

function assertManagedGroupCredentialLocked(group, shadowGroup) {
  const groupPasswordIsLocked = /^[!*]+$/.test(group.password);
  if (group.password !== 'x' && !groupPasswordIsLocked) {
    throw new Error(`managed group password is not locked: ${group.name}`);
  }
  if (group.password === 'x' && !shadowGroup) {
    throw new Error(`managed group shadow credential is missing: ${group.name}`);
  }
  if (!shadowGroup) return;
  if (!/^[!*]+$/.test(shadowGroup.password)) {
    throw new Error(`managed group shadow password is not locked: ${group.name}`);
  }
  if (shadowGroup.administrators.length !== 0 || shadowGroup.members.length !== 0) {
    throw new Error(`managed group has shadow administrators or members: ${group.name}`);
  }
}

function assertManagedUserCredentialLocked(user, shadowUser) {
  const passwordIsLocked = /^[!*]+$/.test(user.password);
  if (user.password !== 'x' && !passwordIsLocked) {
    throw new Error(`managed user password is not locked: ${user.name}`);
  }
  if (user.password === 'x' && !shadowUser) {
    throw new Error(`managed user shadow credential is missing: ${user.name}`);
  }
  if (shadowUser && !/^[!*]+$/.test(shadowUser.password)) {
    throw new Error(`managed user shadow password is not locked: ${user.name}`);
  }
}

function assertAccountContract(user, expected) {
  if (user.home !== expected.home || user.shell !== expected.shell) {
    throw new Error(`managed user account metadata is unexpected: ${user.name}`);
  }
}

function assertExactEffectiveGroups(snapshot, user) {
  const effective = snapshot.effectiveGroups.get(user.name);
  if (!effective || effective.size !== 1 || !effective.has(user.gid)) {
    throw new Error(`managed user has unexpected static groups: ${user.name}`);
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function policyArtifact(kind, sourceName, targetPath) {
  return Object.freeze({ kind, sourceName, targetPath });
}

function rootedPath(root, absolutePath) {
  if (!path.isAbsolute(absolutePath)) throw new Error(`target path is not absolute: ${absolutePath}`);
  return root === '/' ? absolutePath : path.join(root, absolutePath.slice(1));
}

function parseDatabaseId(value, label) {
  if (!/^[0-9]+$/.test(String(value))) throw new Error(`${label} is invalid`);
  const id = Number(value);
  if (!Number.isSafeInteger(id)) throw new Error(`${label} is invalid`);
  return id;
}

function parseGroupMemberList(value, groupName, label) {
  const members = value === '' ? [] : value.split(',');
  if (members.some((member) => member === '') || new Set(members).size !== members.length) {
    throw new Error(`group ${label} list is malformed: ${groupName}`);
  }
  return Object.freeze([...members]);
}

function normalisedState(value, fallback) {
  const state = String(value).trim();
  return state === '' ? fallback : state;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const invokedDirectly = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  runCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    });
}
