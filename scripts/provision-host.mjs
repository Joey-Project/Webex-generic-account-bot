#!/usr/bin/env node

import { execFile, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const SYSTEMD_SOURCE_ROOT = fileURLToPath(
  new URL('../deploy/systemd/', import.meta.url),
);
const FILE_MODE = 0o644;
const TRANSACTION_MODE = 0o600;
const DIRECTORY_MODE = 0o755;
const MAX_POLICY_FILE_BYTES = 256 * 1024;
const MAX_TRANSACTION_BYTES = 8 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const MAX_PROC_LOCKS_BYTES = 1024 * 1024;
const MAX_STALE_CANDIDATES = 256;
const MAX_SCANNED_DIRECTORY_ENTRIES = 4096;
const MAX_LAUNCHER_INSTANCES = 128;
const MAX_SYSTEMD_USERDB_ENTRIES = 16;
const MAX_SYSTEMD_UNIT_PATH_ENTRIES = 4096;
const MAX_SYSTEMD_POLICY_TREE_ENTRIES = 32_768;
const MAX_SYSTEMD_POLICY_FILES = 8192;
const MAX_SYSTEMD_POLICY_BYTES = 64 * 1024 * 1024;
const MAX_MANAGED_ID = 59_999;
const MAX_IDENTITY_FILE_BYTES = 8 * 1024 * 1024;
const TRANSACTION_VERSION = 1;
const TRANSACTION_PATH =
  '/etc/systemd/system/.webex-host-provision.transaction.json';
const PROVISION_LOCK_PATH = '/run/webex-config-deploy/deploy-config.lock';
const PROVISION_LOCK_PARENT = path.dirname(PROVISION_LOCK_PATH);
const PROVISION_LOCK_ENV = 'WEBEX_HOST_PROVISION_LOCKED';
const PROVISION_LOCK_CONFLICT_EXIT = 75;
const CANDIDATE_UUID_PATTERN =
  '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const LAUNCHER_INSTANCE_PATTERN = /^webex-codex-launcher@[^@/\s]+\.service$/;
const LAUNCHER_REFERENCE_PATTERN = /webex-codex-launcher@[^@/\s]*\.service/;
const SYSTEMD_UNIT_NAME_PATTERN =
  /\.(?:automount|device|mount|path|scope|service|slice|socket|swap|target|timer)$/;
const SYSTEMD_USERDB_DIRECTORY = '/run/systemd/userdb';
const SYSTEMD_DYNAMIC_USER_PROVIDER = 'io.systemd.DynamicUser';
const SYSTEMD_SYSTEM_UNIT_LOAD_PATHS = Object.freeze([
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
  '/lib/systemd/system',
  '/run/systemd/generator.late',
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
const MANAGED_IDENTITY_PATTERNS = Object.freeze(
  [...new Set([...Object.values(MANAGED_USERS), ...Object.values(MANAGED_GROUPS)])]
    .map((name) => new RegExp(
      `(^|[^A-Za-z0-9_.-])${escapeRegExp(name)}([^A-Za-z0-9_.-]|$)`,
    )),
);

export const MANAGED_UNITS = Object.freeze([
  'webex-generic-account-bot.service',
  'webex-config-pull-worker.service',
  'webex-codex-launcher.socket',
  'webex-codex-launcher@.service',
  'webex-codex-activation-renew.service',
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
    'Usage: node scripts/provision-host.mjs [--dry-run] [--json]',
    '       node scripts/provision-host.mjs --apply [--json]',
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
      uid,
      gid,
      home: fields[5],
      shell: fields[6],
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
  return Object.freeze({ users, groups, shadowGroups, effectiveGroups: effective });
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

  if (options.apply) await cleanupStaleCandidates(plan, deps);

  const transaction = await readProvisionTransaction(plan, deps);
  if (transaction && !options.apply) {
    throw new Error('host policy recovery is required; run --apply');
  }
  const commands = [];
  if (transaction) {
    const recoveryUnitStates = await deps.readUnitStates(MANAGED_UNITS);
    assertUnitsDormant(recoveryUnitStates, plan, {
      requireLoaded: false,
      allowDaemonReloadRequired: true,
    });
    await recoverPolicyTransaction(transaction, plan, deps, { removeTransaction: false });
    try {
      commands.push(await deps.runCommand('/usr/bin/systemctl', ['daemon-reload']));
      const recoveredUnitStates = await deps.readUnitStates(MANAGED_UNITS);
      assertUnitsDormant(recoveredUnitStates, plan, { requireLoaded: false });
      await removeProvisionTransaction(plan, deps);
    } catch (error) {
      throw new Error(
        `host policy recovery finalisation failed; rerun --apply after correction: ${error.message}`,
        { cause: error },
      );
    }
  }

  const identityBefore = await deps.readIdentitySnapshot();
  validateIdentityPolicy(identityBefore);
  const unitStatesBefore = await deps.readUnitStates(MANAGED_UNITS);
  const inspected = await inspectArtifacts(plan, deps);
  auditBootPolicyCatalogs(
    await deps.readBootPolicyCatalogs(),
    inspected,
    identityBefore,
  );
  const canRecoverManagerCache = options.apply
    && inspected.artifacts.every(({ changed }) => !changed);
  assertUnitsDormant(unitStatesBefore, plan, {
    requireLoaded: false,
    allowDaemonReloadRequired: canRecoverManagerCache,
  });
  if (unitStatesNeedDaemonReload(unitStatesBefore)) {
    commands.push(await deps.runCommand('/usr/bin/systemctl', ['daemon-reload']));
    const reloadedUnitStates = await deps.readUnitStates(MANAGED_UNITS);
    assertUnitsDormant(reloadedUnitStates, plan, { requireLoaded: true });
  }

  if (!options.apply) {
    return provisionReport('dry-run', plan, inspected, commands);
  }

  await ensureTargetDirectories(plan, deps);
  const installed = await installPolicySetAtomically(inspected, plan, deps);
  try {
    commands.push(await deps.runCommand('/usr/bin/systemd-sysusers', plan.sysusers));
    const identityAfter = await deps.readIdentitySnapshot();
    validateIdentityPolicy(identityAfter, { requireAccounts: true });
    auditBootPolicyCatalogs(
      await deps.readBootPolicyCatalogs(),
      inspected,
      identityAfter,
      { requireManagedPolicy: true },
    );
    commands.push(await deps.runCommand('/usr/bin/systemd-tmpfiles', [
      '--create',
      ...plan.tmpfiles,
    ]));
    await deps.verifyProvisionLockConverged();
    commands.push(await deps.runCommand('/usr/bin/systemctl', ['daemon-reload']));
    await verifyInstalledArtifacts(inspected, deps);
    const unitStatesAfter = await deps.readUnitStates(MANAGED_UNITS);
    assertUnitsDormant(unitStatesAfter, plan, { requireLoaded: true });
    if (installed.length > 0) await removeProvisionTransaction(plan, deps);
  } catch (error) {
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
  scriptPath = fileURLToPath(import.meta.url),
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
      nodePath,
      scriptPath,
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

async function executeLockedApply(argv) {
  await ensureProvisionLockFile(fs);
  const scriptPath = fileURLToPath(import.meta.url);
  await assertTrustedReexecFile(process.execPath, { executable: true }, fs);
  await assertTrustedReexecFile(scriptPath, { mode: FILE_MODE }, fs);
  const command = buildLockedApplyCommand({ argv, scriptPath });
  return new Promise((resolve, reject) => {
    const child = spawn(command.command, command.args, {
      cwd: '/',
      env: {
        PATH: '/usr/bin:/bin',
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        [PROVISION_LOCK_ENV]: '1',
      },
      stdio: 'inherit',
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
}

async function assertProvisionLockHeld({ allowInterruptedMigration = true } = {}) {
  const configPullGid = await readConfigPullGroupGid(fs);
  const parentStat = await fs.lstat(PROVISION_LOCK_PARENT);
  const lockPolicy = assertTrustedProvisionLockParent(parentStat, configPullGid);
  const lock = await fs.open(
    PROVISION_LOCK_PATH,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  let stat;
  try {
    stat = await lock.stat();
    assertTrustedProvisionLock(stat, lockPolicy, { allowInterruptedMigration });
  } finally {
    await lock.close();
  }
  const procLocks = await readBoundedProcFile('/proc/locks', MAX_PROC_LOCKS_BYTES, fs);
  if (!hasProvisionLock(procLocks, process.pid, stat)) {
    throw new Error('current process does not hold the host provision lock');
  }
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
    );
  }
}

async function cleanupStaleCandidates(plan, deps) {
  const targets = [...plan.artifacts.map(({ target }) => target), plan.transactionFile];
  const targetsByDirectory = new Map();
  for (const target of targets) {
    const directory = path.dirname(target);
    const prefixes = targetsByDirectory.get(directory) ?? [];
    prefixes.push(`.${path.basename(target)}.provision-`);
    targetsByDirectory.set(directory, prefixes);
  }

  let candidateCount = 0;
  let scannedEntryCount = 0;
  for (const [directory, prefixes] of targetsByDirectory) {
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
    let changed = false;
    try {
      for await (const entry of directoryHandle) {
        scannedEntryCount += 1;
        if (scannedEntryCount > MAX_SCANNED_DIRECTORY_ENTRIES) {
          throw new Error('too many policy directory entries');
        }
        const prefix = prefixes.find((value) => entry.name.startsWith(value));
        if (!prefix) continue;
        candidateCount += 1;
        if (candidateCount > MAX_STALE_CANDIDATES) {
          throw new Error('too many stale policy candidates');
        }
        const suffix = entry.name.slice(prefix.length);
        if (!new RegExp(`^${CANDIDATE_UUID_PATTERN}\\.tmp$`).test(suffix)) {
          throw new Error(`stale policy candidate name is malformed: ${entry.name}`);
        }
        const candidate = path.join(directory, entry.name);
        const stat = await deps.fsApi.lstat(candidate);
        const mode = stat.mode & 0o7777;
        assertTrustedFileMetadata(candidate, stat, deps.targetUid, deps.targetGid, null);
        if (!entry.isFile() || ![0o600, FILE_MODE].includes(mode)) {
          throw new Error(`stale policy candidate metadata is not trusted: ${candidate}`);
        }
        await deps.fsApi.rm(candidate);
        changed = true;
      }
    } finally {
      try {
        await directoryHandle.close();
      } catch (error) {
        if (error?.code !== 'ERR_DIR_CLOSED') throw error;
      }
    }
    if (changed) await syncDirectory(directory, deps.fsApi);
  }
}

async function installPolicySetAtomically(inspected, plan, deps) {
  const changed = inspected.artifacts.filter(({ changed }) => changed);
  if (changed.length === 0) return [];
  const staged = [];
  const rollbackTransaction = transactionFromInspected(inspected);
  await writeProvisionTransaction(inspected, plan, deps);
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
      .map(({ temporary }) => deps.fsApi.rm(temporary, { force: true })));
  }
  return changed.map(({ target }) => target);
}

function transactionFromInspected(inspected) {
  return Object.freeze({
    version: TRANSACTION_VERSION,
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

async function writeCandidate(target, contents, deps) {
  return writeCandidateWithMode(target, contents, FILE_MODE, deps);
}

async function writeCandidateWithMode(target, contents, mode, deps) {
  const temporary = path.join(
    path.dirname(target),
    `.${path.basename(target)}.provision-${deps.randomUUID()}.tmp`,
  );
  let handle;
  try {
    handle = await deps.fsApi.open(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(contents);
    await handle.chown(deps.targetUid, deps.targetGid);
    await handle.chmod(mode);
    await handle.sync();
    await handle.close();
    handle = null;
    return temporary;
  } catch (error) {
    await handle?.close().catch(() => {});
    await deps.fsApi.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

async function ensureProvisionLockFile(fsApi) {
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
    await fsApi.mkdir(PROVISION_LOCK_PARENT, { mode: DIRECTORY_MODE });
    await fsApi.chown(PROVISION_LOCK_PARENT, 0, 0);
    await fsApi.chmod(PROVISION_LOCK_PARENT, DIRECTORY_MODE);
    await syncDirectory(path.dirname(PROVISION_LOCK_PARENT), fsApi);
    parentStat = await fsApi.lstat(PROVISION_LOCK_PARENT);
  }
  let lockPolicy = assertTrustedProvisionLockParent(parentStat, configPullGid);
  if (
    lockPolicy.state === 'bootstrap'
    && (parentStat.mode & 0o7777) !== DIRECTORY_MODE
  ) {
    await fsApi.chmod(PROVISION_LOCK_PARENT, DIRECTORY_MODE);
    await syncDirectory(path.dirname(PROVISION_LOCK_PARENT), fsApi);
    parentStat = await fsApi.lstat(PROVISION_LOCK_PARENT);
    lockPolicy = assertTrustedProvisionLockParent(parentStat, configPullGid);
  }
  let handle;
  try {
    handle = await fsApi.open(
      PROVISION_LOCK_PATH,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await handle.chown(0, lockPolicy.gid);
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
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  try {
    assertTrustedProvisionLock(await existing.stat(), lockPolicy);
  } finally {
    await existing.close();
  }
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

function assertTrustedProvisionLockParent(stat, configPullGid) {
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.uid !== 0
  ) {
    throw new Error(`provision lock parent is not trusted: ${PROVISION_LOCK_PARENT}`);
  }
  const mode = stat.mode & 0o7777;
  const recoverableBootstrapMode = (mode & 0o7000) === 0 && (mode & 0o022) === 0;
  if (stat.gid === 0 && recoverableBootstrapMode) {
    return Object.freeze({ state: 'bootstrap', gid: 0, mode: 0o600 });
  }
  if (configPullGid !== null && stat.gid === configPullGid && mode === 0o750) {
    return Object.freeze({ state: 'deployed', gid: configPullGid, mode: 0o660 });
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

export function validateProvisionLockMetadata(
  parentStat,
  lockStat,
  configPullGid,
  options = {},
) {
  const policy = assertTrustedProvisionLockParent(parentStat, configPullGid);
  assertTrustedProvisionLock(lockStat, policy, options);
  return policy;
}

async function assertTrustedReexecFile(file, policy, fsApi) {
  if (!path.isAbsolute(file)) throw new Error(`re-exec path is not absolute: ${file}`);
  await assertTrustedDirectoryChain('/', path.dirname(file), 0, 0, fsApi);
  const handle = await fsApi.open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
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
  const handle = await fsApi.open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
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
  const handle = await fsApi.open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
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

async function readBoundedProcFile(file, maxBytes, fsApi) {
  const handle = await fsApi.open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const buffer = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > maxBytes) throw new Error(`proc file is too large: ${file}`);
    return buffer.subarray(0, bytesRead).toString('utf8');
  } finally {
    await handle.close();
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

async function createTrustedDirectoryChain(root, directory, uid, gid, fsApi) {
  for (const candidate of pathComponentsWithin(root, directory)) {
    try {
      const stat = await fsApi.lstat(candidate);
      assertTrustedDirectory(candidate, stat, uid, gid);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      const parent = path.dirname(candidate);
      await fsApi.mkdir(candidate, { mode: DIRECTORY_MODE });
      await fsApi.chown(candidate, uid, gid);
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
  if (
    !value
    || typeof value !== 'object'
    || Array.isArray(value)
    || value.version !== TRANSACTION_VERSION
    || Object.keys(value).sort().join(',') !== 'artifacts,version'
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
  return Object.freeze({ version: TRANSACTION_VERSION, artifacts: Object.freeze(artifacts) });
}

async function writeProvisionTransaction(inspected, plan, deps) {
  const value = {
    version: TRANSACTION_VERSION,
    artifacts: inspected.artifacts.map((artifact) => ({
      target: artifact.target,
      desired_sha256: artifact.source.sha256,
      existing: artifact.existing
        ? {
          contents_base64: artifact.existing.contents.toString('base64'),
          sha256: artifact.existing.sha256,
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
    await deps.fsApi.rename(temporary, plan.transactionFile);
    await syncDirectory(path.dirname(plan.transactionFile), deps.fsApi);
  } catch (error) {
    await deps.fsApi.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

async function recoverPolicyTransaction(
  transaction,
  plan,
  deps,
  { removeTransaction = true } = {},
) {
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
    if (current?.sha256 === existingSha256 || (!current && !artifact.existing)) {
      recovery.push(Object.freeze({ artifact, current, restore: false }));
      continue;
    }
    if (current?.sha256 !== artifact.desiredSha256) {
      throw new Error(`policy target has unknown state during recovery: ${artifact.target}`);
    }
    recovery.push(Object.freeze({ artifact, current, restore: true }));
  }
  for (const entry of recovery.reverse()) {
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
        await deps.fsApi.rename(temporary, artifact.target);
      } catch (error) {
        await deps.fsApi.rm(temporary, { force: true }).catch(() => {});
        throw error;
      }
    } else {
      await assertTargetUnchanged(
        { target: artifact.target, existing: entry.current },
        deps.fsApi,
      );
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
    const existingSha256 = artifact.existing
      ? createHash('sha256').update(artifact.existing.contents).digest('hex')
      : null;
    const matchesOldState = artifact.existing
      ? current?.sha256 === existingSha256
      : !current;
    if (!matchesOldState) {
      throw new Error(`policy target changed after recovery: ${artifact.target}`);
    }
  }
  if (removeTransaction) await removeProvisionTransaction(plan, deps);
}

async function removeProvisionTransaction(plan, deps) {
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
  if (!['inactive', 'unknown'].includes(state.active)) {
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
  const gshadow = await readTrustedSensitiveIdentityFile(
    '/etc/gshadow',
    new Set([0, shadowGid]),
    new Set([0o600, 0o640]),
    fsApi,
  );
  const passwdText = passwd.contents.toString('utf8');
  const groupText = group.contents.toString('utf8');
  const gshadowText = gshadow.contents.toString('utf8');
  const complete = parseIdentityDatabases(passwdText, groupText, {}, gshadowText);
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
  return parseIdentityDatabases(passwdText, groupText, effectiveGroups, gshadowText);
}

export async function readSystemBootPolicyCatalogs(runCommand = runFixedCommand) {
  const [sysusers, tmpfiles] = await Promise.all([
    runCommand('/usr/bin/systemd-sysusers', ['--cat-config', '--tldr', '--no-pager']),
    runCommand('/usr/bin/systemd-tmpfiles', ['--cat-config', '--tldr', '--no-pager']),
  ]);
  return Object.freeze({
    sysusers: sysusers.stdout,
    tmpfiles: tmpfiles.stdout,
  });
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
  const protectedPaths = new Set([
    ...inspected.artifacts
      .filter((artifact) => artifact.kind === 'tmpfiles')
      .flatMap((artifact) => policyCatalogLines(artifact.source.contents))
      .map((line) => parseSystemdFields(line)[1]),
    ...inspected.artifacts.map((artifact) => artifact.targetPath),
    TRANSACTION_PATH,
    PROVISION_LOCK_PATH,
  ]);

  for (const kind of ['sysusers', 'tmpfiles']) {
    if (typeof catalogs?.[kind] !== 'string') {
      throw new Error(`boot policy catalog is missing: ${kind}`);
    }
    const allowed = new Set(inspected.artifacts
      .filter((artifact) => artifact.kind === kind)
      .flatMap((artifact) => policyCatalogLines(artifact.source.contents)));
    const observed = new Set(policyCatalogLines(catalogs[kind]));
    if (requireManagedPolicy) {
      for (const line of allowed) {
        if (!observed.has(line)) {
          throw new Error(`managed ${kind} policy is not active: ${line}`);
        }
      }
    }
    for (const line of observed) {
      if (allowed.has(line)) continue;
      if (bootPolicyLineTouchesManagedSurface(
        kind,
        line,
        managedNames,
        managedIds,
        protectedPaths,
      )) {
        throw new Error(`unmanaged ${kind} policy touches the Webex boundary: ${line}`);
      }
    }
  }
}

function policyCatalogLines(contents) {
  const logicalLines = [];
  let pending = '';
  for (const physicalLine of String(contents).split('\n')) {
    const trimmed = physicalLine.trimStart();
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
      logicalLines.push(line);
      pending = '';
    }
  }
  if (pending !== '') throw new Error('boot policy ends with an unterminated continuation');
  return logicalLines
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#') && !line.startsWith(';'));
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
  protectedPaths,
) {
  const fields = parseSystemdFields(line);
  if (kind === 'sysusers') {
    return sysusersLineTouchesManagedSurface(fields, managedNames, managedIds, protectedPaths);
  }
  if (kind === 'tmpfiles') {
    return tmpfilesLineTouchesManagedSurface(fields, managedNames, managedIds, protectedPaths);
  }
  throw new Error(`unsupported boot policy kind: ${kind}`);
}

function sysusersLineTouchesManagedSurface(fields, managedNames, managedIds, protectedPaths) {
  if (fields.length < 3) throw new Error('sysusers policy line is malformed');
  const [type, name, id] = fields;
  if (managedNames.has(name) || [...managedNames].some((managed) => id === managed)) return true;
  if (name.includes('%') || id.includes('%')) return true;
  if (type === 'm') return managedNames.has(name) || managedNames.has(id);
  if (['u', 'u!', 'g', 'g!'].includes(type)) {
    if (id.startsWith('/')) return true;
    for (const component of id.split(':')) {
      if (managedIds.has(component) || managedNames.has(component)) return true;
    }
    for (const field of fields.slice(3)) {
      if (pathFieldTouchesProtected(field, true, protectedPaths)) return true;
    }
    return false;
  }
  if (type === 'r') {
    const match = id.match(/^(\d+)(?:-(\d+))?$/);
    if (!match) return id !== '-';
    const lower = Number(match[1]);
    const upper = Number(match[2] ?? match[1]);
    return [...managedIds].some((managedId) => {
      const value = Number(managedId);
      return value >= lower && value <= upper;
    });
  }
  throw new Error(`unsupported sysusers policy type: ${type}`);
}

function tmpfilesLineTouchesManagedSurface(fields, managedNames, managedIds, protectedPaths) {
  if (fields.length < 2) throw new Error('tmpfiles policy line is malformed');
  const [type, policyPath] = fields;
  const user = normaliseTmpfilesOwner(fields[3] ?? '-');
  const group = normaliseTmpfilesOwner(fields[4] ?? '-');
  if (
    managedNames.has(user)
    || managedNames.has(group)
    || managedIds.has(user)
    || managedIds.has(group)
  ) {
    return true;
  }
  return pathFieldTouchesProtected(
    policyPath,
    tmpfilesAncestorPolicyIsSafe(fields),
    protectedPaths,
  );
}

function normaliseTmpfilesOwner(owner) {
  return owner.startsWith(':') ? owner.slice(1) : owner;
}

function pathFieldTouchesProtected(policyPath, ancestorPolicyIsSafe, protectedPaths) {
  if (/(^|\/)webex(?:-|\/|$)/.test(policyPath)) return true;
  if (!policyPath.startsWith('/')) return policyPath.includes('%');
  const wildcardOffset = policyPath.search(/[%*?[]/);
  const literal = wildcardOffset < 0 ? path.posix.normalize(policyPath) : null;
  const staticPrefix = wildcardOffset < 0
    ? literal
    : policyPath.slice(0, wildcardOffset);
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

function tmpfilesAncestorPolicyIsSafe(fields) {
  const [type, , mode = '-', rawUser = '-', rawGroup = '-', age = '-'] = fields;
  if (!new Set(['d', 'e', 'v', 'q', 'Q', 'z']).has(type?.[0])) return false;
  if (age !== '-') return false;
  const user = normaliseTmpfilesOwner(rawUser);
  const group = normaliseTmpfilesOwner(rawGroup);
  if (!['-', 'root', '0'].includes(user) || !['-', 'root', '0'].includes(group)) return false;
  if (mode === '-') return true;
  if (!/^[0-7]{3,4}$/.test(mode)) return false;
  return (Number.parseInt(mode, 8) & 0o022) === 0;
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

export async function readSystemUnitStates(units, runCommand = runFixedCommand, fsApi = fs) {
  await assertNoUnexpectedManagedUnitPolicy(fsApi);
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
  const discovered = new Set([
    ...parseLauncherInstanceUnits(loadedInstances.stdout),
    ...parseLauncherInstanceUnits(installedInstances.stdout),
  ]);
  if (discovered.size > MAX_LAUNCHER_INSTANCES) {
    throw new Error('too many launcher instances');
  }
  const states = new Map();
  for (const unit of [...units, ...[...discovered].sort()]) {
    const [active, enabled, metadata] = await Promise.all([
      runCommand('/usr/bin/systemctl', ['is-active', unit], [0, 3, 4]),
      runCommand('/usr/bin/systemctl', ['is-enabled', unit], [0, 1, 3, 4]),
      runCommand('/usr/bin/systemctl', [
        'show',
        '--property=LoadState',
        '--property=FragmentPath',
        '--property=DropInPaths',
        '--property=NeedDaemonReload',
        ...REVERSE_ACTIVATION_PROPERTIES.map((property) => `--property=${property}`),
        unit,
      ], [0, 1, 3, 4]),
    ]);
    const loadedPolicy = parseSystemUnitMetadata(metadata.stdout, unit);
    states.set(unit, Object.freeze({
      active: normalisedState(active.stdout, 'unknown'),
      enabled: normalisedState(enabled.stdout, 'not-found'),
      ...loadedPolicy,
    }));
  }
  return states;
}

async function assertNoUnexpectedManagedUnitPolicy(fsApi) {
  const budget = { entries: 0, files: 0, bytes: 0 };
  for (const directory of SYSTEMD_SYSTEM_UNIT_LOAD_PATHS) {
    if (directory === '/lib/systemd/system' && await isUsrMergedLib(fsApi)) continue;
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
      const managedFragmentOutsideTarget = MANAGED_UNITS.includes(entry.name)
        && directory !== '/etc/systemd/system';
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
      await auditSystemdPolicyEntry(directory, entry, budget, fsApi, { nested: false });
    }
  }
}

async function auditSystemdPolicyEntry(directory, entry, budget, fsApi, { nested }) {
  const candidate = path.join(directory, entry.name);
  const unitNames = systemdPolicyUnitNames(directory, entry.name);
  if (nested) assertSystemdPolicyDoesNotReferenceManaged(entry.name, candidate, unitNames);
  const unitFile = SYSTEMD_UNIT_NAME_PATTERN.test(entry.name);
  const policyDirectory = /\.(?:d|wants|requires|upholds)$/.test(entry.name);
  if (!nested && !unitFile && !policyDirectory && !entry.isDirectory?.()) return;
  if (entry.isSymbolicLink?.()) {
    await auditSystemdPolicySymlink(candidate, budget, fsApi, new Set(), unitNames);
    return;
  }
  if (entry.isFile?.()) {
    await auditSystemdPolicyFile(candidate, budget, fsApi, unitNames);
    return;
  }
  if (!entry.isDirectory?.()) return;
  if (!/\.(?:d|wants|requires|upholds)$/.test(entry.name)) return;
  const nestedEntries = await readTrustedDirectoryEntries(
    candidate,
    MAX_SYSTEMD_POLICY_TREE_ENTRIES - budget.entries,
    fsApi,
  );
  budget.entries += nestedEntries.length;
  for (const child of nestedEntries) {
    if (child.isDirectory?.()) {
      throw new Error(`nested systemd policy directory is not supported: ${path.join(candidate, child.name)}`);
    }
    await auditSystemdPolicyEntry(candidate, child, budget, fsApi, { nested: true });
  }
}

async function auditSystemdPolicySymlink(candidate, budget, fsApi, visited, unitNames) {
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
  );
  let resolved = path.resolve(path.dirname(candidate), target);
  if (resolved === '/dev/null') return;
  if (resolved === '/lib/systemd/system' || resolved.startsWith('/lib/systemd/system/')) {
    if (await isUsrMergedLib(fsApi)) resolved = `/usr${resolved}`;
  }
  await assertTrustedDirectoryChain('/', path.dirname(resolved), 0, 0, fsApi);
  let targetStat;
  try {
    targetStat = await fsApi.lstat(resolved);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  if (targetStat.isSymbolicLink()) {
    await auditSystemdPolicySymlink(
      resolved,
      budget,
      fsApi,
      visited,
      mergeSystemdUnitNames(unitNames, path.basename(resolved)),
    );
    return;
  }
  if (!targetStat.isFile()) {
    throw new Error(`systemd policy symlink target is not a regular file: ${candidate}`);
  }
  await auditSystemdPolicyFile(
    resolved,
    budget,
    fsApi,
    mergeSystemdUnitNames(unitNames, path.basename(resolved)),
  );
}

async function auditSystemdPolicyFile(candidate, budget, fsApi, unitNames) {
  budget.files += 1;
  if (budget.files > MAX_SYSTEMD_POLICY_FILES) {
    throw new Error('too many systemd policy files');
  }
  const policy = await readTrustedFile(candidate, 0, 0, null, fsApi);
  budget.bytes += policy.contents.length;
  if (budget.bytes > MAX_SYSTEMD_POLICY_BYTES) {
    throw new Error('systemd policy files exceed the aggregate byte limit');
  }
  for (const line of policyCatalogLines(policy.contents)) {
    assertSystemdPolicyDoesNotReferenceManaged(line, candidate, unitNames);
  }
}

function assertSystemdPolicyDoesNotReferenceManaged(value, source, unitNames = new Set()) {
  const decoded = decodeSystemdEscapesForAudit(String(value));
  const expanded = new Set([
    decoded,
    ...[...unitNames].map((unitName) => expandSystemdUnitNameSpecifiers(decoded, unitName)),
  ]);
  for (const candidate of expanded) {
    if (
      MANAGED_UNITS.some((unit) => candidate.includes(unit))
      || LAUNCHER_REFERENCE_PATTERN.test(candidate)
      || MANAGED_IDENTITY_PATTERNS.some((pattern) => pattern.test(candidate))
    ) {
      throw new Error(`external systemd policy references a managed unit: ${source}`);
    }
  }
}

function systemdPolicyUnitNames(directory, entryName) {
  const unitNames = new Set();
  if (SYSTEMD_UNIT_NAME_PATTERN.test(entryName)) unitNames.add(entryName);
  const parent = path.basename(directory);
  if (parent.endsWith('.d')) {
    const owner = parent.slice(0, -2);
    if (SYSTEMD_UNIT_NAME_PATTERN.test(owner)) unitNames.add(owner);
  }
  return unitNames;
}

function mergeSystemdUnitNames(unitNames, candidate) {
  const merged = new Set(unitNames);
  if (SYSTEMD_UNIT_NAME_PATTERN.test(candidate)) merged.add(candidate);
  return merged;
}

function expandSystemdUnitNameSpecifiers(value, unitName) {
  const suffixOffset = unitName.lastIndexOf('.');
  if (suffixOffset <= 0) return value;
  const stem = unitName.slice(0, suffixOffset);
  const atOffset = stem.indexOf('@');
  const prefix = atOffset < 0 ? stem : stem.slice(0, atOffset);
  const instance = atOffset < 0 ? '' : stem.slice(atOffset + 1);
  const finalComponent = prefix.slice(prefix.lastIndexOf('-') + 1);
  const replacements = new Map([
    ['%%', '%'],
    ['%n', unitName],
    ['%N', stem],
    ['%p', prefix],
    ['%P', decodeSystemdEscapesForAudit(prefix)],
    ['%i', instance],
    ['%I', decodeSystemdEscapesForAudit(instance)],
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
    'LoadState',
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
  const needDaemonReload = values.get('NeedDaemonReload');
  if (!['yes', 'no'].includes(needDaemonReload)) {
    throw new Error(`managed unit daemon-reload state is malformed: ${unit}`);
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
    load: normalisedState(values.get('LoadState'), 'not-found'),
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

async function runFixedCommand(command, args, allowedExitCodes = [0]) {
  try {
    const result = await execFileAsync(command, args, {
      cwd: '/',
      env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' },
      encoding: 'utf8',
      maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
      timeout: 120_000,
    });
    return Object.freeze({ command, args: Object.freeze([...args]), code: 0, ...result });
  } catch (error) {
    if (Number.isInteger(error?.code) && allowedExitCodes.includes(error.code)) {
      return Object.freeze({
        command,
        args: Object.freeze([...args]),
        code: error.code,
        stdout: String(error.stdout ?? ''),
        stderr: String(error.stderr ?? ''),
      });
    }
    throw error;
  }
}

function provisionDependencies(dependencies) {
  const runCommand = dependencies.runCommand ?? runFixedCommand;
  return {
    fsApi: dependencies.fsApi ?? fs,
    processApi: dependencies.processApi ?? process,
    randomUUID: dependencies.randomUUID ?? randomUUID,
    requireRoot: dependencies.requireRoot ?? true,
    allowTestRoot: dependencies.allowTestRoot ?? false,
    sourceTrustRoot: path.resolve(dependencies.sourceTrustRoot ?? '/'),
    sourceUid: dependencies.sourceUid ?? 0,
    sourceGid: dependencies.sourceGid ?? 0,
    targetUid: dependencies.targetUid ?? 0,
    targetGid: dependencies.targetGid ?? 0,
    runCommand,
    readIdentitySnapshot: dependencies.readIdentitySnapshot
      ?? (() => readSystemIdentitySnapshot(dependencies.fsApi ?? fs, runCommand)),
    readBootPolicyCatalogs: dependencies.readBootPolicyCatalogs
      ?? (() => readSystemBootPolicyCatalogs(runCommand)),
    readUnitStates: dependencies.readUnitStates
      ?? ((units) => readSystemUnitStates(units, runCommand, dependencies.fsApi ?? fs)),
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    });
}
