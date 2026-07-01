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
const TRANSACTION_VERSION = 1;
const TRANSACTION_PATH =
  '/etc/systemd/system/.webex-host-provision.transaction.json';
const PROVISION_LOCK_PATH = '/run/webex-host-provision.lock';
const PROVISION_LOCK_ENV = 'WEBEX_HOST_PROVISION_LOCKED';
const PROVISION_LOCK_CONFLICT_EXIT = 75;
const LAUNCHER_INSTANCE_PATTERN = /^webex-codex-launcher@[^@/\s]+\.service$/;
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

export const MANAGED_UNITS = Object.freeze([
  'webex-generic-account-bot.service',
  'webex-config-pull-worker.service',
  'webex-codex-launcher.socket',
  'webex-codex-launcher@.service',
  'webex-codex-activation-renew.service',
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

export function parseIdentityDatabases(passwdText, groupText, effectiveGroups = {}) {
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
    const members = fields[3] === '' ? [] : fields[3].split(',');
    if (members.some((member) => member === '') || new Set(members).size !== members.length) {
      throw new Error(`group member list is malformed: ${fields[0]}`);
    }
    groups.set(fields[0], Object.freeze({
      name: fields[0],
      gid,
      members: Object.freeze([...members]),
    }));
  }

  const effective = new Map();
  for (const [user, gids] of Object.entries(effectiveGroups)) {
    if (!Array.isArray(gids) || gids.some((gid) => !Number.isSafeInteger(gid) || gid < 0)) {
      throw new Error(`effective group list is invalid: ${user}`);
    }
    effective.set(user, new Set(gids));
  }
  return Object.freeze({ users, groups, effectiveGroups: effective });
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
    const aliases = [...snapshot.users.values()]
      .filter((candidate) => candidate.uid === user.uid)
      .map((candidate) => candidate.name);
    if (aliases.length !== 1) {
      throw new Error(`managed user UID has aliases: ${user.name}`);
    }
  }

  for (const groupName of controlledGroups) {
    const group = snapshot.groups.get(groupName);
    if (!group) continue;
    const aliases = [...snapshot.groups.values()]
      .filter((candidate) => candidate.gid === group.gid)
      .map((candidate) => candidate.name);
    if (aliases.length !== 1) {
      throw new Error(`managed group GID has aliases: ${groupName}`);
    }
    if (group.members.length !== 0) {
      throw new Error(`managed group has static members: ${groupName}`);
    }
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
  if (options.apply && deps.requireRoot && deps.processApi.geteuid?.() !== 0) {
    throw new Error('--apply requires root');
  }

  const transaction = await readProvisionTransaction(plan, deps);
  if (transaction && !options.apply) {
    throw new Error('host policy recovery is required; run --apply');
  }
  if (transaction) {
    await recoverPolicyTransaction(transaction, plan, deps);
  }

  const identityBefore = await deps.readIdentitySnapshot();
  validateIdentityPolicy(identityBefore);
  const unitStatesBefore = await deps.readUnitStates(MANAGED_UNITS);
  assertUnitsDormant(unitStatesBefore, { requireLoaded: false });
  const inspected = await inspectArtifacts(plan, deps);

  if (!options.apply) {
    return provisionReport('dry-run', plan, inspected, []);
  }

  await ensureTargetDirectories(plan, deps);
  const installed = await installPolicySetAtomically(inspected, plan, deps);
  const commands = [];
  try {
    commands.push(await deps.runCommand('/usr/bin/systemd-sysusers', plan.sysusers));
    validateIdentityPolicy(await deps.readIdentitySnapshot(), { requireAccounts: true });
    commands.push(await deps.runCommand('/usr/bin/systemd-tmpfiles', [
      '--create',
      ...plan.tmpfiles,
    ]));
    commands.push(await deps.runCommand('/usr/bin/systemctl', ['daemon-reload']));
    await verifyInstalledArtifacts(inspected, deps);
    const unitStatesAfter = await deps.readUnitStates(MANAGED_UNITS);
    assertUnitsDormant(unitStatesAfter, { requireLoaded: true });
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
} = {}) {
  const options = parseArgs(argv);
  if (options.help) {
    stdout.write(`${usage()}\n`);
    return 0;
  }
  if (options.apply && !lockHeld) {
    return runLockedApply(argv);
  }
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

async function executeLockedApply(argv) {
  await ensureProvisionLockFile(fs);
  await assertTrustedRuntimeExecutable(process.execPath, fs);
  const command = buildLockedApplyCommand({ argv });
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

async function installPolicySetAtomically(inspected, plan, deps) {
  const changed = inspected.artifacts.filter(({ changed }) => changed);
  if (changed.length === 0) return [];
  const staged = [];
  const committed = [];
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
      committed.push(entry.artifact);
      await syncDirectory(path.dirname(entry.artifact.target), deps.fsApi);
    }
    await verifyInstalledArtifacts(inspected, deps);
    await removeProvisionTransaction(plan, deps);
  } catch (error) {
    const rollbackErrors = [];
    for (const artifact of committed.reverse()) {
      try {
        if (artifact.existing) {
          const temporary = await writeCandidate(
            artifact.target,
            artifact.existing.contents,
            deps,
          );
          try {
            await deps.fsApi.rename(temporary, artifact.target);
          } catch (error) {
            await deps.fsApi.rm(temporary, { force: true }).catch(() => {});
            throw error;
          }
        } else {
          await deps.fsApi.rm(artifact.target, { force: true });
        }
        await syncDirectory(path.dirname(artifact.target), deps.fsApi);
      } catch (rollbackError) {
        rollbackErrors.push(`${artifact.target}: ${rollbackError.message}`);
      }
    }
    if (rollbackErrors.length > 0) {
      throw new Error(
        `${error.message}; policy rollback failed: ${rollbackErrors.join('; ')}`,
        { cause: error },
      );
    }
    await removeProvisionTransaction(plan, deps);
    throw error;
  } finally {
    await Promise.allSettled(staged
      .filter(({ temporary }) => temporary)
      .map(({ temporary }) => deps.fsApi.rm(temporary, { force: true })));
  }
  return changed.map(({ target }) => target);
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
    path.dirname(PROVISION_LOCK_PATH),
    0,
    0,
    fsApi,
  );
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
    await handle.chown(0, 0);
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = null;
    await syncDirectory(path.dirname(PROVISION_LOCK_PATH), fsApi);
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error?.code !== 'EEXIST') throw error;
  }

  const existing = await fsApi.open(
    PROVISION_LOCK_PATH,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  try {
    assertTrustedFileMetadata(PROVISION_LOCK_PATH, await existing.stat(), 0, 0, 0o600);
  } finally {
    await existing.close();
  }
}

async function assertTrustedRuntimeExecutable(executable, fsApi) {
  if (!path.isAbsolute(executable)) {
    throw new Error('Node runtime path is not absolute');
  }
  const stat = await fsApi.lstat(executable);
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1
    || stat.uid !== 0
    || stat.gid !== 0
    || ((stat.mode & 0o7777) & 0o022) !== 0
    || (stat.mode & 0o111) === 0
  ) {
    throw new Error(`Node runtime metadata is not trusted: ${executable}`);
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

async function recoverPolicyTransaction(transaction, plan, deps) {
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
    await assertTargetUnchanged(
      { target: artifact.target, existing: entry.current },
      deps.fsApi,
    );
    if (artifact.existing) {
      const temporary = await writeCandidate(
        artifact.target,
        artifact.existing.contents,
        deps,
      );
      try {
        await deps.fsApi.rename(temporary, artifact.target);
      } catch (error) {
        await deps.fsApi.rm(temporary, { force: true }).catch(() => {});
        throw error;
      }
    } else {
      await deps.fsApi.rm(artifact.target, { force: true });
    }
    await syncDirectory(path.dirname(artifact.target), deps.fsApi);
  }
  await removeProvisionTransaction(plan, deps);
}

async function removeProvisionTransaction(plan, deps) {
  await deps.fsApi.rm(plan.transactionFile, { force: true });
  await syncDirectory(path.dirname(plan.transactionFile), deps.fsApi);
}

function assertUnitsDormant(states, { requireLoaded }) {
  for (const unit of MANAGED_UNITS) {
    const state = states.get(unit);
    if (!state) throw new Error(`unit state is missing: ${unit}`);
    assertUnitDormant(unit, state, { requireLoaded });
  }
  for (const [unit, state] of states) {
    if (!LAUNCHER_INSTANCE_PATTERN.test(unit)) continue;
    assertUnitDormant(unit, state, { requireLoaded });
  }
}

function assertUnitDormant(unit, state, { requireLoaded }) {
  if (!['inactive', 'unknown'].includes(state.active)) {
    throw new Error(`managed unit is not inactive: ${unit} (${state.active})`);
  }
  if (!['disabled', 'indirect', 'not-found', 'static'].includes(state.enabled)) {
    throw new Error(`managed unit is enabled or masked: ${unit} (${state.enabled})`);
  }
  if (requireLoaded && state.load !== 'loaded') {
    throw new Error(`managed unit did not load after installation: ${unit} (${state.load})`);
  }
}

async function readSystemIdentitySnapshot(runCommand = runFixedCommand) {
  const [passwd, group] = await Promise.all([
    runCommand('/usr/bin/getent', ['passwd']),
    runCommand('/usr/bin/getent', ['group']),
  ]);
  const initial = parseIdentityDatabases(passwd.stdout, group.stdout);
  const effectiveGroups = {};
  for (const user of Object.values(MANAGED_USERS)) {
    if (!initial.users.has(user)) continue;
    const result = await runCommand('/usr/bin/id', ['-G', user]);
    effectiveGroups[user] = result.stdout.trim().split(/\s+/).filter(Boolean)
      .map((gid) => parseDatabaseId(gid, `effective GID for ${user}`));
  }
  return parseIdentityDatabases(passwd.stdout, group.stdout, effectiveGroups);
}

export async function readSystemUnitStates(units, runCommand = runFixedCommand) {
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
  const states = new Map();
  for (const unit of [...units, ...[...discovered].sort()]) {
    const [active, enabled, load] = await Promise.all([
      runCommand('/usr/bin/systemctl', ['is-active', unit], [0, 3, 4]),
      runCommand('/usr/bin/systemctl', ['is-enabled', unit], [0, 1, 3, 4]),
      runCommand(
        '/usr/bin/systemctl',
        ['show', '--property=LoadState', '--value', unit],
        [0, 1, 3, 4],
      ),
    ]);
    states.set(unit, Object.freeze({
      active: normalisedState(active.stdout, 'unknown'),
      enabled: normalisedState(enabled.stdout, 'not-found'),
      load: normalisedState(load.stdout, 'not-found'),
    }));
  }
  return states;
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
      ?? (() => readSystemIdentitySnapshot(runCommand)),
    readUnitStates: dependencies.readUnitStates
      ?? ((units) => readSystemUnitStates(units, runCommand)),
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

function normalisedState(value, fallback) {
  const state = String(value).trim();
  return state === '' ? fallback : state;
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
