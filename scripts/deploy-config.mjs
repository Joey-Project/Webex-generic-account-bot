#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const DEFAULTS = Object.freeze({
  configRepo: 'git@github.com:WebexServices-staging/webex-generic-account-bot-config.git',
  configRef: 'main',
  checkoutDir: '/var/lib/webex-generic-account-bot/config-checkout',
  renderedConfig: '/var/lib/webex-generic-account-bot/rendered/production.toml',
  botCodeDir: '/opt/webex-generic-account-bot/code',
  service: 'webex-generic-account-bot',
  lockDir: '/run/webex-generic-account-bot/deploy-config.lock',
  metadataFile: '/var/lib/webex-generic-account-bot/rendered/deploy-status.json',
  gitBin: '/usr/bin/git',
  bashBin: '/usr/bin/bash',
  nodeBin: '/usr/bin/node',
  pythonBin: '/usr/bin/python3',
  cargoBin: '/usr/bin/cargo',
  systemctlBin: '/usr/bin/systemctl',
  sshBin: '/usr/bin/ssh',
  sshKey: '/var/lib/webex-generic-account-bot/deploy/id_ed25519',
  sshKnownHosts: '/etc/ssh/ssh_known_hosts',
  commandTimeoutMs: 600_000,
  outputLimitBytes: 1_048_576,
});

const TRUSTED_CHILD_PATH = '/usr/bin:/bin';
const TRUSTED_CHILD_CWD = '/';
const HOST_OVERRIDE_ENV = 'WEBEX_BOT_DEPLOY_ALLOW_HOST_OVERRIDES';
const MAX_COMMAND_TIMEOUT_MS = 3_600_000;
const MAX_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024;
const PRLIMIT_BIN = '/usr/bin/prlimit';
const GIT_RESOURCE_LIMITS = Object.freeze([
  '--fsize=33554432',
  '--as=1073741824',
  '--cpu=600',
  '--nproc=128',
  '--nofile=256',
]);
const CONFIG_TREE_ROOT = 'production';
const MAX_CONFIG_TREE_FILES = 128;
const MAX_CONFIG_BLOB_BYTES = 1024 * 1024;
const MAX_CONFIG_TREE_BYTES = 8 * 1024 * 1024;
const MAX_CONFIG_PATH_BYTES = 512;
const SERVICE_READINESS_BIN = '/usr/bin/curl';
const SERVICE_READINESS_URL = 'http://127.0.0.1:8787/healthz';
const LOCK_OWNER_MAX_BYTES = 4096;
const INCOMPLETE_LOCK_GRACE_MS = 60_000;
const CHILD_TERMINATION_GRACE_MS = 5000;
const CHILD_CLOSE_GRACE_MS = 1000;
const DEPLOYMENT_STATUSES = new Set([
  'deployed',
  'installed_without_restart',
  'failed_apply',
  'failed_restart_rollback_failed',
  'failed_restart_rollback_restart_failed',
  'failed_restart_rolled_back',
  'failed_after_commit',
  'failed_after_commit_cleanup',
  'failed_cleanup',
]);
const HOST_OVERRIDE_KEYS = new Set([
  'configRepo',
  'configRef',
  'checkoutDir',
  'renderedConfig',
  'botCodeDir',
  'service',
  'lockDir',
  'metadataFile',
  'gitBin',
  'bashBin',
  'nodeBin',
  'pythonBin',
  'cargoBin',
  'systemctlBin',
  'sshBin',
  'sshKey',
  'sshKnownHosts',
  'commandTimeoutMs',
  'outputLimitBytes',
]);
const GIT_SAFE_CONFIG = [
  '-c',
  'advice.detachedHead=false',
  '-c',
  'core.hooksPath=/dev/null',
  '-c',
  'filter.lfs.required=false',
  '-c',
  'protocol.file.allow=never',
  '-c',
  'protocol.ext.allow=never',
  '-c',
  'submodule.recurse=false',
];
const GIT_NO_LAZY_FETCH_ENV = Object.freeze({ GIT_NO_LAZY_FETCH: '1' });

class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

export function parseArgs(argv, { allowHostOverrides = false } = {}) {
  const options = {
    ...DEFAULTS,
    apply: false,
    dryRun: false,
    skipRestart: false,
    status: false,
    json: false,
    help: false,
  };
  const overrides = new Set();

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--apply') {
      options.apply = true;
    } else if (arg === '--dry-run') {
      options.dryRun = true;
    } else if (arg === '--skip-restart' || arg === '--skip-reload') {
      options.skipRestart = true;
    } else if (arg === '--status') {
      options.status = true;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--config-repo') {
      options.configRepo = requiredValue(argv, (index += 1), arg);
      overrides.add('configRepo');
    } else if (arg === '--config-ref') {
      options.configRef = requiredValue(argv, (index += 1), arg);
      overrides.add('configRef');
    } else if (arg === '--checkout-dir') {
      options.checkoutDir = requiredValue(argv, (index += 1), arg);
      overrides.add('checkoutDir');
    } else if (arg === '--rendered-config') {
      options.renderedConfig = requiredValue(argv, (index += 1), arg);
      overrides.add('renderedConfig');
    } else if (arg === '--bot-code-dir') {
      options.botCodeDir = requiredValue(argv, (index += 1), arg);
      overrides.add('botCodeDir');
    } else if (arg === '--service') {
      options.service = requiredValue(argv, (index += 1), arg);
      overrides.add('service');
    } else if (arg === '--lock-dir') {
      options.lockDir = requiredValue(argv, (index += 1), arg);
      overrides.add('lockDir');
    } else if (arg === '--metadata-file') {
      options.metadataFile = requiredValue(argv, (index += 1), arg);
      overrides.add('metadataFile');
    } else if (arg === '--git-bin') {
      options.gitBin = requiredValue(argv, (index += 1), arg);
      overrides.add('gitBin');
    } else if (arg === '--bash-bin') {
      options.bashBin = requiredValue(argv, (index += 1), arg);
      overrides.add('bashBin');
    } else if (arg === '--node-bin') {
      options.nodeBin = requiredValue(argv, (index += 1), arg);
      overrides.add('nodeBin');
    } else if (arg === '--python-bin') {
      options.pythonBin = requiredValue(argv, (index += 1), arg);
      overrides.add('pythonBin');
    } else if (arg === '--cargo-bin') {
      options.cargoBin = requiredValue(argv, (index += 1), arg);
      overrides.add('cargoBin');
    } else if (arg === '--systemctl-bin') {
      options.systemctlBin = requiredValue(argv, (index += 1), arg);
      overrides.add('systemctlBin');
    } else if (arg === '--ssh-bin') {
      options.sshBin = requiredValue(argv, (index += 1), arg);
      overrides.add('sshBin');
    } else if (arg === '--ssh-key') {
      options.sshKey = requiredValue(argv, (index += 1), arg);
      overrides.add('sshKey');
    } else if (arg === '--ssh-known-hosts') {
      options.sshKnownHosts = requiredValue(argv, (index += 1), arg);
      overrides.add('sshKnownHosts');
    } else if (arg === '--command-timeout-ms') {
      options.commandTimeoutMs = parsePositiveInteger(
        requiredValue(argv, (index += 1), arg),
        arg,
        MAX_COMMAND_TIMEOUT_MS,
      );
      overrides.add('commandTimeoutMs');
    } else if (arg === '--output-limit-bytes') {
      options.outputLimitBytes = parsePositiveInteger(
        requiredValue(argv, (index += 1), arg),
        arg,
        MAX_OUTPUT_LIMIT_BYTES,
      );
      overrides.add('outputLimitBytes');
    } else {
      throw new UsageError(`Unknown argument: ${arg}`);
    }
  }

  if (options.apply && options.dryRun) {
    throw new UsageError('Use either --apply or --dry-run, not both.');
  }
  if (options.status && (options.apply || options.dryRun || options.skipRestart)) {
    throw new UsageError('--status cannot be combined with apply, dry-run, or restart options.');
  }
  validateHostOverrides(overrides, allowHostOverrides);
  options.hostOverrides = Object.freeze([...overrides]);
  validateOptions(options);
  return options;
}

export function usage() {
  return `Usage:
  node scripts/deploy-config.mjs --dry-run
  node scripts/deploy-config.mjs --apply [--skip-restart]
  node scripts/deploy-config.mjs --status [--json]

Options:
      --apply                     Execute the fixed deployment plan.
      --dry-run                   Print the fixed deployment plan without running it.
      --status                    Print the last deployment metadata file when present.
      --skip-restart              Install config but do not restart the service.
      --config-repo <url>         Expected config repo URL.
      --config-ref <name>         Expected config ref, default main.
      --checkout-dir <path>       Host-owned config checkout directory.
      --rendered-config <path>    Final rendered config path.
      --bot-code-dir <path>       Host-installed bot code directory.
      --service <name>            systemd service name.
      --lock-dir <path>           Single-flight lock directory.
      --metadata-file <path>      Deployment metadata JSON path.
      --git-bin <path>            Fixed Git executable path.
      --bash-bin <path>           Fixed Bash executable path.
      --node-bin <path>           Fixed Node.js executable path for trusted render policy.
      --python-bin <path>         Fixed Python executable path for trusted install policy.
      --cargo-bin <path>          Fixed Cargo executable path for bot --check-config.
      --systemctl-bin <path>      Fixed systemctl executable path.
      --ssh-bin <path>            Fixed SSH executable path for GitHub fetch.
      --ssh-key <path>            Host-owned deploy key for GitHub fetch.
      --ssh-known-hosts <path>    Fixed known_hosts file for GitHub fetch.
      --command-timeout-ms <n>    Per-child command timeout, default 600000.
      --output-limit-bytes <n>    Per-stream stdout/stderr capture cap, default 1048576.
      --json                      Emit machine-readable status output.
  -h, --help                      Show this help.
`;
}

export function buildDeployPlan(options) {
  const checkoutDir = path.resolve(options.checkoutDir);
  const checkoutWorkDir = path.join(checkoutDir, 'work');
  const renderedConfig = path.resolve(options.renderedConfig);
  const candidateConfig = `${renderedConfig}.candidate`;
  const backupConfig = `${renderedConfig}.previous`;
  const botCodeDir = path.resolve(options.botCodeDir);
  const metadataFile = path.resolve(options.metadataFile);
  const trustedValidateScript = path.join(botCodeDir, 'scripts/config-policy/validate-config.sh');
  const gitEnv = gitEnvForRepo(options);
  const noLazyGitEnv = { ...gitEnv, ...GIT_NO_LAZY_FETCH_ENV };
  const commandDefaults = {
    cwd: TRUSTED_CHILD_CWD,
    timeoutMs: options.commandTimeoutMs,
    outputLimitBytes: options.outputLimitBytes,
  };

  const commands = [
    gitCommand(options.gitBin, null, ['init', checkoutWorkDir], { ...commandDefaults, env: gitEnv }),
    gitCommand(options.gitBin, checkoutWorkDir, ['remote', 'remove', 'origin'], {
      ...commandDefaults,
      optional: true,
      env: gitEnv,
    }),
    gitCommand(options.gitBin, checkoutWorkDir, ['remote', 'add', 'origin', options.configRepo], {
      ...commandDefaults,
      env: gitEnv,
    }),
    gitCommand(options.gitBin, checkoutWorkDir, [
      'fetch',
      '--depth=1',
      '--filter=blob:none',
      '--recurse-submodules=no',
      'origin',
      options.configRef,
    ], { ...commandDefaults, env: gitEnv }),
    gitCommand(options.gitBin, checkoutWorkDir, [
      'ls-tree',
      '-r',
      '-z',
      '--name-only',
      '--full-tree',
      'FETCH_HEAD',
      '--',
      CONFIG_TREE_ROOT,
    ], { ...commandDefaults, env: noLazyGitEnv, validation: 'config-tree-paths' }),
    gitCommand(options.gitBin, checkoutWorkDir, ['sparse-checkout', 'init', '--no-cone'], {
      ...commandDefaults,
      env: gitEnv,
    }),
    gitCommand(options.gitBin, checkoutWorkDir, [
      'sparse-checkout',
      'set',
      '--no-cone',
      `/${CONFIG_TREE_ROOT}/`,
    ], { ...commandDefaults, env: gitEnv }),
    gitCommand(options.gitBin, checkoutWorkDir, [
      'checkout',
      '--detach',
      '--force',
      'FETCH_HEAD',
    ], {
      ...commandDefaults,
      env: gitEnv,
    }),
    gitCommand(options.gitBin, checkoutWorkDir, [
      'ls-tree',
      '-r',
      '-l',
      '-z',
      '--full-tree',
      'FETCH_HEAD',
      '--',
      CONFIG_TREE_ROOT,
    ], { ...commandDefaults, env: noLazyGitEnv, validation: 'config-tree-manifest' }),
    gitCommand(options.gitBin, checkoutWorkDir, ['rev-parse', 'HEAD'], {
      ...commandDefaults,
      capture: 'configRevision',
      env: gitEnv,
    }),
    command(options.bashBin, [
      trustedValidateScript,
      '--source-root',
      checkoutWorkDir,
      '--env',
      'production',
      '--out',
      candidateConfig,
    ], {
      env: {
        WEBEX_BOT_CODE_DIR: botCodeDir,
        NODE_BIN: path.resolve(options.nodeBin),
        PYTHON_BIN: path.resolve(options.pythonBin),
        CARGO_BIN: path.resolve(options.cargoBin),
      },
      ...commandDefaults,
    }),
  ];

  const serviceCommand = options.skipRestart
    ? null
    : command(options.systemctlBin, ['restart', '--', options.service], commandDefaults);
  const serviceVerificationCommands = options.skipRestart
    ? []
    : [
        command(
          options.systemctlBin,
          ['is-active', '--quiet', '--', options.service],
          commandDefaults,
        ),
        command(SERVICE_READINESS_BIN, [
          '--silent',
          '--show-error',
          '--output',
          '/dev/null',
          '--write-out',
          '%{http_code}',
          '--connect-timeout',
          '2',
          '--max-time',
          '5',
          '--retry',
          '10',
          '--retry-delay',
          '1',
          '--retry-max-time',
          '30',
          '--retry-connrefused',
          '--retry-all-errors',
          SERVICE_READINESS_URL,
        ], { ...commandDefaults, validation: 'service-readiness' }),
      ];

  const plan = {
    checkoutDir,
    checkoutWorkDir,
    renderedConfig,
    candidateConfig,
    backupConfig,
    botCodeDir,
    metadataFile,
    configRepo: options.configRepo,
    configRef: options.configRef,
    service: options.service,
    lockDir: path.resolve(options.lockDir),
    commands,
    serviceCommand,
    serviceVerificationCommands,
    skipRestart: options.skipRestart,
    serviceAction: options.skipRestart ? null : 'restart',
    sshKey: path.resolve(options.sshKey),
    sshKnownHosts: path.resolve(options.sshKnownHosts),
    commandTimeoutMs: options.commandTimeoutMs,
    outputLimitBytes: options.outputLimitBytes,
  };
  assertSafePlanPathTopology(plan);
  return plan;
}

export function scrubEnv(parentEnv = process.env, extra = {}) {
  return {
    PATH: TRUSTED_CHILD_PATH,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    GIT_LFS_SKIP_SMUDGE: '1',
    ...extra,
  };
}

export async function runCli({
  argv = process.argv.slice(2),
  stdout = process.stdout,
  stderr = process.stderr,
  parentEnv = process.env,
  runner = runCommand,
  fsApi = fs,
} = {}) {
  try {
    const options = parseArgs(argv, { allowHostOverrides: hostOverridesAllowed(parentEnv) });
    if (options.help) {
      stdout.write(usage());
      return 0;
    }
    if (options.status) {
      return await printStatus({ options, stdout, stderr, fsApi });
    }

    const plan = buildDeployPlan(options);
    if (!options.apply || options.dryRun) {
      writePlan(stdout, plan, options.json);
      return 0;
    }

    const result = await executePlan({ plan, parentEnv, runner, fsApi });
    writeStatus(stdout, result, options.json);
    return 0;
  } catch (error) {
    const status = error instanceof UsageError ? 2 : 1;
    stderr.write(`${redact(String(error.message))}\n`);
    if (error instanceof UsageError) {
      stderr.write('\n');
      stderr.write(usage());
    }
    return status;
  }
}

export async function executePlan({ plan, parentEnv = process.env, runner = runCommand, fsApi = fs }) {
  await assertPlanHasNoSymlinkAncestors(plan, fsApi);
  const lockOwner = await acquireLock(plan.lockDir, fsApi);
  const captures = {};
  let installState = null;
  let primaryError = null;
  let backupCleanupError = null;
  let commitReached = false;
  let failureMetadataWritten = false;
  let failureMetadataError = null;
  let recordedFailureStatus = null;
  let outputDirectoriesTrusted = false;
  const recordFailure = async (status, reason) => {
    try {
      await writeFailureMetadata(plan, captures.configRevision || null, status, reason, fsApi);
      failureMetadataWritten = true;
      recordedFailureStatus = status;
    } catch (error) {
      failureMetadataError = error;
      throw new Error(`${reason}; failed to write deployment failure metadata: ${error.message}`);
    }
  };
  try {
    await prepareTrustedOutputDirectories(plan, fsApi);
    outputDirectoriesTrusted = true;
    await prepareFreshCheckout(plan, fsApi);
    for (const commandSpec of plan.commands) {
      const env = scrubEnv(parentEnv, commandSpec.env);
      const result = await runner(commandSpec, env);
      if (commandSpec.capture) {
        captures[commandSpec.capture] = result.stdout.trim();
      }
    }
    assertConfigRevision(captures.configRevision);
    installState = await installCandidateConfig(plan, fsApi);
    if (plan.serviceCommand) {
      try {
        await runServiceTransition(plan, runner, parentEnv);
      } catch (error) {
        let rollbackError = null;
        try {
          await rollbackCandidateConfig(plan, installState, fsApi);
          installState = null;
        } catch (restoreError) {
          rollbackError = restoreError;
          installState = null;
        }
        if (rollbackError) {
          await recordFailure(
            'failed_restart_rollback_failed',
            `${error.message}; failed to restore previous config: ${rollbackError.message}`,
          );
          throw new Error(`${error.message}; failed to restore previous config: ${rollbackError.message}`);
        }
        try {
          await runServiceTransition(plan, runner, parentEnv);
        } catch (restoreError) {
          await recordFailure(
            'failed_restart_rollback_restart_failed',
            `${error.message}; restored previous config but service restart also failed: ${restoreError.message}`,
          );
          throw new Error(
            `${error.message}; restored previous config but service restart also failed: ${restoreError.message}`,
          );
        }
        await recordFailure('failed_restart_rolled_back', error.message);
        throw error;
      }
    }
    commitReached = true;
    installState = null;
    try {
      await removeIfPresent(plan.backupConfig, fsApi);
    } catch (error) {
      backupCleanupError = error;
    }
    const metadata = {
      status: plan.skipRestart ? 'installed_without_restart' : 'deployed',
      config_repo: plan.configRepo,
      config_ref: plan.configRef,
      config_revision: captures.configRevision || null,
      bot_code_dir: plan.botCodeDir,
      rendered_config: plan.renderedConfig,
      service: plan.service,
      service_action: plan.serviceAction,
      service_restart_skipped: plan.skipRestart,
      deployed_at: new Date().toISOString(),
    };
    if (backupCleanupError) {
      metadata.backup_cleanup_error = redact(backupCleanupError.message);
    }
    await writeMetadataAtomically(plan.metadataFile, metadata, fsApi);
    return metadata;
  } catch (error) {
    primaryError = error;
    if (outputDirectoriesTrusted && !failureMetadataWritten && !failureMetadataError) {
      await recordFailure(commitReached ? 'failed_after_commit' : 'failed_apply', error.message);
    }
    throw error;
  } finally {
    let cleanupError = null;
    let rollbackCleanupFailed = false;
    let candidateCleanupFailed = false;
    let lockCleanupFailed = false;
    if (installState) {
      try {
        await rollbackCandidateConfig(plan, installState, fsApi);
      } catch (error) {
        cleanupError = error;
        rollbackCleanupFailed = true;
      }
    }
    if (outputDirectoriesTrusted) {
      try {
        await removeIfPresent(plan.candidateConfig, fsApi);
      } catch (error) {
        cleanupError ??= error;
        candidateCleanupFailed = true;
      }
    }
    try {
      await releaseLock(plan.lockDir, lockOwner, fsApi);
    } catch (error) {
      cleanupError ??= error;
      lockCleanupFailed = true;
    }
    if (cleanupError) {
      let combinedReason = primaryError
        ? `${primaryError.message}; deployment cleanup failed: ${cleanupError.message}`
        : `deployment cleanup failed: ${cleanupError.message}`;
      if (outputDirectoriesTrusted) {
        try {
          await writeFailureMetadata(
            plan,
            captures.configRevision || null,
            recordedFailureStatus
              ?? (commitReached ? 'failed_after_commit_cleanup' : 'failed_cleanup'),
            combinedReason,
            fsApi,
            {
              cleanup_failed: true,
              rollback_cleanup_failed: rollbackCleanupFailed,
              candidate_cleanup_failed: candidateCleanupFailed,
              lock_cleanup_failed: lockCleanupFailed,
            },
          );
        } catch (metadataError) {
          combinedReason = `${combinedReason}; failed to record cleanup state: ${metadataError.message}`;
        }
      }
      throw new Error(combinedReason);
    }
  }
}

async function runServiceTransition(plan, runner, parentEnv) {
  await runner(plan.serviceCommand, scrubEnv(parentEnv, plan.serviceCommand.env));
  for (const verificationCommand of plan.serviceVerificationCommands) {
    await runner(
      verificationCommand,
      scrubEnv(parentEnv, verificationCommand.env),
    );
  }
}

async function printStatus({ options, stdout, stderr, fsApi }) {
  try {
    const contents = await fsApi.readFile(path.resolve(options.metadataFile), 'utf8');
    const parsed = validateDeploymentMetadata(JSON.parse(contents));
    if (options.json) {
      stdout.write(`${JSON.stringify(parsed, null, 2)}\n`);
    } else {
      stdout.write(
        `status=${parsed.status}\nconfig_revision=${parsed.config_revision || ''}\n` +
          `rendered_config=${parsed.rendered_config || ''}\nservice=${parsed.service || ''}\n`,
      );
    }
    return 0;
  } catch (error) {
    stderr.write(`status=unknown reason=${redact(error.code || error.message)}\n`);
    return 1;
  }
}

function validateDeploymentMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw new Error('deployment metadata must be a JSON object');
  }
  if (!DEPLOYMENT_STATUSES.has(metadata.status)) {
    throw new Error('deployment metadata contains an invalid status');
  }
  for (const key of [
    'config_repo',
    'config_ref',
    'bot_code_dir',
    'rendered_config',
    'service',
    'deployed_at',
  ]) {
    if (typeof metadata[key] !== 'string' || metadata[key].length === 0) {
      throw new Error(`deployment metadata contains an invalid ${key}`);
    }
  }
  if (typeof metadata.service_restart_skipped !== 'boolean') {
    throw new Error('deployment metadata contains an invalid service_restart_skipped');
  }
  if (
    (metadata.service_restart_skipped && metadata.service_action !== null)
    || (!metadata.service_restart_skipped && metadata.service_action !== 'restart')
  ) {
    throw new Error('deployment metadata contains an invalid service_action');
  }
  if (
    metadata.config_revision !== null
    && !/^[0-9a-f]{40,64}$/.test(metadata.config_revision ?? '')
  ) {
    throw new Error('deployment metadata contains an invalid config_revision');
  }
  if (metadata.status.startsWith('failed_') && typeof metadata.reason !== 'string') {
    throw new Error('failed deployment metadata must contain a reason');
  }
  return metadata;
}

async function acquireLock(lockDir, fsApi) {
  const lockParent = path.dirname(lockDir);
  await fsApi.mkdir(lockParent, { recursive: true, mode: 0o700 });
  const lockParentStat = await fsApi.lstat(lockParent);
  assertTrustedDeploymentDirectory(lockParent, lockParentStat, 'lock parent');
  const processStartTicks = await readProcessStartTicks(process.pid, fsApi);

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const owner = {
      version: 1,
      token: randomUUID(),
      pid: process.pid,
      process_start_ticks: processStartTicks,
      acquired_at: new Date().toISOString(),
    };
    let handle;
    try {
      handle = await fsApi.open(lockDir, 'wx', 0o600);
    } catch (error) {
      if (!error || error.code !== 'EEXIST') {
        throw error;
      }
      const reclaimed = await reclaimStaleLock(lockDir, fsApi);
      if (reclaimed) {
        continue;
      }
      throw new Error(`deployment already in progress: ${lockDir}`);
    }

    let identity;
    try {
      identity = await handle.stat();
      await handle.chmod(0o600);
      await handle.writeFile(`${JSON.stringify(owner)}\n`, 'utf8');
      await handle.sync();
    } catch (error) {
      await handle.close().catch(() => {});
      throw error;
    }
    await handle.close();
    await syncDirectory(lockParent, fsApi);

    let currentIdentity;
    try {
      currentIdentity = await fsApi.lstat(lockDir);
    } catch (error) {
      if (error && error.code === 'ENOENT') {
        continue;
      }
      throw error;
    }
    if (!sameFileIdentity(identity, currentIdentity)) {
      continue;
    }
    const persistedOwner = await readLockOwner(lockDir, fsApi, currentIdentity);
    if (persistedOwner?.token !== owner.token) {
      throw new Error(`deployment lock owner could not be verified: ${lockDir}`);
    }
    return owner;
  }
  throw new Error(`failed to acquire deployment lock after stale-lock recovery: ${lockDir}`);
}

async function reclaimStaleLock(lockDir, fsApi) {
  let lockStat;
  try {
    lockStat = await fsApi.lstat(lockDir);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return true;
    }
    throw error;
  }
  assertTrustedDeploymentLock(lockDir, lockStat);
  const owner = await readLockOwner(lockDir, fsApi, lockStat);
  if (owner && await lockOwnerIsActive(owner, fsApi)) {
    return false;
  }
  if (!owner && Date.now() - lockStat.mtimeMs < INCOMPLETE_LOCK_GRACE_MS) {
    return false;
  }

  const staleFile = `${lockDir}.stale-${randomUUID()}`;
  try {
    await fsApi.rename(lockDir, staleFile);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return true;
    }
    throw error;
  }
  await fsApi.rm(staleFile, { force: true });
  return true;
}

async function releaseLock(lockDir, expectedOwner, fsApi) {
  const owner = await readLockOwner(lockDir, fsApi);
  if (!owner || owner.token !== expectedOwner.token) {
    throw new Error(`deployment lock ownership changed before cleanup: ${lockDir}`);
  }
  await fsApi.rm(lockDir, { force: true });
}

async function readLockOwner(lockDir, fsApi, knownMetadata = null) {
  let metadata = knownMetadata;
  try {
    metadata ??= await fsApi.lstat(lockDir);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
  assertTrustedDeploymentLock(lockDir, metadata);
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.size > LOCK_OWNER_MAX_BYTES
  ) {
    return null;
  }
  try {
    const owner = JSON.parse(await fsApi.readFile(lockDir, 'utf8'));
    if (
      owner?.version !== 1
      || typeof owner.token !== 'string'
      || owner.token.length < 16
      || !Number.isSafeInteger(owner.pid)
      || owner.pid <= 0
      || !/^[0-9]+$/.test(owner.process_start_ticks ?? '')
      || typeof owner.acquired_at !== 'string'
    ) {
      return null;
    }
    return owner;
  } catch (_) {
    return null;
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function lockOwnerIsActive(owner, fsApi) {
  try {
    return await readProcessStartTicks(owner.pid, fsApi) === owner.process_start_ticks;
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

async function readProcessStartTicks(pid, fsApi) {
  const stat = await fsApi.readFile(`/proc/${pid}/stat`, 'utf8');
  const commandEnd = stat.lastIndexOf(')');
  if (commandEnd < 0) {
    throw new Error(`invalid /proc/${pid}/stat format`);
  }
  const fieldsAfterCommand = stat.slice(commandEnd + 1).trim().split(/\s+/);
  const startTicks = fieldsAfterCommand[19];
  if (!/^[0-9]+$/.test(startTicks ?? '')) {
    throw new Error(`invalid /proc/${pid}/stat start time`);
  }
  return startTicks;
}

function command(bin, args, options = {}) {
  return {
    bin,
    args,
    cwd: options.cwd || TRUSTED_CHILD_CWD,
    optional: Boolean(options.optional),
    capture: options.capture,
    validation: options.validation,
    env: options.env || {},
    timeoutMs: options.timeoutMs,
    outputLimitBytes: options.outputLimitBytes,
    resourceLimits: options.resourceLimits || null,
    terminationGraceMs: options.terminationGraceMs,
    closeGraceMs: options.closeGraceMs,
  };
}

function gitCommand(bin, cwd, args, options = {}) {
  const gitArgs = cwd ? ['-C', cwd, ...GIT_SAFE_CONFIG, ...args] : [...GIT_SAFE_CONFIG, ...args];
  return command(bin, gitArgs, {
    ...options,
    resourceLimits: GIT_RESOURCE_LIMITS,
  });
}

function gitEnvForRepo(options) {
  if (!options.configRepo.startsWith('git@github.com:')) {
    return {};
  }
  return {
    GIT_SSH_COMMAND: [
      shellQuoteForCommand(path.resolve(options.sshBin)),
      '-F',
      '/dev/null',
      '-i',
      shellQuoteForCommand(path.resolve(options.sshKey)),
      '-o',
      'BatchMode=yes',
      '-o',
      'IdentitiesOnly=yes',
      '-o',
      'StrictHostKeyChecking=yes',
      '-o',
      `UserKnownHostsFile=${shellQuoteForCommand(path.resolve(options.sshKnownHosts))}`,
    ].join(' '),
    GIT_SSH_VARIANT: 'ssh',
  };
}

export async function runCommand(commandSpec, env) {
  return await new Promise((resolve, reject) => {
    const detached = process.platform !== 'win32';
    const invocation = commandInvocation(commandSpec);
    const child = spawn(invocation.bin, invocation.args, {
      cwd: commandSpec.cwd || TRUSTED_CHILD_CWD,
      env,
      detached,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const stdoutCapture = outputCapture(commandSpec.outputLimitBytes);
    const stderrCapture = outputCapture(commandSpec.outputLimitBytes);
    let timedOut = false;
    let killTimer = null;
    let closeTimer = null;
    let settled = false;
    const clearTimers = () => {
      clearTimeout(timeoutTimer);
      if (killTimer) {
        clearTimeout(killTimer);
      }
      if (closeTimer) {
        clearTimeout(closeTimer);
      }
    };
    const rejectOnce = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimers();
      reject(error);
    };
    const resolveOnce = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimers();
      resolve(result);
    };
    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      killChildProcess(child, detached, 'SIGTERM');
      killTimer = setTimeout(() => {
        killChildProcess(child, detached, 'SIGKILL');
        closeTimer = setTimeout(() => {
          child.stdout.destroy();
          child.stderr.destroy();
          child.unref();
          rejectOnce(new Error(
            `${commandSpec.bin} timed out after ` +
              `${commandSpec.timeoutMs || DEFAULTS.commandTimeoutMs}ms and did not close after SIGKILL`,
          ));
        }, commandSpec.closeGraceMs ?? CHILD_CLOSE_GRACE_MS);
        closeTimer.unref?.();
      }, commandSpec.terminationGraceMs ?? CHILD_TERMINATION_GRACE_MS);
      killTimer.unref?.();
    }, commandSpec.timeoutMs || DEFAULTS.commandTimeoutMs);
    timeoutTimer.unref?.();
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout = stdoutCapture.append(stdout, chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr = stderrCapture.append(stderr, chunk);
    });
    child.on('error', (error) => {
      rejectOnce(error);
    });
    child.on('close', (code) => {
      if (timedOut) {
        rejectOnce(new Error(`${commandSpec.bin} timed out after ${commandSpec.timeoutMs || DEFAULTS.commandTimeoutMs}ms`));
        return;
      }
      if (code === 0 || commandSpec.optional) {
        const result = {
          stdout,
          stderr,
          code,
          stdoutTruncated: stdoutCapture.truncated,
          stderrTruncated: stderrCapture.truncated,
        };
        try {
          validateCommandResult(commandSpec, result);
        } catch (error) {
          rejectOnce(error);
          return;
        }
        resolveOnce(result);
        return;
      }
      const suffix = stderrCapture.truncated ? ' [stderr truncated]' : '';
      rejectOnce(new Error(`${commandSpec.bin} failed with code ${code}: ${truncate(redact(stderr), 2000)}${suffix}`));
    });
  });
}

function commandInvocation(commandSpec) {
  if (!commandSpec.resourceLimits) {
    return { bin: commandSpec.bin, args: commandSpec.args };
  }
  return {
    bin: PRLIMIT_BIN,
    args: [...commandSpec.resourceLimits, '--', commandSpec.bin, ...commandSpec.args],
  };
}

function validateCommandResult(commandSpec, result) {
  if (!commandSpec.validation) {
    return;
  }
  if (result.stdoutTruncated) {
    throw new Error(`${commandSpec.validation} output exceeded the trusted capture limit`);
  }
  if (commandSpec.validation === 'config-tree-paths') {
    validateConfigTreePaths(result.stdout);
    return;
  }
  if (commandSpec.validation === 'config-tree-manifest') {
    validateConfigTreeManifest(result.stdout);
    return;
  }
  if (commandSpec.validation === 'service-readiness') {
    const status = result.stdout.trim();
    if (status !== '200' && status !== '401') {
      throw new Error(`service readiness endpoint returned HTTP ${status || 'none'}`);
    }
    return;
  }
  throw new Error(`unknown command output validation: ${commandSpec.validation}`);
}

export function validateConfigTreePaths(output) {
  const paths = parseNulRecords(output, 'config tree path list');
  validateConfigPaths(paths);
  return paths;
}

export function validateConfigTreeManifest(output) {
  const records = parseNulRecords(output, 'config tree manifest');
  const paths = [];
  let totalBytes = 0;
  for (const record of records) {
    const match = /^(\d{6}) (\S+) ([0-9a-f]{40,64})\s+(\d+|BAD|-)\t(.+)$/.exec(record);
    if (!match) {
      throw new Error('config tree manifest contains an invalid entry');
    }
    const [, mode, objectType, , sizeText, file] = match;
    if (sizeText === 'BAD' || sizeText === '-') {
      throw new Error(`config tree blob is missing after bounded fetch: ${file}`);
    }
    if (mode !== '100644' || objectType !== 'blob') {
      throw new Error(`config tree entry must be a non-executable regular file: ${file}`);
    }
    const size = Number(sizeText);
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_CONFIG_BLOB_BYTES) {
      throw new Error(`config tree blob exceeds max bytes ${MAX_CONFIG_BLOB_BYTES}: ${file}`);
    }
    totalBytes += size;
    if (totalBytes > MAX_CONFIG_TREE_BYTES) {
      throw new Error(`config tree exceeds max total bytes ${MAX_CONFIG_TREE_BYTES}`);
    }
    paths.push(file);
  }
  validateConfigPaths(paths);
  return { files: paths.length, totalBytes };
}

function parseNulRecords(output, label) {
  if (!output.endsWith('\0')) {
    throw new Error(`${label} must be NUL terminated`);
  }
  return output.slice(0, -1).split('\0');
}

function validateConfigPaths(paths) {
  if (paths.length === 0) {
    throw new Error('config tree must contain production config files');
  }
  if (paths.length > MAX_CONFIG_TREE_FILES) {
    throw new Error(`config tree exceeds max files ${MAX_CONFIG_TREE_FILES}`);
  }
  const seen = new Set();
  for (const file of paths) {
    if (Buffer.byteLength(file, 'utf8') > MAX_CONFIG_PATH_BYTES) {
      throw new Error(`config tree path exceeds max bytes ${MAX_CONFIG_PATH_BYTES}`);
    }
    if (
      file !== `${CONFIG_TREE_ROOT}/bot.toml`
      && !new RegExp(`^${CONFIG_TREE_ROOT}/spaces/[A-Za-z0-9._-]+\\.toml$`).test(file)
    ) {
      throw new Error(`config tree contains an unexpected path: ${file}`);
    }
    if (seen.has(file)) {
      throw new Error(`config tree contains duplicate path: ${file}`);
    }
    seen.add(file);
  }
  if (!seen.has(`${CONFIG_TREE_ROOT}/bot.toml`)) {
    throw new Error(`config tree is missing ${CONFIG_TREE_ROOT}/bot.toml`);
  }
  if (![...seen].some((file) => file.startsWith(`${CONFIG_TREE_ROOT}/spaces/`))) {
    throw new Error(`config tree must contain at least one ${CONFIG_TREE_ROOT}/spaces/*.toml file`);
  }
}

function outputCapture(limit = DEFAULTS.outputLimitBytes) {
  let bytes = 0;
  let truncated = false;
  return {
    get truncated() {
      return truncated;
    },
    append(current, chunk) {
      const buffer = Buffer.from(chunk, 'utf8');
      const nextBytes = bytes + buffer.length;
      if (bytes >= limit) {
        truncated = true;
        bytes = nextBytes;
        return current;
      }
      const remaining = limit - bytes;
      bytes = nextBytes;
      if (buffer.length <= remaining) {
        return current + chunk;
      }
      truncated = true;
      return current + buffer.subarray(0, remaining).toString('utf8');
    },
  };
}

function killChildProcess(child, detached, signal) {
  try {
    if (detached && child.pid) {
      process.kill(-child.pid, signal);
      return;
    }
  } catch (error) {
    return;
  }
  try {
    child.kill(signal);
  } catch (_) {}
}

function writePlan(stdout, plan, json) {
  if (json) {
    stdout.write(`${JSON.stringify({ mode: 'dry-run', plan: serialisablePlan(plan) }, null, 2)}\n`);
    return;
  }
  stdout.write('mode=dry-run\n');
  stdout.write(`config_repo=${plan.configRepo}\n`);
  stdout.write(`config_ref=${plan.configRef}\n`);
  stdout.write(`checkout_dir=${plan.checkoutDir}\n`);
  stdout.write(`checkout_work_dir=${plan.checkoutWorkDir}\n`);
  stdout.write(`rendered_config=${plan.renderedConfig}\n`);
  stdout.write(`candidate_config=${plan.candidateConfig}\n`);
  for (const [index, commandSpec] of allPlanCommands(plan).entries()) {
    const invocation = commandInvocation(commandSpec);
    stdout.write(`command_${index + 1}=${invocation.bin} ${invocation.args.map(shellQuoteForDisplay).join(' ')}\n`);
  }
}

function writeStatus(stdout, metadata, json) {
  if (json) {
    stdout.write(`${JSON.stringify(metadata, null, 2)}\n`);
    return;
  }
  stdout.write(`status=${metadata.status}\n`);
  stdout.write(`config_revision=${metadata.config_revision || ''}\n`);
  stdout.write(`rendered_config=${metadata.rendered_config}\n`);
  stdout.write(`service=${metadata.service}\n`);
}

function serialisablePlan(plan) {
  return {
    config_repo: plan.configRepo,
    config_ref: plan.configRef,
    checkout_dir: plan.checkoutDir,
    checkout_work_dir: plan.checkoutWorkDir,
    rendered_config: plan.renderedConfig,
    candidate_config: plan.candidateConfig,
    bot_code_dir: plan.botCodeDir,
    service: plan.service,
    lock_dir: plan.lockDir,
    service_action: plan.serviceAction,
    ssh_key: plan.sshKey,
    ssh_known_hosts: plan.sshKnownHosts,
    command_timeout_ms: plan.commandTimeoutMs,
    output_limit_bytes: plan.outputLimitBytes,
    commands: allPlanCommands(plan),
  };
}

function validateOptions(options) {
  validateRef(options.configRef);
  validateRepo(options.configRepo);
  validateService(options.service);
  for (const key of [
    'checkoutDir',
    'renderedConfig',
    'botCodeDir',
    'lockDir',
    'metadataFile',
    'gitBin',
    'bashBin',
    'nodeBin',
    'pythonBin',
    'cargoBin',
    'systemctlBin',
    'sshBin',
    'sshKey',
    'sshKnownHosts',
  ]) {
    if (!path.isAbsolute(options[key])) {
      throw new UsageError(`${kebab(key)} must be an absolute path`);
    }
  }
}

function validateRef(value) {
  if (!/^[A-Za-z0-9._/-]+$/.test(value) || value.includes('..') || value.startsWith('/') || value.startsWith('-')) {
    throw new UsageError(`config-ref must be a simple ref name: ${value}`);
  }
}

async function writeFailureMetadata(
  plan,
  configRevision,
  status,
  reason,
  fsApi,
  details = {},
) {
  const metadata = {
    status,
    reason: redact(reason),
    config_repo: plan.configRepo,
    config_ref: plan.configRef,
    config_revision: configRevision,
    bot_code_dir: plan.botCodeDir,
    rendered_config: plan.renderedConfig,
    service: plan.service,
    service_action: plan.serviceAction,
    service_restart_skipped: plan.skipRestart,
    deployed_at: new Date().toISOString(),
    ...details,
  };
  await writeMetadataAtomically(plan.metadataFile, metadata, fsApi);
}

async function writeMetadataAtomically(file, metadata, fsApi) {
  const directory = path.dirname(file);
  const temporary = path.join(
    directory,
    `.${path.basename(file)}.${process.pid}.${randomUUID()}.tmp`,
  );
  await fsApi.mkdir(directory, { recursive: true, mode: 0o755 });
  let handle = null;
  try {
    handle = await fsApi.open(temporary, 'wx', 0o644);
    await handle.writeFile(`${JSON.stringify(metadata, null, 2)}\n`, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await fsApi.rename(temporary, file);
    const directoryHandle = await fsApi.open(directory, 'r');
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } finally {
    if (handle) {
      await handle.close().catch(() => {});
    }
    await fsApi.rm(temporary, { force: true }).catch(() => {});
  }
}

function validateRepo(value) {
  if (!/^(git@github\.com:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git|https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git)$/.test(value)) {
    throw new UsageError('config-repo must be a github.com SSH or HTTPS repository URL');
  }
}

function validateService(value) {
  if (!/^[A-Za-z0-9_.@-]+$/.test(value) || value.startsWith('-')) {
    throw new UsageError(`service must be a systemd unit name without path separators: ${value}`);
  }
}

function parsePositiveInteger(value, flag, max) {
  if (!/^[0-9]+$/.test(value)) {
    throw new UsageError(`${flag} must be a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new UsageError(`${flag} must be a positive integer`);
  }
  if (parsed > max) {
    throw new UsageError(`${flag} must be at most ${max}`);
  }
  return parsed;
}

function validateHostOverrides(overrides, allowHostOverrides) {
  const unexpected = [...overrides].filter((override) => !HOST_OVERRIDE_KEYS.has(override));
  if (unexpected.length > 0) {
    throw new UsageError(`unknown host override key: ${unexpected.join(', ')}`);
  }
  if (overrides.size > 0 && !allowHostOverrides) {
    throw new UsageError(
      `host policy overrides require ${HOST_OVERRIDE_ENV}=1 in the deployment host environment`,
    );
  }
}

function hostOverridesAllowed(parentEnv) {
  return parentEnv?.[HOST_OVERRIDE_ENV] === '1';
}

async function prepareFreshCheckout(plan, fsApi) {
  assertManagedSubpath(plan.checkoutWorkDir, plan.checkoutDir, 'checkout work directory');
  await fsApi.mkdir(plan.checkoutDir, { recursive: true, mode: 0o700 });
  const checkoutStat = await fsApi.lstat(plan.checkoutDir);
  assertTrustedDeploymentDirectory(plan.checkoutDir, checkoutStat, 'checkout-dir');
  await fsApi.rm(plan.checkoutWorkDir, { recursive: true, force: true });
  await fsApi.mkdir(plan.checkoutWorkDir, { recursive: true, mode: 0o700 });
  await removeIfPresent(plan.candidateConfig, fsApi);
  await removeIfPresent(plan.backupConfig, fsApi);
}

async function assertPlanHasNoSymlinkAncestors(plan, fsApi) {
  const paths = [
    ['checkout directory', plan.checkoutDir],
    ['lock parent directory', path.dirname(plan.lockDir)],
    ['rendered config directory', path.dirname(plan.renderedConfig)],
    ['metadata directory', path.dirname(plan.metadataFile)],
    ['bot code directory', plan.botCodeDir],
    ['SSH key directory', path.dirname(plan.sshKey)],
    ['SSH known-hosts directory', path.dirname(plan.sshKnownHosts)],
  ];
  const seen = new Set();
  for (const [label, candidate] of paths) {
    const resolved = path.resolve(candidate);
    if (seen.has(resolved)) {
      continue;
    }
    seen.add(resolved);
    const canonical = await canonicalPathWithMissingSuffix(resolved, fsApi);
    if (canonical !== resolved) {
      throw new Error(`${label} must not contain symlink ancestors: ${resolved}`);
    }
  }
}

async function canonicalPathWithMissingSuffix(candidate, fsApi) {
  let current = path.resolve(candidate);
  const missing = [];
  for (;;) {
    try {
      const canonical = await fsApi.realpath(current);
      return path.join(canonical, ...missing);
    } catch (error) {
      if (!error || error.code !== 'ENOENT') {
        throw error;
      }
      const parent = path.dirname(current);
      if (parent === current) {
        throw error;
      }
      missing.unshift(path.basename(current));
      current = parent;
    }
  }
}

async function prepareTrustedOutputDirectories(plan, fsApi) {
  const directories = [
    [path.dirname(plan.renderedConfig), 'rendered config directory'],
    [path.dirname(plan.metadataFile), 'metadata directory'],
  ];
  const seen = new Set();
  for (const [directory, label] of directories) {
    if (seen.has(directory)) {
      continue;
    }
    seen.add(directory);
    await fsApi.mkdir(directory, { recursive: true, mode: 0o755 });
    const resolved = await fsApi.realpath(directory);
    if (resolved !== path.resolve(directory)) {
      throw new Error(`${label} must not contain symlinks: ${directory}`);
    }
    const directoryStat = await fsApi.lstat(directory);
    assertTrustedOutputDirectory(directory, directoryStat, label);
  }
}

async function installCandidateConfig(plan, fsApi) {
  const candidateStat = await fsApi.lstat(plan.candidateConfig);
  if (!candidateStat.isFile() || candidateStat.isSymbolicLink()) {
    throw new Error(`candidate config must be a regular file: ${plan.candidateConfig}`);
  }

  let hadPrevious = false;
  try {
    const currentStat = await fsApi.lstat(plan.renderedConfig);
    if (!currentStat.isFile() || currentStat.isSymbolicLink()) {
      throw new Error(`rendered config must be a regular file when present: ${plan.renderedConfig}`);
    }
    assertSafeRenderedConfigMetadata(plan.renderedConfig, currentStat);
    await fsApi.copyFile(plan.renderedConfig, plan.backupConfig);
    await fsApi.chmod(plan.backupConfig, currentStat.mode & 0o777);
    await syncFile(plan.backupConfig, fsApi);
    if (candidateStat.uid !== currentStat.uid || candidateStat.gid !== currentStat.gid) {
      await fsApi.chown(plan.candidateConfig, currentStat.uid, currentStat.gid);
    }
    await fsApi.chmod(plan.candidateConfig, currentStat.mode & 0o777);
    hadPrevious = true;
  } catch (error) {
    if (!error || error.code !== 'ENOENT') {
      throw error;
    }
    await fsApi.chmod(plan.candidateConfig, 0o644);
  }

  await syncFile(plan.candidateConfig, fsApi);
  await fsApi.rename(plan.candidateConfig, plan.renderedConfig);
  try {
    await syncDirectory(path.dirname(plan.renderedConfig), fsApi);
  } catch (error) {
    try {
      await rollbackCandidateConfig(plan, { hadPrevious }, fsApi);
    } catch (rollbackError) {
      throw new Error(
        `${error.message}; failed to restore config after install durability failure: ${rollbackError.message}`,
      );
    }
    throw error;
  }
  return { hadPrevious };
}

async function rollbackCandidateConfig(plan, installState, fsApi) {
  if (installState?.hadPrevious) {
    await fsApi.rename(plan.backupConfig, plan.renderedConfig);
  } else {
    await removeIfPresent(plan.renderedConfig, fsApi);
  }
  await syncDirectory(path.dirname(plan.renderedConfig), fsApi);
}

async function syncFile(file, fsApi) {
  const handle = await fsApi.open(file, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectory(directory, fsApi) {
  const handle = await fsApi.open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function removeIfPresent(file, fsApi) {
  await fsApi.rm(file, { force: true });
}

function assertManagedSubpath(child, parent, label) {
  const relative = path.relative(parent, child);
  if (!relative || isParentTraversal(relative) || path.isAbsolute(relative)) {
    throw new Error(`${label} must stay inside checkout-dir`);
  }
}

function assertTrustedDeploymentDirectory(file, fileStat, label) {
  if (!fileStat.isDirectory() || fileStat.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory: ${file}`);
  }
  const mode = fileStat.mode & 0o7777;
  const uid = typeof process.getuid === 'function' ? process.getuid() : fileStat.uid;
  const gid = typeof process.getgid === 'function' ? process.getgid() : fileStat.gid;
  if (fileStat.uid !== uid || fileStat.gid !== gid) {
    throw new Error(`${label} ownership is not trusted: ${file}`);
  }
  if ((mode & 0o700) !== 0o700 || (mode & 0o077) !== 0) {
    throw new Error(`${label} mode is not trusted: ${file}`);
  }
}

function assertTrustedDeploymentLock(file, fileStat) {
  if (!fileStat.isFile() || fileStat.isSymbolicLink()) {
    throw new Error(`deployment lock must be a real file: ${file}`);
  }
  const mode = fileStat.mode & 0o7777;
  const uid = typeof process.getuid === 'function' ? process.getuid() : fileStat.uid;
  const gid = typeof process.getgid === 'function' ? process.getgid() : fileStat.gid;
  if (fileStat.uid !== uid || fileStat.gid !== gid) {
    throw new Error(`deployment lock ownership is not trusted: ${file}`);
  }
  if (mode !== 0o600) {
    throw new Error(`deployment lock mode is not trusted: ${file}`);
  }
}

function assertTrustedOutputDirectory(file, fileStat, label) {
  if (!fileStat.isDirectory() || fileStat.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory: ${file}`);
  }
  const mode = fileStat.mode & 0o7777;
  const uid = typeof process.getuid === 'function' ? process.getuid() : fileStat.uid;
  const gid = typeof process.getgid === 'function' ? process.getgid() : fileStat.gid;
  if (fileStat.uid !== uid || fileStat.gid !== gid) {
    throw new Error(`${label} ownership is not trusted: ${file}`);
  }
  if ((mode & 0o700) !== 0o700 || (mode & 0o022) !== 0) {
    throw new Error(`${label} mode is not trusted: ${file}`);
  }
}

function assertConfigRevision(value) {
  if (!/^[0-9a-f]{40}$/i.test(value || '')) {
    throw new Error(`git rev-parse returned an invalid config revision: ${redact(value || '')}`);
  }
}

function allPlanCommands(plan) {
  return plan.serviceCommand
    ? [...plan.commands, plan.serviceCommand, ...plan.serviceVerificationCommands]
    : plan.commands;
}

function assertSafePlanPathTopology(plan) {
  const checkoutRoot = path.resolve(plan.checkoutDir);
  const checkoutWork = path.resolve(plan.checkoutWorkDir);
  const lockDir = path.resolve(plan.lockDir);
  const botCodeDir = path.resolve(plan.botCodeDir);
  const outputPaths = [
    ['rendered config', path.resolve(plan.renderedConfig)],
    ['candidate config', path.resolve(plan.candidateConfig)],
    ['backup config', path.resolve(plan.backupConfig)],
    ['metadata file', path.resolve(plan.metadataFile)],
  ];
  const credentialPaths = [
    ['SSH key', path.resolve(plan.sshKey)],
    ['SSH known-hosts file', path.resolve(plan.sshKnownHosts)],
  ];
  const protectedPaths = [
    ...outputPaths,
    ['bot code directory', botCodeDir],
    ...credentialPaths,
  ];
  for (const [label, protectedPath] of protectedPaths) {
    if (pathsOverlap(checkoutWork, protectedPath)) {
      throw new UsageError(`${label} must not overlap checkout work directory`);
    }
    if (pathsOverlap(lockDir, protectedPath)) {
      throw new UsageError(`${label} must not overlap deployment lock directory`);
    }
  }
  if (pathsOverlap(checkoutRoot, lockDir)) {
    throw new UsageError('deployment lock directory must not overlap checkout directory');
  }
  if (pathsOverlap(checkoutRoot, botCodeDir)) {
    throw new UsageError('bot code directory must not overlap checkout directory');
  }
  for (let index = 0; index < outputPaths.length; index += 1) {
    const [leftLabel, leftPath] = outputPaths[index];
    if (pathsOverlap(botCodeDir, leftPath)) {
      throw new UsageError(`${leftLabel} must not overlap bot code directory`);
    }
    for (const [credentialLabel, credentialPath] of credentialPaths) {
      if (pathsOverlap(leftPath, credentialPath)) {
        throw new UsageError(`${leftLabel} must not overlap ${credentialLabel}`);
      }
    }
    for (const [rightLabel, rightPath] of outputPaths.slice(index + 1)) {
      if (pathsOverlap(leftPath, rightPath)) {
        throw new UsageError(`${leftLabel} must not overlap ${rightLabel}`);
      }
    }
  }
}

function pathsOverlap(left, right) {
  return isPathWithin(left, right) || isPathWithin(right, left);
}

function isPathWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!isParentTraversal(relative) && !path.isAbsolute(relative));
}

function isParentTraversal(relative) {
  return relative === '..' || relative.startsWith(`..${path.sep}`);
}

function assertSafeRenderedConfigMetadata(file, fileStat) {
  const mode = fileStat.mode & 0o7777;
  const uid = typeof process.getuid === 'function' ? process.getuid() : fileStat.uid;
  const gid = typeof process.getgid === 'function' ? process.getgid() : fileStat.gid;
  if (fileStat.uid !== uid || fileStat.gid !== gid) {
    throw new Error(`rendered config metadata is not safe to preserve: ${file}`);
  }
  if ((mode & 0o400) === 0 || (mode & 0o004) === 0) {
    throw new Error(`rendered config mode is not safe to preserve: ${file}`);
  }
  if ((mode & 0o111) !== 0 || (mode & 0o6000) !== 0 || (mode & 0o022) !== 0) {
    throw new Error(`rendered config mode is not safe to preserve: ${file}`);
  }
}

function requiredValue(argv, index, flag) {
  const value = argv[index];
  if (!value || value.startsWith('--')) {
    throw new UsageError(`${flag} requires a value`);
  }
  return value;
}

function shellQuoteForDisplay(value) {
  if (/^[A-Za-z0-9_./:@=-]+$/.test(value)) {
    return value;
  }
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function shellQuoteForCommand(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function kebab(value) {
  return value.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
}

export function redact(value) {
  return value
    .replace(/([A-Za-z0-9_-]*token[A-Za-z0-9_-]*=)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(Authorization:\s*(?:Bearer|Basic)\s+)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(access[-_ ]?token["']?\s*[:=]\s*["']?)[^"'\s]+/gi, '$1[REDACTED]');
}

function truncate(value, limit) {
  if (value.length <= limit) {
    return value;
  }
  return `${value.slice(0, limit)}...`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const status = await runCli();
  process.exitCode = status;
}
