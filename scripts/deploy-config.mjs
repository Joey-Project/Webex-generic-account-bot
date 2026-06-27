#!/usr/bin/env node
import { spawn } from 'node:child_process';
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
    gitCommand(options.gitBin, checkoutWorkDir, ['checkout', '--detach', '--force', 'FETCH_HEAD'], {
      ...commandDefaults,
      env: gitEnv,
    }),
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

  return {
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
    skipRestart: options.skipRestart,
    serviceAction: options.skipRestart ? null : 'restart',
    sshKey: path.resolve(options.sshKey),
    sshKnownHosts: path.resolve(options.sshKnownHosts),
    commandTimeoutMs: options.commandTimeoutMs,
    outputLimitBytes: options.outputLimitBytes,
  };
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
  await acquireLock(plan.lockDir, fsApi);
  const captures = {};
  let installState = null;
  let primaryError = null;
  let backupCleanupError = null;
  let commitReached = false;
  let failureMetadataWritten = false;
  const recordFailure = async (status, reason) => {
    failureMetadataWritten = true;
    await writeFailureMetadata(plan, captures.configRevision || null, status, reason, fsApi).catch(() => {});
  };
  try {
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
        await runner(plan.serviceCommand, scrubEnv(parentEnv, plan.serviceCommand.env));
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
          await runner(plan.serviceCommand, scrubEnv(parentEnv, plan.serviceCommand.env));
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
    await fsApi.mkdir(path.dirname(plan.metadataFile), { recursive: true, mode: 0o755 });
    await fsApi.writeFile(plan.metadataFile, `${JSON.stringify(metadata, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o644,
    });
    return metadata;
  } catch (error) {
    primaryError = error;
    if (!failureMetadataWritten) {
      await recordFailure(commitReached ? 'failed_after_commit' : 'failed_apply', error.message);
    }
    throw error;
  } finally {
    let cleanupError = null;
    if (installState) {
      try {
        await rollbackCandidateConfig(plan, installState, fsApi);
      } catch (error) {
        cleanupError = error;
      }
    }
    try {
      await removeIfPresent(plan.candidateConfig, fsApi);
    } catch (error) {
      cleanupError ??= error;
    }
    try {
      await fsApi.rm(plan.lockDir, { recursive: true, force: true });
    } catch (error) {
      cleanupError ??= error;
    }
    if (cleanupError && !primaryError) {
      throw cleanupError;
    }
  }
}

async function printStatus({ options, stdout, stderr, fsApi }) {
  try {
    const contents = await fsApi.readFile(path.resolve(options.metadataFile), 'utf8');
    if (options.json) {
      stdout.write(contents.endsWith('\n') ? contents : `${contents}\n`);
    } else {
      const parsed = JSON.parse(contents);
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

async function acquireLock(lockDir, fsApi) {
  try {
    const lockParent = path.dirname(lockDir);
    await fsApi.mkdir(lockParent, { recursive: true, mode: 0o700 });
    const lockParentStat = await fsApi.lstat(lockParent);
    assertTrustedDeploymentDirectory(lockParent, lockParentStat, 'lock parent');
    await fsApi.mkdir(lockDir, { recursive: false, mode: 0o700 });
  } catch (error) {
    if (error && error.code === 'EEXIST') {
      throw new Error(`deployment already in progress: ${lockDir}`);
    }
    throw error;
  }
}

function command(bin, args, options = {}) {
  return {
    bin,
    args,
    cwd: options.cwd || TRUSTED_CHILD_CWD,
    optional: Boolean(options.optional),
    capture: options.capture,
    env: options.env || {},
    timeoutMs: options.timeoutMs,
    outputLimitBytes: options.outputLimitBytes,
  };
}

function gitCommand(bin, cwd, args, options = {}) {
  const gitArgs = cwd ? ['-C', cwd, ...GIT_SAFE_CONFIG, ...args] : [...GIT_SAFE_CONFIG, ...args];
  return command(bin, gitArgs, options);
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
    const child = spawn(commandSpec.bin, commandSpec.args, {
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
    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      killChildProcess(child, detached, 'SIGTERM');
      killTimer = setTimeout(() => {
        killChildProcess(child, detached, 'SIGKILL');
      }, 5000);
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
      clearTimeout(timeoutTimer);
      if (killTimer) {
        clearTimeout(killTimer);
      }
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timeoutTimer);
      if (killTimer) {
        clearTimeout(killTimer);
      }
      if (timedOut) {
        reject(new Error(`${commandSpec.bin} timed out after ${commandSpec.timeoutMs || DEFAULTS.commandTimeoutMs}ms`));
        return;
      }
      if (code === 0 || commandSpec.optional) {
        resolve({
          stdout,
          stderr,
          code,
          stdoutTruncated: stdoutCapture.truncated,
          stderrTruncated: stderrCapture.truncated,
        });
        return;
      }
      const suffix = stderrCapture.truncated ? ' [stderr truncated]' : '';
      reject(new Error(`${commandSpec.bin} failed with code ${code}: ${truncate(redact(stderr), 2000)}${suffix}`));
    });
  });
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
    stdout.write(`command_${index + 1}=${commandSpec.bin} ${commandSpec.args.map(shellQuoteForDisplay).join(' ')}\n`);
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

async function writeFailureMetadata(plan, configRevision, status, reason, fsApi) {
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
  };
  await fsApi.mkdir(path.dirname(plan.metadataFile), { recursive: true, mode: 0o755 });
  await fsApi.writeFile(plan.metadataFile, `${JSON.stringify(metadata, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o644,
  });
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

  await fsApi.rename(plan.candidateConfig, plan.renderedConfig);
  return { hadPrevious };
}

async function rollbackCandidateConfig(plan, installState, fsApi) {
  if (installState?.hadPrevious) {
    await fsApi.rename(plan.backupConfig, plan.renderedConfig);
  } else {
    await removeIfPresent(plan.renderedConfig, fsApi);
  }
}

async function removeIfPresent(file, fsApi) {
  await fsApi.rm(file, { force: true });
}

function assertManagedSubpath(child, parent, label) {
  const relative = path.relative(parent, child);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
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

function assertConfigRevision(value) {
  if (!/^[0-9a-f]{40}$/i.test(value || '')) {
    throw new Error(`git rev-parse returned an invalid config revision: ${redact(value || '')}`);
  }
}

function allPlanCommands(plan) {
  return plan.serviceCommand ? [...plan.commands, plan.serviceCommand] : plan.commands;
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
