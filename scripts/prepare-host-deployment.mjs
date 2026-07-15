#!/usr/bin/env node

import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { withSharedDeploymentLock } from './deploy-config.mjs';
import { assertNoExtendedPosixAcl } from './provision-host.mjs';

const execFileAsync = promisify(execFile);
const SHA1_PATTERN = /^[a-f0-9]{40}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_SECRET_BYTES = 1024 * 1024;
const COMMAND_TIMEOUT_MS = 10 * 60 * 1000;

export const DEFAULTS = Object.freeze({
  releaseInstaller: '/usr/local/libexec/webex-host-release/install-host-release',
  installRoot: '/opt/webex-generic-account-bot',
  provisioner: '/opt/webex-generic-account-bot/code/scripts/provision-host',
  node: '/usr/bin/node',
  runtimeBuilder:
    '/opt/webex-generic-account-bot/code/scripts/build-codex-runtime-image.mjs',
});

export const ACTIVATION_BOUNDARY_PATHS = Object.freeze([
  Object.freeze({ name: 'activation_receipt', path: '/run/webex-codex-activation/receipt.json' }),
  Object.freeze({
    name: 'runner_permission',
    path: '/etc/systemd/system/webex-generic-account-bot.service.d/10-codex-launcher.conf',
  }),
  Object.freeze({
    name: 'reboot_challenge',
    path: '/var/lib/webex-generic-account-bot/canary-fixtures/reboot-challenge.json',
  }),
]);

export const SECRET_ROOTS = Object.freeze([
  Object.freeze({
    name: 'bot_credentials',
    path: '/etc/webex-generic-account-bot',
    group: 'webex-generic-account-bot',
    mode: 0o750,
  }),
  Object.freeze({
    name: 'webex_access',
    path: '/var/lib/webex-headless-access',
    group: 'webex-generic-account-bot',
    mode: 0o750,
  }),
  Object.freeze({
    name: 'config_deploy',
    path: '/var/lib/webex-generic-account-bot/deploy',
    group: 'webex-config-deploy',
    mode: 0o750,
  }),
]);

export const SECRET_FILES = Object.freeze([
  Object.freeze({
    name: 'webex_access_token',
    path: '/var/lib/webex-headless-access/access-token',
    group: 'webex-generic-account-bot',
    modes: Object.freeze([0o440, 0o640]),
  }),
  Object.freeze({
    name: 'bot_environment',
    path: '/etc/webex-generic-account-bot/bot.env',
    group: null,
    modes: Object.freeze([0o400, 0o600]),
  }),
  Object.freeze({
    name: 'jenkins_environment',
    path: '/etc/webex-generic-account-bot/jenkins.env',
    group: 'webex-generic-account-bot',
    modes: Object.freeze([0o440, 0o640]),
  }),
  Object.freeze({
    name: 'codex_auth',
    path: '/etc/webex-generic-account-bot/codex-auth.json',
    group: null,
    modes: Object.freeze([0o400, 0o600]),
  }),
  Object.freeze({
    name: 'config_deploy_key',
    path: '/var/lib/webex-generic-account-bot/deploy/id_ed25519',
    group: 'webex-config-deploy',
    modes: Object.freeze([0o440, 0o640]),
  }),
]);

export function parseArgs(argv) {
  const options = { apply: false, json: false, requireSecrets: false, through: null };
  let selectedMode = null;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--apply' || arg === '--dry-run') {
      if (selectedMode !== null) throw new Error('select exactly one deployment mode');
      selectedMode = arg;
      options.apply = arg === '--apply';
    } else if (arg === '--expected-bot-revision') {
      options.expectedBotRevision = requiredValue(argv, ++index, arg);
    } else if (arg === '--expected-manifest-sha256') {
      options.expectedManifestSha256 = requiredValue(argv, ++index, arg);
    } else if (arg === '--through') {
      options.through = requiredValue(argv, ++index, arg);
      if (!['provisioned', 'preactivation-ready'].includes(options.through)) {
        throw new Error('deployment target must be provisioned or preactivation-ready');
      }
    } else if (arg === '--require-secrets') {
      options.requireSecrets = true;
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
    'Usage: /opt/webex-generic-account-bot/code/scripts/prepare-host-deployment',
    '       [--dry-run] [--through provisioned|preactivation-ready]',
    '       [--require-secrets] [--json]',
    '       --expected-bot-revision <sha>',
    '       --expected-manifest-sha256 <sha256>',
    '       /opt/webex-generic-account-bot/code/scripts/prepare-host-deployment',
    '       --apply --through provisioned|preactivation-ready [--json]',
    '       --expected-bot-revision <sha>',
    '       --expected-manifest-sha256 <sha256>',
    '',
    'Dry-run is the default. Paths, commands, and deployment phases are fixed.',
    'This command never installs secrets, enables services, or activates the runner.',
  ].join('\n');
}

export async function prepareHostDeployment(options, injected = {}) {
  validateOptions(options);
  const requestedState = options.through ?? 'preactivation-ready';
  const settings = Object.freeze({ ...DEFAULTS, ...(injected.settings ?? {}) });
  const euid = injected.euid ?? process.geteuid?.();
  if (euid !== 0) throw new Error('host deployment preparation requires root');
  const runJson = injected.runJson ?? runJsonCommand;
  const inspectSecrets = injected.inspectSecrets ?? inspectDeploymentSecrets;
  const inspectBoundary = injected.inspectBoundary ?? inspectActivationBoundary;
  const withLock = injected.withLock ?? withSharedDeploymentLock;

  const release = validateReleaseReport(await runJson(
    settings.releaseInstaller,
    [
      '--dry-run',
      '--json',
      '--expected-bot-revision',
      options.expectedBotRevision,
      '--expected-manifest-sha256',
      options.expectedManifestSha256,
    ],
    'host release verification',
  ), options, settings);

  const provision = validateProvisionReport(await runJson(
    settings.provisioner,
    [options.apply ? '--apply' : '--dry-run', '--json'],
    'host policy provisioning',
  ), options.apply);

  let boundary;
  let runtime;
  let secrets;
  const inspectReadiness = async () => {
    boundary = await inspectBoundary();
    validateActivationBoundary(boundary);
    secrets = await inspectSecrets();
    validateSecretReport(secrets);
    if (
      (options.requireSecrets || (options.apply && requestedState === 'preactivation-ready'))
      && !secrets.ready
    ) {
      const incomplete = secrets.files
        .filter(({ status }) => status !== 'ready')
        .map(({ name }) => name)
        .join(', ');
      throw new Error(`deployment secrets are not ready: ${incomplete}`);
    }
    if (options.apply && requestedState === 'preactivation-ready' && !boundary.clean) {
      throw new Error('activation boundary is not clean; use the activation recovery workflow');
    }
  };

  if (requestedState === 'preactivation-ready') {
    if (options.apply) {
      await withLock(async () => {
        const lockedProvision = validateProvisionReport(await runJson(
          settings.provisioner,
          ['--dry-run', '--json'],
          'locked host policy revalidation',
        ), false);
        if (lockedProvision.changed_artifact_count !== 0) {
          throw new Error('host policy changed before runtime preparation');
        }
        await inspectReadiness();
        const sourceManifest = validateSourceManifestReport(await runJson(
          settings.node,
          [settings.runtimeBuilder, '--write-source-manifest'],
          'runtime source manifest creation',
        ));
        const active = validateRuntimeReport(await runJson(
          settings.node,
          [settings.runtimeBuilder, '--first-deployment'],
          'runtime image creation',
        ));
        boundary = await inspectBoundary();
        validateActivationBoundary(boundary);
        if (!boundary.clean) {
          throw new Error('activation boundary changed while preparing the runtime');
        }
        runtime = Object.freeze({
          status: 'prepared',
          codex_version: active.codex_version,
          source_file_count: sourceManifest.files.length,
          source_manifest_sha256: active.source_manifest_sha256,
          image_sha256: active.image_sha256,
          image_size: active.image_size,
        });
      });
    } else {
      await inspectReadiness();
      runtime = validateRuntimeInspectionReport(await runJson(
        settings.node,
        [settings.runtimeBuilder, '--dry-run', '--json'],
        'runtime source inspection',
      ));
    }
  } else {
    boundary = await inspectBoundary();
    validateActivationBoundary(boundary);
    secrets = await inspectSecrets();
    validateSecretReport(secrets);
    runtime = Object.freeze({ status: 'not_requested' });
  }

  return Object.freeze({
    version: 1,
    mode: options.apply ? 'applied' : 'dry-run',
    requested_state: requestedState,
    reached_state: options.apply ? requestedState : 'inspected',
    expected_bot_revision: options.expectedBotRevision,
    expected_manifest_sha256: options.expectedManifestSha256,
    release,
    host_policy: provision,
    runtime,
    secrets,
    activation_boundary: boundary,
    service_state: 'unchanged',
    activation_state: 'not_attempted',
  });
}

export async function inspectActivationBoundary(injected = {}) {
  const fsApi = injected.fsApi ?? fs;
  const entries = [];
  for (const descriptor of ACTIVATION_BOUNDARY_PATHS) {
    let status;
    try {
      await fsApi.lstat(descriptor.path);
      status = 'present';
    } catch (error) {
      if (error?.code !== 'ENOENT') status = 'unreadable';
      else status = 'absent';
    }
    entries.push(Object.freeze({ name: descriptor.name, status }));
  }
  return Object.freeze({
    clean: entries.every(({ status }) => status === 'absent'),
    entries: Object.freeze(entries),
  });
}

export async function inspectDeploymentSecrets(injected = {}) {
  const fsApi = injected.fsApi ?? fs;
  const resolveGroup = injected.resolveGroup ?? resolveSystemGroup;
  const verifyNoAcl = injected.verifyNoAcl ?? assertNoExtendedPosixAcl;
  const groupNames = new Set([
    ...SECRET_ROOTS.map(({ group }) => group),
    ...SECRET_FILES.map(({ group }) => group).filter(Boolean),
  ]);
  const groups = new Map();
  for (const group of groupNames) groups.set(group, await resolveGroup(group));

  const rootResults = new Map();
  for (const descriptor of SECRET_ROOTS) {
    rootResults.set(
      descriptor.path,
      await inspectSecretRoot(descriptor, groups, fsApi, verifyNoAcl),
    );
  }
  const files = [];
  for (const descriptor of SECRET_FILES) {
    const root = SECRET_ROOTS.find(({ path: rootPath }) => (
      descriptor.path === rootPath || descriptor.path.startsWith(`${rootPath}/`)
    ));
    const rootResult = rootResults.get(root?.path);
    if (rootResult?.status !== 'ready') {
      files.push(Object.freeze({ name: descriptor.name, status: rootResult?.status ?? 'invalid' }));
      continue;
    }
    files.push(await inspectSecretFile(descriptor, groups, fsApi, verifyNoAcl));
  }
  return Object.freeze({
    ready: files.every(({ status }) => status === 'ready'),
    contents_inspected: false,
    files: Object.freeze(files),
  });
}

async function inspectSecretRoot(descriptor, groups, fsApi, verifyNoAcl) {
  const gid = groups.get(descriptor.group);
  if (gid === null) return Object.freeze({ status: 'identity_pending' });
  let metadata;
  try {
    metadata = await fsApi.lstat(descriptor.path);
  } catch (error) {
    if (error?.code === 'ENOENT') return Object.freeze({ status: 'missing' });
    return Object.freeze({ status: 'unreadable' });
  }
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || metadata.uid !== 0
    || metadata.gid !== gid
    || (metadata.mode & 0o7777) !== descriptor.mode
  ) {
    return Object.freeze({ status: 'invalid' });
  }
  try {
    await verifyNoAcl(descriptor.path);
  } catch {
    return Object.freeze({ status: 'invalid' });
  }
  return Object.freeze({ status: 'ready' });
}

async function inspectSecretFile(descriptor, groups, fsApi, verifyNoAcl) {
  const expectedGid = descriptor.group === null ? 0 : groups.get(descriptor.group);
  if (expectedGid === null) {
    return Object.freeze({ name: descriptor.name, status: 'identity_pending' });
  }
  let metadata;
  try {
    metadata = await fsApi.lstat(descriptor.path);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return Object.freeze({ name: descriptor.name, status: 'missing' });
    }
    return Object.freeze({ name: descriptor.name, status: 'unreadable' });
  }
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1
    || metadata.uid !== 0
    || metadata.gid !== expectedGid
    || !descriptor.modes.includes(metadata.mode & 0o7777)
    || metadata.size <= 0
    || metadata.size > MAX_SECRET_BYTES
  ) {
    return Object.freeze({ name: descriptor.name, status: 'invalid' });
  }
  try {
    await verifyNoAcl(descriptor.path);
  } catch {
    return Object.freeze({ name: descriptor.name, status: 'invalid' });
  }
  return Object.freeze({ name: descriptor.name, status: 'ready' });
}

export async function runJsonCommand(command, args, label, injected = {}) {
  const run = injected.run ?? execFileAsync;
  let result;
  try {
    result = await run(command, args, {
      cwd: '/',
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      encoding: 'utf8',
      maxBuffer: MAX_JSON_BYTES,
      timeout: COMMAND_TIMEOUT_MS,
      windowsHide: true,
    });
  } catch (error) {
    const status = Number.isSafeInteger(error?.code) ? `exit ${error.code}` : 'execution error';
    throw new Error(`${label} failed (${status})`);
  }
  if (result.stderr !== '') throw new Error(`${label} emitted unexpected diagnostics`);
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${label} returned invalid JSON`);
  }
}

async function resolveSystemGroup(name, injected = {}) {
  const run = injected.run ?? execFileAsync;
  let result;
  try {
    result = await run('/usr/bin/getent', ['group', name], {
      cwd: '/',
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      encoding: 'utf8',
      maxBuffer: 64 * 1024,
      timeout: 5000,
      windowsHide: true,
    });
  } catch (error) {
    if (error?.code === 2) return null;
    throw new Error(`managed group lookup failed: ${name}`);
  }
  if (result.stderr !== '') throw new Error(`managed group lookup emitted diagnostics: ${name}`);
  const lines = result.stdout.trimEnd().split('\n');
  if (lines.length !== 1) throw new Error(`managed group lookup is ambiguous: ${name}`);
  const fields = lines[0].split(':');
  if (fields.length !== 4 || fields[0] !== name || !/^\d+$/.test(fields[2])) {
    throw new Error(`managed group lookup is invalid: ${name}`);
  }
  const gid = Number(fields[2]);
  if (!Number.isSafeInteger(gid) || gid <= 0) {
    throw new Error(`managed group ID is invalid: ${name}`);
  }
  return gid;
}

function validateOptions(options) {
  if (!SHA1_PATTERN.test(options.expectedBotRevision ?? '')) {
    throw new Error('expected bot revision must be a lowercase 40-character Git SHA');
  }
  if (!SHA256_PATTERN.test(options.expectedManifestSha256 ?? '')) {
    throw new Error('expected manifest digest must be a lowercase SHA-256');
  }
  if (options.through != null && !['provisioned', 'preactivation-ready'].includes(options.through)) {
    throw new Error('deployment target must be provisioned or preactivation-ready');
  }
  if (options.apply && options.through == null) {
    throw new Error('--apply requires an explicit --through target');
  }
}

function validateReleaseReport(value, options, settings) {
  expectPlainObject(value, 'host release report');
  expectExactKeys(
    value,
    ['bot_revision', 'codex_version', 'file_count', 'install_root', 'status'],
    'host release report',
  );
  if (
    value.status !== 'already_installed'
    || value.bot_revision !== options.expectedBotRevision
    || value.install_root !== settings.installRoot
    || typeof value.codex_version !== 'string'
    || !Number.isSafeInteger(value.file_count)
    || value.file_count <= 0
  ) {
    throw new Error('host release report does not match the approved installed release');
  }
  return Object.freeze({
    status: value.status,
    bot_revision: value.bot_revision,
    codex_version: value.codex_version,
    file_count: value.file_count,
  });
}

function validateProvisionReport(value, apply) {
  expectPlainObject(value, 'host policy report');
  expectExactKeys(
    value,
    [
      'artifact_count',
      'changed_artifact_count',
      'command_count',
      'installed_artifacts',
      'mode',
      'units_enabled',
      'units_started',
      'version',
    ],
    'host policy report',
  );
  if (
    value.version !== 1
    || value.mode !== (apply ? 'applied' : 'dry-run')
    || !Number.isSafeInteger(value.artifact_count)
    || value.artifact_count <= 0
    || !Number.isSafeInteger(value.changed_artifact_count)
    || value.changed_artifact_count < 0
    || value.changed_artifact_count > value.artifact_count
    || !Number.isSafeInteger(value.command_count)
    || value.command_count < 0
    || !Array.isArray(value.installed_artifacts)
    || value.units_started !== 0
    || value.units_enabled !== 0
  ) {
    throw new Error('host policy report is invalid');
  }
  return Object.freeze({
    mode: value.mode,
    artifact_count: value.artifact_count,
    changed_artifact_count: value.changed_artifact_count,
    command_count: value.command_count,
    units_started: 0,
    units_enabled: 0,
  });
}

function validateSourceManifestReport(value) {
  expectPlainObject(value, 'runtime source manifest report');
  if (
    value.version !== 1
    || typeof value.codex_version !== 'string'
    || !Array.isArray(value.files)
    || value.files.length === 0
    || !Array.isArray(value.symlinks)
  ) {
    throw new Error('runtime source manifest report is invalid');
  }
  return value;
}

function validateRuntimeInspectionReport(value) {
  expectPlainObject(value, 'runtime source inspection report');
  expectExactKeys(
    value,
    [
      'codex_target',
      'codex_version',
      'source_file_count',
      'source_manifest_sha256',
      'active_runtime',
      'status',
      'version',
      'writes_performed',
    ],
    'runtime source inspection report',
  );
  if (
    value.version !== 1
    || value.status !== 'inspected'
    || value.writes_performed !== 0
    || typeof value.codex_version !== 'string'
    || value.codex_target !== 'x86_64-unknown-linux-musl'
    || !['absent', 'matching'].includes(value.active_runtime)
    || !Number.isSafeInteger(value.source_file_count)
    || value.source_file_count <= 0
    || !SHA256_PATTERN.test(value.source_manifest_sha256 ?? '')
  ) {
    throw new Error('runtime source inspection report is invalid');
  }
  return Object.freeze({ ...value });
}

function validateRuntimeReport(value) {
  expectPlainObject(value, 'runtime image report');
  for (const digest of ['source_manifest_sha256', 'image_sha256', 'mksquashfs_sha256']) {
    if (!SHA256_PATTERN.test(value[digest] ?? '')) {
      throw new Error('runtime image report is invalid');
    }
  }
  if (
    value.version !== 1
    || typeof value.codex_version !== 'string'
    || !Number.isSafeInteger(value.image_size)
    || value.image_size <= 0
  ) {
    throw new Error('runtime image report is invalid');
  }
  return value;
}

function validateSecretReport(value) {
  expectPlainObject(value, 'deployment secret report');
  expectExactKeys(value, ['contents_inspected', 'files', 'ready'], 'deployment secret report');
  if (
    typeof value.ready !== 'boolean'
    || value.contents_inspected !== false
    || !Array.isArray(value.files)
    || value.files.length !== SECRET_FILES.length
    || value.files.some((entry, index) => (
      entry?.name !== SECRET_FILES[index].name
      || !['identity_pending', 'invalid', 'missing', 'ready', 'unreadable'].includes(entry.status)
    ))
  ) {
    throw new Error('deployment secret report is invalid');
  }
  if (value.ready !== value.files.every(({ status }) => status === 'ready')) {
    throw new Error('deployment secret report readiness is inconsistent');
  }
}

function validateActivationBoundary(value) {
  expectPlainObject(value, 'activation boundary report');
  expectExactKeys(value, ['clean', 'entries'], 'activation boundary report');
  if (
    typeof value.clean !== 'boolean'
    || !Array.isArray(value.entries)
    || value.entries.length !== ACTIVATION_BOUNDARY_PATHS.length
    || value.entries.some((entry, index) => (
      entry?.name !== ACTIVATION_BOUNDARY_PATHS[index].name
      || !['absent', 'present', 'unreadable'].includes(entry.status)
    ))
    || value.clean !== value.entries.every(({ status }) => status === 'absent')
  ) {
    throw new Error('activation boundary report is invalid');
  }
}

function expectPlainObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function expectExactKeys(value, expected, label) {
  if (JSON.stringify(Object.keys(value).toSorted()) !== JSON.stringify(expected.toSorted())) {
    throw new Error(`${label} fields are invalid`);
  }
}

function requiredValue(argv, index, flag) {
  if (index >= argv.length || argv[index].startsWith('-')) {
    throw new Error(`${flag} requires a value`);
  }
  return argv[index];
}

function writeReport(stdout, report, json) {
  if (json) {
    stdout.write(`${JSON.stringify(report)}\n`);
    return;
  }
  stdout.write(`mode=${report.mode}\n`);
  stdout.write(`requested_state=${report.requested_state}\n`);
  stdout.write(`reached_state=${report.reached_state}\n`);
  stdout.write(`bot_revision=${report.release.bot_revision}\n`);
  stdout.write(`host_policy=${report.host_policy.mode}\n`);
  stdout.write(`runtime=${report.runtime.status}\n`);
  stdout.write(`secrets_ready=${report.secrets.ready}\n`);
  stdout.write('service_state=unchanged\n');
  stdout.write('activation_state=not_attempted\n');
}

export async function runCli({
  argv = process.argv.slice(2),
  stdout = process.stdout,
  dependencies = {},
} = {}) {
  const options = parseArgs(argv);
  if (options.help) {
    stdout.write(`${usage()}\n`);
    return 0;
  }
  const report = await prepareHostDeployment(options, dependencies);
  writeReport(stdout, report, options.json);
  return 0;
}

const isMain = process.argv[1]
  && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  runCli().catch((error) => {
    process.stderr.write(`prepare-host-deployment: ${error.message}\n`);
    process.exitCode = 1;
  });
}
