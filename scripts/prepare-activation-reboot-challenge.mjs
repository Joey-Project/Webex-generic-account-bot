#!/usr/bin/env node

import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  DEPLOY_EXIT_LOCK_BUSY,
  withSharedDeploymentLock,
} from './deploy-config.mjs';
import {
  inspectActivationBoundary,
  prepareHostDeployment,
  runJsonCommand,
} from './prepare-host-deployment.mjs';

const execFileAsync = promisify(execFile);
const SHA1_PATTERN = /^[a-f0-9]{40}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const COMMAND_TIMEOUT_MS = 30_000;

export const DEFAULTS = Object.freeze({
  activationHelper: '/opt/webex-generic-account-bot/bin/webex-codex-activation',
  systemctl: '/usr/bin/systemctl',
  transactionFile:
    '/var/lib/webex-generic-account-bot/rendered/production.toml.transaction',
});

export const MANAGED_UNITS = Object.freeze([
  'webex-generic-account-bot.service',
  'webex-codex-activation-renew.service',
  'webex-codex-launcher.socket',
  'webex-config-pull-worker.service',
]);

export function parseArgs(argv) {
  const options = { apply: false, json: false };
  let selectedMode = null;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--apply' || arg === '--dry-run') {
      if (selectedMode !== null) throw new Error('select exactly one challenge mode');
      selectedMode = arg;
      options.apply = arg === '--apply';
    } else if (arg === '--expected-bot-revision') {
      options.expectedBotRevision = requiredValue(argv, ++index, arg);
    } else if (arg === '--expected-manifest-sha256') {
      options.expectedManifestSha256 = requiredValue(argv, ++index, arg);
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
    'Usage: /opt/webex-generic-account-bot/code/scripts/prepare-activation-reboot-challenge',
    '       [--dry-run] [--json]',
    '       --expected-bot-revision <sha>',
    '       --expected-manifest-sha256 <sha256>',
    '       /opt/webex-generic-account-bot/code/scripts/prepare-activation-reboot-challenge',
    '       --apply [--json]',
    '       --expected-bot-revision <sha>',
    '       --expected-manifest-sha256 <sha256>',
    '',
    'Dry-run is the default. Paths, commands, and managed units are fixed.',
    'Apply prepares only the first-activation reboot challenge; it never reboots or starts the bot.',
  ].join('\n');
}

export async function prepareActivationRebootChallenge(options, injected = {}) {
  validateOptions(options);
  const settings = Object.freeze({ ...DEFAULTS, ...(injected.settings ?? {}) });
  const euid = injected.euid ?? process.geteuid?.();
  if (euid !== 0) throw new Error('activation reboot challenge preparation requires root');
  const prepareHost = injected.prepareHost ?? prepareHostDeployment;
  const inspectBoundary = injected.inspectBoundary ?? inspectActivationBoundary;
  const inspectUnits = injected.inspectUnits ?? ((settingsValue) => inspectManagedUnits(settingsValue));
  const assertNoTransaction = injected.assertNoTransaction
    ?? ((settingsValue) => assertDeploymentTransactionAbsent(settingsValue));
  const runHelper = injected.runHelper
    ?? ((apply) => runActivationHelper(settings, apply));
  const withLock = injected.withLock ?? withSharedDeploymentLock;

  const execute = async () => {
    const preflight = await prepareHost(
      {
        apply: false,
        json: true,
        requireSecrets: true,
        through: 'preactivation-ready',
        expectedBotRevision: options.expectedBotRevision,
        expectedManifestSha256: options.expectedManifestSha256,
      },
      injected.preflightDependencies,
    );
    validatePreflight(preflight, options);
    validatePreChallengeBoundary(preflight.activation_boundary);
    await assertNoTransaction(settings);

    const unitsBefore = await inspectUnits(settings);
    validateManagedUnitStates(unitsBefore);
    const challengeBefore = validateHelperReport(await runHelper(false), false);
    validateBoundaryMatchesChallenge(preflight.activation_boundary, challengeBefore.challenge);

    if (!options.apply) {
      return buildReport({
        options,
        preflight,
        challengeBefore,
        challengeAfter: challengeBefore,
        unitsBefore,
        unitsAfter: unitsBefore,
      });
    }

    const applied = validateHelperReport(await runHelper(true), true);
    if (applied.status !== 'reboot_required') {
      throw new Error('activation helper did not establish the reboot-required state');
    }
    assertSameActivationBinding(challengeBefore, applied);

    const boundaryAfter = await inspectBoundary();
    validatePostChallengeBoundary(boundaryAfter);
    await assertNoTransaction(settings);
    const unitsAfter = await inspectUnits(settings);
    validateManagedUnitStates(unitsAfter);
    if (JSON.stringify(unitsAfter) !== JSON.stringify(unitsBefore)) {
      throw new Error('managed systemd unit state changed while preparing the reboot challenge');
    }

    const challengeAfter = validateHelperReport(await runHelper(false), false);
    if (challengeAfter.status !== 'reboot_required') {
      throw new Error('prepared reboot challenge is not stable');
    }
    assertSameActivationBinding(applied, challengeAfter);
    validateBoundaryMatchesChallenge(boundaryAfter, challengeAfter.challenge);

    return buildReport({
      options,
      preflight: { ...preflight, activation_boundary: boundaryAfter },
      challengeBefore,
      challengeAfter,
      unitsBefore,
      unitsAfter,
    });
  };

  return options.apply ? withLock(execute) : execute();
}

function buildReport({
  options,
  preflight,
  challengeBefore,
  challengeAfter,
  unitsBefore,
  unitsAfter,
}) {
  return Object.freeze({
    version: 1,
    mode: options.apply ? 'applied' : 'dry-run',
    status: challengeAfter.status,
    expected_bot_revision: options.expectedBotRevision,
    expected_manifest_sha256: options.expectedManifestSha256,
    release: Object.freeze({ ...preflight.release }),
    activation_binding: Object.freeze({ ...challengeAfter.activation_binding }),
    challenge_before: Object.freeze({ ...challengeBefore.challenge }),
    challenge_after: Object.freeze({ ...challengeAfter.challenge }),
    activation_boundary: preflight.activation_boundary,
    managed_units_before: unitsBefore,
    managed_units_after: unitsAfter,
    deployment_transaction: 'absent',
    service_state: 'unchanged',
    units_started: 0,
    bot_start_attempted: false,
    reboot_performed: false,
  });
}

export async function inspectManagedUnits(settings = DEFAULTS, injected = {}) {
  const run = injected.run ?? execFileAsync;
  const units = [];
  for (const unit of MANAGED_UNITS) {
    let result;
    try {
      result = await run(
        settings.systemctl,
        ['show', '--property=ActiveState', '--value', '--', unit],
        {
          cwd: '/',
          env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
          encoding: 'utf8',
          maxBuffer: 64 * 1024,
          timeout: COMMAND_TIMEOUT_MS,
          windowsHide: true,
        },
      );
    } catch {
      throw new Error(`managed unit state inspection failed: ${unit}`);
    }
    if (result.stderr !== '' || result.stdout !== 'inactive\n') {
      throw new Error(`managed unit must be inactive before first activation: ${unit}`);
    }
    units.push(Object.freeze({ unit, active_state: 'inactive' }));
  }
  return Object.freeze(units);
}

export async function assertDeploymentTransactionAbsent(settings = DEFAULTS, injected = {}) {
  const fsApi = injected.fsApi ?? fs;
  try {
    await fsApi.lstat(settings.transactionFile);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw new Error('deployment transaction state is unreadable');
  }
  throw new Error('deployment recovery must be completed before preparing the reboot challenge');
}

async function runActivationHelper(settings, apply) {
  return runJsonCommand(
    settings.activationHelper,
    ['prepare-reboot-challenge', ...(apply ? ['--apply'] : [])],
    apply ? 'activation reboot challenge creation' : 'activation reboot challenge inspection',
  );
}

function validateOptions(options) {
  if (!SHA1_PATTERN.test(options.expectedBotRevision ?? '')) {
    throw new Error('expected bot revision must be a lowercase 40-character Git SHA');
  }
  if (!SHA256_PATTERN.test(options.expectedManifestSha256 ?? '')) {
    throw new Error('expected manifest digest must be a lowercase SHA-256');
  }
}

function validatePreflight(report, options) {
  expectPlainObject(report, 'host preparation report');
  if (
    report.version !== 1
    || report.mode !== 'dry-run'
    || report.requested_state !== 'preactivation-ready'
    || report.reached_state !== 'inspected'
    || report.expected_bot_revision !== options.expectedBotRevision
    || report.expected_manifest_sha256 !== options.expectedManifestSha256
    || report.release?.bot_revision !== options.expectedBotRevision
    || report.host_policy?.mode !== 'dry-run'
    || report.host_policy?.changed_artifact_count !== 0
    || report.runtime?.status !== 'inspected'
    || report.runtime?.active_runtime !== 'matching'
    || report.secrets?.ready !== true
    || report.secrets?.contents_inspected !== false
    || report.service_state !== 'unchanged'
    || report.activation_state !== 'not_attempted'
  ) {
    throw new Error('host is not ready for the first activation reboot challenge');
  }
}

function validatePreChallengeBoundary(boundary) {
  validateBoundaryShape(boundary);
  const states = new Map(boundary.entries.map(({ name, status }) => [name, status]));
  if (
    states.get('activation_receipt') !== 'absent'
    || states.get('runner_permission') !== 'absent'
    || !['absent', 'present'].includes(states.get('reboot_challenge'))
  ) {
    throw new Error('preactivation boundary is not safe for reboot challenge preparation');
  }
}

function validatePostChallengeBoundary(boundary) {
  validateBoundaryShape(boundary);
  const states = new Map(boundary.entries.map(({ name, status }) => [name, status]));
  if (
    boundary.clean
    || states.get('activation_receipt') !== 'absent'
    || states.get('runner_permission') !== 'absent'
    || states.get('reboot_challenge') !== 'present'
  ) {
    throw new Error('activation boundary is invalid after reboot challenge preparation');
  }
}

function validateBoundaryShape(boundary) {
  expectPlainObject(boundary, 'activation boundary report');
  if (!Array.isArray(boundary.entries) || typeof boundary.clean !== 'boolean') {
    throw new Error('activation boundary report is invalid');
  }
  const expectedNames = ['activation_receipt', 'runner_permission', 'reboot_challenge'];
  if (
    boundary.entries.length !== expectedNames.length
    || boundary.entries.some((entry, index) => (
      entry?.name !== expectedNames[index]
      || !['absent', 'present', 'unreadable'].includes(entry.status)
    ))
    || boundary.clean !== boundary.entries.every(({ status }) => status === 'absent')
  ) {
    throw new Error('activation boundary report is invalid');
  }
}

function validateHelperReport(report, apply) {
  expectPlainObject(report, 'activation helper report');
  expectExactKeys(
    report,
    ['activation_binding', 'challenge', 'mode', 'status', 'version', 'writes_performed'],
    'activation helper report',
  );
  if (
    report.version !== 2
    || report.mode !== (apply ? 'applied' : 'dry-run')
    || !['ready', 'reboot_required'].includes(report.status)
    || !Number.isSafeInteger(report.writes_performed)
    || (apply
      ? ![0, 2].includes(report.writes_performed)
      : report.writes_performed !== 0)
  ) {
    throw new Error('activation helper report is invalid');
  }
  validateActivationBinding(report.activation_binding);
  validateChallengeReport(report.challenge, report.status);
  return Object.freeze({
    ...report,
    activation_binding: Object.freeze({ ...report.activation_binding }),
    challenge: Object.freeze({ ...report.challenge }),
  });
}

function validateActivationBinding(binding) {
  expectPlainObject(binding, 'activation binding');
  const digestFields = [
    'active_manifest_sha256',
    'runtime_image_sha256',
    'bot_executable_sha256',
    'launcher_executable_sha256',
    'runtime_executable_sha256',
  ];
  expectExactKeys(binding, [...digestFields, 'codex_version', 'model'], 'activation binding');
  if (
    digestFields.some((field) => !SHA256_PATTERN.test(binding[field] ?? ''))
    || typeof binding.codex_version !== 'string'
    || binding.codex_version.length === 0
    || typeof binding.model !== 'string'
    || binding.model.length === 0
  ) {
    throw new Error('activation binding is invalid');
  }
}

function validateChallengeReport(challenge, status) {
  expectPlainObject(challenge, 'reboot challenge');
  expectExactKeys(
    challenge,
    ['current_boot_matches', 'marker_valid', 'state', 'validated'],
    'reboot challenge',
  );
  const absent = status === 'ready'
    && challenge.state === 'absent'
    && challenge.current_boot_matches === false
    && challenge.validated === false
    && challenge.marker_valid === false;
  const pending = status === 'reboot_required'
    && challenge.state === 'pending_current_boot'
    && challenge.current_boot_matches === true
    && challenge.validated === false
    && challenge.marker_valid === true;
  if (!absent && !pending) throw new Error('reboot challenge report is invalid');
}

function validateBoundaryMatchesChallenge(boundary, challenge) {
  const challengeStatus = boundary.entries.find(({ name }) => name === 'reboot_challenge')?.status;
  const expected = challenge.state === 'absent' ? 'absent' : 'present';
  if (challengeStatus !== expected) {
    throw new Error('activation boundary and reboot challenge reports disagree');
  }
}

function validateManagedUnitStates(units) {
  if (
    !Array.isArray(units)
    || units.length !== MANAGED_UNITS.length
    || units.some((entry, index) => (
      entry?.unit !== MANAGED_UNITS[index] || entry.active_state !== 'inactive'
    ))
  ) {
    throw new Error('managed systemd unit state report is invalid');
  }
}

function assertSameActivationBinding(left, right) {
  if (JSON.stringify(left.activation_binding) !== JSON.stringify(right.activation_binding)) {
    throw new Error('activation runtime binding changed while preparing the reboot challenge');
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
  stdout.write(`status=${report.status}\n`);
  stdout.write(`bot_revision=${report.release.bot_revision}\n`);
  stdout.write(`runtime_image_sha256=${report.activation_binding.runtime_image_sha256}\n`);
  stdout.write(`challenge_state=${report.challenge_after.state}\n`);
  stdout.write('deployment_transaction=absent\n');
  stdout.write('service_state=unchanged\n');
  stdout.write('units_started=0\n');
  stdout.write('reboot_performed=false\n');
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
  const report = await prepareActivationRebootChallenge(options, dependencies);
  writeReport(stdout, report, options.json);
  return 0;
}

export function exitStatusForError(error) {
  return error?.exitStatus === DEPLOY_EXIT_LOCK_BUSY ? DEPLOY_EXIT_LOCK_BUSY : 1;
}

const isMain = process.argv[1]
  && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  runCli().catch((error) => {
    process.stderr.write(`prepare-activation-reboot-challenge: ${error.message}\n`);
    process.exitCode = exitStatusForError(error);
  });
}
