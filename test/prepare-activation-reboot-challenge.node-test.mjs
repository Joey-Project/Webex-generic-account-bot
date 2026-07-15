import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  DEFAULTS,
  MANAGED_UNITS,
  assertDeploymentTransactionAbsent,
  exitStatusForError,
  inspectManagedUnits,
  parseArgs,
  prepareActivationRebootChallenge,
  runActivationHelper,
  runCli,
  usage,
} from '../scripts/prepare-activation-reboot-challenge.mjs';

const REVISION = 'a'.repeat(40);
const MANIFEST_SHA256 = 'b'.repeat(64);
const DIGEST = 'c'.repeat(64);

describe('first activation reboot challenge preparation', () => {
  it('defaults to dry-run and accepts no path or command overrides', () => {
    assert.deepEqual(parseArgs([]), { apply: false, json: false });
    assert.deepEqual(parseArgs([
      '--apply',
      '--json',
      '--expected-bot-revision',
      REVISION,
      '--expected-manifest-sha256',
      MANIFEST_SHA256,
    ]), {
      apply: true,
      json: true,
      expectedBotRevision: REVISION,
      expectedManifestSha256: MANIFEST_SHA256,
    });
    assert.throws(
      () => parseArgs(['--apply', '--dry-run']),
      /select exactly one challenge mode/,
    );
    assert.throws(() => parseArgs(['--systemctl', '/tmp/systemctl']), /unknown argument/);
    assert.match(usage(), /never reboots or starts the bot/);
  });

  it('keeps default dry-run read-only and reports a ready challenge', async () => {
    let lockCalled = false;
    const helperCalls = [];
    const report = await prepareActivationRebootChallenge(options(), dependencies({
      runHelper: async (apply) => {
        helperCalls.push(apply);
        return helperReport(false, 'ready');
      },
      withLock: async () => {
        lockCalled = true;
        assert.fail('dry-run must not acquire the deployment lock');
      },
    }));

    assert.deepEqual(helperCalls, [false]);
    assert.equal(lockCalled, false);
    assert.equal(report.mode, 'dry-run');
    assert.equal(report.status, 'ready');
    assert.equal(report.challenge_after.state, 'absent');
    assert.equal(report.units_started, 0);
    assert.equal(report.bot_start_attempted, false);
    assert.equal(report.reboot_performed, false);
  });

  it('atomically prepares an idempotent reboot-required state under the shared lock', async () => {
    let lockCalls = 0;
    let boundaryCalls = 0;
    const helperCalls = [];
    const report = await prepareActivationRebootChallenge(options({ apply: true }), dependencies({
      inspectBoundary: async () => {
        boundaryCalls += 1;
        return boundary(true);
      },
      runHelper: async (apply) => {
        helperCalls.push(apply);
        if (apply) return helperReport(true, 'reboot_required', 2);
        return helperCalls.length === 1
          ? helperReport(false, 'ready')
          : helperReport(false, 'reboot_required');
      },
      withLock: async (operation) => {
        lockCalls += 1;
        return operation();
      },
    }));

    assert.equal(lockCalls, 1);
    assert.equal(boundaryCalls, 1);
    assert.deepEqual(helperCalls, [false, true, false]);
    assert.equal(report.status, 'reboot_required');
    assert.equal(report.challenge_before.state, 'absent');
    assert.equal(report.challenge_after.state, 'pending_current_boot');
    assert.deepEqual(report.managed_units_before, inactiveUnits());
    assert.deepEqual(report.managed_units_after, inactiveUnits());
    assert.equal(report.activation_boundary.clean, false);
  });

  it('accepts a same-boot pending challenge as an idempotent apply retry', async () => {
    const helperCalls = [];
    const report = await prepareActivationRebootChallenge(options({ apply: true }), dependencies({
      prepareHost: async () => preflight(false),
      inspectBoundary: async () => boundary(true),
      runHelper: async (apply) => {
        helperCalls.push(apply);
        return helperReport(apply, 'reboot_required', 0);
      },
    }));

    assert.deepEqual(helperCalls, [false, true, false]);
    assert.equal(report.challenge_before.state, 'pending_current_boot');
    assert.equal(report.challenge_after.state, 'pending_current_boot');
  });

  it('rejects host drift before invoking the activation helper', async () => {
    let helperCalled = false;
    await assert.rejects(
      prepareActivationRebootChallenge(options({ apply: true }), dependencies({
        prepareHost: async () => ({
          ...preflight(true),
          runtime: { ...preflight(true).runtime, active_runtime: 'conflict' },
        }),
        runHelper: async () => {
          helperCalled = true;
        },
      })),
      /host is not ready/,
    );
    assert.equal(helperCalled, false);
  });

  it('rejects dirty activation and deployment recovery boundaries', async () => {
    await assert.rejects(
      prepareActivationRebootChallenge(options(), dependencies({
        prepareHost: async () => ({
          ...preflight(false),
          activation_boundary: {
            clean: false,
            entries: [
              { name: 'activation_receipt', status: 'present' },
              { name: 'runner_permission', status: 'absent' },
              { name: 'reboot_challenge', status: 'absent' },
            ],
          },
        }),
      })),
      /preactivation boundary is not safe/,
    );
    await assert.rejects(
      prepareActivationRebootChallenge(options(), dependencies({
        assertNoTransaction: async () => {
          throw new Error('deployment recovery must be completed');
        },
      })),
      /deployment recovery must be completed/,
    );
  });

  it('fails closed when apply changes units, runtime binding, or the post-boundary', async () => {
    let unitInspection = 0;
    await assert.rejects(
      prepareActivationRebootChallenge(options({ apply: true }), dependencies({
        inspectBoundary: async () => boundary(true),
        inspectUnits: async () => {
          unitInspection += 1;
          return unitInspection === 1
            ? inactiveUnits()
            : inactiveUnits().map((entry, index) => (
              index === 0 ? { ...entry, active_state: 'active' } : entry
            ));
        },
        runHelper: helperSequence(),
      })),
      /managed systemd unit state report is invalid/,
    );

    let helperCall = 0;
    await assert.rejects(
      prepareActivationRebootChallenge(options({ apply: true }), dependencies({
        inspectBoundary: async () => boundary(true),
        runHelper: async (apply) => {
          helperCall += 1;
          const report = helperSequenceReport(helperCall, apply);
          if (helperCall === 2) {
            report.activation_binding.runtime_image_sha256 = 'd'.repeat(64);
          }
          return report;
        },
      })),
      /runtime binding changed/,
    );

    await assert.rejects(
      prepareActivationRebootChallenge(options({ apply: true }), dependencies({
        inspectBoundary: async () => boundary(false),
        runHelper: helperSequence(),
      })),
      /activation boundary is invalid after/,
    );
  });

  it('uses fixed systemctl argv and checks transaction absence without reading it', async () => {
    const calls = [];
    const units = await inspectManagedUnits(undefined, {
      run: async (command, args, optionsValue) => {
        calls.push({ command, args, options: optionsValue });
        if (args[0] === 'list-units' || args[0] === 'list-unit-files') {
          return { stdout: '', stderr: '' };
        }
        return { stdout: 'inactive\n', stderr: '' };
      },
    });
    assert.deepEqual(units, inactiveUnits());
    assert(calls.every(({ command }) => command === '/usr/bin/systemctl'));
    assert.deepEqual(
      calls.map(({ args }) => args),
      [
        [
          'list-units', '--all', '--full', '--plain', '--no-legend', '--no-pager',
          '--type=service', 'webex-codex-launcher@*.service',
        ],
        [
          'list-unit-files', '--full', '--no-legend', '--no-pager',
          'webex-codex-launcher@*.service',
        ],
        ...MANAGED_UNITS.map((unit) => [
          'show', '--property=ActiveState', '--value', '--', unit,
        ]),
      ],
    );

    let lstatCalls = 0;
    await assertDeploymentTransactionAbsent(undefined, {
      fsApi: {
        async lstat() {
          lstatCalls += 1;
          const error = new Error('missing');
          error.code = 'ENOENT';
          throw error;
        },
      },
    });
    assert.equal(lstatCalls, 1);
  });

  it('discovers launcher instances and rejects an active instance', async () => {
    const instance = 'webex-codex-launcher@test.service';
    const run = async (_command, args) => {
      if (args[0] === 'list-units') {
        return { stdout: `${instance} loaded inactive dead test\n`, stderr: '' };
      }
      if (args[0] === 'list-unit-files') {
        return {
          stdout: `webex-codex-launcher@.service static -\n${instance} static -\n`,
          stderr: '',
        };
      }
      return { stdout: 'inactive\n', stderr: '' };
    };
    assert.deepEqual(
      await inspectManagedUnits(undefined, { run }),
      [...inactiveUnits(), { unit: instance, active_state: 'inactive' }],
    );

    await assert.rejects(
      inspectManagedUnits(undefined, {
        run: async (command, args, optionsValue) => {
          const result = await run(command, args, optionsValue);
          if (args.at(-1) === instance && args[0] === 'show') {
            return { stdout: 'active\n', stderr: '' };
          }
          return result;
        },
      }),
      /managed unit must be inactive.*webex-codex-launcher@test\.service/,
    );
  });

  it('surfaces only bounded single-line activation helper diagnostics', async () => {
    const legacy = 'legacy reboot challenge schema version 1 requires operator recovery';
    const calls = [];
    await assert.rejects(
      runActivationHelper(DEFAULTS, false, {
        run: async (command, args, optionsValue) => {
          calls.push({ command, args, options: optionsValue });
          throw Object.assign(new Error('helper failed'), {
            code: 1,
            stderr: `Error: ${legacy}\n`,
          });
        },
      }),
      new RegExp(legacy),
    );
    assert.equal(calls[0].command, DEFAULTS.activationHelper);
    assert.deepEqual(calls[0].args, ['prepare-reboot-challenge']);
    assert.deepEqual(calls[0].options.env, {
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    });

    const secret = 'do-not-surface';
    await assert.rejects(
      runActivationHelper(DEFAULTS, true, {
        run: async () => {
          throw Object.assign(new Error('helper failed'), {
            code: 1,
            stderr: `Error: ${secret}\nCaused by: second line\n`,
          });
        },
      }),
      (error) => {
        assert.match(error.message, /creation failed \(exit 1\)/);
        assert.doesNotMatch(error.message, new RegExp(secret));
        return true;
      },
    );
  });

  it('preserves lock contention status through the CLI', async () => {
    const error = new Error('deployment already in progress');
    error.exitStatus = 75;
    assert.equal(exitStatusForError(error), 75);
    assert.equal(exitStatusForError(new Error('failure')), 1);

    let stdout = '';
    const status = await runCli({
      argv: ['--help'],
      stdout: { write: (chunk) => { stdout += chunk; } },
    });
    assert.equal(status, 0);
    assert.match(stdout, /Dry-run is the default/);
  });
});

function options(overrides = {}) {
  return {
    apply: false,
    json: false,
    expectedBotRevision: REVISION,
    expectedManifestSha256: MANIFEST_SHA256,
    ...overrides,
  };
}

function dependencies(overrides = {}) {
  return {
    euid: 0,
    prepareHost: async () => preflight(true),
    inspectBoundary: async () => boundary(true),
    inspectUnits: async () => inactiveUnits(),
    assertNoTransaction: async () => {},
    runHelper: async () => helperReport(false, 'ready'),
    withLock: async (operation) => operation(),
    ...overrides,
  };
}

function preflight(clean) {
  return {
    version: 1,
    mode: 'dry-run',
    requested_state: 'preactivation-ready',
    reached_state: 'inspected',
    expected_bot_revision: REVISION,
    expected_manifest_sha256: MANIFEST_SHA256,
    release: {
      status: 'already_installed',
      bot_revision: REVISION,
      codex_version: '0.142.3',
      file_count: 42,
    },
    host_policy: {
      mode: 'dry-run',
      artifact_count: 10,
      changed_artifact_count: 0,
      command_count: 0,
      units_started: 0,
      units_enabled: 0,
    },
    runtime: {
      version: 1,
      status: 'inspected',
      active_runtime: 'matching',
      source_manifest_sha256: DIGEST,
    },
    secrets: { ready: true, contents_inspected: false, files: [] },
    activation_boundary: boundary(!clean ? true : false),
    service_state: 'unchanged',
    activation_state: 'not_attempted',
  };
}

function boundary(challengePresent) {
  return {
    clean: !challengePresent,
    entries: [
      { name: 'activation_receipt', status: 'absent' },
      { name: 'runner_permission', status: 'absent' },
      { name: 'reboot_challenge', status: challengePresent ? 'present' : 'absent' },
    ],
  };
}

function helperReport(apply, status, writes = 0) {
  const pending = status === 'reboot_required';
  return {
    version: 2,
    mode: apply ? 'applied' : 'dry-run',
    status,
    writes_performed: writes,
    activation_binding: {
      active_manifest_sha256: DIGEST,
      runtime_image_sha256: DIGEST,
      bot_executable_sha256: DIGEST,
      launcher_executable_sha256: DIGEST,
      runtime_executable_sha256: DIGEST,
      codex_version: '0.142.3',
      model: 'gpt-5.5',
    },
    challenge: {
      state: pending ? 'pending_current_boot' : 'absent',
      current_boot_matches: pending,
      validated: false,
      marker_valid: pending,
    },
  };
}

function helperSequence() {
  let call = 0;
  return async (apply) => {
    call += 1;
    return helperSequenceReport(call, apply);
  };
}

function helperSequenceReport(call, apply) {
  return call === 1
    ? helperReport(false, 'ready')
    : helperReport(apply, 'reboot_required', apply ? 2 : 0);
}

function inactiveUnits() {
  return MANAGED_UNITS.map((unit) => ({ unit, active_state: 'inactive' }));
}
