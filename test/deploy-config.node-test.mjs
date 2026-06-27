import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import {
  buildDeployPlan,
  executePlan,
  parseArgs,
  redact,
  runCli,
  runCommand,
  scrubEnv,
} from '../scripts/deploy-config.mjs';
import {
  assertMaxRenderedBytes,
  REPO_ROOT,
  renderEnvironment,
} from '../scripts/config-policy/render-config.mjs';
import {
  buildGraphSummary,
  collectBuildGraph,
  diagnoseBundle,
  diagnoseBuild,
  fetchBuildReport,
  formatReport,
  formatBundleStdout,
  formatBundleSummary,
  jenkinsLogFileName,
  redactedConsoleLinesFromText,
} from '../scripts/jenkins-readonly.mjs';

describe('deploy-config argument parsing', () => {
  it('defaults to dry-run-safe host deployment paths', () => {
    const options = parseArgs(['--dry-run']);

    assert.equal(options.apply, false);
    assert.equal(options.dryRun, true);
    assert.equal(options.configRef, 'main');
    assert.equal(options.checkoutDir, '/var/lib/webex-generic-account-bot/config-checkout');
    assert.equal(options.renderedConfig, '/var/lib/webex-generic-account-bot/rendered/production.toml');
    assert.equal(options.botCodeDir, '/opt/webex-generic-account-bot/code');
    assert.equal(options.gitBin, '/usr/bin/git');
    assert.equal(options.bashBin, '/usr/bin/bash');
    assert.equal(options.nodeBin, '/usr/bin/node');
    assert.equal(options.pythonBin, '/usr/bin/python3');
    assert.equal(options.cargoBin, '/usr/bin/cargo');
    assert.equal(options.systemctlBin, '/usr/bin/systemctl');
    assert.equal(options.sshBin, '/usr/bin/ssh');
    assert.equal(options.sshKey, '/var/lib/webex-generic-account-bot/deploy/id_ed25519');
    assert.equal(options.sshKnownHosts, '/etc/ssh/ssh_known_hosts');
    assert.equal(options.commandTimeoutMs, 600_000);
    assert.equal(options.outputLimitBytes, 1_048_576);
  });

  it('rejects refs, repositories, services, and paths that cannot be fixed host policy', () => {
    assert.throws(() => parseArgsAllow(['--config-ref', '../main']), /config-ref/);
    assert.throws(() => parseArgsAllow(['--config-ref', 'main;id']), /config-ref/);
    assert.throws(() => parseArgsAllow(['--config-ref', '-n']), /config-ref/);
    assert.throws(() => parseArgsAllow(['--config-repo', 'ssh://github.com/org/repo.git']), /config-repo/);
    assert.throws(() => parseArgsAllow(['--service', 'bad/unit']), /service/);
    assert.throws(() => parseArgsAllow(['--service', '-Hroot@example']), /service/);
    assert.throws(() => parseArgsAllow(['--checkout-dir', 'relative/path']), /checkout-dir/);
    assert.throws(() => parseArgsAllow(['--git-bin', 'git']), /git-bin/);
    assert.throws(() => parseArgsAllow(['--node-bin', 'node']), /node-bin/);
    assert.throws(() => parseArgsAllow(['--python-bin', 'python3']), /python-bin/);
    assert.throws(() => parseArgsAllow(['--cargo-bin', 'cargo']), /cargo-bin/);
    assert.throws(() => parseArgsAllow(['--command-timeout-ms', '0']), /command-timeout-ms/);
    assert.throws(() => parseArgsAllow(['--command-timeout-ms', '3600001']), /at most 3600000/);
    assert.throws(() => parseArgsAllow(['--output-limit-bytes', 'many']), /output-limit-bytes/);
    assert.throws(() => parseArgsAllow(['--output-limit-bytes', '8388609']), /at most 8388608/);
  });

  it('requires host opt-in before accepting deployment policy overrides', () => {
    assert.throws(
      () => parseArgs(['--bot-code-dir', '/opt/evil']),
      /WEBEX_BOT_DEPLOY_ALLOW_HOST_OVERRIDES=1/,
    );
    assert.equal(
      parseArgsAllow(['--bot-code-dir', '/opt/webex-generic-account-bot/code']).botCodeDir,
      '/opt/webex-generic-account-bot/code',
    );
  });

  it('requires apply or dry-run to be unambiguous', () => {
    assert.throws(() => parseArgs(['--apply', '--dry-run']), /either --apply or --dry-run/);
  });
});

describe('deploy-config plan', () => {
  it('uses fixed argv arrays for git, validation, and restart', () => {
    const plan = buildDeployPlan(parseArgs(['--apply']));
    const commands = plan.commands.map((command) => [command.bin, command.args]);
    const allGitCommands = plan.commands.filter((command) => command.bin === '/usr/bin/git');

    assert.equal(plan.checkoutWorkDir, path.join(plan.checkoutDir, 'work'));
    assert.deepEqual(commands[0], ['/usr/bin/git', ['-c', 'advice.detachedHead=false', '-c', 'core.hooksPath=/dev/null', '-c', 'filter.lfs.required=false', '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', '-c', 'submodule.recurse=false', 'init', plan.checkoutWorkDir]]);
    assert.deepEqual(commands[2], [
      '/usr/bin/git',
      ['-C', plan.checkoutWorkDir, '-c', 'advice.detachedHead=false', '-c', 'core.hooksPath=/dev/null', '-c', 'filter.lfs.required=false', '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', '-c', 'submodule.recurse=false', 'remote', 'add', 'origin', plan.configRepo],
    ]);
    assert(allGitCommands.every((command) => command.args.includes('core.hooksPath=/dev/null')));
    assert(allGitCommands.every((command) => command.args.includes('protocol.file.allow=never')));
    assert(allGitCommands.every((command) => command.args.includes('protocol.ext.allow=never')));
    assert(commands.some(([bin, args]) => bin === '/usr/bin/git' && args.includes('--recurse-submodules=no')));
    assert(commands.some(([bin, args]) => bin === '/usr/bin/bash' && args.includes('--source-root')));
    assert.equal(plan.serviceCommand.bin, '/usr/bin/systemctl');
    assert.deepEqual(plan.serviceCommand.args, ['restart', '--', plan.service]);

    const validate = plan.commands.find((command) => command.bin === '/usr/bin/bash');
    assert.equal(validate.args[0], path.join(plan.botCodeDir, 'scripts/config-policy/validate-config.sh'));
    assert.equal(validate.args[validate.args.indexOf('--source-root') + 1], plan.checkoutWorkDir);
    assert.equal(validate.args[validate.args.indexOf('--out') + 1], plan.candidateConfig);
    assert.equal(validate.env.WEBEX_BOT_CODE_DIR, plan.botCodeDir);
    assert.equal(validate.env.NODE_BIN, '/usr/bin/node');
    assert.equal(validate.env.PYTHON_BIN, '/usr/bin/python3');
    assert.equal(validate.env.CARGO_BIN, '/usr/bin/cargo');
    assert(allGitCommands.every((command) => command.env.GIT_SSH_COMMAND.includes('/usr/bin/ssh')));
    assert(allGitCommands.every((command) => command.env.GIT_SSH_COMMAND.includes('/var/lib/webex-generic-account-bot/deploy/id_ed25519')));
    assert(allGitCommands.every((command) => command.env.GIT_SSH_COMMAND.includes('/etc/ssh/ssh_known_hosts')));
    assert(plan.commands.every((command) => command.cwd === '/'));
    assert.equal(plan.serviceCommand.cwd, '/');
    assert(plan.commands.every((command) => command.timeoutMs === 600_000));
    assert(plan.commands.every((command) => command.outputLimitBytes === 1_048_576));
  });

  it('can build an install-only plan without restart', () => {
    const plan = buildDeployPlan(parseArgs(['--apply', '--skip-restart']));

    assert.equal(plan.serviceCommand, null);
  });
});

describe('deploy-config environment and output hygiene', () => {
  it('scrubs inherited Git, SSH, proxy, home, and token variables', () => {
    const env = scrubEnv(
      {
        PATH: '/bin',
        HOME: '/home/user',
        SSH_AUTH_SOCK: '/tmp/agent.sock',
        GIT_CONFIG_COUNT: '1',
        HTTPS_PROXY: 'http://proxy',
        WEBEX_ACCESS_TOKEN: 'secret',
      },
      { WEBEX_BOT_CODE_DIR: '/opt/bot' },
    );

    assert.equal(env.PATH, '/usr/bin:/bin');
    assert.equal(env.HOME, undefined);
    assert.equal(env.SSH_AUTH_SOCK, undefined);
    assert.equal(env.GIT_CONFIG_COUNT, undefined);
    assert.equal(env.HTTPS_PROXY, undefined);
    assert.equal(env.WEBEX_ACCESS_TOKEN, undefined);
    assert.equal(env.GIT_CONFIG_NOSYSTEM, '1');
    assert.equal(env.GIT_CONFIG_GLOBAL, '/dev/null');
    assert.equal(env.WEBEX_BOT_CODE_DIR, '/opt/bot');
    assert.equal(env.GIT_SSH_COMMAND, undefined);
  });

  it('redacts token-shaped output', () => {
    assert.equal(redact('access_token=abc Authorization: Bearer secret'), 'access_token=[REDACTED] Authorization: Bearer [REDACTED]');
  });
});

describe('trusted config policy', () => {
  it('allowlists the bot-owned Jenkins helper path, not the config checkout path', async () => {
    const policy = await fs.readFile('scripts/config-policy/static-config-check.py', 'utf8');
    const example = await fs.readFile('config/example.toml', 'utf8');

    assert.match(policy, /"\/opt\/webex-generic-account-bot\/code\/scripts\/jenkins-readonly\.mjs"/);
    assert.doesNotMatch(policy, /"\/opt\/webex-generic-account-bot\/config\/scripts\/jenkins-readonly\.mjs"/);
    assert.match(policy, /"\/var\/lib\/webex-generic-account-bot\/codex-workspace"/);
    assert.match(policy, /"skip_git_repo_check", True/);
    assert.match(example, /script = "\/opt\/webex-generic-account-bot\/code\/scripts\/jenkins-readonly\.mjs"/);
    assert.doesNotMatch(example, /script = "\/opt\/webex-generic-account-bot\/scripts\/jenkins-readonly\.mjs"/);
  });

  it('runs static policy against rendered Jenkins helper paths', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'static-config-policy-test-'));
    const allowed = path.join(temp, 'allowed.toml');
    await fs.writeFile(
      allowed,
      staticPolicyRenderedConfig('/opt/webex-generic-account-bot/code/scripts/jenkins-readonly.mjs'),
      'utf8',
    );

    const allowedResult = runStaticConfigPolicy(allowed);
    assert.equal(allowedResult.status, 0, allowedResult.stderr);

    for (const scriptPath of [
      '/opt/webex-generic-account-bot/scripts/jenkins-readonly.mjs',
      '/var/lib/webex-generic-account-bot/config-checkout/scripts/jenkins-readonly.mjs',
    ]) {
      const rejected = path.join(temp, `${safeTestName(scriptPath)}.toml`);
      await fs.writeFile(rejected, staticPolicyRenderedConfig(scriptPath), 'utf8');
      const rejectedResult = runStaticConfigPolicy(rejected);

      assert.notEqual(rejectedResult.status, 0, `expected ${scriptPath} to be rejected`);
      assert.match(rejectedResult.stderr, /jenkins_context\.script/);
    }
  });

  it('bounds rendered config output before shell redirection writes it', () => {
    assert.doesNotThrow(() => assertMaxRenderedBytes('abc', 3));
    assert.throws(() => assertMaxRenderedBytes('abcd', 3), /rendered config exceeds max bytes/);
  });

  it('defaults the renderer source root to the repository root', async () => {
    assert.equal(await fs.realpath(REPO_ROOT), await fs.realpath(process.cwd()));
  });

  it('bounds rendered config source bytes before reading all config data', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'render-config-test-'));
    await fs.mkdir(path.join(temp, 'production', 'spaces'), { recursive: true });
    await fs.writeFile(path.join(temp, 'production', 'bot.toml'), 'abcdef', 'utf8');
    await fs.writeFile(path.join(temp, 'production', 'spaces', 'space.toml'), 'room_id = "room-1"', 'utf8');

    await assert.rejects(
      () => renderEnvironment('production', temp, { maxBytes: 5 }),
      /rendered config source exceeds max bytes/,
    );
  });

  it('redacts console-derived snippets before summaries or stdout can use them', () => {
    const lines = redactedConsoleLinesFromText(
      'ERROR password=secret-token\nAuthorization: Bearer abc.def\nfatal https://user:url-token@example.com/repo.git\nclone https://url-token@example.com/repo.git\ntoken="quoted-secret"\ncredential: \'single-secret\'\nnormal line',
    );

    assert.deepEqual(lines, [
      'ERROR password=[REDACTED]',
      'Authorization: Bearer [REDACTED]',
      'fatal https://[REDACTED]@example.com/repo.git',
      'clone https://[REDACTED]@example.com/repo.git',
      'token="[REDACTED]"',
      "credential: '[REDACTED]'",
      'normal line',
    ]);
    assert.equal(
      redactedConsoleLinesFromText(
        '{"access_token":"json-secret","client_secret":"json-client-secret","token":"json-token","password":"json-password"}',
      )[0],
      '{"access_token":"[REDACTED]","client_secret":"[REDACTED]","token":"[REDACTED]","password":"[REDACTED]"}',
    );
  });

  it('redacts graph-derived Jenkins diagnostics before summaries or stdout can use them', () => {
    const buildUrl = 'https://jenkins.example/job/root/1/';
    const graph = buildGraphSummary({
      initialUrl: buildUrl,
      rootUrl: buildUrl,
      limits: jenkinsLimits(),
      nodes: [
        {
          buildUrl,
          consoleUrl: `${buildUrl}console`,
          consoleTextUrl: `${buildUrl}consoleText`,
          parentUrls: new Set(),
          childUrls: new Set(),
          fullDisplayName: 'root',
          number: '1',
          result: 'FAILURE',
          signalLines: ['fatal https://user:url-token@example.com/repo.git'],
          infraSignals: [{ kind: 'checkout', line: 'Authorization: Bearer abc.def' }],
          logBytes: 1,
        },
      ],
    });
    const summary = formatBundleSummary(graph);
    const stdout = formatBundleStdout({
      artifactDir: '/tmp/jenkins-artifacts',
      summaryPath: '/tmp/jenkins-artifacts/summary.md',
      graphPath: '/tmp/jenkins-artifacts/graph.json',
      logIndexPath: '/tmp/jenkins-artifacts/logs/index.json',
      graph,
    });

    for (const payload of [JSON.stringify(graph), summary, stdout]) {
      assert.doesNotMatch(payload, /url-token|abc\.def/);
      assert.match(payload, /\[REDACTED\]/);
    }
  });

  it('limits Jenkins downstream graph fetches to max_parallel_fetches', async () => {
    const rootUrl = 'https://jenkins.example/job/root/1/';
    const childUrls = Array.from(
      { length: 6 },
      (_, index) => `https://jenkins.example/job/child-${index + 1}/1/`,
    );
    let activeFetches = 0;
    let maxActiveFetches = 0;
    const fetchedUrls = [];
    const fetcher = {
      nodes: new Map(),
      limits: { maxNodes: 10, maxParallelFetches: 2 },
      shouldStop() {
        return false;
      },
      async fetch(url, parentUrls = []) {
        activeFetches += 1;
        maxActiveFetches = Math.max(maxActiveFetches, activeFetches);
        fetchedUrls.push(url);
        const parents = Array.isArray(parentUrls) ? parentUrls : [parentUrls].filter(Boolean);
        let node = this.nodes.get(url);
        if (!node) {
          node = {
            buildUrl: url,
            parentUrls: new Set(parents),
            childUrls: new Set(),
            fetchError: null,
            downstreamBuilds: url === rootUrl ? childUrls.map((childUrl) => ({ url: childUrl })) : [],
          };
          this.nodes.set(url, node);
        } else {
          for (const parentUrl of parents) {
            node.parentUrls.add(parentUrl);
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 5));
        activeFetches -= 1;
        return node;
      },
    };

    await collectBuildGraph({ fetcher, rootUrl });

    assert.equal(maxActiveFetches, 2);
    assert.equal(fetchedUrls.length, 7);
  });

  it('queues already fetched Jenkins children for graph expansion', async () => {
    const rootUrl = 'https://jenkins.example/job/root/1/';
    const childUrl = 'https://jenkins.example/job/child/1/';
    const grandchildUrl = 'https://jenkins.example/job/grandchild/1/';
    const fetchedUrls = [];
    const fetcher = {
      nodes: new Map([
        [
          childUrl,
          {
            buildUrl: childUrl,
            parentUrls: new Set(),
            childUrls: new Set(),
            fetchError: null,
            downstreamBuilds: [{ url: grandchildUrl }],
          },
        ],
      ]),
      limits: { maxNodes: 10, maxParallelFetches: 2 },
      shouldStop() {
        return false;
      },
      async fetch(url, parentUrls = []) {
        fetchedUrls.push(url);
        const parents = Array.isArray(parentUrls) ? parentUrls : [parentUrls].filter(Boolean);
        let node = this.nodes.get(url);
        if (!node) {
          node = {
            buildUrl: url,
            parentUrls: new Set(parents),
            childUrls: new Set(),
            fetchError: null,
            downstreamBuilds: url === rootUrl ? [{ url: childUrl }] : [],
          };
          this.nodes.set(url, node);
        } else {
          for (const parentUrl of parents) {
            node.parentUrls.add(parentUrl);
          }
        }
        return node;
      },
    };

    await collectBuildGraph({ fetcher, rootUrl });

    assert.deepEqual(fetchedUrls, [rootUrl, childUrl, grandchildUrl]);
    assert(fetcher.nodes.get(childUrl).parentUrls.has(rootUrl));
    assert(fetcher.nodes.get(childUrl).childUrls.has(grandchildUrl));
  });

  it('uses URL-derived suffixes to keep Jenkins log filenames unique', () => {
    const first = jenkinsLogFileName(
      { fullDisplayName: 'same/display name', number: '1' },
      'https://jenkins.example/job/same%2Fdisplay-name/1/',
    );
    const second = jenkinsLogFileName(
      { fullDisplayName: 'same display name', number: '1' },
      'https://jenkins.example/job/same-display-name/1/',
    );

    assert.notEqual(first, second);
    assert.match(first, /^same_display_name-1-[a-f0-9]{12}\.log$/);
    assert.match(second, /^same_display_name-1-[a-f0-9]{12}\.log$/);
  });

  it('stops queued Jenkins graph fetches after the fetcher reaches a stop reason', async () => {
    const rootUrl = 'https://jenkins.example/job/root/1/';
    const childUrls = [
      'https://jenkins.example/job/child-1/1/',
      'https://jenkins.example/job/child-2/1/',
      'https://jenkins.example/job/child-3/1/',
    ];
    const fetchedUrls = [];
    const fetcher = {
      nodes: new Map(),
      limits: { maxNodes: 10, maxParallelFetches: 1 },
      stopReason: null,
      shouldStop() {
        return Boolean(this.stopReason);
      },
      stop(reason) {
        this.stopReason ??= reason;
        return this.stopReason;
      },
      async fetch(url, parentUrls = []) {
        fetchedUrls.push(url);
        const parents = Array.isArray(parentUrls) ? parentUrls : [parentUrls].filter(Boolean);
        const node = {
          buildUrl: url,
          parentUrls: new Set(parents),
          childUrls: new Set(),
          fetchError: null,
          downstreamBuilds: url === rootUrl ? childUrls.map((childUrl) => ({ url: childUrl })) : [],
        };
        if (url === childUrls[0]) {
          node.fetchError = this.stop('Jenkins diagnostics exceeded max_total_log_bytes=10');
        }
        this.nodes.set(url, node);
        return node;
      },
    };

    await collectBuildGraph({ fetcher, rootUrl });
    const graph = buildGraphSummary({
      initialUrl: rootUrl,
      rootUrl,
      limits: jenkinsLimits(),
      nodes: [...fetcher.nodes.values()],
      stopReason: fetcher.stopReason,
    });
    const stdout = formatBundleStdout({
      artifactDir: '/tmp/jenkins-artifacts',
      summaryPath: '/tmp/jenkins-artifacts/summary.md',
      graphPath: '/tmp/jenkins-artifacts/graph.json',
      logIndexPath: '/tmp/jenkins-artifacts/logs/index.json',
      graph,
    });

    assert.deepEqual(fetchedUrls, [rootUrl, childUrls[0]]);
    assert.equal(graph.partial, true);
    assert.match(stdout, /partial=true/);
    assert.match(stdout, /stop_reason=Jenkins diagnostics exceeded max_total_log_bytes=10/);
  });

  it('exposes every prefetched Jenkins console URL to the reply renderer', () => {
    const nodes = Array.from({ length: 6 }, (_, index) => {
      const number = index + 1;
      const buildUrl = `https://jenkins.example/job/child-${number}/1/`;
      return {
        buildUrl,
        consoleUrl: `${buildUrl}console`,
        consoleTextUrl: `${buildUrl}consoleText`,
        parentUrls: new Set(),
        childUrls: new Set(),
        fullDisplayName: `child-${number}`,
        number: '1',
        result: 'FAILURE',
        signalLines: [],
        infraSignals: [],
        logBytes: 1,
        localLog: `/tmp/jenkins-artifacts/logs/child-${number}.log`,
        localLogRelative: `logs/child-${number}.log`,
      };
    });
    const graph = buildGraphSummary({
      initialUrl: nodes[0].buildUrl,
      rootUrl: nodes[0].buildUrl,
      limits: jenkinsLimits(),
      nodes,
    });
    const stdout = formatBundleStdout({
      artifactDir: '/tmp/jenkins-artifacts',
      summaryPath: '/tmp/jenkins-artifacts/summary.md',
      graphPath: '/tmp/jenkins-artifacts/graph.json',
      logIndexPath: '/tmp/jenkins-artifacts/logs/index.json',
      graph,
    });

    assert.match(stdout, /prefetched_jenkins_console_urls:/);
    assert.match(stdout, /jenkins_console: https:\/\/jenkins\.example\/job\/child-6\/1\/console/);
    assert.equal(
      stdout.match(/recommended_reading_order_preview:[\s\S]*jenkins_console:/g)?.[0]
        .match(/jenkins_console:/g).length,
      5,
    );
  });

  it('continues Jenkins graph traversal when root console log fetch fails', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'jenkins-bundle-test-'));
    await withMockedJenkinsFetch(
      {
        '/job/root/1/api/json': {
          fullDisplayName: 'root',
          number: 1,
          result: 'FAILURE',
          downstreamBuilds: [
            {
              fullName: 'child',
              buildNumber: 2,
              result: 'UNSTABLE',
            },
          ],
          artifacts: [],
        },
        '/job/root/1/consoleText': 'x'.repeat(20),
        '/job/child/2/api/json': {
          fullDisplayName: 'child #2',
          number: 2,
          result: 'UNSTABLE',
          artifacts: [],
        },
        '/job/child/2/consoleText': 'fail',
      },
      async () => {
        const bundle = await diagnoseBundle({
          config: jenkinsConfig(),
          url: 'https://jenkins.example/job/root/1/',
          tailLines: 10,
          artifactDir: temp,
          limits: {
            ...jenkinsLimits(),
            maxLogBytesPerNode: 5,
          },
        });

        assert.equal(bundle.graph.counts.total_jobs_discovered, 2);
        assert.equal(bundle.graph.counts.fetch_error_jobs, 1);
        assert.deepEqual(
          bundle.graph.recommended_reading_order.map((node) => node.id),
          ['child#2', 'root#1'],
        );
        assert.match(bundle.graph.nodes.find((node) => node.id === 'root#1').fetch_error, /max_log_bytes_per_node=5/);
      },
    );
  });

  it('does not hydrate console-derived Jenkins URLs or build-line text', async () => {
    await withMockedJenkinsFetch(
      {
        '/job/root/1/api/json': {
          fullDisplayName: 'root',
          number: 1,
          result: 'FAILURE',
          artifacts: [],
        },
        '/job/root/1/consoleText':
          [
            'Starting building: unrelated-secret-job #99',
            'Build unrelated-secret-job #99 completed: FAILURE',
            'fatal see https://jenkins.example/job/unrelated-secret-job/99/console',
          ].join('\n'),
      },
      async () => {
        const report = await fetchBuildReport({
          config: jenkinsConfig(),
          url: 'https://jenkins.example/job/root/1/',
          tailLines: 10,
          maxLogBytes: 1000,
          fetchTimeoutMs: 1000,
          fetchRetries: 1,
        });

        assert.deepEqual(report.downstreamBuilds, []);
      },
    );
  });

  it('hydrates downstream builds only from Jenkins API metadata', async () => {
    await withMockedJenkinsFetch(
      {
        '/job/root/1/api/json': {
          fullDisplayName: 'root',
          number: 1,
          result: 'FAILURE',
          actions: [
            {
              builds: [
                {
                  fullDisplayName: 'folder » child #2',
                  number: 2,
                  result: 'FAILURE',
                  url: 'https://jenkins.example/job/folder/job/child/2/',
                },
              ],
              triggeredBuilds: [
                {
                  jobName: 'folder/triggered-child',
                  buildNumber: 3,
                  result: 'SUCCESS',
                },
              ],
            },
          ],
          downstreamBuilds: [
            {
              fullName: 'folder/direct-child',
              buildNumber: 4,
              result: 'UNSTABLE',
            },
          ],
          subBuilds: [
            {
              jobName: 'matrix-child',
              buildNumber: 5,
              result: 'FAILURE',
              url: 'https://jenkins.example/job/matrix-child/5/',
            },
          ],
          artifacts: [],
        },
        '/job/root/1/consoleText':
          [
            'Starting building: spoofed-secret-job #99',
            'Build spoofed-secret-job #99 completed: FAILURE',
            'fatal see https://jenkins.example/job/spoofed-secret-job/99/console',
          ].join('\n'),
      },
      async () => {
        const report = await fetchBuildReport({
          config: jenkinsConfig(),
          url: 'https://jenkins.example/job/root/1/',
          tailLines: 10,
          maxLogBytes: 1000,
          fetchTimeoutMs: 1000,
          fetchRetries: 1,
        });

        assert.deepEqual(
          report.downstreamBuilds.map((build) => build.url).sort(),
          [
            'https://jenkins.example/job/folder/job/child/2/',
            'https://jenkins.example/job/folder/job/direct-child/4/',
            'https://jenkins.example/job/folder/job/triggered-child/3/',
            'https://jenkins.example/job/matrix-child/5/',
          ],
        );
        assert.deepEqual(
          report.downstreamFailedBuilds.map((build) => build.url).sort(),
          [
            'https://jenkins.example/job/folder/job/child/2/',
            'https://jenkins.example/job/folder/job/direct-child/4/',
            'https://jenkins.example/job/matrix-child/5/',
          ],
        );
        assert(!report.downstreamBuilds.some((build) => build.url.includes('spoofed-secret-job')));
      },
    );
  });

  it('bounds non-bundle Jenkins diagnose console fetches without retrying budget errors', async () => {
    let consoleFetches = 0;
    await withMockedJenkinsFetch(
      {
        '/job/root/1/api/json': {
          fullDisplayName: 'root',
          number: 1,
          result: 'FAILURE',
          artifacts: [],
        },
        '/job/root/1/consoleText': 'x'.repeat(20),
      },
      async () => {
        await assert.rejects(
          () => diagnoseBuild({
            config: jenkinsConfig(),
            url: 'https://jenkins.example/job/root/1/',
            tailLines: 10,
            limits: {
              ...jenkinsLimits(),
              maxTotalLogBytes: 5,
              maxLogBytesPerNode: 5,
            },
          }),
          /exceeded max_log_bytes_per_node=5/,
        );
        consoleFetches = fetchCallCount('/job/root/1/consoleText');
      },
    );
    assert.equal(consoleFetches, 1);
  });

  it('reports GUI console links from non-bundle Jenkins diagnose', async () => {
    await withMockedJenkinsFetch(
      {
        '/job/root/1/api/json': {
          fullDisplayName: 'root',
          number: 1,
          result: 'FAILURE',
          artifacts: [],
        },
        '/job/root/1/consoleText': 'fatal failure',
      },
      async () => {
        const report = await diagnoseBuild({
          config: jenkinsConfig(),
          url: 'https://jenkins.example/job/root/1/',
          tailLines: 10,
          limits: jenkinsLimits(),
        });

        assert.equal(report.consoleUrl, 'https://jenkins.example/job/root/1/console');
        assert.doesNotMatch(formatReport(report), /consoleText/);
      },
    );
  });
});

describe('deploy-config CLI and execution', () => {
  it('dry-run prints a plan without executing commands', async () => {
    let stdout = '';
    let executed = false;
    const status = await runCli({
      argv: ['--dry-run'],
      stdout: writer((chunk) => {
        stdout += chunk;
      }),
      stderr: writer(),
      runner: async () => {
        executed = true;
      },
    });

    assert.equal(status, 0);
    assert.equal(executed, false);
    assert.match(stdout, /mode=dry-run/);
    assert.match(stdout, /checkout_work_dir=/);
    assert.match(stdout, /command_1=\/usr\/bin\/git -c advice\.detachedHead=false/);
  });

  it('apply executes commands with scrubbed env, installs candidate metadata, and clears the lock', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'deploy-config-test-'));
    const plan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--skip-restart',
        '--checkout-dir',
        path.join(temp, 'checkout'),
        '--rendered-config',
        path.join(temp, 'rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(temp, 'run', 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );
    const calls = [];

    const metadata = await executePlan({
      plan,
      parentEnv: {
        PATH: '/bin',
        SSH_AUTH_SOCK: '/tmp/agent.sock',
        WEBEX_ACCESS_TOKEN: 'secret',
      },
      runner: async (command, env) => {
        calls.push({ command, env });
        if (command.bin === '/usr/bin/bash') {
          await fs.mkdir(path.dirname(plan.candidateConfig), { recursive: true });
          await fs.writeFile(plan.candidateConfig, 'candidate config\n', 'utf8');
        }
        return { stdout: command.capture === 'configRevision' ? `${'a'.repeat(40)}\n` : '', stderr: '' };
      },
    });

    assert.equal(metadata.status, 'installed_without_restart');
    assert.equal(metadata.service_restart_skipped, true);
    assert.equal(metadata.config_revision, 'a'.repeat(40));
    assert.equal(calls.length, plan.commands.length);
    assert(calls.every((call) => call.env.SSH_AUTH_SOCK === undefined));
    assert(calls.every((call) => call.env.WEBEX_ACCESS_TOKEN === undefined));
    assert(calls.every((call) => call.env.PATH === '/usr/bin:/bin'));
    assert(calls.every((call) => call.command.cwd === '/'));
    assert(calls.filter((call) => call.command.bin === '/usr/bin/git').every((call) => call.env.GIT_SSH_COMMAND.includes('/usr/bin/ssh')));
    assert.equal(JSON.parse(await fs.readFile(plan.metadataFile, 'utf8')).config_revision, 'a'.repeat(40));
    assert.equal(await fs.readFile(plan.renderedConfig, 'utf8'), 'candidate config\n');
    assert.equal((await fs.stat(plan.renderedConfig)).mode & 0o777, 0o644);
    assert.equal((await fs.stat(path.dirname(plan.lockDir))).isDirectory(), true);
    await assert.rejects(() => fs.stat(plan.lockDir), /ENOENT/);
  });

  it('preserves existing rendered config metadata while installing', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'deploy-config-test-'));
    const plan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--skip-restart',
        '--checkout-dir',
        path.join(temp, 'checkout'),
        '--rendered-config',
        path.join(temp, 'rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(temp, 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );
    await fs.mkdir(path.dirname(plan.renderedConfig), { recursive: true });
    await fs.writeFile(plan.renderedConfig, 'old config\n', { mode: 0o444 });

    await executePlan({
      plan,
      runner: async (command) => {
        if (command.bin === '/usr/bin/bash') {
          await fs.writeFile(plan.candidateConfig, 'new config\n', { mode: 0o644 });
        }
        return { stdout: command.capture === 'configRevision' ? `${'b'.repeat(40)}\n` : '', stderr: '' };
      },
    });

    assert.equal(await fs.readFile(plan.renderedConfig, 'utf8'), 'new config\n');
    assert.equal((await fs.stat(plan.renderedConfig)).mode & 0o777, 0o444);
  });

  it('rejects untrusted existing deployment directories', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'deploy-config-test-'));
    const checkoutDir = path.join(temp, 'checkout');
    await fs.mkdir(checkoutDir, { recursive: true });
    await fs.chmod(checkoutDir, 0o777);
    const plan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--skip-restart',
        '--checkout-dir',
        checkoutDir,
        '--rendered-config',
        path.join(temp, 'rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(temp, 'run', 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );
    let commandRan = false;

    await assert.rejects(
      () => executePlan({
        plan,
        runner: async () => {
          commandRan = true;
          return { stdout: '', stderr: '' };
        },
      }),
      /checkout-dir mode is not trusted/,
    );

    assert.equal(commandRan, false);
    await assert.rejects(() => fs.stat(plan.lockDir), /ENOENT/);

    const lockParent = path.join(temp, 'unsafe-run');
    await fs.mkdir(lockParent, { recursive: true });
    await fs.chmod(lockParent, 0o777);
    const lockPlan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--skip-restart',
        '--checkout-dir',
        path.join(temp, 'safe-checkout'),
        '--rendered-config',
        path.join(temp, 'safe-rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'safe-rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(lockParent, 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );

    await assert.rejects(
      () => executePlan({ plan: lockPlan }),
      /lock parent mode is not trusted/,
    );
  });

  it('does not roll back a successful deployment when backup cleanup fails', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'deploy-config-test-'));
    const plan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--checkout-dir',
        path.join(temp, 'checkout'),
        '--rendered-config',
        path.join(temp, 'rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(temp, 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );
    await fs.mkdir(path.dirname(plan.renderedConfig), { recursive: true });
    await fs.writeFile(plan.renderedConfig, 'old config\n', { mode: 0o644 });
    let failBackupCleanup = false;
    const fsApi = {
      ...fs,
      async rm(file, options) {
        if (failBackupCleanup && file === plan.backupConfig) {
          throw new Error('backup cleanup failed');
        }
        return await fs.rm(file, options);
      },
    };

    const metadata = await executePlan({
      plan,
      fsApi,
      runner: async (command) => {
        if (command.bin === '/usr/bin/bash') {
          await fs.writeFile(plan.candidateConfig, 'new config\n', 'utf8');
        }
        if (command.bin === '/usr/bin/systemctl') {
          failBackupCleanup = true;
        }
        return { stdout: command.capture === 'configRevision' ? `${'f'.repeat(40)}\n` : '', stderr: '' };
      },
    });

    assert.equal(await fs.readFile(plan.renderedConfig, 'utf8'), 'new config\n');
    assert.equal(metadata.status, 'deployed');
    assert.equal(metadata.backup_cleanup_error, 'backup cleanup failed');
    assert.equal(JSON.parse(await fs.readFile(plan.metadataFile, 'utf8')).backup_cleanup_error, 'backup cleanup failed');
  });

  it('records post-commit metadata failures without implying apply rollback', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'deploy-config-test-'));
    const plan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--checkout-dir',
        path.join(temp, 'checkout'),
        '--rendered-config',
        path.join(temp, 'rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(temp, 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );
    const fsApi = {
      ...fs,
      async writeFile(file, data, options) {
        if (file === plan.metadataFile && String(data).includes('"status": "deployed"')) {
          throw new Error('metadata write failed');
        }
        return await fs.writeFile(file, data, options);
      },
    };
    let restartAttempts = 0;

    await assert.rejects(
      () => executePlan({
        plan,
        fsApi,
        runner: async (command) => {
          if (command.bin === '/usr/bin/bash') {
            await fs.mkdir(path.dirname(plan.candidateConfig), { recursive: true });
            await fs.writeFile(plan.candidateConfig, 'new config\n', 'utf8');
          }
          if (command.bin === '/usr/bin/systemctl') {
            restartAttempts += 1;
          }
          return { stdout: command.capture === 'configRevision' ? `${'8'.repeat(40)}\n` : '', stderr: '' };
        },
      }),
      /metadata write failed/,
    );

    assert.equal(await fs.readFile(plan.renderedConfig, 'utf8'), 'new config\n');
    assert.equal(restartAttempts, 1);
    const metadata = JSON.parse(await fs.readFile(plan.metadataFile, 'utf8'));
    assert.equal(metadata.status, 'failed_after_commit');
    assert.equal(metadata.config_revision, '8'.repeat(40));
  });

  it('records failure metadata when validation fails before install', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'deploy-config-test-'));
    const plan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--skip-restart',
        '--checkout-dir',
        path.join(temp, 'checkout'),
        '--rendered-config',
        path.join(temp, 'rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(temp, 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );
    await fs.mkdir(path.dirname(plan.renderedConfig), { recursive: true });
    await fs.writeFile(plan.renderedConfig, 'old config\n', 'utf8');
    await fs.writeFile(
      plan.metadataFile,
      `${JSON.stringify({ status: 'deployed', config_revision: 'old' }, null, 2)}\n`,
      'utf8',
    );

    await assert.rejects(
      () => executePlan({
        plan,
        runner: async (command) => {
          if (command.bin === '/usr/bin/bash') {
            throw new Error('validation failed access_token=secret');
          }
          return { stdout: command.capture === 'configRevision' ? `${'7'.repeat(40)}\n` : '', stderr: '' };
        },
      }),
      /validation failed/,
    );

    assert.equal(await fs.readFile(plan.renderedConfig, 'utf8'), 'old config\n');
    const failureMetadata = JSON.parse(await fs.readFile(plan.metadataFile, 'utf8'));
    assert.equal(failureMetadata.status, 'failed_apply');
    assert.equal(failureMetadata.config_revision, '7'.repeat(40));
    assert.match(failureMetadata.reason, /validation failed/);
    assert.doesNotMatch(failureMetadata.reason, /secret/);
    await assert.rejects(() => fs.stat(plan.lockDir), /ENOENT/);
  });

  it('rolls back the rendered config and records failure metadata if service restart fails', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'deploy-config-test-'));
    const plan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--checkout-dir',
        path.join(temp, 'checkout'),
        '--rendered-config',
        path.join(temp, 'rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(temp, 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );
    await fs.mkdir(path.dirname(plan.renderedConfig), { recursive: true });
    await fs.writeFile(plan.renderedConfig, 'old config\n', { mode: 0o644 });
    let restartAttempts = 0;

    await assert.rejects(
      () => executePlan({
        plan,
        runner: async (command) => {
          if (command.bin === '/usr/bin/bash') {
            await fs.writeFile(plan.candidateConfig, 'new config\n', 'utf8');
          }
          if (command.bin === '/usr/bin/systemctl') {
            restartAttempts += 1;
            if (restartAttempts === 1) {
              throw new Error('restart failed');
            }
          }
          return { stdout: command.capture === 'configRevision' ? `${'c'.repeat(40)}\n` : '', stderr: '' };
        },
      }),
      /restart failed/,
    );

    assert.equal(await fs.readFile(plan.renderedConfig, 'utf8'), 'old config\n');
    assert.equal(restartAttempts, 2);
    const failureMetadata = JSON.parse(await fs.readFile(plan.metadataFile, 'utf8'));
    assert.equal(failureMetadata.status, 'failed_restart_rolled_back');
    assert.equal(failureMetadata.config_revision, 'c'.repeat(40));
    await assert.rejects(() => fs.stat(plan.lockDir), /ENOENT/);
  });

  it('records failure metadata if rollback succeeds but service still cannot restart', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'deploy-config-test-'));
    const plan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--checkout-dir',
        path.join(temp, 'checkout'),
        '--rendered-config',
        path.join(temp, 'rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(temp, 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );
    await fs.mkdir(path.dirname(plan.renderedConfig), { recursive: true });
    await fs.writeFile(plan.renderedConfig, 'old config\n', { mode: 0o644 });
    let restartAttempts = 0;

    await assert.rejects(
      () => executePlan({
        plan,
        runner: async (command) => {
          if (command.bin === '/usr/bin/bash') {
            await fs.writeFile(plan.candidateConfig, 'new config\n', 'utf8');
          }
          if (command.bin === '/usr/bin/systemctl') {
            restartAttempts += 1;
            throw new Error(`restart failed ${restartAttempts}`);
          }
          return { stdout: command.capture === 'configRevision' ? `${'e'.repeat(40)}\n` : '', stderr: '' };
        },
      }),
      /restored previous config but service restart also failed/,
    );

    assert.equal(await fs.readFile(plan.renderedConfig, 'utf8'), 'old config\n');
    assert.equal(restartAttempts, 2);
    const failureMetadata = JSON.parse(await fs.readFile(plan.metadataFile, 'utf8'));
    assert.equal(failureMetadata.status, 'failed_restart_rollback_restart_failed');
    assert.equal(failureMetadata.config_revision, 'e'.repeat(40));
    assert.match(failureMetadata.reason, /restart failed 1/);
    assert.match(failureMetadata.reason, /restart failed 2/);
    await assert.rejects(() => fs.stat(plan.lockDir), /ENOENT/);
  });

  it('cleans candidate and lock even when rollback fails', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'deploy-config-test-'));
    const plan = buildDeployPlan(
      parseArgsAllow([
        '--apply',
        '--checkout-dir',
        path.join(temp, 'checkout'),
        '--rendered-config',
        path.join(temp, 'rendered', 'production.toml'),
        '--metadata-file',
        path.join(temp, 'rendered', 'deploy-status.json'),
        '--lock-dir',
        path.join(temp, 'deploy.lock'),
        '--bot-code-dir',
        path.join(temp, 'bot-code'),
      ]),
    );
    await fs.mkdir(path.dirname(plan.renderedConfig), { recursive: true });
    await fs.writeFile(plan.renderedConfig, 'old config\n', { mode: 0o644 });
    let failRollback = false;
    let rollbackRenameAttempts = 0;
    const fsApi = {
      ...fs,
      async rename(source, target) {
        if (failRollback && source === plan.backupConfig && target === plan.renderedConfig) {
          rollbackRenameAttempts += 1;
          throw new Error('rollback rename failed');
        }
        return await fs.rename(source, target);
      },
    };

    await assert.rejects(
      () => executePlan({
        plan,
        fsApi,
        runner: async (command) => {
          if (command.bin === '/usr/bin/bash') {
            await fs.writeFile(plan.candidateConfig, 'new config\n', 'utf8');
          }
          if (command.bin === '/usr/bin/systemctl') {
            failRollback = true;
            throw new Error('restart failed');
          }
          return { stdout: command.capture === 'configRevision' ? `${'d'.repeat(40)}\n` : '', stderr: '' };
        },
      }),
      /restart failed; failed to restore previous config: rollback rename failed/,
    );

    await assert.rejects(() => fs.stat(plan.candidateConfig), /ENOENT/);
    await assert.rejects(() => fs.stat(plan.lockDir), /ENOENT/);
    assert.equal(rollbackRenameAttempts, 1);
    assert.equal(await fs.readFile(plan.renderedConfig, 'utf8'), 'new config\n');
    const failureMetadata = JSON.parse(await fs.readFile(plan.metadataFile, 'utf8'));
    assert.equal(failureMetadata.status, 'failed_restart_rollback_failed');
    assert.equal(failureMetadata.config_revision, 'd'.repeat(40));
  });

  it('bounds child output captured by runCommand', async () => {
    const result = await runCommand(
      {
        bin: '/usr/bin/python3',
        args: ['-c', 'import sys; sys.stdout.write("x" * 20); sys.stderr.write("y" * 20)'],
        timeoutMs: 5_000,
        outputLimitBytes: 5,
      },
      scrubEnv(),
    );

    assert.equal(result.stdout, 'xxxxx');
    assert.equal(result.stderr, 'yyyyy');
    assert.equal(result.stdoutTruncated, true);
    assert.equal(result.stderrTruncated, true);
  });

  it('times out child processes', async () => {
    await assert.rejects(
      () => runCommand(
        {
          bin: process.execPath,
          args: [
            '-e',
            'const { spawn } = require("node:child_process"); spawn("sleep", ["10"]); setTimeout(() => {}, 10_000);',
          ],
          timeoutMs: 50,
          outputLimitBytes: 100,
        },
        scrubEnv(),
      ),
      /timed out after 50ms/,
    );
  });
});

function parseArgsAllow(args) {
  return parseArgs(args, { allowHostOverrides: true });
}

function runStaticConfigPolicy(configPath) {
  return spawnSync('python3', ['scripts/config-policy/static-config-check.py', configPath], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
}

function staticPolicyRenderedConfig(jenkinsHelperPath) {
  const productionRoom = 'Y2lzY29zcGFyazovL3VzL1JPT00vZjY2Yzg5MDAtYzdiYi0xMWU4LTk2NmQtYzU3YTQxMzQxYjI4';
  const stagingRoom = 'Y2lzY29zcGFyazovL3VzL1JPT00vNTMxMzQ4ZjAtNmJlZC0xMWYxLWFhNWUtZGY0YjBjYzc4YzY5';
  const diagnosisPrompt = [
    'Use British English only',
    'Use only the prefetched Jenkins diagnostics bundle',
    'Do not use network commands',
    'Jenkins APIs',
    'write commands',
    'credentials',
    'token values',
    'Output only compact JSON',
    'Do not use consoleText links',
    'Markdown, code fences',
  ].join('\\n');
  const productionPrompt = [
    diagnosisPrompt,
    'staging-only',
    'read-only production Webex space',
    'mirrored into the staging Webex space',
    'do not suggest or imply any action in the production space',
  ].join('\\n');
  const followupPrompt = [
    'staging Webex thread',
    'mirrored read-only production Jenkins alert',
    'Use British English only',
    'Do not suggest or imply any action in the production space',
    'prefetched Jenkins diagnostics bundle',
    'Do not use network commands',
    'Jenkins APIs',
    'write commands',
    'credentials',
    'token values',
    'Output only compact JSON',
    'Set `include_evidence` to false for ordinary follow-up answers',
    'Set `include_evidence` to true only when the current follow-up explicitly asks',
    'Do not use consoleText links',
    'Markdown, code fences',
  ].join('\\n');

  return `
state_file = "/var/lib/webex-generic-account-bot/state/state.jsonl"
self_person_id = "Y2lzY29zcGFyazovL3VzL1BFT1BMRS9iYTcyOTQzZi1jNjdlLTRlNjUtOGYyYi01MGQwNmJlNGM0MzQ"

[server]
bind = "127.0.0.1:8787"
event_path = "/webex/events"
health_path = "/healthz"
sidecar_token_env = "WEBEX_SIDECAR_TOKEN"
allow_unauthenticated = false
max_concurrent_requests = 4
attempt_lease_secs = 1200

[webex]
access_token_file = "/var/lib/webex-headless-access/access-token"

[codex]
bin = "codex"
cwd = "/var/lib/webex-generic-account-bot/codex-workspace"
codex_home = "/var/lib/webex-generic-account-bot/codex-home"
model = "gpt-5.5"
model_reasoning_effort = "xhigh"
sandbox = "read-only"
approval_policy = "never"
timeout_secs = 600
output_limit_chars = 6000
skip_git_repo_check = true
ephemeral = true

[codex.isolation]
mode = "current-user"
trusted_prompt_authors = true

[[rooms]]
name = "Production source mirrored to staging"
room_id = "${productionRoom}"
output_room_id = "${stagingRoom}"
forward_source_message = true
read_only_source = true
reply_format = "jenkins-diagnosis-json"
trigger = "always"
prefixes = ["@miku.gen"]
allowed_person_emails = ["wmejenkin@sparkbot.io"]
allowed_person_ids = []
prompt_template = """${productionPrompt}"""

[rooms.codex]
model = "gpt-5.5"
model_reasoning_effort = "xhigh"

[rooms.jenkins_context]
enabled = true
node_bin = "node"
script = "${jenkinsHelperPath}"
env_file = "/etc/webex-generic-account-bot/jenkins.env"
timeout_secs = 600
max_urls = 3
output_limit_chars = 5000

[rooms.followup]
enabled = true
triggers = ["mention", "quoted-bot-reply"]
allowed_person_emails = ["hoteng@cisco.com", "webex-generic-account-E2E-tester@webex.bot"]
allowed_person_ids = []
allow_all_senders = false
reply_format = "jenkins-followup-json"
max_thread_messages = 30
max_thread_context_chars = 12000
prompt_template = """${followupPrompt}"""

[[rooms]]
name = "Staging Jenkins room"
room_id = "${stagingRoom}"
reply_format = "jenkins-diagnosis-json"
trigger = "prefix"
prefixes = ["wme jenkins"]
allowed_person_emails = ["hoteng@cisco.com", "wmejenkin@sparkbot.io", "webex-generic-account-E2E-tester@webex.bot"]
allowed_person_ids = []
prompt_template = """${diagnosisPrompt}"""

[rooms.codex]
model = "gpt-5.5"
model_reasoning_effort = "xhigh"

[rooms.jenkins_context]
enabled = true
node_bin = "node"
script = "${jenkinsHelperPath}"
env_file = "/etc/webex-generic-account-bot/jenkins.env"
timeout_secs = 600
max_urls = 3
output_limit_chars = 5000
`;
}

function safeTestName(value) {
  return value.replace(/[^A-Za-z0-9_.-]+/g, '_').replace(/^_+|_+$/g, '');
}

function writer(onWrite = () => {}) {
  return {
    write(chunk) {
      onWrite(String(chunk));
    },
  };
}

function jenkinsLimits() {
  return {
    maxNodes: 10,
    maxTotalLogBytes: 1000,
    maxLogBytesPerNode: 500,
    maxFetchSeconds: 10,
    fetchRetries: 1,
    maxParallelFetches: 2,
  };
}

function jenkinsConfig() {
  return {
    baseUrl: new URL('https://jenkins.example/'),
    username: 'user',
    token: 'token',
  };
}

async function withMockedJenkinsFetch(routes, callback) {
  const originalFetch = globalThis.fetch;
  const previousFetchCallCounts = currentFetchCallCounts;
  currentFetchCallCounts = new Map();
  globalThis.fetch = async (url) => {
    const parsed = new URL(url);
    currentFetchCallCounts.set(
      parsed.pathname,
      (currentFetchCallCounts.get(parsed.pathname) ?? 0) + 1,
    );
    const payload = routes[parsed.pathname];
    if (payload === undefined) {
      return new Response('not found', { status: 404 });
    }
    if (typeof payload === 'string') {
      return new Response(payload, { status: 200 });
    }
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  try {
    await callback();
  } finally {
    globalThis.fetch = originalFetch;
    currentFetchCallCounts = previousFetchCallCounts;
  }
}

let currentFetchCallCounts = null;

function fetchCallCount(pathname) {
  return currentFetchCallCounts?.get(pathname) ?? 0;
}
