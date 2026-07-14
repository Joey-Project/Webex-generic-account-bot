import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';

import {
  assertCargoConfigurationIsolated,
  buildEnvironment,
  buildHostRelease,
  cargoBuildInvocation,
  copyMeasuredFile,
  parseArgs as parseBuildArgs,
  publishDirectoryNoReplace,
  readBoundedRegularFile,
  resyncBundle,
} from '../scripts/build-host-release.mjs';
import * as releaseContract from '../scripts/host-release-contract.mjs';
import {
  CARGO_VERSION,
  CODEX_VERSION,
  MINIMUM_NODE_MAJOR,
  RELEASE_FILES,
  RELEASE_PATHS,
  RUSTC_VERSION,
  RUST_TOOLCHAIN_IMAGE_SHA256,
  bundlePayloadPath,
  compareReleasePaths,
} from '../scripts/host-release-contract.mjs';
import {
  assertSupportedNodeVersion,
  consumeExactFile,
  installHostRelease,
  parseArgs as parseInstallArgs,
  publishCandidate,
  resyncInstalledRelease,
  validateBundle,
} from '../scripts/install-host-release.mjs';

const REVISION = 'a'.repeat(40);
const execFileAsync = promisify(execFile);

describe('host release bootstrap', () => {
  it('keeps the release contract unique and path confined', () => {
    assert.equal(new Set(RELEASE_PATHS).size, RELEASE_FILES.length);
    assert.deepEqual(
      [
        'webex-codex-launcher@.service',
        'webex-codex-launcher.socket',
        'webex-codex-launcher.sysusers.conf',
      ].sort(compareReleasePaths),
      [
        'webex-codex-launcher.socket',
        'webex-codex-launcher.sysusers.conf',
        'webex-codex-launcher@.service',
      ],
    );
    for (const entry of RELEASE_FILES) {
      assert.match(entry.installPath, /^(?:bin|code|runtime-sources)\//);
      assert.equal(path.posix.normalize(entry.installPath), entry.installPath);
      assert.equal(path.posix.isAbsolute(entry.installPath), false);
      assert.equal(entry.installPath.split('/').includes('..'), false);
      assert.ok(entry.mode === 0o444 || entry.mode === 0o555 || entry.mode === 0o644);
    }
    assert.equal(
      RELEASE_FILES.find(({ installPath }) => installPath === 'code/scripts/provision-host.mjs').mode,
      0o644,
    );
    for (const entry of RELEASE_FILES.filter(({ installPath }) => (
      installPath.startsWith('code/deploy/systemd/')
    ))) {
      assert.equal(entry.mode, 0o644);
    }
  });

  it('parses only explicit build inputs and fixed install modes', () => {
    assert.deepEqual(
      parseBuildArgs([
        '--output', '/tmp/release',
        '--input-root', '/tmp/release-inputs',
        '--codex-package-root', '/tmp/codex',
        '--rust-toolchain-image', '/tmp/rust-toolchain.squashfs',
      ]),
      {
        output: '/tmp/release',
        inputRoot: '/tmp/release-inputs',
        codexPackageRoot: '/tmp/codex',
        rustToolchainImage: '/tmp/rust-toolchain.squashfs',
      },
    );
    assert.deepEqual(parseInstallArgs([]), { apply: false, json: false });
    assert.deepEqual(
      parseInstallArgs([
        '--apply',
        '--json',
        '--expected-bot-revision',
        REVISION,
        '--expected-manifest-sha256',
        'b'.repeat(64),
      ]),
      {
        apply: true,
        json: true,
        expectedBotRevision: REVISION,
        expectedManifestSha256: 'b'.repeat(64),
      },
    );
    assert.throws(() => parseInstallArgs(['--apply', '--dry-run']), /exactly one install mode/);
    assert.throws(() => parseInstallArgs(['--bundle', '/tmp/x']), /unknown argument/);
  });

  it('requires the deployment host Node.js runtime contract', () => {
    assert.equal(MINIMUM_NODE_MAJOR, 24);
    assert.doesNotThrow(() => assertSupportedNodeVersion('24.0.0'));
    assert.doesNotThrow(() => assertSupportedNodeVersion('26.3.0'));
    assert.throws(() => assertSupportedNodeVersion('23.11.1'), /Node\.js 24 or newer/);
    assert.throws(() => assertSupportedNodeVersion('invalid'), /Node\.js 24 or newer/);
  });

  it('remaps private build paths and fixes reproducibility inputs', () => {
    const environment = buildEnvironment(
      '/tmp/release scratch',
      '/tmp/release scratch/rust-toolchain',
      { CARGO_TARGET_DIR: '/tmp/release scratch/target' },
      ['-Ctarget-feature=+crt-static'],
    );
    assert.equal(environment.HOME, '/tmp/release scratch/home');
    assert.equal(environment.CARGO_HOME, '/tmp/release scratch/cargo-home');
    assert.equal(environment.SOURCE_DATE_EPOCH, '0');
    assert.equal(environment.CC, '/usr/bin/cc');
    assert.equal(environment.AR, '/usr/bin/ar');
    assert.equal(environment.CC_x86_64_unknown_linux_gnu, '/usr/bin/cc');
    assert.equal(environment.AR_x86_64_unknown_linux_gnu, '/usr/bin/ar');
    assert.equal(environment.CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER, '/usr/bin/cc');
    assert.equal(
      environment.CARGO_ENCODED_RUSTFLAGS,
      [
        '--remap-path-prefix=/tmp/release scratch=/build',
        '-Ctarget-feature=+crt-static',
      ].join('\u001f'),
    );
    assert.equal('RUSTUP_HOME' in environment, false);
  });

  it('keeps caller Cargo configuration outside the build search path', () => {
    const invocation = cargoBuildInvocation('/tmp/caller-controlled/release/source', [
      '--locked',
      '--release',
    ]);
    assert.deepEqual(invocation, {
      args: [
        'build',
        '--manifest-path',
        '/tmp/caller-controlled/release/source/Cargo.toml',
        '--locked',
        '--release',
      ],
      cwd: '/',
    });
  });

  it('does not load Cargo configuration above the frozen source snapshot', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-cargo-config-test-'));
    const source = path.join(root, 'source');
    try {
      await fs.mkdir(path.join(root, '.cargo'));
      await fs.mkdir(path.join(source, 'src'), { recursive: true });
      await fs.writeFile(
        path.join(root, '.cargo', 'config.toml'),
        '[build]\nrustc-wrapper = "/caller-controlled/rustc-wrapper"\n',
      );
      await fs.writeFile(
        path.join(source, 'Cargo.toml'),
        '[package]\nname = "cargo-config-isolation"\nversion = "0.0.0"\nedition = "2024"\n',
      );
      await fs.writeFile(path.join(source, 'src', 'main.rs'), 'fn main() {}\n');
      const invocation = cargoBuildInvocation(source, [
        '--offline',
        '--target-dir',
        path.join(root, 'target'),
      ]);
      const cargo = process.env.CARGO ?? path.join(os.homedir(), '.cargo', 'bin', 'cargo');
      await execFileAsync(cargo, invocation.args, {
        cwd: invocation.cwd,
        env: {
          CARGO_HOME: path.join(root, 'cargo-home'),
          HOME: process.env.HOME,
          LANG: 'C',
          LC_ALL: 'C',
          PATH: `${path.dirname(cargo)}:${process.env.PATH}`,
          ...(process.env.RUSTUP_HOME === undefined
            ? {}
            : { RUSTUP_HOME: process.env.RUSTUP_HOME }),
        },
        maxBuffer: 1024 * 1024,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('rejects Cargo configuration at the fixed build working-directory root', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-cargo-root-config-test-'));
    try {
      const absent = await assertCargoConfigurationIsolated(
        undefined,
        root,
        process.getuid(),
      );
      await assert.doesNotReject(assertCargoConfigurationIsolated(
        absent,
        root,
        process.getuid(),
      ));
      await fs.mkdir(path.join(root, '.cargo'), { mode: 0o700 });
      await fs.writeFile(
        path.join(root, '.cargo', 'config.toml'),
        '[build]\nrustc-wrapper = "/unreviewed/rustc-wrapper"\n',
      );
      await assert.rejects(
        assertCargoConfigurationIsolated(undefined, root, process.getuid()),
        /Cargo configuration is not permitted/,
      );
      await fs.rm(path.join(root, '.cargo'), { recursive: true });
      await fs.mkdir(path.join(root, '.cargo'), { mode: 0o777 });
      await fs.chmod(path.join(root, '.cargo'), 0o777);
      await assert.rejects(
        assertCargoConfigurationIsolated(undefined, root, process.getuid()),
        /Cargo configuration root is untrusted/,
      );
      await fs.chmod(path.join(root, '.cargo'), 0o700);
      const present = await assertCargoConfigurationIsolated(
        undefined,
        root,
        process.getuid(),
      );
      const transient = path.join(root, '.cargo', 'config.toml');
      await fs.writeFile(transient, '[build]\nrustc-wrapper = "/transient/wrapper"\n');
      await fs.rm(transient);
      await assert.rejects(
        assertCargoConfigurationIsolated(present, root, process.getuid()),
        /Cargo configuration root changed during release build/,
      );
      const stable = await assertCargoConfigurationIsolated(
        undefined,
        root,
        process.getuid(),
      );
      await fs.chmod(path.join(root, '.cargo'), 0o755);
      await assert.rejects(
        assertCargoConfigurationIsolated(stable, root, process.getuid()),
        /Cargo configuration root changed during release build/,
      );
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('stops exact reads at the trusted size and probes EOF once', async () => {
    const reads = [];
    const chunks = [];
    const handle = {
      async read(buffer, offset, length, position) {
        reads.push({ length, position });
        buffer.fill(0x61, offset, offset + length);
        return { bytesRead: position < 4 ? length : 1 };
      },
    };
    await assert.rejects(
      consumeExactFile(handle, 4, 'fixture', (chunk) => chunks.push(Buffer.from(chunk))),
      /host release file changed/,
    );
    assert.deepEqual(reads, [
      { length: 4, position: 0 },
      { length: 1, position: 4 },
    ]);
    assert.equal(Buffer.concat(chunks).toString('utf8'), 'aaaa');
  });

  it('builds, validates, and atomically installs the exact first-release tree', async () => {
    const fixture = await createFixture();
    try {
      const priorUmask = process.umask(0o077);
      let manifest;
      try {
        manifest = await buildFixtureBundle(fixture);
      } finally {
        process.umask(priorUmask);
      }
      assert.equal(manifest.bot_revision, REVISION);
      assert.equal(manifest.codex_version, CODEX_VERSION);
      assert.deepEqual(manifest.build, {
        cargo_version: CARGO_VERSION,
        rustc_version: RUSTC_VERSION,
        toolchain_sha256: RUST_TOOLCHAIN_IMAGE_SHA256,
      });
      assert.deepEqual(manifest.files.map(({ path: file }) => file), RELEASE_PATHS);

      const validated = await validateBundle(
        fixture.bundle,
        process.getuid(),
        process.getgid(),
        fixture.manifestSha256,
        REVISION,
        releaseContract,
      );
      assert.equal(validated.files.length, RELEASE_FILES.length);
      const dryRun = await installFixture(fixture, false);
      assert.equal(dryRun.status, 'dry_run');
      await assertMissing(fixture.installRoot);

      const installed = await installFixture(fixture, true);
      assert.equal(installed.status, 'installed');
      for (const entry of manifest.files) {
        const target = path.join(fixture.installRoot, entry.path);
        const metadata = await fs.lstat(target);
        assert.equal(metadata.isFile(), true);
        assert.equal(metadata.mode & 0o7777, Number.parseInt(entry.mode, 8));
        assert.equal(await fs.readFile(target, 'utf8'), expectedInstalledContents(entry.path));
      }
      const runtime = await fs.lstat(path.join(fixture.installRoot, 'runtime'));
      assert.equal(runtime.isDirectory(), true);
      assert.equal(runtime.mode & 0o7777, 0o755);
      const release = JSON.parse(
        await fs.readFile(path.join(fixture.installRoot, 'release.json'), 'utf8'),
      );
      assert.equal(release.bot_revision, REVISION);
      assert.equal(release.codex_version, CODEX_VERSION);
      assert.deepEqual(release.files, manifest.files);
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('starts the trusted installer through an exact environment-clearing wrapper', async () => {
    const wrapperPath = new URL('../scripts/install-host-release', import.meta.url);
    const wrapper = await fs.readFile(wrapperPath, 'utf8');
    const metadata = await fs.lstat(wrapperPath);
    assert.equal(metadata.mode & 0o111, 0o111);
    assert.equal(wrapper, [
      '#!/bin/sh',
      'set -eu',
      '',
      'exec /usr/bin/env -i \\',
      '  HOME=/root \\',
      '  LANG=C \\',
      '  LC_ALL=C \\',
      '  PATH=/usr/bin:/bin \\',
      '  /usr/bin/node \\',
      '  /usr/local/libexec/webex-host-release/install-host-release.mjs \\',
      '  "$@"',
      '',
    ].join('\n'));
  });

  it('starts the release builder with a fixed Node runtime and cleared environment', async () => {
    const builderPath = new URL('../scripts/build-host-release.mjs', import.meta.url);
    const builder = await fs.readFile(builderPath, 'utf8');
    const metadata = await fs.lstat(builderPath);
    assert.equal(metadata.mode & 0o111, 0o111);
    assert.equal(
      builder.split('\n', 1)[0],
      '#!/usr/bin/env -S -i HOME=/ LANG=C LC_ALL=C PATH=/usr/bin:/bin /usr/bin/node',
    );

    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-builder-env-test-'));
    const marker = path.join(root, 'preload-ran');
    const preload = path.join(root, 'preload.cjs');
    try {
      await fs.writeFile(
        preload,
        `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ran');\n`,
      );
      const { stdout } = await execFileAsync('/usr/bin/env', [
        '-S',
        `-i HOME=/ LANG=C LC_ALL=C PATH=/usr/bin:/bin ${process.execPath}`,
        '-e',
        'process.stdout.write(JSON.stringify(process.env))',
      ], {
        env: { ...process.env, NODE_OPTIONS: `--require=${preload}` },
        maxBuffer: 1024 * 1024,
      });
      assert.deepEqual(JSON.parse(stdout), {
        HOME: '/',
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
      });
      await assertMissing(marker);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('rejects tampering, extra files, links, and an existing install', async () => {
    for (const mutation of ['tamper', 'extra', 'symlink', 'existing']) {
      const fixture = await createFixture();
      try {
        const manifest = await buildFixtureBundle(fixture);
        const first = path.join(fixture.bundle, bundlePayloadPath(manifest.files[0].path));
        if (mutation === 'tamper') {
          const mode = (await fs.lstat(first)).mode & 0o7777;
          await fs.chmod(first, 0o600);
          await fs.writeFile(first, 'changed');
          await fs.chmod(first, mode);
        }
        if (mutation === 'extra') await fs.writeFile(path.join(fixture.bundle, 'extra'), 'extra');
        if (mutation === 'symlink') {
          await fs.unlink(first);
          await fs.symlink('/etc/passwd', first);
        }
        if (mutation === 'existing') await fs.mkdir(fixture.installRoot);

        await assert.rejects(
          installFixture(fixture, false),
          mutation === 'tamper'
            ? /size mismatch|digest mismatch/
            : mutation === 'extra'
              ? /missing or unexpected entries/
              : mutation === 'symlink'
                ? /special file/
                : /existing host release does not match|directory metadata is invalid/,
        );
      } finally {
        await fs.rm(fixture.root, { recursive: true, force: true });
      }
    }
  });

  it('requires out-of-band release evidence and fixed third-party digests', async () => {
    const fixture = await createFixture();
    try {
      const trustedDigests = await trustedFixtureDigests(fixture);
      await fs.writeFile(fixture.busybox, 'replacement busybox');
      await assert.rejects(
        buildFixtureBundle(fixture, trustedDigests),
        /trusted release source digest mismatch/,
      );
      await assertMissing(fixture.bundle);

      await fs.writeFile(fixture.busybox, sourceContents('runtime-sources/busybox'));
      await buildFixtureBundle(fixture);
      await assert.rejects(
        validateBundle(
          fixture.bundle,
          process.getuid(),
          process.getgid(),
          'b'.repeat(64),
          REVISION,
          releaseContract,
        ),
        /trusted digest/,
      );
      await assert.rejects(
        installHostRelease(
          { apply: false, json: false },
          {
            bundleRoot: fixture.bundle,
            installRoot: fixture.installRoot,
            expectedUid: process.getuid(),
            expectedGid: process.getgid(),
            requireRoot: false,
            trustAncestors: false,
            contract: releaseContract,
          },
        ),
        /expected-bot-revision/,
      );
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('rejects untrusted Rust toolchain provenance in the bundle manifest', async () => {
    const fixture = await createFixture();
    try {
      await buildFixtureBundle(fixture);
      const manifestPath = path.join(fixture.bundle, 'manifest.json');
      const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
      manifest.build.toolchain_sha256 = '0'.repeat(64);
      const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
      await fs.chmod(manifestPath, 0o600);
      await fs.writeFile(manifestPath, bytes);
      await fs.chmod(manifestPath, 0o444);
      const digest = crypto.createHash('sha256').update(bytes).digest('hex');

      await assert.rejects(
        validateBundle(
          fixture.bundle,
          process.getuid(),
          process.getgid(),
          digest,
          REVISION,
          releaseContract,
        ),
        /Rust toolchain provenance is invalid/,
      );
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('publishes without clobbering a destination that appears concurrently', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-host-publish-test-'));
    const candidate = path.join(root, 'candidate');
    const installRoot = path.join(root, 'installed');
    try {
      await fs.mkdir(candidate);
      await fs.writeFile(path.join(candidate, 'candidate'), 'candidate');
      await fs.mkdir(installRoot);
      await fs.writeFile(path.join(installRoot, 'existing'), 'existing');
      await assert.rejects(
        publishCandidate(candidate, installRoot),
        /appeared during publish/,
      );
      assert.equal(await fs.readFile(path.join(installRoot, 'existing'), 'utf8'), 'existing');
      assert.equal(await fs.readFile(path.join(candidate, 'candidate'), 'utf8'), 'candidate');
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('does not replace a release output that appears during a build', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-bundle-publish-test-'));
    const candidate = path.join(root, 'candidate');
    const output = path.join(root, 'output');
    try {
      await fs.mkdir(candidate);
      await fs.writeFile(path.join(candidate, 'candidate'), 'candidate');
      await fs.mkdir(output);
      await fs.writeFile(path.join(output, 'existing'), 'existing');
      await assert.rejects(
        publishDirectoryNoReplace(candidate, output),
        /appeared during publish/,
      );
      assert.equal(await fs.readFile(path.join(output, 'existing'), 'utf8'), 'existing');
      assert.equal(await fs.readFile(path.join(candidate, 'candidate'), 'utf8'), 'candidate');
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('exports committed blobs instead of repository replacement objects', async () => {
    const fixture = await createFixture();
    const sourcePath = 'scripts/provision-host.mjs';
    const replacementPath = path.join(fixture.root, 'replacement-provision-host.mjs');
    const git = (args) => execFileAsync('/usr/bin/git', args, {
      cwd: fixture.repoRoot,
      env: {
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
      },
      maxBuffer: 1024 * 1024,
    });
    try {
      await git(['init', '--initial-branch=main']);
      await git(['add', '.']);
      await git([
        '-c', 'user.name=Host Release Test',
        '-c', 'user.email=host-release@example.invalid',
        'commit',
        '-m', 'fixture',
      ]);
      const original = (await git(['rev-parse', `HEAD:${sourcePath}`])).stdout.trim();
      await fs.writeFile(replacementPath, 'replacement source\n');
      const replacement = (await git(['hash-object', '-w', replacementPath])).stdout.trim();
      await git(['replace', original, replacement]);
      assert.equal((await git(['cat-file', 'blob', original])).stdout, 'replacement source\n');

      const result = await buildFixtureResult(fixture, undefined, { revision: undefined });
      assert.notEqual(result.manifest.bot_revision, REVISION);
      assert.equal(
        await fs.readFile(
          path.join(fixture.bundle, bundlePayloadPath(`code/${sourcePath}`)),
          'utf8',
        ),
        sourceContents(`code/${sourcePath}`),
      );
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('does not execute local Git behaviour or apply unreviewed archive attributes', async () => {
    const fixture = await createFixture();
    const sourcePath = 'scripts/provision-host.mjs';
    const fsmonitor = path.join(fixture.root, 'fsmonitor');
    const fsmonitorMarker = path.join(fixture.root, 'fsmonitor-ran');
    const attributes = path.join(fixture.root, 'global-attributes');
    const git = (args) => execFileAsync('/usr/bin/git', args, {
      cwd: fixture.repoRoot,
      env: {
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
      },
      maxBuffer: 1024 * 1024,
    });
    try {
      await git(['init', '--initial-branch=main']);
      await git(['add', '.']);
      await git([
        '-c', 'user.name=Host Release Test',
        '-c', 'user.email=host-release@example.invalid',
        'commit',
        '-m', 'fixture',
      ]);
      await fs.writeFile(
        fsmonitor,
        `#!/bin/sh\nprintf ran > "${fsmonitorMarker}"\n/bin/cat\n`,
        { mode: 0o755 },
      );
      await fs.writeFile(attributes, `${sourcePath} filter=host-release-test export-ignore\n`);
      await fs.writeFile(
        path.join(fixture.repoRoot, '.git', 'info', 'attributes'),
        `${sourcePath} filter=host-release-test export-ignore\n`,
      );
      await git(['config', 'core.fsmonitor', fsmonitor]);
      await git(['config', 'core.attributesFile', attributes]);
      await git(['config', 'filter.host-release-test.clean', fsmonitor]);
      await git(['config', 'filter.host-release-test.required', 'true']);
      await fs.writeFile(path.join(fixture.repoRoot, sourcePath), 'worktree-only source\n');

      const result = await buildFixtureResult(fixture, undefined, { revision: undefined });
      assert.notEqual(result.manifest.bot_revision, REVISION);
      await assertMissing(fsmonitorMarker);
      assert.equal(
        await fs.readFile(
          path.join(fixture.bundle, bundlePayloadPath(`code/${sourcePath}`)),
          'utf8',
        ),
        sourceContents(`code/${sourcePath}`),
      );
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses to compound interrupted staging trees', async () => {
    const fixture = await createFixture();
    const stale = path.join(fixture.root, `.bundle-123-${'a'.repeat(24)}.build`);
    try {
      await fs.mkdir(stale, { mode: 0o700 });
      await assert.rejects(
        buildFixtureResult(fixture),
        /stale release staging path requires cleanup/,
      );
      assert.equal((await fs.lstat(stale)).isDirectory(), true);
      await assertMissing(fixture.bundle);
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('rejects shared, writable, symlinked, and missing build parents', async () => {
    for (const mutation of ['shared', 'writable', 'symlink', 'missing']) {
      const fixture = await createFixture();
      try {
        if (mutation === 'shared') {
          fixture.bundle = path.join(os.tmpdir(), `webex-host-release-${crypto.randomUUID()}`);
        } else if (mutation === 'writable') {
          await fs.chmod(fixture.root, 0o777);
        } else if (mutation === 'symlink') {
          const realParent = path.join(fixture.root, 'real-output');
          const linkParent = path.join(fixture.root, 'output-link');
          await fs.mkdir(realParent, { mode: 0o700 });
          await fs.symlink(realParent, linkParent);
          fixture.bundle = path.join(linkParent, 'bundle');
        } else {
          fixture.bundle = path.join(fixture.root, 'missing-output', 'bundle');
        }
        await assert.rejects(
          buildFixtureResult(fixture),
          /untrusted release build (?:ancestor|directory)|release build parent must already exist/,
        );
        await assertMissing(fixture.bundle);
      } finally {
        await fs.chmod(fixture.root, 0o700).catch(() => {});
        await fs.rm(fixture.root, { recursive: true, force: true });
      }
    }
  });

  it('rejects shared, writable, symlinked, missing, and escaped input roots', async () => {
    for (const mutation of ['shared', 'writable', 'symlink', 'missing', 'escaped']) {
      const fixture = await createFixture();
      try {
        if (mutation === 'shared') {
          fixture.inputRoot = os.tmpdir();
        } else if (mutation === 'writable') {
          await fs.chmod(fixture.inputRoot, 0o777);
        } else if (mutation === 'symlink') {
          const realInputRoot = path.join(fixture.root, 'real-inputs');
          await fs.rename(fixture.inputRoot, realInputRoot);
          await fs.symlink(realInputRoot, fixture.inputRoot);
        } else if (mutation === 'missing') {
          fixture.inputRoot = path.join(fixture.root, 'missing-inputs');
        } else {
          const escaped = path.join(fixture.root, 'escaped-toolchain.squashfs');
          await fs.rename(fixture.rustToolchainImage, escaped);
          fixture.rustToolchainImage = escaped;
        }
        await assert.rejects(
          buildFixtureResult(fixture),
          /untrusted release (?:build ancestor|input root)|release input is outside input root|ENOENT/,
        );
        await assertMissing(fixture.bundle);
      } finally {
        await fs.rm(fixture.root, { recursive: true, force: true });
      }
    }
  });

  it('rejects FIFO inputs without waiting for a writer', async () => {
    const fixture = await createFixture();
    const metadata = path.join(fixture.codexRoot, 'codex-package.json');
    const destination = path.join(fixture.root, 'copied-toolchain');
    try {
      await fs.rm(metadata);
      await execFileAsync('/usr/bin/mkfifo', [metadata]);
      await assert.rejects(
        readBoundedRegularFile(metadata, 64 * 1024),
        /outside the permitted size/,
      );
      await fs.rm(fixture.rustToolchainImage);
      await execFileAsync('/usr/bin/mkfifo', [fixture.rustToolchainImage]);
      await assert.rejects(
        copyMeasuredFile(fixture.rustToolchainImage, destination, 0o400),
        /not a bounded regular file/,
      );
      await assertMissing(destination);
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('rechecks build parent trust before publishing', async () => {
    const fixture = await createFixture();
    try {
      await assert.rejects(
        buildFixtureResult(fixture, undefined, {
          buildArtifacts: async () => {
            await fs.chmod(fixture.root, 0o777);
            return {
              hostBinDir: fixture.hostBinDir,
              staticBinDir: fixture.staticBinDir,
              cargoVersion: CARGO_VERSION,
              rustcVersion: RUSTC_VERSION,
              toolchainSha256: RUST_TOOLCHAIN_IMAGE_SHA256,
            };
          },
        }),
        /untrusted release build ancestor/,
      );
      await assertMissing(fixture.bundle);
    } finally {
      await fs.chmod(fixture.root, 0o700).catch(() => {});
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('recovers a matching bundle output after parent sync failure', async () => {
    const fixture = await createFixture();
    try {
      await assert.rejects(
        buildFixtureResult(fixture, undefined, {
          syncDirectory: async () => {
            throw new Error('simulated bundle parent sync failure');
          },
        }),
        /simulated bundle parent sync failure/,
      );
      assert.equal((await fs.lstat(fixture.bundle)).isDirectory(), true);

      const events = [];
      const recovered = await buildFixtureResult(fixture, undefined, {
        resyncBundle: async (root, manifest) => {
          events.push('resync');
          await resyncBundle(root, manifest);
        },
      });
      assert.equal(recovered.status, 'recovered');
      assert.equal(recovered.manifest.bot_revision, REVISION);
      assert.deepEqual(events, ['resync']);
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('does not recover a mismatching pre-existing bundle output', async () => {
    const fixture = await createFixture();
    try {
      const manifest = await buildFixtureBundle(fixture);
      const target = path.join(fixture.bundle, bundlePayloadPath(manifest.files[0].path));
      const mode = (await fs.lstat(target)).mode & 0o7777;
      await fs.chmod(target, 0o600);
      await fs.writeFile(target, 'x'.repeat(manifest.files[0].size));
      await fs.chmod(target, mode);

      await assert.rejects(
        buildFixtureResult(fixture),
        /release output appeared during publish/,
      );
      assert.equal(await fs.readFile(target, 'utf8'), 'x'.repeat(manifest.files[0].size));
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('recovers a fully published release after parent sync failure', async () => {
    const fixture = await createFixture();
    try {
      await buildFixtureBundle(fixture);
      await assert.rejects(
        installFixture(fixture, true, {
          syncDirectory: async (directory) => {
            if (directory === path.dirname(fixture.installRoot)) {
              try {
                await fs.lstat(fixture.installRoot);
                throw new Error('simulated parent sync failure');
              } catch (error) {
                if (error?.code !== 'ENOENT') throw error;
              }
            }
          },
        }),
        /simulated parent sync failure/,
      );
      const recovered = await installFixture(fixture, true);
      assert.equal(recovered.status, 'recovered');
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('recovers one complete pre-publish candidate and rejects an incomplete one', async () => {
    for (const state of ['complete', 'incomplete']) {
      const fixture = await createFixture();
      try {
        await buildFixtureBundle(fixture);
        const candidate = path.join(
          path.dirname(fixture.installRoot),
          `.webex-generic-account-bot-install-${state}`,
        );
        if (state === 'complete') {
          await installFixture(fixture, true);
          await fs.rename(fixture.installRoot, candidate);
          const dryRun = await installFixture(fixture, false);
          assert.equal(dryRun.status, 'recoverable_candidate');
          const events = [];
          const recovered = await installFixture(fixture, true, {
            resyncInstalledRelease: async (root, manifest) => {
              assert.equal(root, candidate);
              assert.equal(manifest.bot_revision, REVISION);
              events.push('resync');
              await resyncInstalledRelease(root, manifest);
            },
            publishCandidate: async (source, destination) => {
              events.push('publish');
              await publishCandidate(source, destination);
            },
          });
          assert.equal(recovered.status, 'recovered');
          assert.deepEqual(events, ['resync', 'publish']);
          assert.equal(await fs.lstat(fixture.installRoot).then((value) => value.isDirectory()), true);
        } else {
          await fs.mkdir(candidate, { mode: 0o755 });
          await assert.rejects(
            installFixture(fixture, true),
            /stale host release candidate requires manual inspection/,
          );
        }
      } finally {
        await fs.rm(fixture.root, { recursive: true, force: true });
      }
    }
  });

  it('rejects content drift in a correctly shaped installed release', async () => {
    const fixture = await createFixture();
    try {
      const manifest = await buildFixtureBundle(fixture);
      await installFixture(fixture, true);
      const target = path.join(fixture.installRoot, manifest.files[0].path);
      const mode = (await fs.lstat(target)).mode & 0o7777;
      await fs.chmod(target, 0o600);
      await fs.writeFile(target, 'x'.repeat(manifest.files[0].size));
      await fs.chmod(target, mode);
      await assert.rejects(
        installFixture(fixture, false),
        /existing host release file does not match/,
      );
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('rejects the wrong Codex package layout before writing a bundle', async () => {
    const fixture = await createFixture();
    try {
      const metadata = path.join(fixture.codexRoot, 'codex-package.json');
      const value = JSON.parse(await fs.readFile(metadata, 'utf8'));
      value.version = '0.143.0';
      await fs.writeFile(metadata, `${JSON.stringify(value)}\n`);
      await assert.rejects(buildFixtureBundle(fixture), /reviewed 0\.142\.3 Linux x64 layout/);
      await assertMissing(fixture.bundle);
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });
});

async function createFixture() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-host-release-test-'));
  const inputRoot = path.join(root, 'inputs');
  const repoRoot = path.join(root, 'repo');
  const hostBinDir = path.join(root, 'host-bin');
  const staticBinDir = path.join(root, 'static-bin');
  const codexRoot = path.join(inputRoot, 'codex');
  const busybox = path.join(root, 'busybox');
  const rustToolchainImage = path.join(inputRoot, 'rust-toolchain.squashfs');
  const bundle = path.join(root, 'bundle');
  const installParent = path.join(root, 'install-parent');
  const installRoot = path.join(installParent, 'webex-generic-account-bot');
  await fs.mkdir(repoRoot, { recursive: true });
  await fs.mkdir(inputRoot, { mode: 0o700 });
  await fs.mkdir(hostBinDir, { recursive: true });
  await fs.mkdir(staticBinDir, { recursive: true });
  await fs.mkdir(codexRoot, { recursive: true, mode: 0o755 });
  await fs.mkdir(installParent, { recursive: true });
  await fs.writeFile(
    rustToolchainImage,
    'unused fixture Rust toolchain image',
    { mode: 0o600 },
  );

  for (const entry of RELEASE_FILES) {
    let source;
    if (entry.kind === 'code') source = path.join(repoRoot, entry.source);
    else if (entry.kind === 'host-binary') source = path.join(hostBinDir, entry.source);
    else if (entry.kind === 'static-binary') source = path.join(staticBinDir, entry.source);
    else if (entry.kind === 'busybox') source = busybox;
    else source = path.join(codexRoot, entry.source.slice('codex/'.length));
    await fs.mkdir(path.dirname(source), { recursive: true, mode: 0o755 });
    await fs.writeFile(source, sourceContents(entry.installPath), { mode: 0o700 });
  }
  await fs.writeFile(
    path.join(codexRoot, 'codex-package.json'),
    `${JSON.stringify({
      entrypoint: 'bin/codex',
      layoutVersion: 1,
      pathDir: 'codex-path',
      resourcesDir: 'codex-resources',
      target: 'x86_64-unknown-linux-musl',
      variant: 'codex',
      version: CODEX_VERSION,
    })}\n`,
  );
  return {
    root,
    inputRoot,
    repoRoot,
    hostBinDir,
    staticBinDir,
    codexRoot,
    busybox,
    rustToolchainImage,
    bundle,
    installRoot,
  };
}

async function buildFixtureBundle(fixture, trustedSourceSha256) {
  const result = await buildFixtureResult(fixture, trustedSourceSha256);
  fixture.manifestSha256 = result.manifestSha256;
  return result.manifest;
}

async function buildFixtureResult(fixture, trustedSourceSha256, injected = {}) {
  const result = await buildHostRelease(
    {
      output: fixture.bundle,
      inputRoot: fixture.inputRoot,
      codexPackageRoot: fixture.codexRoot,
      rustToolchainImage: fixture.rustToolchainImage,
    },
    {
      repoRoot: fixture.repoRoot,
      hostBinDir: fixture.hostBinDir,
      busybox: fixture.busybox,
      revision: REVISION,
      buildArtifacts: async () => ({
        hostBinDir: fixture.hostBinDir,
        staticBinDir: fixture.staticBinDir,
        cargoVersion: CARGO_VERSION,
        rustcVersion: RUSTC_VERSION,
        toolchainSha256: RUST_TOOLCHAIN_IMAGE_SHA256,
      }),
      trustedSourceSha256: trustedSourceSha256 ?? await trustedFixtureDigests(fixture),
      ...injected,
    },
  );
  fixture.manifestSha256 = result.manifestSha256;
  return result;
}

function installFixture(fixture, apply, injected = {}) {
  return installHostRelease(
    {
      apply,
      json: false,
      expectedBotRevision: REVISION,
      expectedManifestSha256: fixture.manifestSha256,
    },
    {
      bundleRoot: fixture.bundle,
      installRoot: fixture.installRoot,
      expectedUid: process.getuid(),
      expectedGid: process.getgid(),
      requireRoot: false,
      trustAncestors: false,
      contract: releaseContract,
      ...injected,
    },
  );
}

function sourceContents(installPath) {
  return `release fixture: ${installPath}\n`;
}

function expectedInstalledContents(installPath) {
  if (installPath !== 'runtime-sources/codex/codex-package.json') {
    return sourceContents(installPath);
  }
  return `${JSON.stringify({
    entrypoint: 'bin/codex',
    layoutVersion: 1,
    pathDir: 'codex-path',
    resourcesDir: 'codex-resources',
    target: 'x86_64-unknown-linux-musl',
    variant: 'codex',
    version: CODEX_VERSION,
  })}\n`;
}

async function trustedFixtureDigests(fixture) {
  const result = {};
  for (const entry of RELEASE_FILES) {
    let source;
    if (entry.kind === 'busybox') source = fixture.busybox;
    else if (entry.kind === 'codex-runtime') {
      source = path.join(fixture.codexRoot, entry.source.slice('codex/'.length));
    } else continue;
    result[entry.installPath] = crypto
      .createHash('sha256')
      .update(await fs.readFile(source))
      .digest('hex');
  }
  return result;
}

async function assertMissing(file) {
  await assert.rejects(fs.lstat(file), { code: 'ENOENT' });
}
