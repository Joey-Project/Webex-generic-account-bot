import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';
import { deflateSync } from 'node:zlib';

import {
  accountSourceBlobBytes,
  assertCargoConfigurationIsolated,
  assertUnprivilegedBuilder,
  buildEnvironment,
  buildHostRelease,
  cargoBuildInvocation,
  cargoVendorConfiguration,
  copyMeasuredFile,
  parseArgs as parseBuildArgs,
  publishDirectoryNoReplace,
  readBoundedRegularFile,
  resolveBusyboxPath,
  resyncBundle,
  snapshotToolchainTree,
  snapshotCargoHomeTree,
  snapshotCargoVendorTree,
  verifyCargoVendorTree,
  verifyToolchainTree,
} from '../scripts/build-host-release.mjs';
import * as releaseContract from '../scripts/host-release-contract.mjs';
import {
  CARGO_VENDOR_IMAGE_SHA256,
  CARGO_VENDOR_TREE_SHA256,
  CARGO_VERSION,
  CODEX_VERSION,
  MINIMUM_NODE_MAJOR,
  RELEASE_FILES,
  RELEASE_PATHS,
  RUSTC_VERSION,
  RUST_TOOLCHAIN_IMAGE_SHA256,
  RUST_TOOLCHAIN_TREE_SHA256,
  TRUSTED_SOURCE_SHA256,
  bundlePayloadPath,
  compareReleasePaths,
} from '../scripts/host-release-contract.mjs';
import {
  assertNoCopyMoveSupported,
  assertSupportedNodeVersion,
  consumeExactFile,
  installHostRelease,
  parseArgs as parseInstallArgs,
  publishCandidate,
  resyncInstalledRelease,
  usage as installUsage,
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
      if (entry.kind === 'code') {
        assert.equal(TRUSTED_SOURCE_SHA256[entry.installPath], undefined);
      } else {
        assert.match(TRUSTED_SOURCE_SHA256[entry.installPath], /^[a-f0-9]{64}$/);
      }
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
        '--repo', '/tmp/repo',
        '--output', '/tmp/release',
        '--input-root', '/tmp/release-inputs',
        '--codex-package-root', '/tmp/codex',
        '--rust-toolchain-image', '/tmp/rust-toolchain.squashfs',
        '--cargo-vendor-image', '/tmp/cargo-vendor.squashfs',
      ]),
      {
        repoRoot: '/tmp/repo',
        output: '/tmp/release',
        inputRoot: '/tmp/release-inputs',
        codexPackageRoot: '/tmp/codex',
        rustToolchainImage: '/tmp/rust-toolchain.squashfs',
        cargoVendorImage: '/tmp/cargo-vendor.squashfs',
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
    assert.match(
      installUsage(),
      /^Usage: \/usr\/local\/libexec\/webex-host-release\/install-host-release /,
    );
    assert.doesNotMatch(installUsage(), /\/usr\/bin\/node/);
  });

  it('requires the deployment host Node.js runtime contract', () => {
    assert.equal(MINIMUM_NODE_MAJOR, 24);
    assert.doesNotThrow(() => assertSupportedNodeVersion('24.0.0'));
    assert.doesNotThrow(() => assertSupportedNodeVersion('26.3.0'));
    assert.throws(() => assertSupportedNodeVersion('23.11.1'), /Node\.js 24 or newer/);
    assert.throws(() => assertSupportedNodeVersion('invalid'), /Node\.js 24 or newer/);
  });

  it('binds production BusyBox and no-copy publication to fixed host contracts', async () => {
    assert.equal(
      resolveBusyboxPath(),
      '/usr/local/libexec/webex-host-release/busybox',
    );
    assert.equal(resolveBusyboxPath('/tmp/../usr/bin/busybox'), '/usr/bin/busybox');

    const calls = [];
    await assertNoCopyMoveSupported(async (command, args, options) => {
      calls.push({ command, args, options });
    });
    assert.deepEqual(calls, [{
      command: '/usr/bin/mv',
      args: ['--no-copy', '--version'],
      options: {
        cwd: '/',
        env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
        maxBuffer: 1024 * 1024,
      },
    }]);
    await assert.rejects(
      assertNoCopyMoveSupported(async () => {
        throw new Error('unsupported option');
      }),
      /requires GNU Coreutils mv with --no-copy support/,
    );
  });

  it('requires an unprivileged builder and bounds the complete source snapshot', () => {
    assert.doesNotThrow(() => assertUnprivilegedBuilder(1000, 1000));
    assert.throws(() => assertUnprivilegedBuilder(0, 1000), /must not run as root/);
    assert.throws(() => assertUnprivilegedBuilder(1000, 0), /must not run as root/);
    assert.equal(accountSourceBlobBytes(4, 6, 'source', 10), 10);
    assert.throws(
      () => accountSourceBlobBytes(10, 1, 'source', 10),
      /aggregate byte limit/,
    );
    assert.throws(
      () => accountSourceBlobBytes(0, (64 * 1024 * 1024) + 1, 'source'),
      /blob is too large/,
    );
  });

  it('pins the normalised Rust toolchain tree and detects restored tampering', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-toolchain-tree-test-'));
    const bin = path.join(root, 'bin');
    const cargo = path.join(bin, 'cargo');
    const library = path.join(root, 'libstd.rlib');
    try {
      await fs.mkdir(bin);
      await fs.writeFile(cargo, 'cargo fixture\n', { mode: 0o755 });
      await fs.writeFile(library, 'library fixture\n', { mode: 0o644 });
      const snapshot = await snapshotToolchainTree(root);
      assert.match(snapshot.sha256, /^[a-f0-9]{64}$/);
      assert.equal((await fs.lstat(root)).mode & 0o7777, 0o500);
      assert.equal((await fs.lstat(bin)).mode & 0o7777, 0o500);
      assert.equal((await fs.lstat(cargo)).mode & 0o7777, 0o500);
      assert.equal((await fs.lstat(library)).mode & 0o7777, 0o400);
      await assert.doesNotReject(verifyToolchainTree(snapshot));

      const original = await fs.readFile(library);
      await fs.chmod(library, 0o600);
      await new Promise((resolve) => setTimeout(resolve, 2));
      await fs.writeFile(library, 'tampered library\n');
      await fs.writeFile(library, original);
      await fs.chmod(library, 0o400);
      await assert.rejects(
        verifyToolchainTree(snapshot),
        /trusted Rust toolchain changed/,
      );
      await assert.rejects(
        snapshotToolchainTree(root, '0'.repeat(64)),
        /does not match the trusted tree digest/,
      );

      const topologySnapshot = await snapshotToolchainTree(root);
      await fs.chmod(bin, 0o700);
      await fs.writeFile(path.join(bin, 'transient'), 'transient\n');
      await fs.chmod(path.join(bin, 'transient'), 0o400);
      await fs.chmod(bin, 0o500);
      await assert.rejects(
        verifyToolchainTree(topologySnapshot),
        /unexpected topology/,
      );
    } finally {
      await fs.chmod(root, 0o700).catch(() => {});
      await fs.chmod(bin, 0o700).catch(() => {});
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('rejects special files in an extracted Rust toolchain', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-toolchain-link-test-'));
    try {
      await fs.symlink('/etc/passwd', path.join(root, 'rustc'));
      await assert.rejects(
        snapshotToolchainTree(root),
        /contains an untrusted file/,
      );
    } finally {
      await fs.chmod(root, 0o700).catch(() => {});
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('normalises and binds the complete Cargo vendor tree', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-cargo-vendor-tree-test-'));
    const packageRoot = path.join(root, 'fixture-1.0.0');
    const buildScript = path.join(packageRoot, 'build.rs');
    try {
      await fs.mkdir(packageRoot);
      await fs.writeFile(buildScript, 'fn main() {}\n', { mode: 0o755 });
      const snapshot = await snapshotCargoVendorTree(root);
      assert.equal((await fs.lstat(root)).mode & 0o7777, 0o500);
      assert.equal((await fs.lstat(packageRoot)).mode & 0o7777, 0o500);
      assert.equal((await fs.lstat(buildScript)).mode & 0o7777, 0o400);
      await assert.doesNotReject(verifyCargoVendorTree(snapshot));
      await fs.chmod(buildScript, 0o600);
      await fs.writeFile(buildScript, 'fn main() { panic!() }\n');
      await fs.chmod(buildScript, 0o400);
      await assert.rejects(
        verifyCargoVendorTree(snapshot),
        /trusted Cargo vendor tree changed/,
      );
    } finally {
      await fs.chmod(root, 0o700).catch(() => {});
      await fs.chmod(packageRoot, 0o700).catch(() => {});
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('rejects special files in an extracted Cargo vendor tree', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-cargo-vendor-link-test-'));
    try {
      await fs.symlink('/etc/passwd', path.join(root, 'crate-source'));
      await assert.rejects(
        snapshotCargoVendorTree(root),
        /contains an untrusted file/,
      );
    } finally {
      await fs.chmod(root, 0o700).catch(() => {});
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('binds the Cargo home baseline to the fixed source replacement', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-cargo-home-tree-test-'));
    const config = path.join(root, 'config.toml');
    try {
      const expected = Buffer.from(cargoVendorConfiguration('/tmp/cargo-vendor'), 'utf8');
      await fs.writeFile(config, '[build]\nrustc-wrapper = "/tmp/attacker"\n', { mode: 0o400 });
      await assert.rejects(
        snapshotCargoHomeTree(root, expected),
        /private Cargo home does not match the trusted tree digest/,
      );
    } finally {
      await fs.chmod(root, 0o700).catch(() => {});
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('rejects output paths that can inject build environment fields', async () => {
    const options = {
      output: '/tmp/release',
      inputRoot: '/tmp/release-inputs',
      codexPackageRoot: '/tmp/codex',
      rustToolchainImage: '/tmp/rust-toolchain.squashfs',
      cargoVendorImage: '/tmp/cargo-vendor.squashfs',
    };
    for (const delimiter of [':', '=', '\u001f', '\n']) {
      await assert.rejects(
        buildHostRelease(
          { ...options, output: `/tmp/release${delimiter}injected` },
          {
            repoRoot: '/tmp/repo',
            builderRealUid: 1000,
            builderEffectiveUid: 1000,
          },
        ),
        /--output must not contain build-environment delimiters/,
      );
    }
    assert.throws(
      () => buildEnvironment('/tmp/release:injected', '/tmp/rust-toolchain'),
      /build scratch path must not contain build-environment delimiters/,
    );
    assert.throws(
      () => buildEnvironment('/tmp/release', '/tmp/rust=toolchain'),
      /Rust toolchain path must not contain build-environment delimiters/,
    );
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
    assert.equal(environment.CARGO_NET_OFFLINE, 'true');
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
      '--release',
    ]);
    assert.deepEqual(invocation, {
      args: [
        'build',
        '--manifest-path',
        '/tmp/caller-controlled/release/source/Cargo.toml',
        '--locked',
        '--offline',
        '--release',
      ],
      cwd: '/',
    });
  });

  it('pins Cargo to one offline vendored source tree', () => {
    assert.equal(
      cargoVendorConfiguration('/tmp/release scratch/cargo-vendor'),
      [
        '[source.crates-io]',
        'replace-with = "vendored-sources"',
        '',
        '[source.vendored-sources]',
        'directory = "/tmp/release scratch/cargo-vendor"',
        '',
        '[net]',
        'offline = true',
        '',
      ].join('\n'),
    );
    assert.deepEqual(
      cargoBuildInvocation('/tmp/source', ['--release']).args,
      [
        'build',
        '--manifest-path',
        '/tmp/source/Cargo.toml',
        '--locked',
        '--offline',
        '--release',
      ],
    );
  });

  it('does not load Cargo configuration or a workspace above the frozen source', async () => {
    assert.match(
      await fs.readFile(new URL('../Cargo.toml', import.meta.url), 'utf8'),
      /\n\[workspace\]\nresolver = "3"\n/,
    );
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
        path.join(root, 'Cargo.toml'),
        '[workspace]\nmembers = ["source"]\nresolver = "3"\n',
      );
      await fs.writeFile(path.join(root, 'Cargo.lock'), 'not a valid lockfile\n');
      await fs.writeFile(
        path.join(source, 'Cargo.toml'),
        [
          '[package]',
          'name = "cargo-config-isolation"',
          'version = "0.0.0"',
          'edition = "2024"',
          '',
          '[workspace]',
          'resolver = "3"',
          '',
        ].join('\n'),
      );
      await fs.writeFile(
        path.join(source, 'Cargo.lock'),
        [
          '# This file is automatically @generated by Cargo.',
          '# It is not intended for manual editing.',
          'version = 4',
          '',
          '[[package]]',
          'name = "cargo-config-isolation"',
          'version = "0.0.0"',
          '',
        ].join('\n'),
      );
      await fs.writeFile(path.join(source, 'src', 'main.rs'), 'fn main() {}\n');
      const invocation = cargoBuildInvocation(source, [
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
        cargo_vendor_sha256: CARGO_VENDOR_IMAGE_SHA256,
        cargo_vendor_tree_sha256: CARGO_VENDOR_TREE_SHA256,
        cargo_version: CARGO_VERSION,
        rustc_version: RUSTC_VERSION,
        toolchain_sha256: RUST_TOOLCHAIN_IMAGE_SHA256,
        toolchain_tree_sha256: RUST_TOOLCHAIN_TREE_SHA256,
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

  it('authenticates bootstrap modules before starting Node.js', async () => {
    const modules = [
      ['build-host-release.mjs', new URL('../scripts/build-host-release.mjs', import.meta.url)],
      ['install-host-release.mjs', new URL('../scripts/install-host-release.mjs', import.meta.url)],
      ['host-release-contract.mjs', new URL('../scripts/host-release-contract.mjs', import.meta.url)],
    ];
    const digests = new Map(await Promise.all(modules.map(async ([name, modulePath]) => [
      name,
      await sha256File(modulePath),
    ])));

    for (const [name, home, expectedUidCheck] of [
      ['build-host-release', 'HOME=/', 'effective UID must be non-root'],
      ['install-host-release', 'HOME=/root', 'effective UID must be root'],
    ]) {
      const wrapperPath = new URL(`../scripts/${name}`, import.meta.url);
      const wrapper = await fs.readFile(wrapperPath, 'utf8');
      const metadata = await fs.lstat(wrapperPath);
      assert.equal(metadata.mode & 0o7777, 0o755);
      assert.ok(wrapper.startsWith([
        '#!/usr/local/libexec/webex-host-release/busybox sh',
        '# shellcheck shell=dash',
        'set -eu',
        '',
        '# shellcheck disable=SC2016',
        'exec /usr/local/libexec/webex-host-release/busybox env -i \\',
        `  ${home} \\`,
      ].join('\n')));
      assert.match(wrapper, new RegExp(expectedUidCheck));
      assert.doesNotMatch(wrapper, /__[A-Z_]+__/);

      let lastDigestCheck = -1;
      for (const [moduleName] of modules) {
        const check = `check_sha256 "$trust_root/${moduleName}" ${digests.get(moduleName)}`;
        const index = wrapper.indexOf(check);
        assert.notEqual(index, -1, `${name} does not pin ${moduleName}`);
        lastDigestCheck = Math.max(lastDigestCheck, index);
      }
      const nodeVersionCheck = wrapper.indexOf('node_version=$(/usr/bin/node --version)');
      const nodeEntrypoint = wrapper.lastIndexOf('  /usr/bin/node \\\n');
      assert.ok(lastDigestCheck < nodeVersionCheck);
      assert.ok(nodeVersionCheck < nodeEntrypoint);
      assert.ok(nodeEntrypoint < wrapper.lastIndexOf(`  "$trust_root/${name}.mjs" \\`));
    }
  });

  it('clears inherited loader state and rejects module drift before import', async (context) => {
    const wrapperPath = new URL('../scripts/build-host-release', import.meta.url);
    const builderPath = new URL('../scripts/build-host-release.mjs', import.meta.url);
    const installerPath = new URL('../scripts/install-host-release.mjs', import.meta.url);
    const contractPath = new URL('../scripts/host-release-contract.mjs', import.meta.url);
    const wrapper = await fs.readFile(wrapperPath, 'utf8');

    let hostBusybox;
    try {
      hostBusybox = await fs.readFile('/usr/bin/busybox');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      context.skip('pinned host BusyBox is unavailable');
      return;
    }
    if (
      crypto.createHash('sha256').update(hostBusybox).digest('hex')
      !== TRUSTED_SOURCE_SHA256['runtime-sources/busybox']
    ) {
      context.skip('host BusyBox does not match the pinned production binary');
      return;
    }

    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-builder-env-test-'));
    const nativeMarker = path.join(root, 'native-preload-ran');
    const nodeMarker = path.join(root, 'node-preload-ran');
    const importMarker = path.join(root, 'builder-import-ran');
    const environmentMarker = path.join(root, 'builder-environment.json');
    const nativeSource = path.join(root, 'preload.c');
    const nativePreload = path.join(root, 'preload.so');
    const nodePreload = path.join(root, 'preload.cjs');
    const probe = path.join(root, 'build-host-release.mjs');
    const probeWrapper = path.join(root, 'build-host-release');
    const probeInstallerWrapper = path.join(root, 'install-host-release');
    const probeInstaller = path.join(root, 'install-host-release.mjs');
    const probeContract = path.join(root, 'host-release-contract.mjs');
    const probeBusybox = path.join(root, 'busybox');
    try {
      await fs.writeFile(
        nativeSource,
        [
          '#include <fcntl.h>',
          '#include <unistd.h>',
          '__attribute__((constructor)) static void loaded(void) {',
          `  int fd = open(${JSON.stringify(nativeMarker)}, O_WRONLY | O_CREAT | O_TRUNC, 0600);`,
          '  if (fd >= 0) {',
          '    (void)write(fd, "ran", 3);',
          '    (void)close(fd);',
          '  }',
          '}',
          '',
        ].join('\n'),
      );
      await execFileAsync('/usr/bin/cc', [
        '-shared',
        '-fPIC',
        '-o',
        nativePreload,
        nativeSource,
      ]);
      await execFileAsync('/usr/bin/env', ['-i', '/usr/bin/true'], {
        env: { LD_PRELOAD: nativePreload },
      });
      assert.equal(await fs.readFile(nativeMarker, 'utf8'), 'ran');
      await fs.rm(nativeMarker);
      await fs.writeFile(
        nodePreload,
        `require('node:fs').writeFileSync(${JSON.stringify(nodeMarker)}, 'ran');\n`,
      );
      await fs.writeFile(
        probe,
        [
          "const fs = await import('node:fs/promises');",
          `await fs.writeFile(${JSON.stringify(importMarker)}, 'ran');`,
          `await fs.writeFile(${JSON.stringify(environmentMarker)}, JSON.stringify(process.env));`,
          '',
        ].join('\n'),
        { mode: 0o444 },
      );
      await fs.writeFile(probeInstaller, 'export {};\n', { mode: 0o444 });
      await fs.writeFile(probeContract, 'export {};\n', { mode: 0o444 });
      await fs.copyFile('/usr/bin/busybox', probeBusybox);
      await fs.chmod(probeBusybox, 0o555);
      await fs.writeFile(probeInstallerWrapper, '#!/bin/false\n', { mode: 0o555 });

      const uid = process.getuid();
      const gid = process.getgid();
      const nodeMode = ((await fs.lstat(process.execPath)).mode & 0o7777).toString(8);
      const productionDigests = new Map([
        [await sha256File(builderPath), await sha256File(probe)],
        [await sha256File(installerPath), await sha256File(probeInstaller)],
        [await sha256File(contractPath), await sha256File(probeContract)],
      ]);
      let fixtureWrapper = wrapper
        .replaceAll('/usr/local/libexec/webex-host-release', root)
        .replaceAll('/usr/bin/node', process.execPath)
        .replace(
          'for directory in / /usr /usr/bin /usr/local /usr/local/libexec "$trust_root"; do',
          'for directory in "$trust_root"; do',
        )
        .replaceAll('0:0:', `${uid}:${gid}:`)
        .replace(`check_file ${process.execPath} 555`, `check_file ${process.execPath} ${nodeMode}`);
      for (const [productionDigest, fixtureDigest] of productionDigests) {
        fixtureWrapper = fixtureWrapper.replaceAll(productionDigest, fixtureDigest);
      }
      await fs.writeFile(
        probeWrapper,
        fixtureWrapper,
        { mode: 0o555 },
      );
      await fs.chmod(root, 0o755);
      await execFileAsync(probeWrapper, [], {
        env: {
          ...process.env,
          LD_PRELOAD: nativePreload,
          NODE_OPTIONS: `--require=${nodePreload}`,
        },
        maxBuffer: 1024 * 1024,
      });
      assert.equal(await fs.readFile(importMarker, 'utf8'), 'ran');
      assert.deepEqual(JSON.parse(await fs.readFile(environmentMarker, 'utf8')), {
        HOME: '/',
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
      });
      await assertMissing(nativeMarker);
      await assertMissing(nodeMarker);

      await fs.rm(importMarker);
      await fs.rm(environmentMarker);
      await fs.chmod(probe, 0o600);
      await fs.appendFile(probe, '// tampered\n');
      await fs.chmod(probe, 0o444);
      await assert.rejects(
        execFileAsync(probeWrapper, [], { maxBuffer: 1024 * 1024 }),
        /build-host-release\.mjs digest is invalid/,
      );
      await assertMissing(importMarker);
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
      const hostBinary = RELEASE_FILES.find(({ kind }) => kind === 'host-binary');
      const missingDigest = { ...trustedDigests };
      delete missingDigest[hostBinary.installPath];
      await assert.rejects(
        buildFixtureBundle(fixture, missingDigest),
        /trusted release source digest is missing/,
      );
      await assertMissing(fixture.bundle);

      await fs.writeFile(fixture.busybox, 'replacement busybox');
      await assert.rejects(
        buildFixtureBundle(fixture, trustedDigests),
        /trusted release source digest mismatch/,
      );
      await assertMissing(fixture.bundle);

      await fs.writeFile(fixture.busybox, sourceContents('runtime-sources/busybox'));
      await fs.writeFile(
        path.join(fixture.hostBinDir, hostBinary.source),
        'replacement host binary',
      );
      await assert.rejects(
        buildFixtureBundle(fixture, trustedDigests),
        /trusted release source digest mismatch/,
      );
      await assertMissing(fixture.bundle);

      await fs.writeFile(
        path.join(fixture.hostBinDir, hostBinary.source),
        sourceContents(hostBinary.installPath),
      );
      const staticBinary = RELEASE_FILES.find(({ kind }) => kind === 'static-binary');
      await fs.writeFile(
        path.join(fixture.staticBinDir, staticBinary.source),
        'replacement static binary',
      );
      await assert.rejects(
        buildFixtureBundle(fixture, trustedDigests),
        /trusted release source digest mismatch/,
      );
      await assertMissing(fixture.bundle);

      await fs.writeFile(
        path.join(fixture.staticBinDir, staticBinary.source),
        sourceContents(staticBinary.installPath),
      );
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

  it('rejects untrusted build provenance in the bundle manifest', async () => {
    for (const field of [
      'cargo_vendor_sha256',
      'cargo_vendor_tree_sha256',
      'toolchain_tree_sha256',
    ]) {
      const fixture = await createFixture();
      try {
        await buildFixtureBundle(fixture);
        const manifestPath = path.join(fixture.bundle, 'manifest.json');
        const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
        manifest.build[field] = '0'.repeat(64);
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
          /build provenance is invalid/,
        );
      } finally {
        await fs.rm(fixture.root, { recursive: true, force: true });
      }
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

  it('rejects source snapshot tampering restored before build completion', async () => {
    const fixture = await createFixture();
    const sourcePath = 'scripts/provision-host.mjs';
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

      await assert.rejects(
        buildFixtureResult(fixture, undefined, {
          revision: undefined,
          buildArtifacts: async ({ repoRoot }) => {
            const source = path.join(repoRoot, sourcePath);
            const original = await fs.readFile(source);
            const before = await fs.lstat(source, { bigint: true });
            await new Promise((resolve) => setTimeout(resolve, 2));
            await fs.writeFile(source, 'build-side tampering\n');
            await fs.writeFile(source, original);
            const after = await fs.lstat(source, { bigint: true });
            assert.notEqual(after.ctimeNs, before.ctimeNs);
            return {
              hostBinDir: fixture.hostBinDir,
              staticBinDir: fixture.staticBinDir,
              cargoVendorSha256: CARGO_VENDOR_IMAGE_SHA256,
              cargoVendorTreeSha256: CARGO_VENDOR_TREE_SHA256,
              cargoVersion: CARGO_VERSION,
              rustcVersion: RUSTC_VERSION,
              toolchainSha256: RUST_TOOLCHAIN_IMAGE_SHA256,
              toolchainTreeSha256: RUST_TOOLCHAIN_TREE_SHA256,
            };
          },
        }),
        /committed source snapshot changed/,
      );
      await assertMissing(fixture.bundle);
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('rejects source topology tampering restored before build completion', async () => {
    const fixture = await createFixture();
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

      await assert.rejects(
        buildFixtureResult(fixture, undefined, {
          revision: undefined,
          buildArtifacts: async ({ repoRoot }) => {
            const directory = path.join(repoRoot, 'scripts');
            const transient = path.join(directory, 'build-side-transient');
            const before = await fs.lstat(directory, { bigint: true });
            await new Promise((resolve) => setTimeout(resolve, 2));
            await fs.writeFile(transient, 'transient\n');
            await fs.rm(transient);
            const after = await fs.lstat(directory, { bigint: true });
            assert.notEqual(after.ctimeNs, before.ctimeNs);
            return {
              hostBinDir: fixture.hostBinDir,
              staticBinDir: fixture.staticBinDir,
              cargoVendorSha256: CARGO_VENDOR_IMAGE_SHA256,
              cargoVendorTreeSha256: CARGO_VENDOR_TREE_SHA256,
              cargoVersion: CARGO_VERSION,
              rustcVersion: RUSTC_VERSION,
              toolchainSha256: RUST_TOOLCHAIN_IMAGE_SHA256,
              toolchainTreeSha256: RUST_TOOLCHAIN_TREE_SHA256,
            };
          },
        }),
        /committed source snapshot changed/,
      );
      await assertMissing(fixture.bundle);
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('rejects a forged loose blob that does not match its advertised object ID', async () => {
    const fixture = await createFixture();
    const sourcePath = 'scripts/provision-host.mjs';
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
      const blob = (await git(['rev-parse', `HEAD:${sourcePath}`])).stdout.trim();
      const objectPath = path.join(
        fixture.repoRoot,
        '.git',
        'objects',
        blob.slice(0, 2),
        blob.slice(2),
      );
      const forged = Buffer.from(await fs.readFile(path.join(fixture.repoRoot, sourcePath)));
      forged[0] ^= 0x20;
      const forgedObject = Buffer.concat([
        Buffer.from(`blob ${forged.length}\0`, 'ascii'),
        forged,
      ]);
      await fs.rm(objectPath);
      await fs.writeFile(objectPath, deflateSync(forgedObject));

      assert.equal((await git(['cat-file', 'blob', blob])).stdout, forged.toString('utf8'));
      await assert.rejects(
        buildFixtureResult(fixture, undefined, { revision: undefined }),
        /committed source blob object ID mismatch/,
      );
      await assertMissing(fixture.bundle);
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('rejects forged loose commit and tree objects', async () => {
    const fixture = await createFixture();
    const git = (args, encoding = 'utf8') => execFileAsync('/usr/bin/git', args, {
      cwd: fixture.repoRoot,
      encoding,
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
      const revision = (await git(['rev-parse', 'HEAD^{commit}'])).stdout.trim();
      const commitPath = looseObjectPath(fixture.repoRoot, revision);
      const storedCommit = await fs.readFile(commitPath);
      const forgedCommit = Buffer.from((await git(['cat-file', 'commit', revision], 'buffer')).stdout);
      const messageOffset = forgedCommit.indexOf(Buffer.from('fixture', 'ascii'));
      assert.notEqual(messageOffset, -1);
      forgedCommit[messageOffset] ^= 0x20;
      await replaceLooseObject(commitPath, 'commit', forgedCommit);
      assert.deepEqual(
        (await git(['cat-file', 'commit', revision], 'buffer')).stdout,
        forgedCommit,
      );
      await assert.rejects(
        buildFixtureResult(fixture, undefined, { revision: undefined }),
        /hash mismatch|committed source commit object ID mismatch/,
      );
      await assertMissing(fixture.bundle);

      await fs.rm(commitPath);
      await fs.writeFile(commitPath, storedCommit);
      const tree = (await git(['rev-parse', 'HEAD^{tree}'])).stdout.trim();
      const treePath = looseObjectPath(fixture.repoRoot, tree);
      const forgedTree = Buffer.from((await git(['cat-file', 'tree', tree], 'buffer')).stdout);
      const directoryOffset = forgedTree.indexOf(Buffer.from('scripts', 'ascii'));
      assert.notEqual(directoryOffset, -1);
      forgedTree[directoryOffset] ^= 0x20;
      await replaceLooseObject(treePath, 'tree', forgedTree);
      assert.deepEqual((await git(['cat-file', 'tree', tree], 'buffer')).stdout, forgedTree);
      await assert.rejects(
        buildFixtureResult(fixture, undefined, { revision: undefined }),
        /hash mismatch|committed source tree object ID mismatch/,
      );
      await assertMissing(fixture.bundle);
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('fails on a missing promisor blob without executing a lazy-fetch helper', async () => {
    const fixture = await createFixture();
    const sourcePath = 'scripts/provision-host.mjs';
    const helper = path.join(fixture.root, 'promisor-helper');
    const marker = path.join(fixture.root, 'promisor-helper-ran');
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
      const blob = (await git(['rev-parse', `HEAD:${sourcePath}`])).stdout.trim();
      const objectPath = path.join(
        fixture.repoRoot,
        '.git',
        'objects',
        blob.slice(0, 2),
        blob.slice(2),
      );
      await fs.writeFile(
        helper,
        `#!/bin/sh\nprintf ran > ${JSON.stringify(marker)}\nexit 1\n`,
        { mode: 0o755 },
      );
      await git(['config', 'remote.origin.promisor', 'true']);
      await git(['config', 'remote.origin.partialclonefilter', 'blob:none']);
      await git(['config', 'remote.origin.url', `ext::${helper}`]);
      await git(['config', 'protocol.ext.allow', 'always']);
      await fs.rm(objectPath);

      await assert.rejects(git(['cat-file', 'blob', blob]));
      assert.equal(await fs.readFile(marker, 'utf8'), 'ran');
      await fs.rm(marker);

      await assert.rejects(
        buildFixtureResult(fixture, undefined, { revision: undefined }),
      );
      await assertMissing(marker);
      await assertMissing(fixture.bundle);
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
    for (const mutation of [
      'shared',
      'writable',
      'symlink',
      'missing',
      'escaped-toolchain',
      'escaped-vendor',
    ]) {
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
        } else if (mutation === 'escaped-toolchain') {
          const escaped = path.join(fixture.root, 'escaped-toolchain.squashfs');
          await fs.rename(fixture.rustToolchainImage, escaped);
          fixture.rustToolchainImage = escaped;
        } else {
          const escaped = path.join(fixture.root, 'escaped-cargo-vendor.squashfs');
          await fs.rename(fixture.cargoVendorImage, escaped);
          fixture.cargoVendorImage = escaped;
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
              cargoVendorSha256: CARGO_VENDOR_IMAGE_SHA256,
              cargoVendorTreeSha256: CARGO_VENDOR_TREE_SHA256,
              cargoVersion: CARGO_VERSION,
              rustcVersion: RUSTC_VERSION,
              toolchainSha256: RUST_TOOLCHAIN_IMAGE_SHA256,
              toolchainTreeSha256: RUST_TOOLCHAIN_TREE_SHA256,
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

async function sha256File(file) {
  return crypto.createHash('sha256').update(await fs.readFile(file)).digest('hex');
}

async function createFixture() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-host-release-test-'));
  const inputRoot = path.join(root, 'inputs');
  const repoRoot = path.join(root, 'repo');
  const hostBinDir = path.join(root, 'host-bin');
  const staticBinDir = path.join(root, 'static-bin');
  const codexRoot = path.join(inputRoot, 'codex');
  const busybox = path.join(root, 'busybox');
  const rustToolchainImage = path.join(inputRoot, 'rust-toolchain.squashfs');
  const cargoVendorImage = path.join(inputRoot, 'cargo-vendor.squashfs');
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
  await fs.writeFile(
    cargoVendorImage,
    'unused fixture Cargo vendor image',
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
    cargoVendorImage,
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
      cargoVendorImage: fixture.cargoVendorImage,
    },
    {
      repoRoot: fixture.repoRoot,
      hostBinDir: fixture.hostBinDir,
      busybox: fixture.busybox,
      builderRealUid: 1000,
      builderEffectiveUid: 1000,
      revision: REVISION,
      buildArtifacts: async () => ({
        hostBinDir: fixture.hostBinDir,
        staticBinDir: fixture.staticBinDir,
        cargoVendorSha256: CARGO_VENDOR_IMAGE_SHA256,
        cargoVendorTreeSha256: CARGO_VENDOR_TREE_SHA256,
        cargoVersion: CARGO_VERSION,
        rustcVersion: RUSTC_VERSION,
        toolchainSha256: RUST_TOOLCHAIN_IMAGE_SHA256,
        toolchainTreeSha256: RUST_TOOLCHAIN_TREE_SHA256,
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

function looseObjectPath(repoRoot, objectId) {
  return path.join(repoRoot, '.git', 'objects', objectId.slice(0, 2), objectId.slice(2));
}

async function replaceLooseObject(objectPath, type, bytes) {
  await fs.rm(objectPath);
  await fs.writeFile(
    objectPath,
    deflateSync(Buffer.concat([
      Buffer.from(`${type} ${bytes.length}\0`, 'ascii'),
      bytes,
    ])),
  );
}

async function trustedFixtureDigests(fixture) {
  const result = {};
  for (const entry of RELEASE_FILES) {
    let source;
    if (entry.kind === 'host-binary') source = path.join(fixture.hostBinDir, entry.source);
    else if (entry.kind === 'static-binary') {
      source = path.join(fixture.staticBinDir, entry.source);
    } else if (entry.kind === 'busybox') source = fixture.busybox;
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
