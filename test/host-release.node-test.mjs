import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import { buildHostRelease, parseArgs as parseBuildArgs } from '../scripts/build-host-release.mjs';
import {
  CODEX_VERSION,
  RELEASE_FILES,
  RELEASE_PATHS,
  bundlePayloadPath,
} from '../scripts/host-release-contract.mjs';
import {
  installHostRelease,
  parseArgs as parseInstallArgs,
  validateBundle,
} from '../scripts/install-host-release.mjs';

const REVISION = 'a'.repeat(40);

describe('host release bootstrap', () => {
  it('keeps the release contract unique and path confined', () => {
    assert.equal(new Set(RELEASE_PATHS).size, RELEASE_FILES.length);
    for (const entry of RELEASE_FILES) {
      assert.match(entry.installPath, /^(?:bin|code|runtime-sources)\//);
      assert.equal(path.posix.normalize(entry.installPath), entry.installPath);
      assert.equal(path.posix.isAbsolute(entry.installPath), false);
      assert.equal(entry.installPath.split('/').includes('..'), false);
      assert.ok(entry.mode === 0o444 || entry.mode === 0o555);
    }
  });

  it('parses only explicit build inputs and fixed install modes', () => {
    assert.deepEqual(
      parseBuildArgs([
        '--output', '/tmp/release',
        '--codex-package-root', '/tmp/codex',
        '--static-bin-dir', '/tmp/static',
      ]),
      {
        output: '/tmp/release',
        codexPackageRoot: '/tmp/codex',
        staticBinDir: '/tmp/static',
      },
    );
    assert.deepEqual(parseInstallArgs([]), { apply: false, json: false });
    assert.deepEqual(parseInstallArgs(['--apply', '--json']), { apply: true, json: true });
    assert.throws(() => parseInstallArgs(['--apply', '--dry-run']), /exactly one install mode/);
    assert.throws(() => parseInstallArgs(['--bundle', '/tmp/x']), /unknown argument/);
  });

  it('builds, validates, and atomically installs the exact first-release tree', async () => {
    const fixture = await createFixture();
    try {
      const manifest = await buildFixtureBundle(fixture);
      assert.equal(manifest.bot_revision, REVISION);
      assert.equal(manifest.codex_version, CODEX_VERSION);
      assert.deepEqual(manifest.files.map(({ path: file }) => file), RELEASE_PATHS);

      const validated = await validateBundle(fixture.bundle, process.getuid(), process.getgid());
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
                : /install root already exists/,
        );
      } finally {
        await fs.rm(fixture.root, { recursive: true, force: true });
      }
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
  const repoRoot = path.join(root, 'repo');
  const hostBinDir = path.join(root, 'host-bin');
  const staticBinDir = path.join(root, 'static-bin');
  const codexRoot = path.join(root, 'codex');
  const busybox = path.join(root, 'busybox');
  const bundle = path.join(root, 'bundle');
  const installParent = path.join(root, 'install-parent');
  const installRoot = path.join(installParent, 'webex-generic-account-bot');
  await fs.mkdir(repoRoot, { recursive: true });
  await fs.mkdir(hostBinDir, { recursive: true });
  await fs.mkdir(staticBinDir, { recursive: true });
  await fs.mkdir(codexRoot, { recursive: true });
  await fs.mkdir(installParent, { recursive: true });

  for (const entry of RELEASE_FILES) {
    let source;
    if (entry.kind === 'code') source = path.join(repoRoot, entry.source);
    else if (entry.kind === 'host-binary') source = path.join(hostBinDir, entry.source);
    else if (entry.kind === 'static-binary') source = path.join(staticBinDir, entry.source);
    else if (entry.kind === 'busybox') source = busybox;
    else source = path.join(codexRoot, entry.source.slice('codex/'.length));
    await fs.mkdir(path.dirname(source), { recursive: true });
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
    repoRoot,
    hostBinDir,
    staticBinDir,
    codexRoot,
    busybox,
    bundle,
    installRoot,
  };
}

function buildFixtureBundle(fixture) {
  return buildHostRelease(
    {
      output: fixture.bundle,
      codexPackageRoot: fixture.codexRoot,
      staticBinDir: fixture.staticBinDir,
    },
    {
      repoRoot: fixture.repoRoot,
      hostBinDir: fixture.hostBinDir,
      busybox: fixture.busybox,
      revision: REVISION,
    },
  );
}

function installFixture(fixture, apply) {
  return installHostRelease(
    { apply, json: false },
    {
      bundleRoot: fixture.bundle,
      installRoot: fixture.installRoot,
      expectedUid: process.getuid(),
      expectedGid: process.getgid(),
      requireRoot: false,
      trustAncestors: false,
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

async function assertMissing(file) {
  await assert.rejects(fs.lstat(file), { code: 'ENOENT' });
}
