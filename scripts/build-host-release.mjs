#!/usr/bin/env node

import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  CARGO_BIN,
  CARGO_VERSION,
  CODEX_VERSION,
  RELEASE_FILES,
  RELEASE_VERSION,
  RUSTC_BIN,
  RUSTC_VERSION,
  TRUSTED_SOURCE_SHA256,
  bundlePayloadPath,
} from './host-release-contract.mjs';

const execFileAsync = promisify(execFile);
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const MANIFEST_NAME = 'manifest.json';
const MAX_FILE_BYTES = 1024 * 1024 * 1024;
const COPY_BUFFER_BYTES = 1024 * 1024;

export function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--output') options.output = requireValue(argv, ++index, arg);
    else if (arg === '--codex-package-root') {
      options.codexPackageRoot = requireValue(argv, ++index, arg);
    } else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return options;
}

export function usage() {
  return [
    'Usage: node scripts/build-host-release.mjs --output <directory>',
    '       --codex-package-root <vendor-root>',
    '',
    'Builds an unprivileged, content-manifested first-install host release bundle.',
  ].join('\n');
}

export async function buildHostRelease(options, injected = {}) {
  const repoRoot = path.resolve(injected.repoRoot ?? REPO_ROOT);
  const output = requireAbsolutePath(options.output, '--output');
  const codexPackageRoot = requireAbsolutePath(
    options.codexPackageRoot,
    '--codex-package-root',
  );
  const busybox = path.resolve(injected.busybox ?? '/usr/bin/busybox');
  const run = injected.execFileAsync ?? execFileAsync;
  const revision = injected.revision ?? await readCleanRevision(repoRoot, run);
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error('bot revision must be a full Git SHA');

  await validateCodexPackage(codexPackageRoot);
  const parent = path.dirname(output);
  await fs.mkdir(parent, { recursive: true, mode: 0o700 });
  await assertOutputAbsent(output);
  const scratch = path.join(
    parent,
    `.${path.basename(output)}-${process.pid}-${crypto.randomBytes(12).toString('hex')}.build`,
  );
  const temporary = path.join(
    parent,
    `.${path.basename(output)}-${process.pid}-${crypto.randomBytes(12).toString('hex')}.tmp`,
  );
  await fs.mkdir(scratch, { mode: 0o700 });
  try {
    const sourceRoot = injected.revision
      ? repoRoot
      : await materializeRevision(repoRoot, scratch, revision, run);
    const artifacts = injected.buildArtifacts
      ? await injected.buildArtifacts({ repoRoot: sourceRoot, scratch, revision })
      : await buildRustArtifacts(sourceRoot, scratch, run);
    await fs.mkdir(temporary, { mode: 0o700 });
    const files = [];
    for (const entry of RELEASE_FILES) {
      const source = releaseSource(entry, {
        repoRoot: sourceRoot,
        hostBinDir: artifacts.hostBinDir,
        staticBinDir: artifacts.staticBinDir,
        busybox,
        codexPackageRoot,
      });
      const destination = path.join(temporary, bundlePayloadPath(entry.installPath));
      const measured = await copyMeasuredFile(source, destination, entry.mode);
      const trustedDigest = (injected.trustedSourceSha256 ?? TRUSTED_SOURCE_SHA256)[
        entry.installPath
      ];
      if (
        (entry.kind === 'busybox' || entry.kind === 'codex-runtime')
        && trustedDigest === undefined
      ) {
        throw new Error(`trusted release source digest is missing: ${entry.installPath}`);
      }
      if (trustedDigest !== undefined && measured.sha256 !== trustedDigest) {
        throw new Error(`trusted release source digest mismatch: ${entry.installPath}`);
      }
      files.push({
        path: entry.installPath,
        mode: modeString(entry.mode),
        size: measured.size,
        sha256: measured.sha256,
      });
    }
    files.sort((left, right) => left.path.localeCompare(right.path));
    const manifest = {
      version: RELEASE_VERSION,
      bot_revision: revision,
      codex_version: CODEX_VERSION,
      build: {
        cargo_version: artifacts.cargoVersion,
        rustc_version: artifacts.rustcVersion,
      },
      files,
    };
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
    const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');
    await writeBytesFile(path.join(temporary, MANIFEST_NAME), manifestBytes, 0o444);
    await normaliseAndSyncBundleDirectories(temporary);
    await (injected.publishOutput ?? publishDirectoryNoReplace)(temporary, output);
    await syncDirectory(parent);
    return { manifest, manifestSha256 };
  } catch (error) {
    await fs.rm(temporary, { recursive: true, force: true });
    throw error;
  } finally {
    await fs.rm(scratch, { recursive: true, force: true });
  }
}

async function materializeRevision(repoRoot, scratch, revision, run) {
  const sourceRoot = path.join(scratch, 'source');
  const archive = path.join(scratch, 'source.tar');
  await fs.mkdir(sourceRoot, { mode: 0o700 });
  const environment = gitEnvironment();
  await run('/usr/bin/git', [
    'archive',
    '--format=tar',
    `--output=${archive}`,
    revision,
  ], {
    cwd: repoRoot,
    env: environment,
    maxBuffer: 1024 * 1024,
  });
  await run('/usr/bin/tar', [
    '--extract',
    `--file=${archive}`,
    `--directory=${sourceRoot}`,
    '--no-same-owner',
    '--no-same-permissions',
  ], {
    cwd: '/',
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    maxBuffer: 1024 * 1024,
  });
  await fs.rm(archive);
  return sourceRoot;
}

async function buildRustArtifacts(repoRoot, scratch, run) {
  await fs.mkdir(path.join(scratch, 'cargo-home'), { mode: 0o700 });
  const cargoVersion = (await run(CARGO_BIN, ['--version'], {
    cwd: repoRoot,
    env: buildEnvironment(scratch),
    maxBuffer: 1024 * 1024,
  })).stdout.trim();
  const rustcVersion = (await run(RUSTC_BIN, ['--version'], {
    cwd: repoRoot,
    env: buildEnvironment(scratch),
    maxBuffer: 1024 * 1024,
  })).stdout.trim();
  if (cargoVersion !== CARGO_VERSION || rustcVersion !== RUSTC_VERSION) {
    throw new Error(`release build requires ${CARGO_VERSION} and ${RUSTC_VERSION}`);
  }

  const hostTarget = path.join(scratch, 'host-target');
  const staticTarget = path.join(scratch, 'static-target');
  await run(CARGO_BIN, [
    'build',
    '--locked',
    '--release',
    '--all-features',
    '--target',
    'x86_64-unknown-linux-gnu',
    '--bins',
  ], {
    cwd: repoRoot,
    env: buildEnvironment(scratch, { CARGO_TARGET_DIR: hostTarget }),
    maxBuffer: 16 * 1024 * 1024,
  });
  await run(CARGO_BIN, [
    'build',
    '--locked',
    '--release',
    '--all-features',
    '--target',
    'x86_64-unknown-linux-gnu',
    '--bin',
    'webex-codex-runtime',
    '--bin',
    'webex-codex-canary-probe',
  ], {
    cwd: repoRoot,
    env: buildEnvironment(scratch, {
      CARGO_TARGET_DIR: staticTarget,
      CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS: '-Ctarget-feature=+crt-static',
    }),
    maxBuffer: 16 * 1024 * 1024,
  });
  return {
    hostBinDir: path.join(hostTarget, 'x86_64-unknown-linux-gnu', 'release'),
    staticBinDir: path.join(staticTarget, 'x86_64-unknown-linux-gnu', 'release'),
    cargoVersion,
    rustcVersion,
  };
}

function buildEnvironment(scratch, extra = {}) {
  return {
    HOME: '/home/codex',
    CARGO_HOME: path.join(scratch, 'cargo-home'),
    RUSTUP_HOME: '/home/codex/.rustup',
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/home/codex/.cargo/bin:/usr/bin:/bin',
    CARGO_INCREMENTAL: '0',
    ...extra,
  };
}

async function readCleanRevision(repoRoot, run = execFileAsync) {
  const environment = gitEnvironment();
  const status = await run('/usr/bin/git', ['status', '--porcelain', '--untracked-files=all'], {
    cwd: repoRoot,
    env: environment,
    maxBuffer: 1024 * 1024,
  });
  if (status.stdout !== '') throw new Error('worktree must contain no tracked or untracked changes');
  const revision = await run('/usr/bin/git', ['rev-parse', 'HEAD'], {
    cwd: repoRoot,
    env: environment,
    maxBuffer: 1024 * 1024,
  });
  return revision.stdout.trim();
}

function gitEnvironment() {
  return {
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
  };
}

function releaseSource(entry, roots) {
  if (entry.kind === 'code') return path.join(roots.repoRoot, entry.source);
  if (entry.kind === 'host-binary') return path.join(roots.hostBinDir, entry.source);
  if (entry.kind === 'static-binary') return path.join(roots.staticBinDir, entry.source);
  if (entry.kind === 'busybox') return roots.busybox;
  if (entry.kind === 'codex-runtime') {
    return path.join(roots.codexPackageRoot, entry.source.slice('codex/'.length));
  }
  throw new Error(`unsupported release file kind: ${entry.kind}`);
}

async function validateCodexPackage(root) {
  const metadataPath = path.join(root, 'codex-package.json');
  const bytes = await readBoundedRegularFile(metadataPath, 64 * 1024);
  const value = JSON.parse(bytes.toString('utf8'));
  const expected = {
    entrypoint: 'bin/codex',
    layoutVersion: 1,
    pathDir: 'codex-path',
    resourcesDir: 'codex-resources',
    target: 'x86_64-unknown-linux-musl',
    variant: 'codex',
    version: CODEX_VERSION,
  };
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || JSON.stringify(Object.keys(value).toSorted()) !== JSON.stringify(Object.keys(expected).toSorted())
    || Object.entries(expected).some(([key, expectedValue]) => value[key] !== expectedValue)
  ) {
    throw new Error(`Codex package must be the reviewed ${CODEX_VERSION} Linux x64 layout`);
  }
}

async function copyMeasuredFile(source, destination, mode) {
  const input = await fs.open(
    source,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  let output;
  try {
    const before = await input.stat();
    if (!before.isFile() || before.size <= 0 || before.size > MAX_FILE_BYTES) {
      throw new Error(`release source is not a bounded regular file: ${source}`);
    }
    await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o755 });
    output = await fs.open(
      destination,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | fsConstants.O_CLOEXEC
        | fsConstants.O_NOFOLLOW,
      mode,
    );
    const digest = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES);
    let position = 0;
    while (true) {
      const { bytesRead } = await input.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      digest.update(chunk);
      await writeAll(output, chunk, position);
      position += bytesRead;
    }
    const after = await input.stat();
    assertStableMetadata(before, after, source);
    await output.chmod(mode);
    await output.sync();
    return { size: position, sha256: digest.digest('hex') };
  } finally {
    await output?.close();
    await input.close();
  }
}

async function writeBytesFile(file, bytes, mode) {
  const handle = await fs.open(
    file,
    fsConstants.O_WRONLY
      | fsConstants.O_CREAT
      | fsConstants.O_EXCL
      | fsConstants.O_CLOEXEC
      | fsConstants.O_NOFOLLOW,
    mode,
  );
  try {
    await handle.writeFile(bytes);
    await handle.chmod(mode);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readBoundedRegularFile(file, limit) {
  const handle = await fs.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > limit) {
      throw new Error(`file is outside the permitted size: ${file}`);
    }
    return handle.readFile();
  } finally {
    await handle.close();
  }
}

async function writeAll(handle, bytes, start) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(
      bytes,
      offset,
      bytes.length - offset,
      start + offset,
    );
    if (bytesWritten === 0) throw new Error('release bundle write made no progress');
    offset += bytesWritten;
  }
}

function assertStableMetadata(before, after, file) {
  for (const key of ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'mtimeMs', 'ctimeMs']) {
    if (before[key] !== after[key]) throw new Error(`release source changed: ${file}`);
  }
}

async function normaliseAndSyncBundleDirectories(root) {
  const directories = await collectDirectories(root);
  for (const directory of directories.toSorted((left, right) => depth(right) - depth(left))) {
    await fs.chmod(directory, directory === root ? 0o700 : 0o755);
    await syncDirectory(directory);
  }
}

async function collectDirectories(root, current = root, result = []) {
  result.push(current);
  for (const name of await fs.readdir(current)) {
    const full = path.join(current, name);
    const metadata = await fs.lstat(full);
    if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
      await collectDirectories(root, full, result);
    }
  }
  return result;
}

export async function publishDirectoryNoReplace(source, destination, run = execFileAsync) {
  try {
    await run('/usr/bin/mv', [
      '--no-copy',
      '--no-clobber',
      '--no-target-directory',
      source,
      destination,
    ], {
      cwd: '/',
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    if (await pathExists(source) && await pathExists(destination)) {
      throw new Error(`release output appeared during publish: ${destination}`);
    }
    throw error;
  }
  if (await pathExists(source)) {
    throw new Error(`release output appeared during publish: ${destination}`);
  }
  if (!await pathExists(destination)) throw new Error('release publish did not create output');
}

async function pathExists(file) {
  try {
    await fs.lstat(file);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function assertOutputAbsent(output) {
  try {
    await fs.lstat(output);
    throw new Error(`release output already exists: ${output}`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

async function syncDirectory(directory) {
  const handle = await fs.open(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function modeString(mode) {
  return `0${mode.toString(8).padStart(3, '0')}`;
}

function depth(value) {
  return value.split(path.sep).length;
}

function requireAbsolutePath(value, flag) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value) {
    throw new Error(`${flag} must be a normalized absolute path`);
  }
  return value;
}

function requireValue(argv, index, flag) {
  if (index >= argv.length || argv[index].startsWith('-')) {
    throw new Error(`${flag} requires a value`);
  }
  return argv[index];
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const result = await buildHostRelease(options);
  process.stdout.write(`status=built\n`);
  process.stdout.write(`bot_revision=${result.manifest.bot_revision}\n`);
  process.stdout.write(`codex_version=${result.manifest.codex_version}\n`);
  process.stdout.write(`manifest_sha256=${result.manifestSha256}\n`);
  process.stdout.write(`file_count=${result.manifest.files.length}\n`);
  process.stdout.write(`output=${options.output}\n`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`build-host-release: ${error.message}\n`);
    process.exitCode = 1;
  });
}
