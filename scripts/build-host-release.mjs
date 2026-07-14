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
  CODEX_VERSION,
  RELEASE_FILES,
  RELEASE_VERSION,
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
    } else if (arg === '--static-bin-dir') {
      options.staticBinDir = requireValue(argv, ++index, arg);
    } else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return options;
}

export function usage() {
  return [
    'Usage: node scripts/build-host-release.mjs --output <directory>',
    '       --codex-package-root <vendor-root> --static-bin-dir <directory>',
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
  const staticBinDir = requireAbsolutePath(options.staticBinDir, '--static-bin-dir');
  const hostBinDir = path.resolve(injected.hostBinDir ?? path.join(repoRoot, 'target/release'));
  const busybox = path.resolve(injected.busybox ?? '/usr/bin/busybox');
  const revision = injected.revision ?? await readCleanRevision(repoRoot, injected.execFileAsync);
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error('bot revision must be a full Git SHA');

  await validateCodexPackage(codexPackageRoot);
  const parent = path.dirname(output);
  await fs.mkdir(parent, { recursive: true, mode: 0o700 });
  await assertOutputAbsent(output);
  const temporary = path.join(
    parent,
    `.${path.basename(output)}-${process.pid}-${crypto.randomBytes(12).toString('hex')}.tmp`,
  );
  await fs.mkdir(temporary, { mode: 0o700 });
  try {
    const files = [];
    for (const entry of RELEASE_FILES) {
      const source = releaseSource(entry, {
        repoRoot,
        hostBinDir,
        staticBinDir,
        busybox,
        codexPackageRoot,
      });
      const destination = path.join(temporary, bundlePayloadPath(entry.installPath));
      const measured = await copyMeasuredFile(source, destination, entry.mode);
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
      files,
    };
    await writeJsonFile(path.join(temporary, MANIFEST_NAME), manifest, 0o444);
    await fs.rename(temporary, output);
    await syncDirectory(parent);
    return manifest;
  } catch (error) {
    await fs.rm(temporary, { recursive: true, force: true });
    throw error;
  }
}

async function readCleanRevision(repoRoot, run = execFileAsync) {
  const environment = {
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
  };
  const status = await run('/usr/bin/git', ['status', '--porcelain', '--untracked-files=no'], {
    cwd: repoRoot,
    env: environment,
    maxBuffer: 1024 * 1024,
  });
  if (status.stdout !== '') throw new Error('tracked worktree must be clean');
  const revision = await run('/usr/bin/git', ['rev-parse', 'HEAD'], {
    cwd: repoRoot,
    env: environment,
    maxBuffer: 1024 * 1024,
  });
  return revision.stdout.trim();
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

async function writeJsonFile(file, value, mode) {
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
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
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
  const manifest = await buildHostRelease(options);
  process.stdout.write(`${JSON.stringify(manifest)}\n`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`build-host-release: ${error.message}\n`);
    process.exitCode = 1;
  });
}
