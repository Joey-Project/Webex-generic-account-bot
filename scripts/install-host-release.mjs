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
  CARGO_VERSION,
  CODEX_VERSION,
  PRODUCTION_BUNDLE_ROOT,
  PRODUCTION_CONTRACT_PATH,
  PRODUCTION_INSTALLER_PATH,
  PRODUCTION_INSTALL_ROOT,
  PRODUCTION_TRUST_ROOT,
  RELEASE_FILES,
  RELEASE_PATHS,
  RELEASE_VERSION,
  RUSTC_VERSION,
  bundlePayloadPath,
} from './host-release-contract.mjs';

const execFileAsync = promisify(execFile);
const MANIFEST_NAME = 'manifest.json';
const MANIFEST_MAX_BYTES = 1024 * 1024;
const MAX_FILE_BYTES = 1024 * 1024 * 1024;
const COPY_BUFFER_BYTES = 1024 * 1024;
const CANDIDATE_PREFIX = '.webex-generic-account-bot-install-';

export function parseArgs(argv) {
  const options = { apply: false, json: false };
  let selectedMode = null;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--apply') {
      if (selectedMode !== null) throw new Error('select exactly one install mode');
      selectedMode = 'apply';
      options.apply = true;
    } else if (arg === '--dry-run') {
      if (selectedMode !== null) throw new Error('select exactly one install mode');
      selectedMode = 'dry-run';
    } else if (arg === '--expected-bot-revision') {
      options.expectedBotRevision = requireValue(argv, ++index, arg);
    } else if (arg === '--expected-manifest-sha256') {
      options.expectedManifestSha256 = requireValue(argv, ++index, arg);
    } else if (arg === '--json') options.json = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return options;
}

export function usage() {
  return [
    `Usage: /usr/bin/node ${PRODUCTION_INSTALLER_PATH} [--dry-run] [--json]`,
    '       --expected-bot-revision <sha> --expected-manifest-sha256 <sha256>',
    `       /usr/bin/node ${PRODUCTION_INSTALLER_PATH} --apply [--json]`,
    '       --expected-bot-revision <sha> --expected-manifest-sha256 <sha256>',
    '',
    'Dry-run is the default. Trust, bundle, and install paths are fixed.',
  ].join('\n');
}

export async function installHostRelease(options, injected = {}) {
  const bundleRoot = path.resolve(injected.bundleRoot ?? PRODUCTION_BUNDLE_ROOT);
  const installRoot = path.resolve(injected.installRoot ?? PRODUCTION_INSTALL_ROOT);
  const expectedUid = injected.expectedUid ?? 0;
  const expectedGid = injected.expectedGid ?? 0;
  const requireRoot = injected.requireRoot ?? true;
  const trustAncestors = injected.trustAncestors ?? true;
  const publish = injected.publishCandidate ?? publishCandidate;
  const sync = injected.syncDirectory ?? syncDirectory;
  assertExpectedRelease(options);
  if (requireRoot && process.geteuid() !== 0) {
    throw new Error('host release installation requires root, including dry-run');
  }
  if (trustAncestors) {
    await assertTrustedAncestors(bundleRoot, expectedUid);
    await assertTrustedAncestors(path.dirname(installRoot), expectedUid);
  }
  await assertNoStaleCandidates(path.dirname(installRoot), expectedUid);
  const manifest = await validateBundle(
    bundleRoot,
    expectedUid,
    expectedGid,
    options.expectedManifestSha256,
    options.expectedBotRevision,
  );
  if (await pathExists(installRoot)) {
    await validateInstalledRelease(installRoot, manifest, expectedUid, expectedGid);
    await sync(path.dirname(installRoot));
    return {
      status: options.apply ? 'recovered' : 'already_installed',
      bot_revision: manifest.bot_revision,
      codex_version: manifest.codex_version,
      file_count: manifest.files.length,
      install_root: installRoot,
    };
  }
  const result = {
    status: options.apply ? 'installed' : 'dry_run',
    bot_revision: manifest.bot_revision,
    codex_version: manifest.codex_version,
    file_count: manifest.files.length,
    install_root: installRoot,
  };
  if (!options.apply) return result;

  const candidate = path.join(
    path.dirname(installRoot),
    `${CANDIDATE_PREFIX}${crypto.randomUUID()}`,
  );
  await fs.mkdir(candidate, { mode: 0o755 });
  let published = false;
  try {
    for (const entry of manifest.files) {
      const source = path.join(bundleRoot, bundlePayloadPath(entry.path));
      const destination = path.join(candidate, entry.path);
      await copyVerifiedFile(source, destination, entry, expectedUid, expectedGid);
    }
    await writeReleaseMetadata(
      path.join(candidate, 'release.json'),
      manifest,
      expectedUid,
      expectedGid,
    );
    await fs.mkdir(path.join(candidate, 'runtime'), { mode: 0o755 });
    const directories = await collectDirectories(candidate);
    for (const directory of directories.toSorted((left, right) => depth(right) - depth(left))) {
      await fs.chmod(directory, 0o755);
      await fs.chown(directory, expectedUid, expectedGid);
      await sync(directory);
    }
    await publish(candidate, installRoot);
    published = true;
    await sync(path.dirname(installRoot));
    return result;
  } catch (error) {
    if (!published) await fs.rm(candidate, { recursive: true, force: true });
    throw error;
  }
}

export async function validateBundle(
  bundleRoot,
  expectedUid = 0,
  expectedGid = 0,
  expectedManifestSha256,
  expectedBotRevision,
) {
  const rootMetadata = await fs.lstat(bundleRoot);
  assertDirectoryMetadata(rootMetadata, bundleRoot, expectedUid, expectedGid, 0o700);
  const manifestPath = path.join(bundleRoot, MANIFEST_NAME);
  const manifestMetadata = await fs.lstat(manifestPath);
  assertFileMetadata(manifestMetadata, manifestPath, expectedUid, expectedGid, 0o444);
  if (manifestMetadata.size <= 0 || manifestMetadata.size > MANIFEST_MAX_BYTES) {
    throw new Error('host release manifest is outside the permitted size');
  }
  const manifestBytes = await readStableFile(manifestPath, manifestMetadata);
  const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');
  if (manifestSha256 !== expectedManifestSha256) {
    throw new Error('host release manifest does not match the trusted digest');
  }
  const manifest = parseManifest(JSON.parse(manifestBytes.toString('utf8')));
  if (manifest.bot_revision !== expectedBotRevision) {
    throw new Error('host release manifest does not match the trusted bot revision');
  }
  const expectedTree = expectedBundleTree(manifest);
  const actualTree = await readBundleTree(bundleRoot, expectedUid, expectedGid);
  if (
    actualTree.size !== expectedTree.size
    || [...expectedTree].some(([entry, kind]) => actualTree.get(entry) !== kind)
  ) {
    throw new Error('host release bundle contains missing or unexpected entries');
  }
  for (const entry of manifest.files) {
    const file = path.join(bundleRoot, bundlePayloadPath(entry.path));
    const metadata = await fs.lstat(file);
    assertFileMetadata(
      metadata,
      file,
      expectedUid,
      expectedGid,
      Number.parseInt(entry.mode, 8),
    );
    if (metadata.size !== entry.size) throw new Error(`host release size mismatch: ${entry.path}`);
    const digest = await hashStableFile(file, metadata);
    if (digest !== entry.sha256) throw new Error(`host release digest mismatch: ${entry.path}`);
  }
  return manifest;
}

export function parseManifest(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('host release manifest must be an object');
  }
  const keys = Object.keys(value).toSorted();
  if (
    JSON.stringify(keys)
    !== JSON.stringify(['bot_revision', 'build', 'codex_version', 'files', 'version'])
  ) {
    throw new Error('host release manifest fields are invalid');
  }
  if (value.version !== RELEASE_VERSION) throw new Error('host release version is unsupported');
  if (!/^[a-f0-9]{40}$/.test(value.bot_revision)) {
    throw new Error('host release bot revision is invalid');
  }
  if (value.codex_version !== CODEX_VERSION) {
    throw new Error(`host release Codex version must be ${CODEX_VERSION}`);
  }
  if (
    value.build === null
    || typeof value.build !== 'object'
    || Array.isArray(value.build)
    || JSON.stringify(Object.keys(value.build).toSorted())
      !== JSON.stringify(['cargo_version', 'rustc_version'])
    || value.build.cargo_version !== CARGO_VERSION
    || value.build.rustc_version !== RUSTC_VERSION
  ) {
    throw new Error('host release Rust toolchain provenance is invalid');
  }
  if (!Array.isArray(value.files) || value.files.length !== RELEASE_FILES.length) {
    throw new Error('host release file list is invalid');
  }
  const expectedModes = new Map(
    RELEASE_FILES.map(({ installPath, mode }) => [installPath, modeString(mode)]),
  );
  const seen = new Set();
  const files = value.files.map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`host release files[${index}] must be an object`);
    }
    if (
      JSON.stringify(Object.keys(entry).toSorted())
      !== JSON.stringify(['mode', 'path', 'sha256', 'size'])
    ) {
      throw new Error(`host release files[${index}] fields are invalid`);
    }
    if (!expectedModes.has(entry.path) || seen.has(entry.path)) {
      throw new Error(`host release path is not allowlisted: ${entry.path}`);
    }
    if (entry.mode !== expectedModes.get(entry.path)) {
      throw new Error(`host release mode is invalid: ${entry.path}`);
    }
    if (!Number.isSafeInteger(entry.size) || entry.size <= 0 || entry.size > MAX_FILE_BYTES) {
      throw new Error(`host release size is invalid: ${entry.path}`);
    }
    if (typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
      throw new Error(`host release digest is invalid: ${entry.path}`);
    }
    seen.add(entry.path);
    return Object.freeze({ ...entry });
  });
  if (RELEASE_PATHS.some((entry) => !seen.has(entry))) {
    throw new Error('host release file list is incomplete');
  }
  return Object.freeze({
    version: value.version,
    bot_revision: value.bot_revision,
    codex_version: value.codex_version,
    build: Object.freeze({ ...value.build }),
    files: Object.freeze(files.toSorted((left, right) => left.path.localeCompare(right.path))),
  });
}

async function readBundleTree(root, expectedUid, expectedGid, current = root, result = new Map()) {
  for (const name of await fs.readdir(current)) {
    const full = path.join(current, name);
    const relative = path.relative(root, full).split(path.sep).join('/');
    const metadata = await fs.lstat(full);
    if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
      if (
        metadata.uid !== expectedUid
        || metadata.gid !== expectedGid
        || (metadata.mode & 0o7777) !== 0o755
      ) {
        throw new Error(`host release directory metadata is invalid: ${relative}`);
      }
      result.set(relative, 'directory');
      await readBundleTree(root, expectedUid, expectedGid, full, result);
    } else if (metadata.isFile() && !metadata.isSymbolicLink()) {
      result.set(relative, 'file');
    } else {
      throw new Error(`host release bundle contains a special file: ${relative}`);
    }
  }
  return result;
}

async function validateInstalledRelease(root, manifest, expectedUid, expectedGid) {
  const rootMetadata = await fs.lstat(root);
  assertDirectoryMetadata(rootMetadata, root, expectedUid, expectedGid, 0o755);
  const expectedTree = expectedInstalledTree(manifest);
  const actualTree = await readInstalledTree(root, expectedUid, expectedGid);
  if (
    actualTree.size !== expectedTree.size
    || [...expectedTree].some(([entry, kind]) => actualTree.get(entry) !== kind)
  ) {
    throw new Error('existing host release does not match the trusted release tree');
  }
  for (const entry of manifest.files) {
    const file = path.join(root, entry.path);
    const metadata = await fs.lstat(file);
    assertFileMetadata(
      metadata,
      file,
      expectedUid,
      expectedGid,
      Number.parseInt(entry.mode, 8),
    );
    if (metadata.size !== entry.size || await hashStableFile(file, metadata) !== entry.sha256) {
      throw new Error(`existing host release file does not match: ${entry.path}`);
    }
  }
  const releasePath = path.join(root, 'release.json');
  const releaseMetadata = await fs.lstat(releasePath);
  assertFileMetadata(releaseMetadata, releasePath, expectedUid, expectedGid, 0o444);
  const expectedRelease = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  const releaseBytes = await readStableFile(releasePath, releaseMetadata);
  if (!releaseBytes.equals(expectedRelease)) {
    throw new Error('existing host release metadata does not match the trusted manifest');
  }
}

async function readInstalledTree(root, expectedUid, expectedGid, current = root, result = new Map()) {
  for (const name of await fs.readdir(current)) {
    const full = path.join(current, name);
    const relative = path.relative(root, full).split(path.sep).join('/');
    const metadata = await fs.lstat(full);
    if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
      assertDirectoryMetadata(metadata, full, expectedUid, expectedGid, 0o755);
      result.set(relative, 'directory');
      await readInstalledTree(root, expectedUid, expectedGid, full, result);
    } else if (metadata.isFile() && !metadata.isSymbolicLink()) {
      result.set(relative, 'file');
    } else {
      throw new Error(`existing host release contains a special file: ${relative}`);
    }
  }
  return result;
}

function expectedInstalledTree(manifest) {
  const result = new Map([
    ['release.json', 'file'],
    ['runtime', 'directory'],
  ]);
  for (const entry of manifest.files) {
    result.set(entry.path, 'file');
    let directory = path.posix.dirname(entry.path);
    while (directory !== '.') {
      result.set(directory, 'directory');
      directory = path.posix.dirname(directory);
    }
  }
  return result;
}

function expectedBundleTree(manifest) {
  const result = new Map([[MANIFEST_NAME, 'file']]);
  for (const entry of manifest.files) {
    const file = bundlePayloadPath(entry.path);
    result.set(file, 'file');
    let directory = path.posix.dirname(file);
    while (directory !== '.') {
      result.set(directory, 'directory');
      directory = path.posix.dirname(directory);
    }
  }
  return result;
}

async function copyVerifiedFile(source, destination, expected, expectedUid, expectedGid) {
  const input = await fs.open(
    source,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  let output;
  try {
    const before = await input.stat();
    await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o755 });
    output = await fs.open(
      destination,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | fsConstants.O_CLOEXEC
        | fsConstants.O_NOFOLLOW,
      Number.parseInt(expected.mode, 8),
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
    if (position !== expected.size || digest.digest('hex') !== expected.sha256) {
      throw new Error(`host release source changed during install: ${expected.path}`);
    }
    await output.chmod(Number.parseInt(expected.mode, 8));
    await output.chown(expectedUid, expectedGid);
    await output.sync();
  } finally {
    await output?.close();
    await input.close();
  }
}

async function hashStableFile(file, before) {
  const handle = await fs.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  try {
    const digest = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES);
    let position = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    assertStableMetadata(before, await handle.stat(), file);
    return digest.digest('hex');
  } finally {
    await handle.close();
  }
}

async function readStableFile(file, expectedMetadata) {
  const handle = await fs.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat();
    assertStableMetadata(expectedMetadata, before, file);
    const bytes = await handle.readFile();
    assertStableMetadata(before, await handle.stat(), file);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function writeReleaseMetadata(file, manifest, expectedUid, expectedGid) {
  const handle = await fs.open(
    file,
    fsConstants.O_WRONLY
      | fsConstants.O_CREAT
      | fsConstants.O_EXCL
      | fsConstants.O_CLOEXEC
      | fsConstants.O_NOFOLLOW,
    0o444,
  );
  try {
    await handle.writeFile(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
    await handle.chmod(0o444);
    await handle.chown(expectedUid, expectedGid);
    await handle.sync();
  } finally {
    await handle.close();
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

async function assertTrustedAncestors(start, expectedUid) {
  let current = path.resolve(start);
  while (true) {
    const metadata = await fs.lstat(current);
    if (
      !metadata.isDirectory()
      || metadata.isSymbolicLink()
      || metadata.uid !== expectedUid
      || (metadata.mode & 0o022) !== 0
    ) {
      throw new Error(`trusted host release ancestor is invalid: ${current}`);
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
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

export async function publishCandidate(candidate, installRoot, run = execFileAsync) {
  try {
    await run('/usr/bin/mv', [
      '--no-copy',
      '--no-clobber',
      '--no-target-directory',
      candidate,
      installRoot,
    ], {
      cwd: '/',
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    if (await pathExists(candidate) && await pathExists(installRoot)) {
      throw new Error(`host release install root appeared during publish: ${installRoot}`);
    }
    throw error;
  }
  if (await pathExists(candidate)) {
    throw new Error(`host release install root appeared during publish: ${installRoot}`);
  }
  if (!await pathExists(installRoot)) {
    throw new Error('host release publish did not create the install root');
  }
}

function assertExpectedRelease(options) {
  if (!/^[a-f0-9]{40}$/.test(options.expectedBotRevision ?? '')) {
    throw new Error('--expected-bot-revision must be a full trusted Git SHA');
  }
  if (!/^[a-f0-9]{64}$/.test(options.expectedManifestSha256 ?? '')) {
    throw new Error('--expected-manifest-sha256 must be a trusted SHA-256 digest');
  }
}

async function assertNoStaleCandidates(parent, expectedUid) {
  for (const name of await fs.readdir(parent)) {
    if (!name.startsWith(CANDIDATE_PREFIX)) continue;
    const candidate = path.join(parent, name);
    const metadata = await fs.lstat(candidate);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== expectedUid) {
      throw new Error(`untrusted host release candidate exists: ${candidate}`);
    }
    throw new Error(`stale host release candidate requires manual inspection: ${candidate}`);
  }
}

function assertDirectoryMetadata(metadata, file, uid, gid, mode) {
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || metadata.uid !== uid
    || metadata.gid !== gid
    || (metadata.mode & 0o7777) !== mode
  ) {
    throw new Error(`host release directory metadata is invalid: ${file}`);
  }
}

function assertFileMetadata(metadata, file, uid, gid, mode) {
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.uid !== uid
    || metadata.gid !== gid
    || metadata.nlink !== 1
    || (metadata.mode & 0o7777) !== mode
  ) {
    throw new Error(`host release file metadata is invalid: ${file}`);
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
    if (bytesWritten === 0) throw new Error('host release install write made no progress');
    offset += bytesWritten;
  }
}

function assertStableMetadata(before, after, file) {
  for (const key of ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'mtimeMs', 'ctimeMs']) {
    if (before[key] !== after[key]) throw new Error(`host release file changed: ${file}`);
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

function requireValue(argv, index, flag) {
  if (index >= argv.length || argv[index].startsWith('-')) {
    throw new Error(`${flag} requires a value`);
  }
  return argv[index];
}

async function assertProductionTrustAnchor() {
  const currentScript = fileURLToPath(import.meta.url);
  if (currentScript !== PRODUCTION_INSTALLER_PATH) {
    throw new Error(`production installer must run from ${PRODUCTION_INSTALLER_PATH}`);
  }
  await assertTrustedAncestors(PRODUCTION_TRUST_ROOT, 0);
  assertDirectoryMetadata(
    await fs.lstat(PRODUCTION_TRUST_ROOT),
    PRODUCTION_TRUST_ROOT,
    0,
    0,
    0o755,
  );
  assertFileMetadata(
    await fs.lstat(PRODUCTION_INSTALLER_PATH),
    PRODUCTION_INSTALLER_PATH,
    0,
    0,
    0o444,
  );
  assertFileMetadata(
    await fs.lstat(PRODUCTION_CONTRACT_PATH),
    PRODUCTION_CONTRACT_PATH,
    0,
    0,
    0o444,
  );
}

async function main() {
  await assertProductionTrustAnchor();
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const result = await installHostRelease(options);
  if (options.json) process.stdout.write(`${JSON.stringify(result)}\n`);
  else {
    process.stdout.write(`status=${result.status}\n`);
    process.stdout.write(`bot_revision=${result.bot_revision}\n`);
    process.stdout.write(`codex_version=${result.codex_version}\n`);
    process.stdout.write(`file_count=${result.file_count}\n`);
    process.stdout.write(`install_root=${result.install_root}\n`);
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`install-host-release: ${error.message}\n`);
    process.exitCode = 1;
  });
}
