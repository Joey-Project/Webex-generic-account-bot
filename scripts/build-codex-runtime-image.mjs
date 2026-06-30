#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULTS = Object.freeze({
  manifest: '/etc/webex-generic-account-bot/codex-runtime-sources.json',
  outputRoot: '/opt/webex-generic-account-bot/runtime',
  mksquashfs: '/usr/bin/mksquashfs',
});

const CODEX_SOURCE_ROOT = '/opt/webex-generic-account-bot/runtime-sources/codex';
const CODEX_PACKAGE_METADATA = `${CODEX_SOURCE_ROOT}/codex-package.json`;
const SOURCE_DEFINITIONS = Object.freeze([
  {
    source: '/opt/webex-generic-account-bot/runtime-sources/busybox',
    destination: '/bin/busybox',
    mode: '0555',
  },
  {
    source: '/opt/webex-generic-account-bot/bin/webex-codex-canary-probe',
    destination: '/bin/webex-codex-canary-probe',
    mode: '0555',
  },
  {
    source: '/etc/ssl/certs/ca-certificates.crt',
    destination: '/etc/ssl/certs/ca-certificates.crt',
    mode: '0444',
  },
  {
    source: `${CODEX_SOURCE_ROOT}/bin/codex`,
    destination: '/opt/codex/bin/codex',
    mode: '0555',
  },
  {
    source: `${CODEX_SOURCE_ROOT}/codex-path/rg`,
    destination: '/opt/codex/codex-path/rg',
    mode: '0555',
  },
  {
    source: `${CODEX_SOURCE_ROOT}/codex-resources/bwrap`,
    destination: '/opt/codex/codex-resources/bwrap',
    mode: '0555',
  },
  {
    source: '/opt/webex-generic-account-bot/bin/webex-codex-runtime',
    destination: '/usr/libexec/webex-codex-runtime',
    mode: '0555',
  },
]);

const BUILDER_VERSION = 1;
const SOURCE_MANIFEST_VERSION = 1;
const ACTIVE_MANIFEST_VERSION = 1;
const SUPPORTED_CODEX_VERSION = '0.142.3';
const SUPPORTED_CODEX_TARGET = 'x86_64-unknown-linux-musl';
const SUPPORTED_CODEX_LAYOUT_VERSION = 1;
const IMAGE_MAX_BYTES = 1024 * 1024 * 1024;
const SQUASHFS_MAGIC = Buffer.from('hsqs', 'ascii');
const COPY_BUFFER_BYTES = 1024 * 1024;
const MODE_PATTERN = /^0[45][0-7]{2}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const REQUIRED_FILES = new Set([
  '/bin/busybox',
  '/bin/webex-codex-canary-probe',
  '/etc/ssl/certs/ca-certificates.crt',
  '/opt/codex/bin/codex',
  '/opt/codex/codex-path/rg',
  '/opt/codex/codex-resources/bwrap',
  '/usr/libexec/webex-codex-runtime',
]);
const REQUIRED_FILE_MODES = new Map([
  ['/bin/busybox', '0555'],
  ['/bin/webex-codex-canary-probe', '0555'],
  ['/etc/ssl/certs/ca-certificates.crt', '0444'],
  ['/opt/codex/bin/codex', '0555'],
  ['/opt/codex/codex-path/rg', '0555'],
  ['/opt/codex/codex-resources/bwrap', '0555'],
  ['/usr/libexec/webex-codex-runtime', '0555'],
]);
const REQUIRED_SYMLINKS = new Map([
  ['/bin/sh', 'busybox'],
  ['/bin/cat', 'busybox'],
  ['/bin/find', 'busybox'],
  ['/bin/ls', 'busybox'],
  ['/bin/sed', 'busybox'],
  ['/bin/wc', 'busybox'],
]);
const GENERATED_FILES = new Map([
  ['/etc/hosts', 'runtime placeholder\n'],
  ['/etc/nsswitch.conf', 'runtime placeholder\n'],
  ['/etc/resolv.conf', 'runtime placeholder\n'],
]);
const REQUIRED_DIRECTORIES = new Set([
  '/tmp',
  '/var',
  '/var/tmp',
  '/workspace',
]);
const ALLOWED_DESTINATION_ROOTS = [
  '/bin/',
  '/etc/',
  '/opt/codex/',
  '/usr/libexec/',
];

export function parseSourceManifest(value, sourceDefinitions = SOURCE_DEFINITIONS) {
  const expectedFiles = expectedSourceFiles(sourceDefinitions);
  assertPlainObject(value, 'source manifest');
  expectExactKeys(
    value,
    [
      'codex_layout_version',
      'codex_target',
      'codex_version',
      'files',
      'symlinks',
      'version',
    ],
    'source manifest',
  );
  if (value.version !== SOURCE_MANIFEST_VERSION) {
    throw new Error('source manifest version is unsupported');
  }
  if (value.codex_version !== SUPPORTED_CODEX_VERSION) {
    throw new Error(`source manifest codex_version must be ${SUPPORTED_CODEX_VERSION}`);
  }
  if (value.codex_target !== SUPPORTED_CODEX_TARGET) {
    throw new Error(`source manifest codex_target must be ${SUPPORTED_CODEX_TARGET}`);
  }
  if (value.codex_layout_version !== SUPPORTED_CODEX_LAYOUT_VERSION) {
    throw new Error(
      `source manifest codex_layout_version must be ${SUPPORTED_CODEX_LAYOUT_VERSION}`,
    );
  }
  if (!Array.isArray(value.files) || value.files.length !== expectedFiles.size) {
    throw new Error('source manifest files are invalid');
  }
  if (!Array.isArray(value.symlinks) || value.symlinks.length !== REQUIRED_SYMLINKS.size) {
    throw new Error('source manifest symlinks are invalid');
  }

  const destinations = new Set();
  const files = value.files.map((entry, index) => {
    assertPlainObject(entry, `source manifest files[${index}]`);
    expectExactKeys(
      entry,
      ['destination', 'mode', 'sha256', 'size', 'source'],
      `source manifest files[${index}]`,
    );
    assertAbsoluteSource(entry.source, index);
    assertDestination(entry.destination, index);
    const expected = expectedFiles.get(entry.destination);
    if (expected === undefined) {
      throw new Error(`source manifest destination is not allowlisted: ${entry.destination}`);
    }
    if (entry.source !== expected.source) {
      throw new Error(`source manifest source for ${entry.destination} is not fixed`);
    }
    if (!Number.isSafeInteger(entry.size) || entry.size <= 0 || entry.size > IMAGE_MAX_BYTES) {
      throw new Error(`source manifest files[${index}].size is invalid`);
    }
    if (typeof entry.sha256 !== 'string' || !SHA256_PATTERN.test(entry.sha256)) {
      throw new Error(`source manifest files[${index}].sha256 is invalid`);
    }
    if (typeof entry.mode !== 'string' || !MODE_PATTERN.test(entry.mode)) {
      throw new Error(`source manifest files[${index}].mode is invalid`);
    }
    if (entry.mode !== expected.mode) {
      throw new Error(`source manifest mode for ${entry.destination} must be ${expected.mode}`);
    }
    if (destinations.has(entry.destination)) {
      throw new Error(`duplicate runtime destination: ${entry.destination}`);
    }
    destinations.add(entry.destination);
    return Object.freeze({ ...entry });
  });

  for (const required of REQUIRED_FILES) {
    if (!destinations.has(required)) {
      throw new Error(`source manifest is missing required file ${required}`);
    }
  }
  const symlinks = value.symlinks.map((entry, index) => {
    assertPlainObject(entry, `source manifest symlinks[${index}]`);
    expectExactKeys(entry, ['destination', 'target'], `source manifest symlinks[${index}]`);
    assertDestination(entry.destination, index);
    if (
      typeof entry.target !== 'string'
      || entry.target.length === 0
      || entry.target.length > 255
      || path.isAbsolute(entry.target)
      || entry.target.split('/').some((component) => component === '' || component === '.' || component === '..')
    ) {
      throw new Error(`source manifest symlinks[${index}].target is invalid`);
    }
    if (destinations.has(entry.destination)) {
      throw new Error(`duplicate runtime destination: ${entry.destination}`);
    }
    destinations.add(entry.destination);
    return Object.freeze({ ...entry });
  });

  const symlinkMap = new Map(symlinks.map((entry) => [entry.destination, entry.target]));
  for (const [destination, target] of REQUIRED_SYMLINKS) {
    if (symlinkMap.get(destination) !== target) {
      throw new Error(`source manifest must map ${destination} to ${target}`);
    }
  }

  return Object.freeze({
    version: value.version,
    codex_version: value.codex_version,
    codex_target: value.codex_target,
    codex_layout_version: value.codex_layout_version,
    files: Object.freeze(files),
    symlinks: Object.freeze(symlinks),
  });
}

export function mksquashfsArgs(stagingRoot, outputFile) {
  return [
    stagingRoot,
    outputFile,
    '-noappend',
    '-no-recovery',
    '-all-root',
    '-no-xattrs',
    '-mkfs-time',
    '0',
    '-all-time',
    '0',
    '-root-mode',
    '0555',
    '-no-exports',
    '-no-hardlinks',
    '-no-progress',
    '-exit-on-error',
    '-comp',
    'zstd',
    '-Xcompression-level',
    '19',
    '-processors',
    '1',
  ];
}

export async function buildRuntimeImage(options = {}, injected = {}) {
  const settings = {
    ...DEFAULTS,
    ...options,
  };
  const expectedUid = injected.expectedUid ?? 0;
  const expectedGid = injected.expectedGid ?? 0;
  const requireRoot = injected.requireRoot ?? true;
  const runMksquashfs = injected.runMksquashfs ?? defaultRunMksquashfs;
  const trustFile = injected.assertTrustedFile ?? assertTrustedFile;
  const trustDirectory = injected.assertTrustedDirectory ?? assertTrustedDirectory;
  const sourceDefinitions = injected.sourceDefinitions ?? SOURCE_DEFINITIONS;
  if (requireRoot && process.geteuid() !== 0) {
    throw new Error('runtime image builder must run as root');
  }

  await trustFile(settings.manifest, expectedUid, { executable: false });
  await trustFile(settings.mksquashfs, expectedUid, { executable: true });
  await trustDirectory(settings.outputRoot, expectedUid);
  const sourceBytes = await readBoundedFile(settings.manifest, 1024 * 1024);
  const manifest = parseSourceManifest(
    JSON.parse(sourceBytes.toString('utf8')),
    sourceDefinitions,
  );
  const sourceManifestSha256 = sha256(sourceBytes);
  const stagingRoot = await fs.mkdtemp(path.join(settings.outputRoot, '.runtime-build-'));
  const imageTemporary = path.join(
    settings.outputRoot,
    `${path.basename(stagingRoot)}.squashfs.tmp`,
  );
  let mksquashfsHandle;
  try {
    mksquashfsHandle = await fs.open(
      settings.mksquashfs,
      fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
    );
    const mksquashfsMetadata = await mksquashfsHandle.stat();
    assertTrustedSourceMetadata(mksquashfsMetadata, settings.mksquashfs, expectedUid, true);
    const mksquashfsSha256 = await hashOpenFile(
      mksquashfsHandle,
      settings.mksquashfs,
      64 * 1024 * 1024,
    );
    await fs.chmod(stagingRoot, 0o700);
    await stageManifest(stagingRoot, manifest, expectedUid, trustFile);
    await verifyStagedTree(stagingRoot, manifest);
    await runMksquashfs(mksquashfsHandle, mksquashfsArgs(stagingRoot, imageTemporary));
    if (
      await hashOpenFile(mksquashfsHandle, settings.mksquashfs, 64 * 1024 * 1024)
      !== mksquashfsSha256
    ) {
      throw new Error('mksquashfs changed while the runtime image was built');
    }
    const image = await inspectImage(imageTemporary);
    const imageRelativePath = `images/${image.sha256}.squashfs`;
    const imagesRoot = path.join(settings.outputRoot, 'images');
    await ensureTrustedInstallDirectory(imagesRoot, expectedUid, expectedGid, trustDirectory);
    const imageFinal = path.join(settings.outputRoot, imageRelativePath);
    await installContentAddressedImage(
      imageTemporary,
      imageFinal,
      image,
      expectedUid,
      expectedGid,
    );

    const active = Object.freeze({
      version: ACTIVE_MANIFEST_VERSION,
      builder_version: BUILDER_VERSION,
      codex_version: manifest.codex_version,
      codex_target: manifest.codex_target,
      codex_layout_version: manifest.codex_layout_version,
      image: imageRelativePath,
      image_sha256: image.sha256,
      image_size: image.size,
      source_manifest_sha256: sourceManifestSha256,
      mksquashfs_sha256: mksquashfsSha256,
      mksquashfs_argv_sha256: sha256(
        Buffer.from(JSON.stringify(mksquashfsArgs('/staging', '/image')), 'utf8'),
      ),
    });
    await installActiveManifest(settings.outputRoot, active, expectedUid, expectedGid);
    return active;
  } finally {
    await mksquashfsHandle?.close();
    await makeTreeRemovable(stagingRoot);
    await fs.rm(stagingRoot, { recursive: true, force: true });
    await fs.rm(imageTemporary, { force: true });
  }
}

export async function writeSourceManifest(injected = {}) {
  const expectedUid = injected.expectedUid ?? 0;
  const expectedGid = injected.expectedGid ?? 0;
  const requireRoot = injected.requireRoot ?? true;
  const trustFile = injected.assertTrustedFile ?? assertTrustedFile;
  const trustDirectory = injected.assertTrustedDirectory ?? assertTrustedDirectory;
  const definitions = injected.sourceDefinitions ?? SOURCE_DEFINITIONS;
  const packageMetadata = injected.packageMetadata ?? CODEX_PACKAGE_METADATA;
  const output = injected.output ?? DEFAULTS.manifest;
  if (requireRoot && process.geteuid() !== 0) {
    throw new Error('runtime source manifest writer must run as root');
  }
  await trustDirectory(path.dirname(output), expectedUid);
  await trustFile(packageMetadata, expectedUid, { executable: false });
  const packageBytes = await readBoundedFile(packageMetadata, 64 * 1024);
  const packageValue = JSON.parse(packageBytes.toString('utf8'));
  assertPlainObject(packageValue, 'Codex package metadata');
  expectExactKeys(
    packageValue,
    [
      'entrypoint',
      'layoutVersion',
      'pathDir',
      'resourcesDir',
      'target',
      'variant',
      'version',
    ],
    'Codex package metadata',
  );
  if (
    packageValue.version !== SUPPORTED_CODEX_VERSION
    || packageValue.target !== SUPPORTED_CODEX_TARGET
    || packageValue.layoutVersion !== SUPPORTED_CODEX_LAYOUT_VERSION
    || packageValue.variant !== 'codex'
    || packageValue.entrypoint !== 'bin/codex'
    || packageValue.resourcesDir !== 'codex-resources'
    || packageValue.pathDir !== 'codex-path'
  ) {
    throw new Error('Codex package metadata is not the reviewed runtime layout');
  }

  const files = [];
  for (const definition of definitions) {
    await trustFile(definition.source, expectedUid, {
      executable: definition.mode === '0555',
    });
    const measured = await inspectTrustedSource(
      definition.source,
      expectedUid,
      definition.mode === '0555',
    );
    files.push({
      source: definition.source,
      destination: definition.destination,
      size: measured.size,
      sha256: measured.sha256,
      mode: definition.mode,
    });
  }
  const manifest = parseSourceManifest(
    {
      version: SOURCE_MANIFEST_VERSION,
      codex_version: packageValue.version,
      codex_target: packageValue.target,
      codex_layout_version: packageValue.layoutVersion,
      files,
      symlinks: Array.from(REQUIRED_SYMLINKS, ([destination, target]) => ({
        destination,
        target,
      })),
    },
    definitions,
  );
  await atomicWriteJson(output, manifest, expectedUid, expectedGid);
  return manifest;
}

async function makeTreeRemovable(root) {
  try {
    const metadata = await fs.lstat(root);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) return;
    for (const entry of await fs.readdir(root, { withFileTypes: true })) {
      if (entry.isDirectory()) await makeTreeRemovable(path.join(root, entry.name));
    }
    await fs.chmod(root, 0o700);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

async function stageManifest(stagingRoot, manifest, expectedUid, trustFile) {
  const directories = expectedDirectories(manifest);
  for (const directory of [...directories].sort((left, right) => depth(left) - depth(right) || left.localeCompare(right))) {
    const target = stagedPath(stagingRoot, directory);
    await fs.mkdir(target, { recursive: true, mode: 0o755 });
  }

  for (const entry of manifest.files.toSorted((left, right) => left.destination.localeCompare(right.destination))) {
    await trustFile(entry.source, expectedUid, { executable: entry.mode === '0555' });
    await copyVerifiedFile(entry, stagedPath(stagingRoot, entry.destination), expectedUid);
  }
  for (const [destination, contents] of GENERATED_FILES) {
    await writeGeneratedFile(stagedPath(stagingRoot, destination), contents);
  }
  for (const entry of manifest.symlinks.toSorted((left, right) => left.destination.localeCompare(right.destination))) {
    const destination = stagedPath(stagingRoot, entry.destination);
    const target = path.resolve(path.dirname(destination), entry.target);
    if (!isInside(stagingRoot, target)) {
      throw new Error(`runtime symlink escapes staging root: ${entry.destination}`);
    }
    await fs.stat(target);
    await fs.symlink(entry.target, destination);
  }
  for (const directory of [...directories].sort((left, right) => depth(right) - depth(left) || right.localeCompare(left))) {
    const target = stagedPath(stagingRoot, directory);
    await fs.chmod(target, 0o555);
    await fs.utimes(target, 0, 0);
  }
}

async function writeGeneratedFile(destination, contents) {
  const output = await fs.open(
    destination,
    fsConstants.O_WRONLY
      | fsConstants.O_CREAT
      | fsConstants.O_EXCL
      | fsConstants.O_CLOEXEC
      | fsConstants.O_NOFOLLOW,
    0o444,
  );
  try {
    await output.writeFile(contents, 'utf8');
    await output.chmod(0o444);
    await output.sync();
  } finally {
    await output.close();
  }
  await fs.utimes(destination, 0, 0);
}

async function copyVerifiedFile(entry, destination, expectedUid) {
  const source = await fs.open(
    entry.source,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  let output;
  try {
    const before = await source.stat();
    assertTrustedSourceMetadata(before, entry.source, expectedUid);
    if (entry.mode === '0555') {
      await assertStaticX8664Elf(source, entry.source, before.size);
    }
    if (before.size !== entry.size) {
      throw new Error(`runtime source size changed: ${entry.source}`);
    }
    output = await fs.open(
      destination,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | fsConstants.O_CLOEXEC
        | fsConstants.O_NOFOLLOW,
      Number.parseInt(entry.mode, 8),
    );
    const digest = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES);
    let position = 0;
    while (true) {
      const { bytesRead } = await source.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
      await writeAll(output, buffer.subarray(0, bytesRead), position);
      position += bytesRead;
    }
    if (position !== entry.size || digest.digest('hex') !== entry.sha256) {
      throw new Error(`runtime source digest changed: ${entry.source}`);
    }
    const after = await source.stat();
    assertUnchangedMetadata(before, after, entry.source);
    await output.chmod(Number.parseInt(entry.mode, 8));
    await output.sync();
  } finally {
    await output?.close();
    await source.close();
  }
  await fs.utimes(destination, 0, 0);
}

async function writeAll(handle, buffer, start) {
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesWritten } = await handle.write(
      buffer,
      offset,
      buffer.length - offset,
      start + offset,
    );
    if (bytesWritten === 0) throw new Error('runtime image staging write made no progress');
    offset += bytesWritten;
  }
}

async function verifyStagedTree(stagingRoot, manifest) {
  const expected = new Map();
  for (const directory of expectedDirectories(manifest)) expected.set(directory, 'directory');
  for (const entry of manifest.files) expected.set(entry.destination, 'file');
  for (const destination of GENERATED_FILES.keys()) expected.set(destination, 'file');
  for (const entry of manifest.symlinks) expected.set(entry.destination, 'symlink');

  const actual = await listTree(stagingRoot);
  if (actual.size !== expected.size) throw new Error('runtime staged tree has unexpected entries');
  for (const [entry, kind] of expected) {
    if (actual.get(entry) !== kind) throw new Error(`runtime staged tree entry is invalid: ${entry}`);
  }
}

async function listTree(root, current = root, result = new Map()) {
  const entries = await fs.readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(current, entry.name);
    const relative = `/${path.relative(root, full).split(path.sep).join('/')}`;
    if (entry.isDirectory()) {
      result.set(relative, 'directory');
      await listTree(root, full, result);
    } else if (entry.isFile()) {
      result.set(relative, 'file');
    } else if (entry.isSymbolicLink()) {
      result.set(relative, 'symlink');
    } else {
      throw new Error(`runtime staged tree contains a special file: ${relative}`);
    }
  }
  return result;
}

async function inspectImage(file, expectedOwnership = null) {
  const handle = await fs.open(file, fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size <= SQUASHFS_MAGIC.length || before.size > IMAGE_MAX_BYTES) {
      throw new Error('runtime image is invalid');
    }
    if (
      expectedOwnership !== null
      && (
        before.uid !== expectedOwnership.uid
        || before.gid !== expectedOwnership.gid
        || (before.mode & 0o777) !== 0o444
      )
    ) {
      throw new Error('runtime image ownership or mode is invalid');
    }
    const magic = Buffer.alloc(SQUASHFS_MAGIC.length);
    await handle.read(magic, 0, magic.length, 0);
    if (!magic.equals(SQUASHFS_MAGIC)) throw new Error('runtime image is not SquashFS');
    const sha256 = await hashOpenFile(handle, file, IMAGE_MAX_BYTES);
    const after = await handle.stat();
    assertUnchangedMetadata(before, after, file);
    return { sha256, size: before.size };
  } finally {
    await handle.close();
  }
}

async function installContentAddressedImage(
  temporary,
  destination,
  image,
  expectedUid,
  expectedGid,
) {
  const expectedOwnership = { uid: expectedUid, gid: expectedGid };
  try {
    const existing = await inspectImage(destination, expectedOwnership);
    if (existing.sha256 !== image.sha256 || existing.size !== image.size) {
      throw new Error('content-addressed runtime image does not match its name');
    }
    return;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  await fs.chmod(temporary, 0o444);
  await fs.chown(temporary, expectedUid, expectedGid);
  await fsyncFile(temporary);
  try {
    await fs.link(temporary, destination);
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    const existing = await inspectImage(destination, expectedOwnership);
    if (existing.sha256 !== image.sha256 || existing.size !== image.size) {
      throw new Error('content-addressed runtime image does not match its name');
    }
  }
  await fs.unlink(temporary);
  await fsyncDirectory(path.dirname(destination));
}

async function installActiveManifest(outputRoot, active, expectedUid, expectedGid) {
  const target = path.join(outputRoot, 'active.json');
  await atomicWriteJson(target, active, expectedUid, expectedGid);
  await fsyncDirectory(outputRoot);
}

async function atomicWriteJson(target, value, expectedUid, expectedGid) {
  const payload = `${JSON.stringify(value, null, 2)}\n`;
  const outputRoot = path.dirname(target);
  const temporary = path.join(
    outputRoot,
    `.${path.basename(target)}-${process.pid}-${crypto.randomBytes(12).toString('hex')}.tmp`,
  );
  try {
    const handle = await fs.open(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_CLOEXEC,
      0o444,
    );
    try {
      await handle.writeFile(payload, 'utf8');
      await handle.chmod(0o444);
      await handle.chown(expectedUid, expectedGid);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(temporary, target);
    await fsyncDirectory(outputRoot);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

async function defaultRunMksquashfs(executable, args) {
  await new Promise((resolve, reject) => {
    const child = spawn('/proc/self/fd/3', args, {
      cwd: '/',
      env: { LANG: 'C', PATH: '/usr/bin:/bin' },
      shell: false,
      stdio: ['ignore', 'ignore', 'pipe', executable.fd],
    });
    const chunks = [];
    let bytes = 0;
    child.stderr.on('data', (chunk) => {
      if (bytes < 64 * 1024) chunks.push(chunk.subarray(0, 64 * 1024 - bytes));
      bytes += chunk.length;
    });
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (code === 0 && signal === null) return resolve();
      const stderr = Buffer.concat(chunks).toString('utf8').trim();
      reject(new Error(`mksquashfs failed (${signal ?? code}): ${stderr}`));
    });
  });
}

async function assertTrustedFile(file, expectedUid, { executable }) {
  assertAbsolutePath(file, 'trusted file');
  await assertTrustedAncestors(path.dirname(file), expectedUid);
  const metadata = await fs.lstat(file);
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.uid !== expectedUid
    || (metadata.mode & 0o022) !== 0
    || (executable && (metadata.mode & 0o111) === 0)
  ) {
    throw new Error(`trusted file metadata is invalid: ${file}`);
  }
}

async function assertTrustedDirectory(directory, expectedUid) {
  assertAbsolutePath(directory, 'trusted directory');
  await assertTrustedAncestors(directory, expectedUid);
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
      throw new Error(`trusted directory metadata is invalid: ${current}`);
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

async function ensureTrustedInstallDirectory(
  directory,
  expectedUid,
  expectedGid,
  trustDirectory,
) {
  try {
    await fs.mkdir(directory, { mode: 0o755 });
    await fs.chown(directory, expectedUid, expectedGid);
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  await trustDirectory(directory, expectedUid);
}

function assertTrustedSourceMetadata(metadata, file, expectedUid, executable = false) {
  if (
    !metadata.isFile()
    || metadata.uid !== expectedUid
    || (metadata.mode & 0o022) !== 0
    || (executable && (metadata.mode & 0o111) === 0)
  ) {
    throw new Error(`runtime source metadata is invalid: ${file}`);
  }
}

async function hashOpenFile(handle, file, maxBytes) {
  const before = await handle.stat();
  if (!before.isFile() || before.size > maxBytes) {
    throw new Error(`file exceeds hash limit: ${file}`);
  }
  const digest = crypto.createHash('sha256');
  const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES);
  let position = 0;
  while (true) {
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
    if (bytesRead === 0) break;
    digest.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  const after = await handle.stat();
  assertUnchangedMetadata(before, after, file);
  return digest.digest('hex');
}

async function inspectTrustedSource(file, expectedUid, executable) {
  const handle = await fs.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat();
    assertTrustedSourceMetadata(before, file, expectedUid, executable);
    if (executable) await assertStaticX8664Elf(handle, file, before.size);
    const sha256 = await hashOpenFile(handle, file, IMAGE_MAX_BYTES);
    const after = await handle.stat();
    assertUnchangedMetadata(before, after, file);
    return { size: before.size, sha256 };
  } finally {
    await handle.close();
  }
}

async function assertStaticX8664Elf(handle, file, fileSize) {
  const header = Buffer.alloc(64);
  const headerRead = await handle.read(header, 0, header.length, 0);
  if (
    headerRead.bytesRead !== header.length
    || !header.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
    || header[4] !== 2
    || header[5] !== 1
    || header[6] !== 1
    || header.readUInt16LE(18) !== 62
  ) {
    throw new Error(`runtime executable is not a supported x86-64 ELF: ${file}`);
  }
  const programOffset = Number(header.readBigUInt64LE(32));
  const entrySize = header.readUInt16LE(54);
  const entryCount = header.readUInt16LE(56);
  const tableBytes = entrySize * entryCount;
  if (
    !Number.isSafeInteger(programOffset)
    || entrySize < 56
    || entryCount === 0
    || tableBytes > 1024 * 1024
    || programOffset + tableBytes > fileSize
  ) {
    throw new Error(`runtime executable has invalid ELF program headers: ${file}`);
  }
  const table = Buffer.alloc(tableBytes);
  const tableRead = await handle.read(table, 0, table.length, programOffset);
  if (tableRead.bytesRead !== table.length) {
    throw new Error(`runtime executable changed while reading ELF headers: ${file}`);
  }
  for (let index = 0; index < entryCount; index += 1) {
    if (table.readUInt32LE(index * entrySize) === 3) {
      throw new Error(`runtime executable is dynamically linked: ${file}`);
    }
  }
}

async function readBoundedFile(file, maxBytes) {
  const handle = await fs.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maxBytes) {
      throw new Error(`file is outside the permitted size: ${file}`);
    }
    const bytes = Buffer.allocUnsafe(metadata.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) throw new Error(`file changed while being read: ${file}`);
      offset += bytesRead;
    }
    const after = await handle.stat();
    assertUnchangedMetadata(metadata, after, file);
    return bytes;
  } finally {
    await handle.close();
  }
}

function assertUnchangedMetadata(before, after, file) {
  if (
    after.dev !== before.dev
    || after.ino !== before.ino
    || after.size !== before.size
    || after.mode !== before.mode
    || after.uid !== before.uid
    || after.gid !== before.gid
    || after.mtimeMs !== before.mtimeMs
    || after.ctimeMs !== before.ctimeMs
  ) {
    throw new Error(`file changed while being read: ${file}`);
  }
}

function expectedSourceFiles(sourceDefinitions) {
  if (!Array.isArray(sourceDefinitions) || sourceDefinitions.length !== REQUIRED_FILES.size) {
    throw new Error('runtime source definitions are invalid');
  }
  const expected = new Map();
  for (const [index, definition] of sourceDefinitions.entries()) {
    assertPlainObject(definition, `runtime source definitions[${index}]`);
    expectExactKeys(
      definition,
      ['destination', 'mode', 'source'],
      `runtime source definitions[${index}]`,
    );
    assertAbsoluteSource(definition.source, index);
    assertDestination(definition.destination, index);
    const requiredMode = REQUIRED_FILE_MODES.get(definition.destination);
    if (requiredMode === undefined || definition.mode !== requiredMode) {
      throw new Error(`runtime source definition is not fixed: ${definition.destination}`);
    }
    if (expected.has(definition.destination)) {
      throw new Error(`duplicate runtime source definition: ${definition.destination}`);
    }
    expected.set(definition.destination, Object.freeze({ ...definition }));
  }
  for (const destination of REQUIRED_FILES) {
    if (!expected.has(destination)) {
      throw new Error(`runtime source definition is missing ${destination}`);
    }
  }
  return expected;
}

async function fsyncDirectory(directory) {
  const handle = await fs.open(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function fsyncFile(file) {
  const handle = await fs.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function expectedDirectories(manifest) {
  const directories = new Set(REQUIRED_DIRECTORIES);
  const destinations = [
    ...manifest.files.map((entry) => entry.destination),
    ...manifest.symlinks.map((entry) => entry.destination),
    ...GENERATED_FILES.keys(),
  ];
  for (const destination of destinations) {
    let current = path.posix.dirname(destination);
    while (current !== '/') {
      directories.add(current);
      current = path.posix.dirname(current);
    }
  }
  return directories;
}

function stagedPath(stagingRoot, destination) {
  const target = path.join(stagingRoot, destination.slice(1));
  if (!isInside(stagingRoot, target)) throw new Error(`runtime destination escapes staging: ${destination}`);
  return target;
}

function isInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function assertAbsoluteSource(value, index) {
  if (typeof value !== 'string') throw new Error(`source manifest files[${index}].source is invalid`);
  assertAbsolutePath(value, `source manifest files[${index}].source`);
  if (value.split('/').some((component) => component === '.' || component === '..')) {
    throw new Error(`source manifest files[${index}].source is invalid`);
  }
}

function assertDestination(value, index) {
  if (
    typeof value !== 'string'
    || value.length > 4096
    || !path.posix.isAbsolute(value)
    || path.posix.normalize(value) !== value
    || value === '/'
    || value.includes('\0')
    || !ALLOWED_DESTINATION_ROOTS.some((root) => value.startsWith(root))
  ) {
    throw new Error(`source manifest destination at index ${index} is invalid`);
  }
}

function assertAbsolutePath(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value) {
    throw new Error(`${label} must be a normalized absolute path`);
  }
}

function assertPlainObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function expectExactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value).toSorted(), expected.toSorted(), `${label} has unknown or missing fields`);
}

function depth(value) {
  return value.split('/').length;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

async function main() {
  if (process.argv.length === 3 && process.argv[2] === '--write-source-manifest') {
    const manifest = await writeSourceManifest();
    process.stdout.write(`${JSON.stringify(manifest)}\n`);
    return;
  }
  if (process.argv.length !== 2) {
    throw new Error('build-codex-runtime-image does not accept path or policy overrides');
  }
  const active = await buildRuntimeImage();
  process.stdout.write(`${JSON.stringify(active)}\n`);
}

const isMain = process.argv[1]
  && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`build-codex-runtime-image: ${error.message}\n`);
    process.exitCode = 1;
  });
}
