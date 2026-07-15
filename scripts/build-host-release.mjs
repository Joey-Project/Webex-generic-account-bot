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
  RELEASE_FILES,
  RELEASE_VERSION,
  RUSTC_VERSION,
  RUST_TOOLCHAIN_IMAGE_SHA256,
  RUST_TOOLCHAIN_IMAGE_SIZE,
  TRUSTED_SOURCE_SHA256,
  bundlePayloadPath,
  compareReleasePaths,
} from './host-release-contract.mjs';
import * as releaseContract from './host-release-contract.mjs';
import {
  assertNoCopyMoveSupported,
  assertSupportedNodeVersion,
  consumeExactFile,
  validateBundle,
} from './install-host-release.mjs';

const execFileAsync = promisify(execFile);
const PRODUCTION_TRUST_ROOT = '/usr/local/libexec/webex-host-release';
const PRODUCTION_BUSYBOX_PATH = `${PRODUCTION_TRUST_ROOT}/busybox`;
const PRODUCTION_BUILDER_WRAPPER_PATH = `${PRODUCTION_TRUST_ROOT}/build-host-release`;
const PRODUCTION_BUILDER_PATH = `${PRODUCTION_TRUST_ROOT}/build-host-release.mjs`;
const PRODUCTION_INSTALLER_WRAPPER_PATH = `${PRODUCTION_TRUST_ROOT}/install-host-release`;
const PRODUCTION_INSTALLER_PATH = `${PRODUCTION_TRUST_ROOT}/install-host-release.mjs`;
const PRODUCTION_CONTRACT_PATH = `${PRODUCTION_TRUST_ROOT}/host-release-contract.mjs`;
const MANIFEST_NAME = 'manifest.json';
const MAX_FILE_BYTES = 1024 * 1024 * 1024;
const MAX_SOURCE_TREE_BYTES = 16 * 1024 * 1024;
const MAX_SOURCE_BLOB_BYTES = 64 * 1024 * 1024;
const MAX_SOURCE_TOTAL_BYTES = 1024 * 1024 * 1024;
const MAX_SOURCE_FILES = 100_000;

export function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--repo') options.repoRoot = requireValue(argv, ++index, arg);
    else if (arg === '--output') options.output = requireValue(argv, ++index, arg);
    else if (arg === '--input-root') options.inputRoot = requireValue(argv, ++index, arg);
    else if (arg === '--codex-package-root') {
      options.codexPackageRoot = requireValue(argv, ++index, arg);
    } else if (arg === '--rust-toolchain-image') {
      options.rustToolchainImage = requireValue(argv, ++index, arg);
    } else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return options;
}

export function usage() {
  return [
    `Usage: ${PRODUCTION_BUILDER_WRAPPER_PATH} --repo <directory> --output <directory>`,
    '       --input-root <directory>',
    '       --codex-package-root <vendor-root> --rust-toolchain-image <squashfs>',
    '',
    'Builds an unprivileged, content-manifested first-install host release bundle.',
  ].join('\n');
}

export async function buildHostRelease(options, injected = {}) {
  assertSupportedNodeVersion();
  assertUnprivilegedBuilder();
  const repoRoot = requireAbsolutePath(injected.repoRoot ?? options.repoRoot, '--repo');
  const output = requireBuildEnvironmentPath(options.output, '--output');
  const inputRoot = requireAbsolutePath(options.inputRoot, '--input-root');
  const codexPackageRoot = requireAbsolutePath(
    options.codexPackageRoot,
    '--codex-package-root',
  );
  const rustToolchainImage = requireAbsolutePath(
    options.rustToolchainImage,
    '--rust-toolchain-image',
  );
  const busybox = resolveBusyboxPath(injected.busybox);
  const run = injected.execFileAsync ?? execFileAsync;
  const sync = injected.syncDirectory ?? syncDirectory;
  const resync = injected.resyncBundle ?? resyncBundle;
  const revision = injected.revision ?? await readRevision(repoRoot, run);
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error('bot revision must be a full Git SHA');

  const codexInputFiles = RELEASE_FILES
    .filter(({ kind }) => kind === 'codex-runtime')
    .map((entry) => releaseSource(entry, { codexPackageRoot }));
  await assertTrustedBuildInputs(inputRoot, [rustToolchainImage, ...codexInputFiles]);
  await validateCodexPackage(codexPackageRoot);
  const parent = path.dirname(output);
  await assertTrustedBuildParent(parent);
  await assertNoStaleBuildState(parent, output);
  const scratch = path.join(
    parent,
    `.${path.basename(output)}-${process.pid}-${crypto.randomBytes(12).toString('hex')}.build`,
  );
  const temporary = path.join(
    parent,
    `.${path.basename(output)}-${process.pid}-${crypto.randomBytes(12).toString('hex')}.tmp`,
  );
  await fs.mkdir(scratch, { mode: 0o700 });
  await assertPrivateBuildDirectory(scratch);
  try {
    const sourceRoot = injected.revision
      ? repoRoot
      : await materializeRevision(repoRoot, scratch, revision, run);
    const artifacts = injected.buildArtifacts
      ? await injected.buildArtifacts({ repoRoot: sourceRoot, scratch, revision })
      : await buildRustArtifacts(
        sourceRoot,
        scratch,
        rustToolchainImage,
        run,
        injected.assertCargoConfiguration ?? assertCargoConfigurationIsolated,
      );
    await assertTrustedBuildInputs(inputRoot, codexInputFiles);
    await assertTrustedBuildAncestors(parent);
    await assertPrivateBuildDirectory(scratch);
    await fs.mkdir(temporary, { mode: 0o700 });
    await assertPrivateBuildDirectory(temporary);
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
    files.sort((left, right) => compareReleasePaths(left.path, right.path));
    const manifest = {
      version: RELEASE_VERSION,
      bot_revision: revision,
      codex_version: CODEX_VERSION,
      build: {
        cargo_version: artifacts.cargoVersion,
        rustc_version: artifacts.rustcVersion,
        toolchain_sha256: artifacts.toolchainSha256,
      },
      files,
    };
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
    const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');
    await writeBytesFile(path.join(temporary, MANIFEST_NAME), manifestBytes, 0o444);
    await normaliseAndSyncBundleDirectories(temporary);
    await assertTrustedBuildAncestors(parent);
    await assertPrivateBuildDirectory(temporary);
    let status = 'built';
    try {
      await (injected.publishOutput ?? publishDirectoryNoReplace)(temporary, output);
    } catch (publishError) {
      try {
        await validateBundle(
          output,
          process.getuid(),
          process.getgid(),
          manifestSha256,
          revision,
          releaseContract,
        );
      } catch {
        throw publishError;
      }
      await resync(output, manifest);
      await fs.rm(temporary, { recursive: true, force: true });
      status = 'recovered';
    }
    await sync(parent);
    return { manifest, manifestSha256, status };
  } catch (error) {
    await fs.rm(temporary, { recursive: true, force: true });
    throw error;
  } finally {
    await fs.rm(scratch, { recursive: true, force: true });
  }
}

export function resolveBusyboxPath(candidate) {
  return path.resolve(candidate ?? PRODUCTION_BUSYBOX_PATH);
}

async function materializeRevision(repoRoot, scratch, revision, run) {
  const sourceRoot = path.join(scratch, 'source');
  await fs.mkdir(sourceRoot, { mode: 0o700 });
  const environment = gitEnvironment();
  const expectedTree = await readVerifiedCommitTree(repoRoot, revision, run, environment);
  const listing = await run('/usr/bin/git', gitArguments([
    'ls-tree',
    '-rz',
    '--full-tree',
    revision,
  ]), {
    cwd: repoRoot,
    env: environment,
    encoding: 'buffer',
    maxBuffer: MAX_SOURCE_TREE_BYTES,
  });
  const entries = parseGitTree(listing.stdout);
  if (sourceTreeObjectId(entries, expectedTree) !== expectedTree) {
    throw new Error('committed source tree object ID mismatch');
  }
  let totalBytes = 0;
  for (const entry of entries) {
    const sizeResult = await run('/usr/bin/git', gitArguments([
      'cat-file',
      '-s',
      entry.object,
    ]), {
      cwd: repoRoot,
      env: environment,
      maxBuffer: 1024 * 1024,
    });
    const sizeText = sizeResult.stdout.trim();
    if (!/^(?:0|[1-9][0-9]*)$/.test(sizeText)) {
      throw new Error(`committed source blob size is invalid: ${entry.path}`);
    }
    entry.size = Number(sizeText);
    totalBytes = accountSourceBlobBytes(totalBytes, entry.size, entry.path);
  }
  for (const entry of entries) {
    const blob = await run('/usr/bin/git', gitArguments([
      'cat-file',
      'blob',
      entry.object,
    ]), {
      cwd: repoRoot,
      env: environment,
      encoding: 'buffer',
      maxBuffer: MAX_SOURCE_BLOB_BYTES,
    });
    const bytes = toBuffer(blob.stdout);
    if (bytes.length !== entry.size) {
      throw new Error(`committed source blob size changed: ${entry.path}`);
    }
    if (gitObjectId('blob', bytes, entry.object) !== entry.object) {
      throw new Error(`committed source blob object ID mismatch: ${entry.path}`);
    }
    const destination = path.join(sourceRoot, ...entry.path.split('/'));
    await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    await writeBytesFile(destination, bytes, entry.mode);
  }
  return sourceRoot;
}

async function readVerifiedCommitTree(repoRoot, revision, run, environment) {
  const result = await run('/usr/bin/git', gitArguments([
    'cat-file',
    'commit',
    revision,
  ]), {
    cwd: repoRoot,
    env: environment,
    encoding: 'buffer',
    maxBuffer: MAX_SOURCE_TREE_BYTES,
  });
  const bytes = toBuffer(result.stdout);
  if (gitObjectId('commit', bytes, revision) !== revision) {
    throw new Error('committed source commit object ID mismatch');
  }
  const firstLineEnd = bytes.indexOf(0x0a);
  const firstLine = firstLineEnd === -1
    ? ''
    : bytes.subarray(0, firstLineEnd).toString('ascii');
  const match = /^tree ([a-f0-9]{40}|[a-f0-9]{64})$/.exec(firstLine);
  if (match === null || match[1].length !== revision.length) {
    throw new Error('committed source commit is malformed');
  }
  return match[1];
}

function sourceTreeObjectId(entries, expectedTree) {
  const root = { directories: new Map(), files: new Map() };
  for (const entry of entries) {
    if (entry.object.length !== expectedTree.length) {
      throw new Error('committed source tree mixes object formats');
    }
    const parts = entry.path.split('/');
    let node = root;
    for (let index = 0; index < parts.length; index += 1) {
      const name = parts[index];
      if (index === parts.length - 1) {
        if (node.files.has(name) || node.directories.has(name)) {
          throw new Error('committed source tree contains conflicting paths');
        }
        node.files.set(name, entry);
      } else {
        if (node.files.has(name)) {
          throw new Error('committed source tree contains conflicting paths');
        }
        if (!node.directories.has(name)) {
          node.directories.set(name, { directories: new Map(), files: new Map() });
        }
        node = node.directories.get(name);
      }
    }
  }
  return treeNodeObjectId(root, expectedTree);
}

function treeNodeObjectId(node, expectedTree) {
  const records = [];
  for (const [name, entry] of node.files) {
    records.push({
      mode: entry.mode === 0o755 ? '100755' : '100644',
      name: Buffer.from(name, 'utf8'),
      object: entry.object,
      tree: false,
    });
  }
  for (const [name, child] of node.directories) {
    records.push({
      mode: '40000',
      name: Buffer.from(name, 'utf8'),
      object: treeNodeObjectId(child, expectedTree),
      tree: true,
    });
  }
  records.sort(compareGitTreeRecords);
  const body = Buffer.concat(records.map((record) => Buffer.concat([
    Buffer.from(`${record.mode} `, 'ascii'),
    record.name,
    Buffer.from([0]),
    Buffer.from(record.object, 'hex'),
  ])));
  return gitObjectId('tree', body, expectedTree);
}

function compareGitTreeRecords(left, right) {
  const leftKey = Buffer.concat([left.name, Buffer.from([left.tree ? 0x2f : 0])]);
  const rightKey = Buffer.concat([right.name, Buffer.from([right.tree ? 0x2f : 0])]);
  return Buffer.compare(leftKey, rightKey);
}

function gitObjectId(type, bytes, expectedObjectId) {
  let algorithm;
  if (/^[a-f0-9]{40}$/.test(expectedObjectId)) algorithm = 'sha1';
  else if (/^[a-f0-9]{64}$/.test(expectedObjectId)) algorithm = 'sha256';
  else throw new Error('committed source object ID is malformed');
  const header = Buffer.from(`${type} ${bytes.length}\0`, 'ascii');
  return crypto.createHash(algorithm).update(header).update(bytes).digest('hex');
}

export function accountSourceBlobBytes(
  total,
  size,
  sourcePath,
  limit = MAX_SOURCE_TOTAL_BYTES,
) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_SOURCE_BLOB_BYTES) {
    throw new Error(`committed source blob is too large: ${sourcePath}`);
  }
  const next = total + size;
  if (!Number.isSafeInteger(total) || total < 0 || !Number.isSafeInteger(next) || next > limit) {
    throw new Error('committed source tree exceeds the aggregate byte limit');
  }
  return next;
}

export function assertUnprivilegedBuilder(
  realUid = process.getuid(),
  effectiveUid = process.geteuid(),
) {
  if (realUid === 0 || effectiveUid === 0) {
    throw new Error('host release builder must not run as root');
  }
}

async function buildRustArtifacts(
  repoRoot,
  scratch,
  rustToolchainImage,
  run,
  assertCargoConfiguration,
) {
  const toolchainImage = path.join(scratch, 'rust-toolchain.squashfs');
  const measuredToolchain = await copyMeasuredFile(rustToolchainImage, toolchainImage, 0o400);
  if (
    measuredToolchain.size !== RUST_TOOLCHAIN_IMAGE_SIZE
    || measuredToolchain.sha256 !== RUST_TOOLCHAIN_IMAGE_SHA256
  ) {
    throw new Error('Rust toolchain image does not match the trusted release digest');
  }
  const toolchainRoot = path.join(scratch, 'rust-toolchain');
  await run('/usr/bin/unsquashfs', [
    '-no-progress',
    '-dest',
    toolchainRoot,
    toolchainImage,
  ], {
    cwd: '/',
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    maxBuffer: 16 * 1024 * 1024,
  });
  await fs.mkdir(path.join(scratch, 'cargo-home'), { mode: 0o700 });
  await fs.mkdir(path.join(scratch, 'home'), { mode: 0o700 });
  const cargoBin = path.join(toolchainRoot, 'bin/cargo');
  const rustcBin = path.join(toolchainRoot, 'bin/rustc');
  const cargoConfigurationIdentity = await assertCargoConfiguration();
  try {
    const cargoVersion = (await run(cargoBin, ['--version'], {
      cwd: '/',
      env: buildEnvironment(scratch, toolchainRoot),
      maxBuffer: 1024 * 1024,
    })).stdout.trim();
    const rustcVersion = (await run(rustcBin, ['--version'], {
      cwd: '/',
      env: buildEnvironment(scratch, toolchainRoot),
      maxBuffer: 1024 * 1024,
    })).stdout.trim();
    if (cargoVersion !== CARGO_VERSION || rustcVersion !== RUSTC_VERSION) {
      throw new Error(`release build requires ${CARGO_VERSION} and ${RUSTC_VERSION}`);
    }

    const hostTarget = path.join(scratch, 'host-target');
    const staticTarget = path.join(scratch, 'static-target');
    const hostBuild = cargoBuildInvocation(repoRoot, [
      '--locked',
      '--release',
      '--all-features',
      '--target',
      'x86_64-unknown-linux-gnu',
      '--bins',
    ]);
    await run(cargoBin, hostBuild.args, {
      cwd: hostBuild.cwd,
      env: buildEnvironment(scratch, toolchainRoot, { CARGO_TARGET_DIR: hostTarget }),
      maxBuffer: 16 * 1024 * 1024,
    });
    const staticBuild = cargoBuildInvocation(repoRoot, [
      '--locked',
      '--release',
      '--all-features',
      '--target',
      'x86_64-unknown-linux-gnu',
      '--bin',
      'webex-codex-runtime',
      '--bin',
      'webex-codex-canary-probe',
    ]);
    await run(cargoBin, staticBuild.args, {
      cwd: staticBuild.cwd,
      env: buildEnvironment(
        scratch,
        toolchainRoot,
        { CARGO_TARGET_DIR: staticTarget },
        ['-Ctarget-feature=+crt-static'],
      ),
      maxBuffer: 16 * 1024 * 1024,
    });
    return {
      hostBinDir: path.join(hostTarget, 'x86_64-unknown-linux-gnu', 'release'),
      staticBinDir: path.join(staticTarget, 'x86_64-unknown-linux-gnu', 'release'),
      cargoVersion,
      rustcVersion,
      toolchainSha256: measuredToolchain.sha256,
    };
  } finally {
    await assertCargoConfiguration(cargoConfigurationIdentity);
  }
}

export function cargoBuildInvocation(repoRoot, args) {
  return Object.freeze({
    args: Object.freeze([
      'build',
      '--manifest-path',
      path.join(path.resolve(repoRoot), 'Cargo.toml'),
      ...args,
    ]),
    cwd: '/',
  });
}

export function buildEnvironment(scratch, toolchainRoot, extra = {}, additionalRustFlags = []) {
  requireBuildEnvironmentPath(scratch, 'build scratch path');
  requireBuildEnvironmentPath(toolchainRoot, 'Rust toolchain path');
  return {
    HOME: path.join(scratch, 'home'),
    CARGO_HOME: path.join(scratch, 'cargo-home'),
    LANG: 'C',
    LC_ALL: 'C',
    PATH: `${path.join(toolchainRoot, 'bin')}:/usr/bin:/bin`,
    RUSTC: path.join(toolchainRoot, 'bin/rustc'),
    RUSTDOC: path.join(toolchainRoot, 'bin/rustdoc'),
    CC: '/usr/bin/cc',
    AR: '/usr/bin/ar',
    CC_x86_64_unknown_linux_gnu: '/usr/bin/cc',
    AR_x86_64_unknown_linux_gnu: '/usr/bin/ar',
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER: '/usr/bin/cc',
    CARGO_INCREMENTAL: '0',
    CARGO_ENCODED_RUSTFLAGS: [
      `--remap-path-prefix=${scratch}=/build`,
      ...additionalRustFlags,
    ].join('\u001f'),
    SOURCE_DATE_EPOCH: '0',
    ...extra,
  };
}

async function readRevision(repoRoot, run = execFileAsync) {
  const environment = gitEnvironment();
  const revision = await run('/usr/bin/git', gitArguments([
    'rev-parse',
    '--verify',
    'HEAD^{commit}',
  ]), {
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
    GIT_ATTR_NOSYSTEM: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
  };
}

function gitArguments(args) {
  return [
    '-c', 'core.fsmonitor=false',
    '-c', 'core.attributesFile=/dev/null',
    '-c', 'core.hooksPath=/dev/null',
    ...args,
  ];
}

function parseGitTree(stdout) {
  const bytes = toBuffer(stdout);
  const entries = [];
  const seen = new Set();
  let offset = 0;
  while (offset < bytes.length) {
    const end = bytes.indexOf(0, offset);
    if (end === -1) throw new Error('committed source tree listing is malformed');
    const record = bytes.subarray(offset, end);
    const separator = record.indexOf(0x09);
    const header = separator === -1 ? '' : record.subarray(0, separator).toString('ascii');
    const match = /^(100644|100755) blob ([a-f0-9]{40}|[a-f0-9]{64})$/.exec(header);
    if (match === null) throw new Error('committed source tree contains an unsupported entry');
    const pathBytes = record.subarray(separator + 1);
    const sourcePath = pathBytes.toString('utf8');
    if (
      pathBytes.length === 0
      || !Buffer.from(sourcePath, 'utf8').equals(pathBytes)
      || path.posix.isAbsolute(sourcePath)
      || path.posix.normalize(sourcePath) !== sourcePath
      || sourcePath.split('/').some((part) => part === '' || part === '.' || part === '..')
      || seen.has(sourcePath)
    ) {
      throw new Error('committed source tree contains an unsafe path');
    }
    seen.add(sourcePath);
    entries.push({
      mode: match[1] === '100755' ? 0o755 : 0o644,
      object: match[2],
      path: sourcePath,
    });
    if (entries.length > MAX_SOURCE_FILES) {
      throw new Error('committed source tree contains too many files');
    }
    offset = end + 1;
  }
  if (entries.length === 0) throw new Error('committed source tree is empty');
  return entries;
}

function toBuffer(value) {
  return Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
}

export async function assertCargoConfigurationIsolated(
  expectedIdentity,
  root = '/',
  expectedUid = 0,
) {
  const resolvedRoot = path.resolve(root);
  const rootMetadata = await fs.lstat(resolvedRoot);
  assertTrustedCargoDirectory(rootMetadata, resolvedRoot, expectedUid);
  const cargoDirectory = path.join(resolvedRoot, '.cargo');
  let metadata;
  try {
    metadata = await fs.lstat(cargoDirectory);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      const identity = Object.freeze({
        cargo: null,
        root: directoryIdentity(rootMetadata),
      });
      assertCargoIdentityMatches(identity, expectedIdentity);
      return identity;
    }
    throw error;
  }
  assertTrustedCargoDirectory(metadata, cargoDirectory, expectedUid);
  for (const name of ['config', 'config.toml']) {
    try {
      await fs.lstat(path.join(cargoDirectory, name));
      throw new Error(`Cargo configuration is not permitted: ${path.join(cargoDirectory, name)}`);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
  const identity = Object.freeze({
    cargo: directoryIdentity(metadata),
    root: directoryIdentity(rootMetadata),
  });
  assertCargoIdentityMatches(identity, expectedIdentity);
  return identity;
}

function assertTrustedCargoDirectory(metadata, directory, expectedUid) {
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || metadata.uid !== expectedUid
    || (metadata.mode & 0o022) !== 0
  ) {
    throw new Error(`Cargo configuration root is untrusted: ${directory}`);
  }
}

function directoryIdentity(metadata) {
  return Object.freeze({
    ctimeMs: metadata.ctimeMs,
    dev: metadata.dev,
    gid: metadata.gid,
    ino: metadata.ino,
    mode: metadata.mode,
    uid: metadata.uid,
  });
}

function assertCargoIdentityMatches(identity, expectedIdentity) {
  if (
    expectedIdentity !== undefined
    && JSON.stringify(identity) !== JSON.stringify(expectedIdentity)
  ) {
    throw new Error('Cargo configuration root changed during release build');
  }
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

export async function copyMeasuredFile(source, destination, mode) {
  const input = await fs.open(
    source,
    fsConstants.O_RDONLY
      | fsConstants.O_CLOEXEC
      | fsConstants.O_NOFOLLOW
      | fsConstants.O_NONBLOCK,
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
    await consumeExactFile(input, before.size, source, async (chunk, position) => {
      digest.update(chunk);
      await writeAll(output, chunk, position);
    });
    const after = await input.stat();
    assertStableMetadata(before, after, source);
    await output.chmod(mode);
    await output.sync();
    return { size: before.size, sha256: digest.digest('hex') };
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

export async function readBoundedRegularFile(file, limit) {
  const handle = await fs.open(
    file,
    fsConstants.O_RDONLY
      | fsConstants.O_CLOEXEC
      | fsConstants.O_NOFOLLOW
      | fsConstants.O_NONBLOCK,
  );
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > limit) {
      throw new Error(`file is outside the permitted size: ${file}`);
    }
    const bytes = Buffer.allocUnsafe(metadata.size);
    await consumeExactFile(handle, metadata.size, file, (chunk, position) => {
      chunk.copy(bytes, position);
    });
    assertStableMetadata(metadata, await handle.stat(), file);
    return bytes;
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

export async function resyncBundle(root, manifest) {
  for (const entry of manifest.files) {
    await syncRegularFile(path.join(root, bundlePayloadPath(entry.path)));
  }
  await syncRegularFile(path.join(root, MANIFEST_NAME));
  const directories = await collectDirectories(root);
  for (const directory of directories.toSorted((left, right) => depth(right) - depth(left))) {
    await syncDirectory(directory);
  }
}

async function syncRegularFile(file) {
  const handle = await fs.open(
    file,
    fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error(`release bundle sync target is not a file: ${file}`);
    await handle.sync();
    assertStableMetadata(before, await handle.stat(), file);
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

async function assertTrustedBuildParent(parent) {
  try {
    await assertTrustedBuildAncestors(parent);
    await assertPrivateBuildDirectory(parent);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new Error(`release build parent must already exist: ${parent}`);
    }
    throw error;
  }
}

async function assertTrustedBuildInputs(inputRoot, files) {
  await assertTrustedBuildAncestors(inputRoot);
  await assertPrivateBuildDirectory(inputRoot, 'release input root');
  for (const file of files) {
    assertStrictDescendant(inputRoot, file, 'release input');
    await assertTrustedInputDirectoryChain(inputRoot, path.dirname(file));
    const metadata = await fs.lstat(file);
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || metadata.uid !== process.getuid()
      || metadata.gid !== process.getgid()
      || (metadata.mode & 0o022) !== 0
      || metadata.size <= 0
      || metadata.size > MAX_FILE_BYTES
    ) {
      throw new Error(`untrusted release input file: ${file}`);
    }
  }
}

async function assertTrustedInputDirectoryChain(root, directory) {
  let current = path.resolve(directory);
  while (true) {
    const metadata = await fs.lstat(current);
    if (
      !metadata.isDirectory()
      || metadata.isSymbolicLink()
      || metadata.uid !== process.getuid()
      || metadata.gid !== process.getgid()
      || (metadata.mode & 0o022) !== 0
    ) {
      throw new Error(`untrusted release input directory: ${current}`);
    }
    if (current === root) return;
    const ancestor = path.dirname(current);
    if (ancestor === current) throw new Error(`release input is outside input root: ${directory}`);
    current = ancestor;
  }
}

function assertStrictDescendant(root, target, label) {
  const relative = path.relative(root, target);
  if (
    relative === ''
    || relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) {
    throw new Error(`${label} is outside input root: ${target}`);
  }
}

async function assertTrustedBuildAncestors(start) {
  let current = path.resolve(start);
  while (true) {
    const metadata = await fs.lstat(current);
    const mode = metadata.mode & 0o7777;
    const trustedOwner = metadata.uid === 0 || metadata.uid === process.getuid();
    const nonWritable = (mode & 0o022) === 0;
    const rootSticky = metadata.uid === 0 && (mode & 0o1000) !== 0;
    if (
      !metadata.isDirectory()
      || metadata.isSymbolicLink()
      || !trustedOwner
      || (!nonWritable && !rootSticky)
    ) {
      throw new Error(`untrusted release build ancestor: ${current}`);
    }
    const ancestor = path.dirname(current);
    if (ancestor === current) return;
    current = ancestor;
  }
}

async function assertPrivateBuildDirectory(directory, label = 'release build directory') {
  const metadata = await fs.lstat(directory);
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || metadata.uid !== process.getuid()
    || metadata.gid !== process.getgid()
    || (metadata.mode & 0o7777) !== 0o700
  ) {
    throw new Error(`untrusted ${label}: ${directory}`);
  }
}

async function assertNoStaleBuildState(parent, output) {
  const prefix = `.${path.basename(output)}-`;
  const directory = await fs.opendir(parent);
  for await (const entry of directory) {
    if (
      !entry.name.startsWith(prefix)
      || (!entry.name.endsWith('.build') && !entry.name.endsWith('.tmp'))
    ) {
      continue;
    }
    const stagingPath = path.join(parent, entry.name);
    const metadata = await fs.lstat(stagingPath);
    if (
      !metadata.isDirectory()
      || metadata.isSymbolicLink()
      || metadata.uid !== process.getuid()
      || metadata.gid !== process.getgid()
      || (metadata.mode & 0o7777) !== 0o700
    ) {
      throw new Error(`untrusted release staging path requires inspection: ${stagingPath}`);
    }
    throw new Error(`stale release staging path requires cleanup: ${stagingPath}`);
  }
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

function requireBuildEnvironmentPath(value, flag) {
  const absolute = requireAbsolutePath(value, flag);
  if (/[:=\u0000-\u001f\u007f]/.test(absolute)) {
    throw new Error(`${flag} must not contain build-environment delimiters`);
  }
  return absolute;
}

function requireValue(argv, index, flag) {
  if (index >= argv.length || argv[index].startsWith('-')) {
    throw new Error(`${flag} requires a value`);
  }
  return argv[index];
}

async function main() {
  assertSupportedNodeVersion();
  assertUnprivilegedBuilder();
  await assertProductionBuilderTrustAnchor();
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  await assertNoCopyMoveSupported();
  const result = await buildHostRelease(options);
  process.stdout.write(`status=${result.status}\n`);
  process.stdout.write(`bot_revision=${result.manifest.bot_revision}\n`);
  process.stdout.write(`codex_version=${result.manifest.codex_version}\n`);
  process.stdout.write(`manifest_sha256=${result.manifestSha256}\n`);
  process.stdout.write(`file_count=${result.manifest.files.length}\n`);
  process.stdout.write(`output=${options.output}\n`);
}

async function assertProductionBuilderTrustAnchor() {
  if (fileURLToPath(import.meta.url) !== PRODUCTION_BUILDER_PATH) {
    throw new Error(`production builder must run from ${PRODUCTION_BUILDER_PATH}`);
  }
  await assertTrustedRootAncestors(PRODUCTION_TRUST_ROOT);
  assertRootOwnedMetadata(
    await fs.lstat(PRODUCTION_TRUST_ROOT),
    PRODUCTION_TRUST_ROOT,
    0o755,
    'directory',
  );
  assertRootOwnedMetadata(
    await fs.lstat(PRODUCTION_BUSYBOX_PATH),
    PRODUCTION_BUSYBOX_PATH,
    0o555,
    'file',
  );
  const busyboxBytes = await readBoundedRegularFile(PRODUCTION_BUSYBOX_PATH, 16 * 1024 * 1024);
  if (
    crypto.createHash('sha256').update(busyboxBytes).digest('hex')
    !== TRUSTED_SOURCE_SHA256['runtime-sources/busybox']
  ) {
    throw new Error('builder trust-anchor BusyBox digest is invalid');
  }
  assertRootOwnedMetadata(
    await fs.lstat(PRODUCTION_BUILDER_WRAPPER_PATH),
    PRODUCTION_BUILDER_WRAPPER_PATH,
    0o555,
    'file',
  );
  assertRootOwnedMetadata(
    await fs.lstat(PRODUCTION_INSTALLER_WRAPPER_PATH),
    PRODUCTION_INSTALLER_WRAPPER_PATH,
    0o555,
    'file',
  );
  assertRootOwnedMetadata(
    await fs.lstat(PRODUCTION_BUILDER_PATH),
    PRODUCTION_BUILDER_PATH,
    0o444,
    'file',
  );
  assertRootOwnedMetadata(
    await fs.lstat(PRODUCTION_INSTALLER_PATH),
    PRODUCTION_INSTALLER_PATH,
    0o444,
    'file',
  );
  assertRootOwnedMetadata(
    await fs.lstat(PRODUCTION_CONTRACT_PATH),
    PRODUCTION_CONTRACT_PATH,
    0o444,
    'file',
  );
}

async function assertTrustedRootAncestors(start) {
  let current = path.resolve(start);
  while (true) {
    const metadata = await fs.lstat(current);
    assertRootOwnedMetadata(metadata, current, metadata.mode & 0o7777, 'directory');
    if ((metadata.mode & 0o022) !== 0) {
      throw new Error(`builder trust-anchor ancestor is writable: ${current}`);
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function assertRootOwnedMetadata(metadata, target, mode, kind) {
  const expectedType = kind === 'directory' ? metadata.isDirectory() : metadata.isFile();
  if (
    !expectedType
    || metadata.isSymbolicLink()
    || metadata.uid !== 0
    || metadata.gid !== 0
    || (metadata.mode & 0o7777) !== mode
    || (kind === 'file' && metadata.nlink !== 1)
  ) {
    throw new Error(`builder trust-anchor metadata is invalid: ${target}`);
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`build-host-release: ${error.message}\n`);
    process.exitCode = 1;
  });
}
