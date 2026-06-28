import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import {
  buildRuntimeImage,
  mksquashfsArgs,
  parseSourceManifest,
  writeSourceManifest,
} from '../scripts/build-codex-runtime-image.mjs';

const REQUIRED_FILE_DESTINATIONS = [
  '/bin/busybox',
  '/etc/ssl/certs/ca-certificates.crt',
  '/opt/codex/bin/codex',
  '/opt/codex/codex-path/rg',
  '/opt/codex/codex-resources/bwrap',
  '/usr/libexec/webex-codex-runtime',
];

const REQUIRED_SYMLINKS = [
  { destination: '/bin/sh', target: 'busybox' },
  { destination: '/bin/cat', target: 'busybox' },
  { destination: '/bin/find', target: 'busybox' },
  { destination: '/bin/ls', target: 'busybox' },
  { destination: '/bin/sed', target: 'busybox' },
  { destination: '/bin/wc', target: 'busybox' },
];

describe('Codex runtime image contract', () => {
  it('accepts only the exact mandatory runtime source schema', () => {
    const manifest = sourceManifest('/trusted');
    const definitions = sourceDefinitions('/trusted');
    assert.equal(
      parseSourceManifest(manifest, definitions).files.length,
      REQUIRED_FILE_DESTINATIONS.length,
    );

    assert.throws(
      () => parseSourceManifest({ ...manifest, extra: true }, definitions),
      /unknown or missing fields/,
    );
    assert.throws(
      () => parseSourceManifest({
        ...manifest,
        files: manifest.files.filter((entry) => entry.destination !== '/opt/codex/bin/codex'),
      }, definitions),
      /files are invalid/,
    );
    assert.throws(
      () => parseSourceManifest({
        ...manifest,
        files: manifest.files.map((entry, index) => index === 0
          ? { ...entry, destination: '/bin/../etc/passwd' }
          : entry),
      }, definitions),
      /destination.*invalid/,
    );
    assert.throws(
      () => parseSourceManifest({
        ...manifest,
        symlinks: manifest.symlinks.map((entry, index) => index === 0
          ? { ...entry, target: '../busybox' }
          : entry),
      }, definitions),
      /target is invalid/,
    );
    assert.throws(
      () => parseSourceManifest({
        ...manifest,
        files: manifest.files.map((entry, index) => index === 0
          ? { ...entry, mode: '0444' }
          : entry),
      }, definitions),
      /mode for \/bin\/busybox must be 0555/,
    );
    assert.throws(
      () => parseSourceManifest({
        ...manifest,
        files: manifest.files.map((entry, index) => index === 0
          ? { ...entry, source: '/trusted/replacement' }
          : entry),
      }, definitions),
      /source for \/bin\/busybox is not fixed/,
    );
    assert.throws(
      () => parseSourceManifest({
        ...manifest,
        files: [...manifest.files, manifest.files[0]],
      }, definitions),
      /files are invalid/,
    );
    assert.throws(
      () => parseSourceManifest({
        ...manifest,
        symlinks: [...manifest.symlinks, { destination: '/bin/extra', target: 'busybox' }],
      }, definitions),
      /symlinks are invalid/,
    );
    assert.throws(
      () => parseSourceManifest({
        ...manifest,
        codex_target: 'aarch64-unknown-linux-musl',
      }, definitions),
      /codex_target must be x86_64-unknown-linux-musl/,
    );
    assert.throws(
      () => parseSourceManifest({
        ...manifest,
        codex_layout_version: 2,
      }, definitions),
      /codex_layout_version must be 1/,
    );
  });

  it('pins deterministic mksquashfs arguments', () => {
    assert.deepEqual(mksquashfsArgs('/staging', '/image'), [
      '/staging',
      '/image',
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
    ]);
  });

  it('installs an image by content digest before atomically selecting it', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-codex-runtime-image-'));
    try {
      const sourceRoot = path.join(root, 'sources');
      const outputRoot = path.join(root, 'runtime');
      await fs.mkdir(sourceRoot, { mode: 0o700 });
      await fs.mkdir(outputRoot, { mode: 0o700 });
      const files = [];
      for (const [index, destination] of REQUIRED_FILE_DESTINATIONS.entries()) {
        const source = path.join(sourceRoot, `source-${index}`);
        const mode = destination.endsWith('ca-certificates.crt') ? '0444' : '0555';
        const contents = mode === '0555'
          ? staticElfPayload(`contents for ${destination}\n`)
          : Buffer.from(`contents for ${destination}\n`, 'utf8');
        await fs.writeFile(source, contents, { mode: Number.parseInt(mode, 8) });
        await fs.chmod(source, Number.parseInt(mode, 8));
        files.push({
          source,
          destination,
          size: contents.length,
          sha256: digest(contents),
          mode,
        });
      }
      const manifestFile = path.join(root, 'sources.json');
      await fs.writeFile(manifestFile, `${JSON.stringify({
        version: 1,
        codex_version: '0.142.3',
        codex_target: 'x86_64-unknown-linux-musl',
        codex_layout_version: 1,
        files,
        symlinks: REQUIRED_SYMLINKS,
      }, null, 2)}\n`, { mode: 0o444 });
      await fs.chmod(manifestFile, 0o444);
      const fakeMksquashfs = path.join(root, 'mksquashfs');
      await fs.writeFile(fakeMksquashfs, '#!/bin/false\n', { mode: 0o555 });
      await fs.chmod(fakeMksquashfs, 0o555);

      let observedArgs;
      let observedEntries;
      const active = await buildRuntimeImage(
        { manifest: manifestFile, outputRoot, mksquashfs: fakeMksquashfs },
        {
          requireRoot: false,
          expectedUid: process.geteuid(),
          expectedGid: process.getegid(),
          assertTrustedFile: async () => {},
          assertTrustedDirectory: async () => {},
          sourceDefinitions: files.map(({ source, destination, mode }) => ({
            source,
            destination,
            mode,
          })),
          runMksquashfs: async (_executable, args) => {
            observedArgs = args;
            const stagedEntries = await listRelativeFiles(args[0]);
            observedEntries = stagedEntries;
            await fs.writeFile(
              args[1],
              Buffer.concat([
                Buffer.from('hsqs', 'ascii'),
                Buffer.from(JSON.stringify(stagedEntries), 'utf8'),
              ]),
            );
          },
        },
      );

      assert.deepEqual(observedArgs, mksquashfsArgs(observedArgs[0], observedArgs[1]));
      for (const entry of [
        'etc/hosts',
        'etc/nsswitch.conf',
        'etc/resolv.conf',
        'tmp',
        'var/tmp',
        'workspace',
      ]) {
        assert.ok(observedEntries.includes(entry), entry);
      }
      assert.equal(active.version, 1);
      assert.equal(active.codex_version, '0.142.3');
      assert.equal(active.codex_target, 'x86_64-unknown-linux-musl');
      assert.equal(active.codex_layout_version, 1);
      assert.match(active.image, /^images\/[a-f0-9]{64}\.squashfs$/);
      assert.equal(active.image_sha256, path.basename(active.image, '.squashfs'));
      const selected = JSON.parse(await fs.readFile(path.join(outputRoot, 'active.json'), 'utf8'));
      assert.deepEqual(selected, active);
      const image = path.join(outputRoot, active.image);
      assert.equal((await fs.stat(image)).mode & 0o777, 0o444);
      assert.equal((await fs.readFile(image)).subarray(0, 4).toString('ascii'), 'hsqs');
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('writes a fixed-source manifest with measured digests and read-only mode', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'webex-codex-runtime-manifest-'));
    try {
      const metadataFile = path.join(root, 'codex-package.json');
      const output = path.join(root, 'codex-runtime-sources.json');
      await fs.writeFile(metadataFile, `${JSON.stringify({
        layoutVersion: 1,
        version: '0.142.3',
        target: 'x86_64-unknown-linux-musl',
        variant: 'codex',
        entrypoint: 'bin/codex',
        resourcesDir: 'codex-resources',
        pathDir: 'codex-path',
      })}\n`, { mode: 0o444 });
      const definitions = [];
      for (const [index, destination] of REQUIRED_FILE_DESTINATIONS.entries()) {
        const source = path.join(root, `source-${index}`);
        const mode = destination.endsWith('ca-certificates.crt') ? '0444' : '0555';
        const contents = mode === '0555'
          ? staticElfPayload(`source for ${destination}\n`)
          : Buffer.from(`source for ${destination}\n`, 'utf8');
        await fs.writeFile(source, contents, {
          mode: Number.parseInt(mode, 8),
        });
        await fs.chmod(source, Number.parseInt(mode, 8));
        definitions.push({ source, destination, mode });
      }

      const manifest = await writeSourceManifest({
        requireRoot: false,
        expectedUid: process.geteuid(),
        expectedGid: process.getegid(),
        assertTrustedFile: async () => {},
        assertTrustedDirectory: async () => {},
        sourceDefinitions: definitions,
        packageMetadata: metadataFile,
        output,
      });

      assert.equal(manifest.codex_version, '0.142.3');
      assert.equal(manifest.codex_target, 'x86_64-unknown-linux-musl');
      assert.equal(manifest.codex_layout_version, 1);
      assert.deepEqual(manifest.symlinks, REQUIRED_SYMLINKS);
      assert.equal((await fs.stat(output)).mode & 0o777, 0o444);
      assert.deepEqual(JSON.parse(await fs.readFile(output, 'utf8')), manifest);
      for (const entry of manifest.files) {
        assert.equal(entry.sha256, digest(await fs.readFile(entry.source)));
        assert.equal(entry.size, (await fs.stat(entry.source)).size);
      }

      const dynamicSource = definitions.find((entry) => entry.destination === '/bin/busybox');
      const dynamicPayload = staticElfPayload('dynamic loader\n');
      dynamicPayload.writeUInt32LE(3, 64);
      await fs.chmod(dynamicSource.source, 0o755);
      await fs.writeFile(dynamicSource.source, dynamicPayload);
      await fs.chmod(dynamicSource.source, 0o555);
      await assert.rejects(
        writeSourceManifest({
          requireRoot: false,
          expectedUid: process.geteuid(),
          expectedGid: process.getegid(),
          assertTrustedFile: async () => {},
          assertTrustedDirectory: async () => {},
          sourceDefinitions: definitions,
          packageMetadata: metadataFile,
          output: path.join(root, 'dynamic-sources.json'),
        }),
        /dynamically linked/,
      );
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

function sourceManifest(root) {
  return {
    version: 1,
    codex_version: '0.142.3',
    codex_target: 'x86_64-unknown-linux-musl',
    codex_layout_version: 1,
    files: REQUIRED_FILE_DESTINATIONS.map((destination, index) => ({
      source: path.join(root, `source-${index}`),
      destination,
      size: 10 + index,
      sha256: `${index}`.padStart(64, '0'),
      mode: destination.endsWith('ca-certificates.crt') ? '0444' : '0555',
    })),
    symlinks: REQUIRED_SYMLINKS,
  };
}

function sourceDefinitions(root) {
  return REQUIRED_FILE_DESTINATIONS.map((destination, index) => ({
    source: path.join(root, `source-${index}`),
    destination,
    mode: destination.endsWith('ca-certificates.crt') ? '0444' : '0555',
  }));
}

async function listRelativeFiles(root, current = root, result = []) {
  for (const entry of await fs.readdir(current, { withFileTypes: true })) {
    const full = path.join(current, entry.name);
    const relative = path.relative(root, full).split(path.sep).join('/');
    result.push(relative);
    if (entry.isDirectory()) await listRelativeFiles(root, full, result);
  }
  return result.sort();
}

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function staticElfPayload(contents) {
  const header = Buffer.alloc(64 + 56);
  header.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  header.writeUInt16LE(2, 16);
  header.writeUInt16LE(62, 18);
  header.writeUInt32LE(1, 20);
  header.writeBigUInt64LE(64n, 32);
  header.writeUInt16LE(64, 52);
  header.writeUInt16LE(56, 54);
  header.writeUInt16LE(1, 56);
  header.writeUInt32LE(1, 64);
  return Buffer.concat([header, Buffer.from(contents, 'utf8')]);
}
