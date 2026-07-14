export const RELEASE_VERSION = 1;
export const CODEX_VERSION = '0.142.3';
export const CARGO_VERSION = 'cargo 1.96.0 (30a34c682 2026-05-25)';
export const RUSTC_VERSION = 'rustc 1.96.0 (ac68faa20 2026-05-25)';
export const CARGO_BIN = '/home/codex/.cargo/bin/cargo';
export const RUSTC_BIN = '/home/codex/.cargo/bin/rustc';
export const PRODUCTION_BUNDLE_ROOT = '/var/lib/webex-host-release/bundle';
export const PRODUCTION_INSTALL_ROOT = '/opt/webex-generic-account-bot';
export const PRODUCTION_TRUST_ROOT = '/usr/local/libexec/webex-host-release';
export const PRODUCTION_WRAPPER_PATH = `${PRODUCTION_TRUST_ROOT}/install-host-release`;
export const PRODUCTION_INSTALLER_PATH = `${PRODUCTION_TRUST_ROOT}/install-host-release.mjs`;
export const PRODUCTION_CONTRACT_PATH = `${PRODUCTION_TRUST_ROOT}/host-release-contract.mjs`;

const CODE_FILES = [
  'deploy/systemd/webex-codex-activation-renew.service',
  'deploy/systemd/webex-codex-activation.tmpfiles.conf',
  'deploy/systemd/webex-codex-input-staging.tmpfiles.conf',
  'deploy/systemd/webex-codex-launcher.socket',
  'deploy/systemd/webex-codex-launcher.sysusers.conf',
  'deploy/systemd/webex-codex-launcher.tmpfiles.conf',
  'deploy/systemd/webex-codex-launcher@.service',
  'deploy/systemd/webex-codex-runtime.sysusers.conf',
  'deploy/systemd/webex-codex-runtime.tmpfiles.conf',
  'deploy/systemd/webex-config-pull-worker.service',
  'deploy/systemd/webex-config-pull-worker.sysusers.conf',
  'deploy/systemd/webex-config-pull-worker.tmpfiles.conf',
  'deploy/systemd/webex-generic-account-bot.service',
  'deploy/systemd/webex-generic-account-bot.service.d/10-codex-launcher.conf',
  'deploy/systemd/webex-generic-account-bot.sysusers.conf',
  'deploy/systemd/webex-generic-account-bot.tmpfiles.conf',
  'scripts/build-codex-runtime-image.mjs',
  'scripts/config-policy/install-rendered-config.py',
  'scripts/config-policy/render-config.mjs',
  'scripts/config-policy/static-config-check.py',
  'scripts/config-policy/validate-config.sh',
  'scripts/config-pull-worker.mjs',
  'scripts/deploy-config.mjs',
  'scripts/jenkins-readonly.mjs',
  'scripts/provision-host',
  'scripts/provision-host.mjs',
];

const EXECUTABLE_CODE_FILES = new Set([
  'scripts/config-policy/install-rendered-config.py',
  'scripts/config-policy/static-config-check.py',
  'scripts/config-policy/validate-config.sh',
  'scripts/provision-host',
]);

const HOST_BINARIES = [
  'webex-codex-activation',
  'webex-codex-launcher',
  'webex-generic-account-bot',
  'webex-host-identity-lock',
];

const STATIC_BINARIES = [
  'webex-codex-canary-probe',
  'webex-codex-runtime',
];

const RUNTIME_SOURCES = [
  ['busybox', 'busybox'],
  ['codex/bin/codex', 'codex/bin/codex'],
  ['codex/codex-package.json', 'codex/codex-package.json'],
  ['codex/codex-path/rg', 'codex/codex-path/rg'],
  ['codex/codex-resources/bwrap', 'codex/codex-resources/bwrap'],
];

export const RELEASE_FILES = Object.freeze([
  ...CODE_FILES.map((source) => Object.freeze({
    kind: 'code',
    source,
    installPath: `code/${source}`,
    mode: EXECUTABLE_CODE_FILES.has(source) ? 0o555 : 0o444,
  })),
  ...HOST_BINARIES.map((source) => Object.freeze({
    kind: 'host-binary',
    source,
    installPath: `bin/${source}`,
    mode: 0o555,
  })),
  ...STATIC_BINARIES.map((source) => Object.freeze({
    kind: 'static-binary',
    source,
    installPath: `bin/${source}`,
    mode: 0o555,
  })),
  ...RUNTIME_SOURCES.map(([source, installPath]) => Object.freeze({
    kind: source === 'busybox' ? 'busybox' : 'codex-runtime',
    source,
    installPath: `runtime-sources/${installPath}`,
    mode: source.endsWith('.json') ? 0o444 : 0o555,
  })),
]);

export const RELEASE_PATHS = Object.freeze(
  RELEASE_FILES.map(({ installPath }) => installPath).toSorted(),
);

export const TRUSTED_SOURCE_SHA256 = Object.freeze({
  'runtime-sources/busybox': 'dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14',
  'runtime-sources/codex/bin/codex': 'cb1670c25b6e17fd82866a80e55df58bc10f5d18e44d25ec2c6f7c2ab98077cd',
  'runtime-sources/codex/codex-package.json': 'b27002210921372fa043e8e49f6c543cf4cddc0d35bd01a32ecfbc699efd5e2a',
  'runtime-sources/codex/codex-path/rg': 'ebeaf56f8a25e102e9419933423738b3a2a613a444fd749d695e15eba53f71f2',
  'runtime-sources/codex/codex-resources/bwrap': '77360cb751ccedc5971391444ac86a8a33c15b04d6b4a6fe45f5d25496e62c4c',
});

export function bundlePayloadPath(installPath) {
  return `payload/${installPath}`;
}
