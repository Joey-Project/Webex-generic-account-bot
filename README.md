# Codex-Gated Repository Template

This template starts a repository with the Codex review gate workflow already on
the default branch. It also includes a modular CI generator for adding
project-specific formatter, linter, test, and benchmark entrypoints after a
repository is created from the template.

## Included

- `.github/workflows/codex-review-gate.yml`
- `.gitignore`
- `scripts/setup-ci.mjs`
- this README

The workflow writes the `codex/review-gate` status check and requests a controlled
Codex review marker for each ready pull request head. It pins
`JoeyTeng/codex-review-gate-action` to the v1.2.1 commit SHA so privileged
`pull_request_target` runs do not depend on a movable tag.

## Generate Project CI

Run the setup script from a new repository created from this template:

```bash
node scripts/setup-ci.mjs
```

With no arguments, the script opens an interactive selector. For repeatable setup,
pass modules explicitly:

```bash
node scripts/setup-ci.mjs --tool js-ts --tool python --tool docker --tool markdown
node scripts/setup-ci.mjs --all --benchmark --dry-run
```

The script writes `.github/workflows/ci.yml` plus the selected tool configs. It is
idempotent when generated files have not changed. If a target file already exists
with different content, the script refuses to overwrite it unless `--force` is
provided. Use `--dry-run` to inspect planned writes first.

Supported modules:

- `js-ts`: pnpm, ESLint, Prettier, Vite, and Vitest.
- `python`: uv, Ruff, Pyright, and pytest.
- `swift`: swift-format, SwiftLint, and `swift test`.
- `go`: `gofmt`, `go vet`, and `go test`.
- `rust`: `cargo fmt`, `cargo clippy`, and `cargo test`.
- `github-actions`: actionlint.
- `bash`: shfmt, shellcheck, and `bash -n`.
- `markdown`: Prettier and markdownlint-cli2.
- `docker`: hadolint and `docker buildx build --check`.

`--benchmark` creates `scripts/benchmark.sh` only. It does not create or enable a
benchmark workflow, and benchmark commands are not part of the default PR gate.
The script includes benchmark entries for JavaScript/TypeScript, Python, Go, and
Rust when those modules are selected.

## After Creating a Repository

1. Add the project source, tests, and license.
2. Run `node scripts/setup-ci.mjs` and commit the generated CI/tooling files.
3. Install or lock generated dependencies where applicable, such as `pnpm install`
   for JavaScript/TypeScript or Markdown modules.
4. Confirm `.github/workflows/codex-review-gate.yml` is present on the default
   branch before requiring the status check.
5. Enable the required status check with the bootstrap helper from
   `JoeyTeng/codex-review-gate`:

```bash
node scripts/bootstrap-codex-review-gate.mjs --repo OWNER/REPO
node scripts/bootstrap-codex-review-gate.mjs --repo OWNER/REPO --apply
```

The helper defaults to dry-run. It refuses to require `codex/review-gate` until
the workflow exists on the repository default branch.

## Optional Repository Variables

- `CODEX_REVIEW_GATE_RUNNER_LABELS`: JSON runner label array. Defaults to
  `["ubuntu-slim"]`; use `["ubuntu-latest"]` when `ubuntu-slim` is unavailable.
- `CODEX_REVIEW_GATE_AUTO_RETRY=false`: disables scheduled retry jobs before a
  runner is allocated.
- `CODEX_REVIEW_GATE_EVENT_MODE`: `standard`, `comment-only`, or `full`.
- `CODEX_REVIEW_GATE_BOT_LOGINS`: comma-separated additional Codex bot logins.
- `CODEX_REVIEW_GATE_COMPLETION_SIGNAL_BUFFER_SECONDS`: clean completion buffer.
- `CODEX_REVIEW_GATE_FAILED_FINDINGS_RECOVERY`: set to `false` to disable
  same-head recovery after resolved Codex findings.
- `CODEX_REVIEW_GATE_FAILED_FINDINGS_RECOVERY_MODE`: `head` or `fresh`.

## Template Maintenance

Run the generator tests with Node's built-in test runner:

```bash
node --test test/setup-ci.node-test.mjs
```
