import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  buildE2eOptions,
  expectedReply,
  parseDotenv,
  renderBotConfig,
} from '../scripts/e2e-webex-bot.mjs';

describe('e2e dotenv parsing', () => {
  it('parses quoted and unquoted values', () => {
    const parsed = parseDotenv(`
# comment
E2E_BOT_ACCESS_TOKEN="token-value"
E2E_BOT_EMAIL=clean.bot@example.com
E2E_PROMPT=/codex-e2e hello # trailing comment
`);

    assert.equal(parsed.E2E_BOT_ACCESS_TOKEN, 'token-value');
    assert.equal(parsed.E2E_BOT_EMAIL, 'clean.bot@example.com');
    assert.equal(parsed.E2E_PROMPT, '/codex-e2e hello');
  });
});

describe('e2e config rendering', () => {
  it('renders sender allowlist and omits the sender bot token', () => {
    const options = buildE2eOptions({
      E2E_BOT_ACCESS_TOKEN: 'secret-token',
      E2E_BOT_EMAIL: 'clean.bot@example.com',
      E2E_MARKER: 'marker-1',
    });

    const config = renderBotConfig(options);

    assert.match(config, /allowed_person_emails = \["clean\.bot@example\.com"\]/);
    assert.match(config, /trigger = "prefix"/);
    assert.match(config, /prefixes = \["\/codex-e2e"\]/);
    assert.doesNotMatch(config, /secret-token/);
  });

  it('falls back to executable names when PATH lookup is unavailable', () => {
    const options = buildE2eOptions({
      E2E_BOT_ACCESS_TOKEN: 'secret-token',
      E2E_BOT_EMAIL: 'clean.bot@example.com',
      E2E_MARKER: 'marker-1',
      PATH: '',
    });

    assert.equal(options.cargoBin, 'cargo');
    assert.equal(options.codexBin, 'codex');
  });

  it('honors explicit executable overrides', () => {
    const options = buildE2eOptions({
      E2E_BOT_ACCESS_TOKEN: 'secret-token',
      E2E_BOT_EMAIL: 'clean.bot@example.com',
      E2E_CARGO_BIN: '/custom/cargo',
      E2E_CODEX_BIN: '/custom/codex',
      E2E_MARKER: 'marker-1',
      PATH: '',
    });

    assert.equal(options.cargoBin, '/custom/cargo');
    assert.equal(options.codexBin, '/custom/codex');
  });
});

describe('e2e reply matching', () => {
  it('rejects generic-account replies that do not contain the marker', () => {
    assert.throws(
      () =>
        expectedReply(
          [
            {
              id: 'reply-1',
              personId: 'miku-person',
              markdown: 'Codex run failed',
            },
          ],
          { marker: 'expected-marker', selfPersonId: 'miku-person' },
        ),
      /did not contain marker/,
    );
  });

  it('returns null while waiting for the generic account reply', () => {
    assert.equal(
      expectedReply(
        [{ id: 'reply-1', personId: 'someone-else', markdown: 'expected-marker' }],
        { marker: 'expected-marker', selfPersonId: 'miku-person' },
      ),
      null,
    );
  });

  it('rejects generic-account replies from an unexpected email when present', () => {
    assert.throws(
      () =>
        expectedReply(
          [
            {
              id: 'reply-1',
              personId: 'miku-person',
              personEmail: 'wrong@example.com',
              markdown: 'expected-marker',
            },
          ],
          {
            marker: 'expected-marker',
            selfPersonEmail: 'miku.gen@cisco.com',
            selfPersonId: 'miku-person',
          },
        ),
      /email mismatch/,
    );
  });
});
