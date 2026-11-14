import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';
import { generateKeyPairSync } from 'node:crypto';
// Ephemeral test-only provider key: generated in memory, never saved or deployed.
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.toml', environment: 'development' },
    miniflare: { bindings: {
      APPLE_APP_ID_PREFIX: 'TESTPREFIX', APPLE_TEAM_ID: 'TEAMTEST01', APNS_KEY_ID: 'TESTKEY001',
      APNS_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' })
    } }
  })],
  test: { include: ['tests/**/*.test.js'] }
});
