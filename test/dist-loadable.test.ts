import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// The rest of the suite runs against the TypeScript sources in src/, so it is
// blind to emit-level defects: an ESM package whose emitted relative imports
// lack file extensions type-checks fine and fails only once Node loads dist/.
// This test builds first on purpose — that is the only way the assertions
// below describe the artifact that actually gets published and mounted,
// rather than a stale dist/ left over from an earlier commit.
test('dist/ is loadable by Node as ESM and exports the public classes', async () => {
  execFileSync('npm', ['run', 'build'], { cwd: packageRoot, stdio: 'inherit' });

  const entry = pathToFileURL(resolve(packageRoot, 'dist/index.js')).href;
  const module = await import(entry);

  for (const name of [
    'PendingLoginStore',
    'OidcDiscovery',
    'OidcRedirectHandler',
    'OidcCallbackHandler',
  ]) {
    assert.equal(typeof module[name], 'function', `dist/index.js does not export ${name}`);
  }
});
