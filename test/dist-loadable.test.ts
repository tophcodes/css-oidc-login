import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const entry = resolve(packageRoot, 'dist/index.js');

/**
 * What the server does with this package, in the words of the class that does
 * it: `ConstructionStrategyCommonJs` calls `require()` on the entry point and
 * reads the class off what comes back. So that is what is asserted here — not
 * `import()`, which succeeds for either module format and therefore says
 * nothing about whether the server can load the package at all.
 *
 * The probe runs in a child process for two reasons. The suite itself is an ES
 * module, so it has no `require` of its own; and a `require` in this runtime
 * would load an ES module rather than refuse it, which is a newer affordance
 * than the server's loader relies on and would hide exactly the defect this
 * test exists for. `--no-experimental-require-module` puts the child back on
 * the semantics the loader was written against.
 */
const PROBE = `
const loaded = require(${JSON.stringify(entry)});

const store = new loaded.PendingLoginStore();
const discovery = new loaded.OidcDiscovery('https://provider.example/');
const callbackUrl = 'https://pod.example/.account/login/oidc/callback/';

const constructions = {
  PendingLoginStore: () => store,
  OidcDiscovery: () => discovery,
  OidcRedirectHandler: () => new loaded.OidcRedirectHandler({
    store,
    discovery,
    clientId: 'client',
    callbackUrl,
  }),
  OidcCallbackHandler: () => new loaded.OidcCallbackHandler({
    accountStore: {},
    cookieStore: {},
    store,
    storage: { find: async () => [] },
    discovery,
    issuer: 'https://provider.example/',
    clientId: 'client',
    clientSecret: 'secret',
    callbackUrl,
  }),
};

for (const [ name, construct ] of Object.entries(constructions)) {
  if (typeof loaded[name] !== 'function') {
    throw new Error('the required entry point does not export ' + name);
  }
  if (!(construct() instanceof loaded[name])) {
    throw new Error(name + ' did not construct');
  }
}

process.stdout.write('constructed');
`;

/**
 * The rest of the suite runs against the TypeScript sources in src/, so it is
 * blind to emit-level defects: the module format of the build, and emitted
 * relative imports that lack file extensions, both type-check fine and fail
 * only once the server loads dist/. This test builds first on purpose — that
 * is the only way the assertions below describe the artifact that actually
 * gets published and mounted, rather than a stale dist/ left over from an
 * earlier commit.
 */
test('dist/ is loadable by require() and its public classes are constructible', () => {
  execFileSync('npm', ['run', 'build'], { cwd: packageRoot, stdio: 'inherit' });

  const probe = spawnSync(
    process.execPath,
    ['--no-experimental-require-module', '-e', PROBE],
    { cwd: packageRoot, encoding: 'utf8' },
  );

  assert.equal(
    probe.status,
    0,
    `the server loads this package with require(), which failed:\n${probe.stderr}`,
  );
  assert.equal(probe.stdout, 'constructed');
});
