import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (name: string): string => readFileSync(resolve(packageRoot, name), 'utf8');

/**
 * Compiler options the build turns on, against the first TypeScript version
 * that has them. An older compiler does not refuse an option it has never
 * heard of — it ignores it, and the emit silently loses whatever the option
 * was there to do. Nothing in a working tree notices, because the compiler
 * that is installed is whatever the range resolved to long after it was
 * written; only an install that honours the floor would, and nobody does that
 * install twice. So the floor is checked here.
 */
const OPTION_FLOORS: Record<string, [number, number]> = {
  rewriteRelativeImportExtensions: [5, 7],
};

test('declares a TypeScript floor that understands the options the build turns on', () => {
  const tsconfig = read('tsconfig.json');
  const declared = (JSON.parse(read('package.json')) as {
    devDependencies: Record<string, string>;
  }).devDependencies.typescript;
  const version = /(\d+)\.(\d+)/u.exec(declared);
  assert.ok(version, `the declared typescript range ${declared} names no version`);
  const [major, minor] = [Number(version[1]), Number(version[2])];

  for (const [option, [needMajor, needMinor]] of Object.entries(OPTION_FLOORS)) {
    if (!new RegExp(`"${option}"\\s*:\\s*true`, 'u').test(tsconfig)) {
      continue;
    }
    assert.ok(
      major > needMajor || (major === needMajor && minor >= needMinor),
      `tsconfig.json turns on ${option}, which needs TypeScript ${needMajor}.${needMinor}, ` +
      `but ${declared} admits older compilers`,
    );
  }
});
