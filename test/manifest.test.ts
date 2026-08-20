import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (name: string): string => readFileSync(resolve(packageRoot, name), 'utf8');

interface Manifest {
  devDependencies: Record<string, string>;
  scripts: Record<string, string>;
  engines?: { node?: string };
  devEngines?: { runtime?: { version?: string }};
}

const manifest = (): Manifest => JSON.parse(read('package.json')) as Manifest;

/** The first version a range admits, as a major/minor pair. */
const floorOf = (range: string | undefined, what: string): [number, number] => {
  assert.ok(range, `${what} is not declared`);
  const version = /(\d+)\.(\d+)/u.exec(range);
  assert.ok(version, `${what} is declared as ${range}, which names no version`);
  return [Number(version[1]), Number(version[2])];
};

/** Everything in `src/`, as one text to look for a construct in. */
const sourcesOfSrc = (): string => readdirSync(resolve(packageRoot, 'src'))
  .map((name): string => read(`src/${name}`))
  .join('\n');

const atLeast = ([major, minor]: [number, number], [needMajor, needMinor]: [number, number]): boolean =>
  major > needMajor || (major === needMajor && minor >= needMinor);

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
  const declared = manifest().devDependencies.typescript;
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

/**
 * Runtime a source file needs, against the first Node version that has it. A
 * package that names no floor is installed by whatever runtime the installer
 * happens to have, and these two fail at the first login rather than at
 * install time: `fetch` as "not a function", `AbortSignal.timeout` the same,
 * both of them on the path that talks to the provider and nowhere in a
 * type-check. The peer dependency drags a floor in by accident, which is not
 * the same as stating one.
 */
const RUNTIME_FLOORS: Record<string, [number, number]> = {
  'AbortSignal.timeout(': [18, 0],
  'fetch(': [18, 0],
};

/**
 * The same for the runtime a contributor needs, which is a different and
 * higher one: the suite runs TypeScript sources through Node directly, and
 * what makes that possible is younger than the floor the published code asks
 * of a deployment. Two floors, so neither has to be raised to the other: a
 * deployment on Node 18 runs this package, and only running the suite needs
 * more.
 */
const TEST_SCRIPT_FLOORS: Record<string, [number, number]> = {
  '--experimental-strip-types': [22, 6],
};

/**
 * And the flag being accepted is not the same as the sources being run. The
 * runtime that strips the types is a different thing from the flag that turns
 * it on, and it grew what it can erase over several releases: a class member
 * written with an accessibility modifier is a syntax error on the first
 * runtime that takes the flag at all, and stops being one a release later. A
 * floor set at the flag therefore names a runtime the suite does not run on,
 * which is the sort of claim a declared floor exists to stop.
 */
const STRIPPED_SYNTAX_FLOORS: Record<string, [number, number]> = {
  'public constructor': [22, 7],
};

test('declares the Node floor the published code needs', () => {
  const declared = manifest().engines?.node;
  const floor = floorOf(declared, 'engines.node');

  for (const [feature, need] of Object.entries(RUNTIME_FLOORS)) {
    if (!sourcesOfSrc().includes(feature)) {
      continue;
    }
    assert.ok(
      atLeast(floor, need),
      `src/ uses ${feature}, which needs Node ${need[0]}.${need[1]}, ` +
      `but engines.node is ${declared}`,
    );
  }
});

test('declares the Node floor running the suite needs', () => {
  const { scripts, devEngines } = manifest();
  const declared = devEngines?.runtime?.version;
  const floor = floorOf(declared, 'devEngines.runtime.version');

  for (const [flag, need] of Object.entries(TEST_SCRIPT_FLOORS)) {
    if (!scripts.test.includes(flag)) {
      continue;
    }
    assert.ok(
      atLeast(floor, need),
      `the test script passes ${flag}, which needs Node ${need[0]}.${need[1]}, ` +
      `but devEngines.runtime.version is ${declared}`,
    );
  }

  for (const [syntax, need] of Object.entries(STRIPPED_SYNTAX_FLOORS)) {
    if (!sourcesOfSrc().includes(syntax)) {
      continue;
    }
    assert.ok(
      atLeast(floor, need),
      `src/ is written with \`${syntax}\`, which a stripping runtime only erases from ` +
      `Node ${need[0]}.${need[1]}, but devEngines.runtime.version is ${declared}`,
    );
  }
});
