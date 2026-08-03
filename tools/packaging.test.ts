/**
 * **Every published package must actually resolve when it is packed.**
 *
 * THE DEFECT THIS FILE EXISTS FOR, which broke ten repositories at once.
 *
 * Each package here declares `"files": ["dist", ...]` and `"main": "src/index.ts"`. Those two
 * disagree — and npm resolves the disagreement in a way that hides it: **npm always adds the file
 * named by `main` to the tarball**, whether or not `files` includes it. So a package whose `src/`
 * was excluded still shipped `src/index.ts`, and for as long as `src/index.ts` had no relative
 * imports, it worked.
 *
 * The moment `@cloudsforge/auth` grew a second file — `src/serviceToken.ts`, the service-credential
 * provider — the packed package became one that could not be imported: `src/index.ts` was present,
 * `./serviceToken.ts` was not. Ten repositories consume these with `file:` rather than `link:`
 * (activity, billing, custody, identity, indexer, ledger, policy, pricing, service-template,
 * trade), and `file:` PACKS. All ten broke at import time, and the nineteen that use `link:` did
 * not, because a symlinked checkout ignores `files` entirely.
 *
 * WHY NOTHING CAUGHT IT. Every check in this repository — typecheck, the suites, the build — reads
 * the working tree, where every file is present by definition. The packed artefact is the one
 * thing a consumer receives and the one thing nothing looked at. `pnpm build` even passed, because
 * `dist/` was complete; only the `src/` half that `main` points at was not.
 *
 * SO THIS TEST READS THE TARBALL. It asks npm for the exact file list it would publish, walks the
 * relative-import graph from the manifest's own `main`, and asserts the graph is closed inside
 * that list. It is deliberately not a check that `files` contains the string `"src"` — that would
 * be a check that agrees with the fix rather than one that tests the property, and it would pass
 * for a package whose entry point moved somewhere else entirely.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { dirname, join, normalize, posix } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const PACKAGES = join(ROOT, 'packages')

interface Manifest {
  readonly name: string
  readonly main?: string
  readonly types?: string
  readonly files?: readonly string[]
}

function manifestOf(dir: string): Manifest {
  return JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Manifest
}

/** The exact list npm would publish. Asked of npm rather than reimplemented from `files`. */
function packedFiles(dir: string): Set<string> {
  const out = execFileSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: dir,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  const parsed = JSON.parse(out) as Array<{ files: Array<{ path: string }> }>
  const entry = parsed[0]
  assert.ok(entry, `npm pack said nothing about ${dir}`)
  return new Set(entry.files.map((f) => f.path))
}

/**
 * Every relative import reachable from `entry`, as tarball-relative paths.
 *
 * The estate spells relative imports with the `.ts` extension so `tsc` and `node --import tsx`
 * agree on one spelling (`allowImportingTsExtensions` + `rewriteRelativeImportExtensions`), so the
 * specifier IS the filename and no resolution guessing is needed. A bare-specifier import is a
 * dependency, which npm's own resolution handles and this says nothing about.
 */
function relativeImportClosure(pkgDir: string, entry: string): Set<string> {
  const seen = new Set<string>()
  const queue = [entry]
  while (queue.length > 0) {
    const rel = queue.pop() as string
    if (seen.has(rel)) continue
    seen.add(rel)

    const abs = join(pkgDir, rel)
    if (!existsSync(abs)) continue
    const source = readFileSync(abs, 'utf8')
    // `from './x.ts'`, `import './x.ts'`, `export … from './x.ts'`. Static forms only: a dynamic
    // import built from a variable is not something a packaging check can or should chase.
    for (const match of source.matchAll(/from\s+'(\.[^']+)'|import\s+'(\.[^']+)'/g)) {
      const spec = match[1] ?? match[2]
      if (!spec) continue
      queue.push(posix.normalize(posix.join(posix.dirname(rel), spec)))
    }
  }
  return seen
}

const packages = readdirSync(PACKAGES, { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => join(PACKAGES, e.name))

test('there are packages to check at all', () => {
  // Without this, a broken glob would make every test below vacuously pass — which is the exact
  // shape of check this repository has been bitten by.
  assert.ok(packages.length >= 6, `only ${packages.length} packages found under packages/`)
})

for (const dir of packages) {
  const manifest = manifestOf(dir)

  test(`${manifest.name} packs everything its entry point imports`, () => {
    const main = manifest.main
    assert.ok(main, `${manifest.name} declares no main`)

    const packed = packedFiles(dir)
    assert.ok(
      packed.has(normalize(main)),
      `${manifest.name}: main is ${main} and it is not in the tarball`,
    )

    const closure = relativeImportClosure(dir, main)
    const missing = [...closure].filter((rel) => !packed.has(rel))
    assert.deepEqual(
      missing,
      [],
      `${manifest.name}: ${main} imports these, and they are NOT in the published tarball — ` +
        `a 'file:' consumer would fail at import. Reachable: ${[...closure].join(', ')}`,
    )
  })

  test(`${manifest.name} does not ship its own tests`, () => {
    // Not correctness, but a package that ships 30 kB of suite to every consumer is a package
    // nobody trimmed. It is asserted rather than assumed because `src` is now shipped wholesale.
    const shipped = [...packedFiles(dir)].filter((f) => f.endsWith('.test.ts'))
    assert.deepEqual(shipped, [], `${manifest.name} ships test files`)
  })
}
