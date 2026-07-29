# @cloudsforge/runtime

The six packages every CloudsForge service depends on. They exist because the estate currently
carries the same code by hand in every repository:

- `src/obs.ts` — **375 lines, byte-identical in five services** (md5 `2fcb6c10…`), plus a
  divergent 428-line fork in Nimbus. It is meant to be re-copied by hand when it changes.
- The Nimbus JWKS auth middleware — **five separate implementations**, 54 to 93 lines, one per
  service, already diverged.
- `env.ts` — seven hand-written copies.
- Boot-time `CREATE TABLE IF NOT EXISTS` migration arrays — five copies, no version table, no
  lock, `process.exit(1)` on failure.

With one repository per service that duplication stops being untidy and becomes structural: a
cross-cutting fix is forty pull requests. These packages are the answer.

| Package | Replaces | Zero-dep |
| --- | --- | --- |
| `@cloudsforge/lifecycle` | Static `/health` literals, and shutdown that force-exits after 10s | ✅ |
| `@cloudsforge/http` | `fetchJson` with no retry, no breaker, and Nimbus's two bare `fetch` calls with no timeout at all | ✅ |
| `@cloudsforge/jobs` | Eight `setInterval` timers guarded by module-local booleans | needs `postgres` |
| `@cloudsforge/db` | Five boot-time DDL arrays | needs `postgres` |
| `@cloudsforge/auth` | Five divergent JWKS middlewares | needs `jose` |
| `@cloudsforge/telemetry` | Six copies of `obs.ts` | needs OTel |

## The rules these encode

1. **`/livez` is static; `/readyz` checks dependencies.** A replica whose database is
   unreachable must not report healthy while 503-ing every request.
2. **Drain before exit.** `SIGTERM` flips ready to false, keeps serving for one load-balancer
   interval, stops claiming jobs, waits for in-flight work, then exits.
3. **The job lease key names the contended resource, not the row.** `chain` for withdrawals,
   because the resource being contended is the chain's nonce. Keying on the withdrawal row
   permits two withdrawals to sign against the same nonce, which loses a payment permanently.
4. **Migrations are versioned, advisory-locked, and run as a one-shot job** — never inside
   `index.ts`, because two replicas booting together race on `pg_class` and one crash-loops.
5. **Every outbound call has a deadline, and the deadline propagates.** A 10-second budget must
   not be spent three times down a chain.

See `docs/ecosystem/02-target-architecture.md` AD-17 and AD-20.

## Working on it

```bash
pnpm install
pnpm check          # typecheck + tests
```

Tests use `node:test` with no framework. Packages that need Postgres skip unless
`RUNTIME_TEST_DATABASE_URL` is set and its name contains `test`.
