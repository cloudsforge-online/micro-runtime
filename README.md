# @cloudsforge/runtime

[![ci](https://github.com/cloudsforge-online/micro-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudsforge-online/micro-runtime/actions/workflows/ci.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-strict%20ESM-3178C6?logo=typescript&logoColor=white)](./tsconfig.base.json) [![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E?logo=nodedotjs&logoColor=white)](./package.json) [![licence](https://img.shields.io/badge/licence-MIT-blue)](./LICENSE)

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

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

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

6. **A container holds a credential, not a token.** A service token expires in ten minutes. What
   a container is given at deploy time must be able to outlive that, or the deployment has a
   cliff in it. See below — this is the rule that was missing, and the estate fell off it.

See `docs/ecosystem/02-target-architecture.md` AD-17 and AD-20.

## Service-to-service authentication, and the ten-minute cliff

The most important thing in this repository to understand before changing anything, because the
estate has already been broken by getting it wrong.

`micro-identity` issues service tokens with a TTL of **600 seconds** (`identity/src/tokens.ts:28`).
That short lifetime is a deliberate security property: rotation IS expiry, which is why no
revocation list for service tokens exists anywhere. It is not a limitation to be worked around.

Every service used to read its token once, from an environment variable, at boot:

```ts
const token = () => env.serviceToken      // wallet/src/index.ts:90, and eight more like it
```

Nothing re-minted it — nothing *could*, because `POST /service-tokens` requires the `admin` role,
so the only issuer in the estate was a human operator. The result: the estate worked perfectly in
every test and for the first ten minutes of any real deployment, then every service-to-service
call began failing. **No per-service suite could see it**, because each mints a fresh token as it
starts and finishes well inside ten minutes. A test that mints a token and immediately uses it
proves nothing about this class of defect.

The fix was not a longer TTL — that leaves the same defect arriving later, and makes a leaked
token useful for longer. The fix is to change **what a container holds at rest**: a long-lived,
revocable `service_credentials` row (`cfsc_…`), worth nothing by itself, exchanged at
`POST /service-tokens/exchange` for an ordinary ten-minute token whenever one is needed. The
exchange consumes nothing, so N replicas boot from one credential and a restart days later works.

### `ServiceTokenProvider`

`@cloudsforge/auth` holds the credential and keeps a token live. Wire **both** hooks:

```ts
const identityTokens = new ServiceTokenProvider({
  identityUrl: env.identityUrl,          // defaults to IDENTITY_ISSUER in most services
  credential: env.identityCredential,    // <SERVICE>_IDENTITY_CREDENTIAL
})

const ledger = httpLedgerClient({
  baseUrl: env.ledgerUrl,
  token: identityTokens.token,           // per request, so refresh needs no restart
  fetch: identityTokens.authorizedFetch, // so a 401 re-mints and replays instead of failing
})

lifecycle.addProbe(serviceTokenProbe(identityTokens))
```

Four properties worth knowing, each of which exists for a reason:

- **No timer.** Refresh is driven by traffic. `token()` checks whether it is past the refresh
  point and, if so, starts a background exchange while returning the still-valid token it holds.
  There is no `setInterval` (rule 8 forbids one doing domain work) and no `setTimeout`, so there
  is nothing to shut down and a provider cannot hold the event loop open past a drain.
- **Not a leased job**, despite this estate's rule that background work is leased. A lease
  arbitrates a contended *shared* resource; a token is per-process state, so the replica that won
  the lease would mint into memory no other replica can see.
- **No stampede.** The refresh point is 80% of `expiresIn`, jittered per token across
  [75%, 85%] so replicas that boot together do not exchange together. Concurrent callers share
  one in-flight exchange. `failureBackoffMs` floors the interval between attempts, so an identity
  outage cannot become a retry storm against the service everything else depends on.
- **The 401 is the guarantee; the schedule is the optimisation.** The refresh point rests on this
  process's clock and the peer's expiry rests on the peer's. `authorizedFetch` catches a 401,
  discards exactly the token that was refused, mints a replacement and replays **once**.

### What an unreachable identity means

The same distinction `Verifier` already draws inbound, pointed outward:

| Situation | Answer | Why |
| --- | --- | --- |
| Held token still valid | keep using it | identity being down does not retract what it already signed |
| Held token expired, or none | `ServiceTokenUnavailableError` → **503** | we cannot authenticate; a 401 would blame the caller for an outage two services away |
| No credential configured at all | `serviceTokenProbe` fails → not ready | a deployment that is wrong and will stay wrong |
| Identity outage, probe | `warn`, never `fail` | a hard fail would empty every balancer in the estate over one bad minute |

Never send the request unauthenticated, and never send a stale token. Both produce a 401 from a
healthy peer, which sends an operator to the wrong service.

## Working on it

```bash
pnpm install
pnpm check          # typecheck + tests
pnpm -F @cloudsforge/auth test    # one package
```

Tests use `node:test` with no framework — no Jest, no Vitest, no `describe`. Packages that need
Postgres skip unless `RUNTIME_TEST_DATABASE_URL` is set and its name contains `test`:

```bash
docker run -d --name runtime-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test \
  -e POSTGRES_DB=runtime_test -p 55432:5432 postgres:17-alpine
RUNTIME_TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55432/runtime_test pnpm test
```

TypeScript ESM, Node ≥ 22, strict with `noUncheckedIndexedAccess` and
`exactOptionalPropertyTypes`. Sources import each other with the `.ts` extension so `tsc` and
`node --import tsx` agree on one spelling; the emitter rewrites them for `dist`.

### Changing a shared signature

Prefer an options object. Adding a positional parameter before an optional one silently makes
existing call sites pass the wrong value — everything type-checks, and only a suite catches it.
This has already happened here once.

### Adding a guard

Break the thing it guards, watch it go red, then restore it. A guard that has never been observed
failing is not known to be a guard: the `unreferencedEmitters` check in `micro-identity` passed on
its first version because its own prose naming a function counted as a reference.

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, assets
generated with **FLUX 2 Pro**, under human direction and review.
