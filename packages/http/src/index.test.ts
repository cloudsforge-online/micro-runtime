import { test } from 'node:test'
import assert from 'node:assert/strict'
import { CircuitOpenError, HttpClient, HttpError, TimeoutError, redactUrl } from './index.ts'

/** A fetch stand-in driven by a scripted list of responses or thrown errors. */
function scripted(steps: Array<Response | Error | ((req: Request) => Response)>) {
  const calls: Request[] = []
  let i = 0
  const fetchImpl = (async (input: string | URL, init?: RequestInit) => {
    const req = new Request(String(input), init)
    calls.push(req)
    const step = steps[Math.min(i, steps.length - 1)]
    i += 1
    if (step === undefined) throw new Error('scripted fetch ran out of steps')
    if (step instanceof Error) throw step
    if (typeof step === 'function') return step(req)
    return step.clone()
  }) as unknown as typeof globalThis.fetch
  return { fetch: fetchImpl, calls, get count() { return i } }
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const noSleep = async () => {}

function client(steps: Parameters<typeof scripted>[0], overrides = {}) {
  const s = scripted(steps)
  return {
    s,
    c: new HttpClient({
      baseUrl: 'http://peer:4003',
      name: 'peer',
      fetch: s.fetch,
      sleep: noSleep,
      random: () => 0.5,
      ...overrides,
    }),
  }
}

test('returns parsed JSON on success', async () => {
  const { c } = client([json({ shards: 42 })])
  assert.deepEqual(await c.get('/wallet'), { shards: 42 })
})

test('a 4xx is not retried — the peer decided, and asking again wastes the budget', async () => {
  const { c, s } = client([json({ error: 'not_found' }, 404)])
  await assert.rejects(() => c.get('/wallet'), HttpError)
  assert.equal(s.count, 1)
})

test('a 500 is retried and can succeed', async () => {
  const { c, s } = client([json({ e: 1 }, 500), json({ e: 1 }, 500), json({ ok: true })])
  assert.deepEqual(await c.get('/wallet'), { ok: true })
  assert.equal(s.count, 3)
})

test('429 and 503 are retried even though they are 4xx/5xx boundaries', async () => {
  const { c, s } = client([json({}, 429), json({ ok: true })])
  assert.deepEqual(await c.get('/rates'), { ok: true })
  assert.equal(s.count, 2)
})

test('a POST without an idempotency key is attempted exactly once', async () => {
  const { c, s } = client([json({}, 500)])
  await assert.rejects(() => c.post('/spend', { amount: 10 }), HttpError)
  assert.equal(s.count, 1, 'retrying an unkeyed debit is how a user gets charged twice')
})

test('a POST with an idempotency key is retried, and the key is sent', async () => {
  const { c, s } = client([json({}, 500), json({ ok: true })])
  const result = await c.post('/spend', { amount: 10 }, { idempotencyKey: 'order:7' })
  assert.deepEqual(result, { ok: true })
  assert.equal(s.count, 2)
  assert.equal(s.calls[0]?.headers.get('idempotency-key'), 'order:7')
})

test('the deadline is absolute across retries, not per attempt', async () => {
  let clock = 0
  const { c, s } = client([json({}, 500)], {
    now: () => clock,
    // Each attempt burns 40ms of a 100ms budget; the third would exceed it.
    fetch: (async () => {
      clock += 40
      return json({}, 500)
    }) as typeof globalThis.fetch,
  })
  await assert.rejects(() => c.get('/slow', { deadlineMs: 100, retries: 5 }))
  assert.ok(clock <= 140, `budget overspent: ${clock}ms`)
  void s
})

test('a hung peer times out instead of pinning the caller forever', async () => {
  const hang = (async (_url: string, init?: RequestInit) =>
    new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
    })) as unknown as typeof globalThis.fetch

  const c = new HttpClient({
    baseUrl: 'http://vault:4005',
    name: 'vault',
    fetch: hang,
    sleep: noSleep,
    random: () => 0,
  })
  await assert.rejects(
    () => c.get('/admin/keys', { deadlineMs: 25, retries: 0 }),
    (err: unknown) => err instanceof TimeoutError,
    'this is the Nimbus bare-fetch defect: no total-request timeout, so a hung vault pins SSO',
  )
})

test('the circuit opens after repeated server errors and then fails fast', async () => {
  const { c, s } = client([json({}, 500)], { circuit: { threshold: 3, resetMs: 60_000 } })
  for (let i = 0; i < 3; i++) {
    await assert.rejects(() => c.get('/x', { retries: 0 }))
  }
  assert.equal(c.circuitState, 'open')
  const before = s.count
  await assert.rejects(() => c.get('/x'), CircuitOpenError)
  assert.equal(s.count, before, 'an open circuit must not reach the network')
})

test('a 4xx does not open the circuit — bad input is not an unwell peer', async () => {
  const { c } = client([json({ error: 'bad' }, 400)], { circuit: { threshold: 2 } })
  for (let i = 0; i < 5; i++) {
    await assert.rejects(() => c.get('/x', { retries: 0 }))
  }
  assert.equal(c.circuitState, 'closed')
})

/**
 * ── A CREDENTIAL FAULT IS NOT EVIDENCE ABOUT THE PEER ─────────────────────────────────────────
 *
 * These four drive the CloudsForge testnet incident of 2026-08-10 in miniature. Every service
 * credential in that estate was re-minted while the containers kept the revoked generation, so
 * `identity` refused every exchange and `ledger`'s token supplier rejected on every sweep. The
 * first two sweeps recorded the true cause; from the fifth rejection the breaker opened and every
 * sweep after that — for as long as the credential stayed wrong — reported the INDEXER as
 * unreachable, on a service that was healthy and had not been dialled once.
 */
test('a token supplier rejection never opens the circuit — nothing was sent to the peer', async () => {
  const { c, s } = client([json({ ok: true })], {
    token: () => Promise.reject(new Error('identity refused the credential exchange: 401')),
    circuit: { threshold: 3, resetMs: 60_000 },
  })
  for (let i = 0; i < 10; i++) {
    await assert.rejects(() => c.get('/x', { retries: 0 }))
  }
  assert.equal(c.circuitState, 'closed', 'the breaker guards the peer, and the peer never answered')
  assert.equal(s.count, 0, 'and no request was ever attempted')
})

test('the supplier’s error reaches the caller unchanged, so its type still diagnoses it', async () => {
  class ServiceTokenUnavailableError extends Error {}
  const thrown = new ServiceTokenUnavailableError('no credential is configured')
  const { c } = client([json({ ok: true })], { token: () => Promise.reject(thrown) })
  await assert.rejects(
    () => c.get('/x', { retries: 0 }),
    (err: unknown) => {
      assert.equal(err, thrown, 'not wrapped, not renamed, not replaced')
      assert.ok(err instanceof ServiceTokenUnavailableError)
      return true
    },
  )
})

test('a token failure reports token_unavailable, never transport_error', async () => {
  const events: string[] = []
  const { c } = client([json({ ok: true })], {
    token: () => Promise.reject(new Error('identity is unreachable')),
    onResult: (e: { outcome: string }) => void events.push(e.outcome),
  })
  await assert.rejects(() => c.get('/x', { retries: 0 }))
  assert.deepEqual(events, ['token_unavailable'], 'a dashboard must not read this as the peer failing')
})

test('a token failure is not retried — the provider’s own backoff outlives this client’s', async () => {
  let asked = 0
  const { c, s } = client([json({ ok: true })], {
    token: () => {
      asked += 1
      return Promise.reject(new Error('identity refused the credential exchange: 401'))
    },
  })
  await assert.rejects(() => c.get('/x', { retries: 2 }))
  assert.equal(asked, 1, 'three identical rejections inside one backoff window buy nothing')
  assert.equal(s.count, 0)
})

test('a real transport failure still opens the circuit', async () => {
  const { c } = client([new TypeError('fetch failed')], {
    token: () => 'a-live-token',
    circuit: { threshold: 2, resetMs: 60_000 },
  })
  for (let i = 0; i < 2; i++) {
    await assert.rejects(() => c.get('/x', { retries: 0 }))
  }
  assert.equal(c.circuitState, 'open', 'the guard this change must not remove')
})

test('the circuit half-opens after the reset window', async () => {
  let clock = 0
  const { c } = client([json({}, 500)], {
    now: () => clock,
    circuit: { threshold: 1, resetMs: 1_000 },
  })
  await assert.rejects(() => c.get('/x', { retries: 0 }))
  assert.equal(c.circuitState, 'open')
  clock += 1_001
  assert.equal(c.circuitState, 'half_open')
})

test('a success in half-open closes the circuit again', async () => {
  let clock = 0
  const { c } = client([json({}, 500), json({ ok: true })], {
    now: () => clock,
    circuit: { threshold: 1, resetMs: 1_000 },
  })
  await assert.rejects(() => c.get('/x', { retries: 0 }))
  assert.equal(c.circuitState, 'open')
  clock += 1_001
  assert.equal(c.circuitState, 'half_open', 'one probe request is allowed through')
  assert.deepEqual(await c.get('/x', { retries: 0 }), { ok: true })
  assert.equal(c.circuitState, 'closed')
})

test('request id, traceparent and remaining deadline are forwarded', async () => {
  const { c, s } = client([json({ ok: true })])
  await c.get('/wallet', {
    requestId: 'req-abc',
    traceparent: '00-4bf92f-00f067-01',
    deadlineMs: 5_000,
  })
  const h = s.calls[0]?.headers
  assert.equal(h?.get('x-request-id'), 'req-abc')
  assert.equal(h?.get('traceparent'), '00-4bf92f-00f067-01')
  assert.ok(Number(h?.get('x-deadline-ms')) <= 5_000)
})

test('the auth token is fetched per attempt so a short-TTL service token can refresh', async () => {
  let issued = 0
  const { c, s } = client([json({}, 500), json({ ok: true })], {
    token: async () => `tok-${++issued}`,
  })
  await c.get('/wallet')
  assert.equal(s.calls[0]?.headers.get('authorization'), 'Bearer tok-1')
  assert.equal(s.calls[1]?.headers.get('authorization'), 'Bearer tok-2')
})

test('a per-request authorization header beats the client\'s own token', async () => {
  // micro-org#251. `settlement` forwards an OPERATOR's token to custody's admin mint, which needs
  // `role:admin` — an authority the service token does not carry. The service token winning here
  // meant that route could only ever be refused.
  const { c, s } = client([json({ ok: true })], { token: async () => 'service-tok' })
  await c.post('/v1/admin/treasuries', { }, { headers: { authorization: 'Bearer operator-tok' } })
  assert.equal(s.calls[0]?.headers.get('authorization'), 'Bearer operator-tok')
})

test('the caller wins whatever case either side spelled the header in', async () => {
  const { c, s } = client([json({ ok: true })], {
    token: async () => 'service-tok',
    headers: { 'X-Estate': 'cloudsforge' },
  })
  await c.get('/wallet', { headers: { Authorization: 'Bearer operator-tok', 'X-Estate': 'override' } })
  const h = s.calls[0]?.headers
  assert.equal(h?.get('authorization'), 'Bearer operator-tok')
  assert.equal(h?.get('x-estate'), 'override')
})

test('the client token still beats a static client header, which is only a default', async () => {
  const { c, s } = client([json({ ok: true })], {
    token: async () => 'service-tok',
    headers: { authorization: 'Bearer stale-default' },
  })
  await c.get('/wallet')
  assert.equal(s.calls[0]?.headers.get('authorization'), 'Bearer service-tok')
})

test('a non-JSON body from a peer is an error, not a parse crash', async () => {
  const { c } = client([new Response('<html>502 Bad Gateway</html>', { status: 200 })])
  await assert.rejects(
    () => c.get('/wallet'),
    (err: unknown) => err instanceof HttpError && err.body.startsWith('expected JSON'),
  )
})

test('an empty body is undefined rather than a parse error', async () => {
  const { c } = client([new Response(null, { status: 204 })])
  assert.equal(await c.get('/withdrawals/1'), undefined)
})

test('accept:text returns the body verbatim, preserving decimal strings', async () => {
  const { c } = client([new Response('{"usd":"1.10"}', { status: 200 })])
  const body = await c.get<string>('/admin/prices', { accept: 'text' })
  assert.equal(body, '{"usd":"1.10"}', 'relaying as text is what stops a decimal becoming a float')
})

test('an outer abort is not converted into a timeout', async () => {
  const controller = new AbortController()
  const hang = (async (_u: string, init?: RequestInit) =>
    new Promise<Response>((_res, rej) => {
      init?.signal?.addEventListener('abort', () => rej(new Error('aborted by caller')))
    })) as unknown as typeof globalThis.fetch
  const c = new HttpClient({ baseUrl: 'http://p', name: 'p', fetch: hang, sleep: noSleep })
  const p = c.get('/x', { signal: controller.signal, deadlineMs: 5_000 })
  await new Promise((r) => setTimeout(r, 5))
  controller.abort()
  await assert.rejects(p, (err: unknown) => !(err instanceof TimeoutError))
})

test('a caller signal aborted before the call still aborts it immediately', async () => {
  // Regression: registering a listener on an already-aborted signal never fires, so the request
  // hung until its own deadline. Found by the test above racing the first `await`.
  const controller = new AbortController()
  controller.abort()
  const hang = (async () => new Promise<Response>(() => {})) as unknown as typeof globalThis.fetch
  const c = new HttpClient({ baseUrl: 'http://p', name: 'p', fetch: hang, sleep: noSleep })
  await assert.rejects(
    () => c.get('/x', { signal: controller.signal, deadlineMs: 60_000 }),
    (err: unknown) => !(err instanceof TimeoutError),
  )
})

test('observability events are emitted per attempt with an outcome', async () => {
  const events: string[] = []
  const { c } = client([json({}, 500), json({ ok: true })], {
    onResult: (e: { outcome: string }) => void events.push(e.outcome),
  })
  await c.get('/wallet')
  assert.deepEqual(events, ['server_error', 'ok'])
})

test('redactUrl strips query strings and credentials', () => {
  assert.equal(redactUrl('https://api/x?token=secret'), 'https://api/x')
  assert.equal(redactUrl('https://user:pw@api/x'), 'https://api/x')
})

test('an absolute URL bypasses the base URL', async () => {
  const { c, s } = client([json({ ok: true })])
  await c.get('https://other.example/thing')
  assert.equal(s.calls[0]?.url, 'https://other.example/thing')
})

test('the retry backoff settles in a process with nothing else holding the loop open', async () => {
  // THE THIRD INSTANCE OF ONE MISTAKE. `defaultSleep` unref'd its timer, so the promise a retry
  // awaits resolved only if something else kept the event loop alive. A listening socket does that
  // in a service, which is why this survived — but not during a drain, where the server is already
  // closed and the loop is held open only by the in-flight work the drain is waiting for, and not
  // in a library: @cloudsforge/sdk copied this function and eleven of its tests hung.
  //
  // It runs in a CHILD process on purpose. In-process, the test runner's own handles hold the loop
  // open and the defect is invisible — which is exactly how it stayed invisible here.
  const { execFileSync } = await import('node:child_process')
  const script = `
    const sleep = (ms) => new Promise((r) => { setTimeout(r, ms) })
    await sleep(80)
    console.log('SETTLED')
  `
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', script], {
    encoding: 'utf8',
  })
  assert.match(out, /SETTLED/, 'an awaited backoff must resolve even when nothing else keeps the loop alive')

  // And the counterexample, so this test cannot pass by accident: unref'd, the same await never
  // settles and node exits non-zero.
  const bad = `
    const sleep = (ms) => new Promise((r) => { const t = setTimeout(r, ms); t.unref?.() })
    await sleep(80)
    console.log('SETTLED')
  `
  let unrefSettled = true
  try {
    execFileSync(process.execPath, ['--input-type=module', '-e', bad], { encoding: 'utf8', stdio: 'pipe' })
  } catch {
    unrefSettled = false
  }
  assert.equal(unrefSettled, false, 'the unref\'d form must NOT settle — if it does, this test proves nothing')
})

test('THE DEADLINE fires in a process with nothing else holding the loop open', async () => {
  // THE FOURTH INSTANCE OF THE SAME MISTAKE, and the first one in the deadline itself.
  //
  // `#attempt` used `AbortSignal.timeout(remainingMs)`. That is an UNREF'D timer — it does not
  // hold the event loop open — so against a peer that never answers, Node drained the loop and the
  // deadline never fired, leaving `request()`'s promise unsettled for ever. In a service a
  // listening socket hides it. It is not hidden during a drain, where the loop is held open only
  // by the in-flight work the deadline is the ceiling on, and it is not hidden in a short-lived
  // process: this package's own CI reported it as "Promise resolution is still pending but the
  // event loop has already resolved", and took every test after it down as cancelledByParent.
  //
  // THE TEST ABOVE COULD NOT HAVE CAUGHT IT. It runs a REIMPLEMENTATION of `defaultSleep` in a
  // child rather than this package's code, so it says nothing about any other timer here. This one
  // drives the real `HttpClient` against a peer that hangs, in a child process whose loop has
  // nothing else in it at all.
  const { execFileSync } = await import('node:child_process')
  const { fileURLToPath } = await import('node:url')
  const here = fileURLToPath(new URL('./index.ts', import.meta.url))
  const script = `
    const { HttpClient, TimeoutError } = await import(${JSON.stringify(here)})
    // Hangs until aborted, exactly as a real fetch against an unresponsive peer behaves. A fake
    // that ignored the signal would never settle whatever the library did, and would be testing
    // the fake.
    const hang = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
      })
    const c = new HttpClient({ baseUrl: 'http://hung:4000', name: 'hung', fetch: hang })
    try {
      await c.get('/x', { deadlineMs: 60, retries: 0 })
      console.log('NO_TIMEOUT')
    } catch (err) {
      console.log(err instanceof TimeoutError ? 'TIMED_OUT' : 'OTHER:' + err)
    }
  `
  const out = execFileSync(
    process.execPath,
    ['--import', 'tsx', '--input-type=module', '-e', script],
    { encoding: 'utf8', stdio: 'pipe' },
  )
  // An empty stdout is the failure this exists for: the process exited before the deadline fired,
  // so neither branch above ever ran.
  assert.match(
    out,
    /TIMED_OUT/,
    `the deadline must fire even when nothing else keeps the loop alive (got ${JSON.stringify(out)})`,
  )
})

test('a settled request does NOT keep the process alive for the rest of its deadline', async () => {
  // The opposite mistake, and just as real: referencing the deadline timer without clearing it
  // would make a 5ms call under a 30s deadline hold the loop open for thirty seconds. Measured as
  // wall-clock exit time in a child, because "did it exit promptly" is the actual property.
  const { execFileSync } = await import('node:child_process')
  const { fileURLToPath } = await import('node:url')
  const here = fileURLToPath(new URL('./index.ts', import.meta.url))
  const script = `
    const { HttpClient } = await import(${JSON.stringify(here)})
    const ok = async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
    const c = new HttpClient({ baseUrl: 'http://peer:4000', name: 'peer', fetch: ok })
    await c.get('/x', { deadlineMs: 30_000 })
    console.log('DONE')
  `
  const started = Date.now()
  const out = execFileSync(
    process.execPath,
    ['--import', 'tsx', '--input-type=module', '-e', script],
    { encoding: 'utf8', stdio: 'pipe' },
  )
  const elapsed = Date.now() - started
  assert.match(out, /DONE/)
  assert.ok(elapsed < 20_000, `the process took ${elapsed}ms to exit after a request that succeeded`)
})

test('no timer that a promise resolves on is unref\'d', async () => {
  // The rule that came out of three instances: unref() belongs on a timer nobody is waiting for —
  // a poll tick, a force-exit bomb — never on one whose expiry is what a promise resolves on.
  const { readFileSync } = await import('node:fs')
  const { fileURLToPath } = await import('node:url')
  const src = readFileSync(fileURLToPath(new URL('./index.ts', import.meta.url)), 'utf8')
  assert.doesNotMatch(
    src,
    /new Promise\([^)]*\)\s*=>\s*\{[^}]*setTimeout[^}]*unref/s,
    'a timer inside a promise executor must stay referenced',
  )
})
