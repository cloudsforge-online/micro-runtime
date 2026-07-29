/**
 * Readiness, liveness and drain.
 *
 * The estate today returns a static `{ok:true}` from `/health` in every service, never touching
 * Postgres or any upstream, and `depends_on: service_healthy` across the whole compose file
 * rests on that literal. A replica whose database is unreachable reports healthy and 503s every
 * request while the load balancer keeps feeding it.
 *
 * Shutdown has the mirror-image problem: `app.close()` then a force-exit after 10 seconds, with
 * no ready flag ever flipped, so a rolling deploy cuts in-flight requests — and in ForgeMint's
 * case, in-flight chain deploys that hold the request for up to 180 seconds.
 */

export type ProbeState = 'pass' | 'warn' | 'fail'

export interface ProbeResult {
  readonly state: ProbeState
  /** Shown to operators. Must never contain a secret, a DSN or a token. */
  readonly detail?: string
}

export interface Probe {
  readonly name: string
  /**
   * `hard` probes fail readiness. `soft` probes degrade it but keep the service in the load
   * balancer — used for upstreams the service can serve without, so that one slow dependency
   * does not take a whole product offline.
   */
  readonly kind: 'hard' | 'soft'
  check(signal: AbortSignal): Promise<ProbeResult>
}

export interface ReadinessReport {
  readonly ready: boolean
  readonly state: 'starting' | 'ready' | 'degraded' | 'draining' | 'stopped'
  readonly checks: ReadonlyArray<{ name: string; kind: 'hard' | 'soft' } & ProbeResult>
  readonly uptimeMs: number
}

export interface LifecycleOptions {
  /**
   * How long to keep serving after SIGTERM while already reporting unready.
   *
   * This must exceed one load-balancer probe interval, or the balancer will still be sending
   * traffic when the process stops accepting it. Default 5s suits a 2s interval.
   */
  readonly drainDelayMs?: number
  /** Ceiling on waiting for in-flight work once draining. */
  readonly drainTimeoutMs?: number
  /** Per-probe deadline. A readiness check that hangs is a readiness check that fails. */
  readonly probeTimeoutMs?: number
  /** Cached probe results are reused for this long. Keeps `/readyz` cheap under load-balancer polling. */
  readonly cacheMs?: number
  readonly now?: () => number
  readonly onStateChange?: (state: ReadinessReport['state']) => void
}

const DEFAULTS = {
  drainDelayMs: 5_000,
  drainTimeoutMs: 25_000,
  probeTimeoutMs: 2_000,
  cacheMs: 1_000,
} as const

/** Work in flight that a drain must wait for. Returned by `track()`. */
export type Release = () => void

export class Lifecycle {
  readonly #probes: Probe[] = []
  readonly #opts: Required<Omit<LifecycleOptions, 'onStateChange'>> &
    Pick<LifecycleOptions, 'onStateChange'>

  #state: ReadinessReport['state'] = 'starting'
  #startedAt: number
  #inFlight = 0
  #drained: (() => void)[] = []
  #cache: { at: number; report: ReadinessReport } | null = null
  #shutdownHooks: Array<() => Promise<void> | void> = []

  constructor(options: LifecycleOptions = {}) {
    const now = options.now ?? (() => Date.now())
    this.#opts = {
      drainDelayMs: options.drainDelayMs ?? DEFAULTS.drainDelayMs,
      drainTimeoutMs: options.drainTimeoutMs ?? DEFAULTS.drainTimeoutMs,
      probeTimeoutMs: options.probeTimeoutMs ?? DEFAULTS.probeTimeoutMs,
      cacheMs: options.cacheMs ?? DEFAULTS.cacheMs,
      now,
      ...(options.onStateChange ? { onStateChange: options.onStateChange } : {}),
    }
    this.#startedAt = now()
  }

  /** Register a dependency check. Order does not matter; probes run concurrently. */
  addProbe(probe: Probe): this {
    this.#probes.push(probe)
    return this
  }

  /**
   * Run before exit, after in-flight work has drained. Hooks run in reverse registration order,
   * so a service that registers `db` then `server` closes the server first.
   */
  onShutdown(hook: () => Promise<void> | void): this {
    this.#shutdownHooks.push(hook)
    return this
  }

  /** Called once boot has completed: migrations applied, listeners bound. */
  markReady(): void {
    if (this.#state === 'starting') this.#setState('ready')
  }

  get state(): ReadinessReport['state'] {
    return this.#state
  }

  /** True while the service should be sent traffic. */
  get accepting(): boolean {
    return this.#state === 'ready' || this.#state === 'degraded'
  }

  /** True while the job runner should claim new work. Drains earlier than HTTP. */
  get claimingJobs(): boolean {
    return this.#state === 'ready' || this.#state === 'degraded'
  }

  /**
   * Mark a unit of work in flight. The returned release must be called in a `finally`.
   *
   *   const done = lifecycle.track()
   *   try { await deployContract() } finally { done() }
   */
  track(): Release {
    this.#inFlight += 1
    let released = false
    return () => {
      if (released) return
      released = true
      this.#inFlight -= 1
      if (this.#inFlight === 0) {
        const waiters = this.#drained
        this.#drained = []
        for (const w of waiters) w()
      }
    }
  }

  get inFlight(): number {
    return this.#inFlight
  }

  /** Liveness. Deliberately static: if the process answers, it is alive. Restart me if it does not. */
  livez(): { ok: true; state: ReadinessReport['state']; uptimeMs: number } {
    return { ok: true, state: this.#state, uptimeMs: this.#opts.now() - this.#startedAt }
  }

  /** Readiness. Runs the probes. 503 when `ready` is false. */
  async readyz(): Promise<ReadinessReport> {
    const now = this.#opts.now()
    if (this.#cache && now - this.#cache.at < this.#opts.cacheMs) return this.#cache.report

    // Draining and starting are lifecycle facts, not dependency facts. Report them without
    // paying for probes — and never report ready while draining, which is the entire point.
    if (this.#state === 'draining' || this.#state === 'stopped') {
      return { ready: false, state: this.#state, checks: [], uptimeMs: now - this.#startedAt }
    }

    const checks = await Promise.all(this.#probes.map((p) => this.#runProbe(p)))
    const hardFail = checks.some((c) => c.kind === 'hard' && c.state === 'fail')
    const anyDegraded = checks.some((c) => c.state !== 'pass')

    if (this.#state !== 'starting') {
      this.#setState(hardFail ? 'degraded' : anyDegraded ? 'degraded' : 'ready')
    }

    const report: ReadinessReport = {
      // A hard failure is unready. A soft failure is degraded but still serving, because
      // removing a whole product from the balancer over a non-essential upstream is worse
      // than serving it without that upstream.
      ready: this.#state !== 'starting' && !hardFail,
      state: this.#state,
      checks,
      uptimeMs: now - this.#startedAt,
    }
    this.#cache = { at: now, report }
    return report
  }

  async #runProbe(probe: Probe): Promise<{ name: string; kind: 'hard' | 'soft' } & ProbeResult> {
    const controller = new AbortController()
    let timer: NodeJS.Timeout | undefined

    // The signal alone is not enough. Aborting it asks the probe to stop; a driver that ignores
    // the signal — and several database clients do — leaves the await pending forever, so
    // `/readyz` hangs rather than reporting a failure. That is strictly worse than no probe at
    // all, because a hung readiness endpoint looks identical to a slow one to a load balancer.
    // So the abort is a courtesy and the race is the guarantee.
    const timeout = new Promise<'timed-out'>((resolve) => {
      timer = setTimeout(() => {
        controller.abort()
        resolve('timed-out')
      }, this.#opts.probeTimeoutMs)
      timer.unref?.()
    })

    try {
      const outcome = await Promise.race([
        probe.check(controller.signal).then((result) => ({ ok: true as const, result })),
        timeout,
      ])
      if (outcome === 'timed-out') {
        return { name: probe.name, kind: probe.kind, state: 'fail', detail: 'probe timed out' }
      }
      return { name: probe.name, kind: probe.kind, ...outcome.result }
    } catch (err) {
      return {
        name: probe.name,
        kind: probe.kind,
        state: 'fail',
        detail: controller.signal.aborted ? 'probe timed out' : messageOf(err),
      }
    } finally {
      if (timer) clearTimeout(timer)
    }
  }

  /**
   * The drain sequence. Each step exists because skipping it drops a request:
   *
   *   1. stop reporting ready        — the balancer learns before it is told
   *   2. wait one probe interval     — so it actually notices
   *   3. stop claiming jobs          — no new background work
   *   4. wait for in-flight work     — the 180-second chain deploy finishes
   *   5. run shutdown hooks          — close the server, then the pool
   */
  async shutdown(reason = 'SIGTERM'): Promise<{ reason: string; drainedMs: number; forced: boolean }> {
    if (this.#state === 'draining' || this.#state === 'stopped') {
      return { reason, drainedMs: 0, forced: false }
    }
    const began = this.#opts.now()
    this.#setState('draining')
    this.#cache = null

    await sleep(this.#opts.drainDelayMs)

    const forced = !(await this.#awaitInFlight(this.#opts.drainTimeoutMs))

    for (const hook of [...this.#shutdownHooks].reverse()) {
      try {
        await hook()
      } catch {
        // A failing shutdown hook must not prevent the remaining hooks from running.
        // Losing a database pool because the HTTP server refused to close is not an improvement.
      }
    }

    this.#setState('stopped')
    return { reason, drainedMs: this.#opts.now() - began, forced }
  }

  #awaitInFlight(timeoutMs: number): Promise<boolean> {
    if (this.#inFlight === 0) return Promise.resolve(true)
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), timeoutMs)
      this.#drained.push(() => {
        clearTimeout(timer)
        resolve(true)
      })
    })
  }

  #setState(next: ReadinessReport['state']): void {
    if (this.#state === next) return
    this.#state = next
    this.#cache = null
    this.#opts.onStateChange?.(next)
  }
}

/**
 * Wire SIGTERM and SIGINT to a drain, and force-exit only if the drain itself hangs.
 *
 * The force-exit ceiling is deliberately larger than `drainTimeoutMs`: it is the backstop for a
 * hung shutdown hook, not the shutdown budget. Setting it below the drain timeout reintroduces
 * exactly the bug this package exists to fix.
 */
export function installSignalHandlers(
  lifecycle: Lifecycle,
  options: { readonly forceExitAfterMs?: number; readonly exit?: (code: number) => void } = {},
): () => void {
  const forceAfter = options.forceExitAfterMs ?? 45_000
  const exit = options.exit ?? ((code: number) => process.exit(code))
  let shuttingDown = false

  const handler = (signal: NodeJS.Signals) => () => {
    if (shuttingDown) return
    shuttingDown = true
    const bomb = setTimeout(() => exit(1), forceAfter)
    bomb.unref?.()
    void lifecycle.shutdown(signal).then(
      () => exit(0),
      () => exit(1),
    )
  }

  const onTerm = handler('SIGTERM')
  const onInt = handler('SIGINT')
  process.on('SIGTERM', onTerm)
  process.on('SIGINT', onInt)

  return () => {
    process.off('SIGTERM', onTerm)
    process.off('SIGINT', onInt)
  }
}

/** A readiness probe over a Postgres-shaped client. */
export function postgresProbe(
  name: string,
  query: (signal: AbortSignal) => Promise<unknown>,
  kind: 'hard' | 'soft' = 'hard',
): Probe {
  return {
    name,
    kind,
    async check(signal) {
      await query(signal)
      return { state: 'pass' }
    },
  }
}

/**
 * A readiness probe over an HTTP upstream.
 *
 * Default `kind` is `soft`. A service is usually still worth serving when a peer is down, and
 * making every upstream hard means one outage cascades into all of them — which is how a single
 * slow dependency takes an entire estate out of its load balancer.
 */
export function httpProbe(
  name: string,
  url: string,
  options: { readonly kind?: 'hard' | 'soft'; readonly fetch?: typeof globalThis.fetch } = {},
): Probe {
  const doFetch = options.fetch ?? globalThis.fetch
  return {
    name,
    kind: options.kind ?? 'soft',
    async check(signal) {
      const res = await doFetch(url, { signal, redirect: 'manual' })
      if (!res.ok) return { state: 'fail', detail: `HTTP ${res.status}` }
      return { state: 'pass' }
    },
  }
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function sleep(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve()
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms)
    t.unref?.()
  })
}
