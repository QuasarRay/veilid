import { expect } from '@wdio/globals';

const env: Record<string, string | undefined> =
  typeof process !== 'undefined' && process.env ? process.env : {};

function requireStressEnv(): { port: number; hash: Uint8Array<ArrayBuffer>; closeDelayMs: number } {
  const required = {
    WT_STRESS_PORT: env.WT_STRESS_PORT,
    WT_STRESS_HANDSHAKE: env.WT_STRESS_HANDSHAKE,
  };
  const missing = Object.entries(required)
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(
      `webtransport-stress.test.ts requires the environment variable(s) ${missing.join(', ')}, ` +
        `which ${missing.length === 1 ? 'is' : 'are'} not set. WT_STRESS_PORT is the port the ` +
        `native stress server (veilid-core's #[ignore]d serve_wt_stress_for_browser test) bound ` +
        `on 127.0.0.1, and WT_STRESS_HANDSHAKE is the JSON handshake that server wrote to ` +
        `WT_STRESS_HANDSHAKE_FILE. There is no default, so this spec cannot run without them.`,
    );
  }
  const port = Number(required.WT_STRESS_PORT);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(
      `WT_STRESS_PORT must be a TCP/UDP port number, got "${required.WT_STRESS_PORT}"`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(required.WT_STRESS_HANDSHAKE!);
  } catch (e) {
    throw new Error(
      `WT_STRESS_HANDSHAKE must be the JSON handshake written to WT_STRESS_HANDSHAKE_FILE, ` +
        `got "${required.WT_STRESS_HANDSHAKE}": ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  const { cert_hash: certHash, close_delay_ms: closeDelayMs } = (parsed ?? {}) as {
    cert_hash?: unknown;
    close_delay_ms?: unknown;
  };
  if (typeof certHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(certHash.trim())) {
    throw new Error(
      `WT_STRESS_HANDSHAKE.cert_hash must be 64 hex characters (a SHA-256), got "${String(certHash)}"`,
    );
  }
  if (typeof closeDelayMs !== 'number' || !Number.isFinite(closeDelayMs) || closeDelayMs < 0) {
    throw new Error(
      `WT_STRESS_HANDSHAKE.close_delay_ms must be a non-negative number of milliseconds, got ` +
        `"${String(closeDelayMs)}"`,
    );
  }
  const hex = certHash.trim();
  const hash = new Uint8Array(new ArrayBuffer(32));
  for (let i = 0; i < 32; i++) {
    hash[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return { port, hash, closeDelayMs };
}

const {
  port: STRESS_PORT,
  hash: STRESS_HASH,
  closeDelayMs: SERVER_CLOSE_DELAY_MS,
} = requireStressEnv();

const BACKPRESSURE_BYTES = 16 * 1024 * 1024;
const HANG_MS = 20_000;
const MAX_MESSAGE_BYTES = 65507;
const SILENT_READ_MS = 5_000;
const ECHO_READ_MS = 10_000;
const RECV_CLOSE_MS = 45_000;

function url(path: string): string {
  return `https://127.0.0.1:${STRESS_PORT}${path}`;
}

async function openSession(path: string): Promise<WebTransport> {
  const wt = new WebTransport(url(path), {
    serverCertificateHashes: [{ algorithm: 'sha-256', value: STRESS_HASH }],
  });
  await wt.ready;
  return wt;
}

type Settled = { outcome: 'resolved' | 'rejected' | 'pending'; ms: number; detail: string };

// Watch `promise` for at most `limitMs`. Handlers are attached immediately, so a rejection
// after the limit is still handled and never surfaces as an unhandled rejection that would
// fail the run.
async function settle<T>(promise: Promise<T>, limitMs: number): Promise<Settled> {
  const started = performance.now();
  let late = false;
  const observed = promise.then(
    (value) => ({ outcome: 'resolved' as const, detail: explain(value) }),
    (error) => ({ outcome: 'rejected' as const, detail: explain(error) }),
  );
  void observed.then((r) => {
    if (late) {
      console.log(
        `  (settled late after ${Math.round(performance.now() - started)}ms: ${r.outcome} ${r.detail})`,
      );
    }
  });
  const capped = new Promise<{ outcome: 'pending'; detail: string }>((resolve) =>
    setTimeout(
      () => resolve({ outcome: 'pending', detail: `still pending after ${limitMs}ms` }),
      limitMs,
    ),
  );
  const result = await Promise.race([observed, capped]);
  if (result.outcome === 'pending') {
    late = true;
  }
  return {
    outcome: result.outcome,
    ms: Math.round(performance.now() - started),
    detail: result.detail,
  };
}

function explain(value: unknown): string {
  if (value === undefined) return 'undefined';
  if (value instanceof Error) return `${value.name}: ${value.message}`;
  if (typeof value === 'object' && value !== null) {
    if ('done' in value) {
      const result = value as ReadableStreamReadResult<Uint8Array>;
      const size =
        result.value instanceof Uint8Array ? `${result.value.length} bytes` : 'undefined';
      return `{ done: ${result.done}, value: ${result.done ? 'undefined' : size} }`;
    }
    if ('closeCode' in value) {
      const info = value as WebTransportCloseInfo;
      return `closed ${info.closeCode ?? '?'} "${info.reason ?? ''}"`;
    }
    return JSON.stringify(value);
  }
  return JSON.stringify(value) ?? typeof value;
}

function framed(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + payload.length);
  new DataView(out.buffer).setUint32(0, payload.length, false);
  out.set(payload, 4);
  return out;
}

function prefix(length: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, length, false);
  return out;
}

function payloadOf(size: number, seed = 0x5a): Uint8Array {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    out[i] = (i * 31 + seed) & 0xff;
  }
  return out;
}

type Step =
  | { kind: 'read'; result: ReadableStreamReadResult<Uint8Array> }
  | { kind: 'error'; error: unknown }
  | { kind: 'deadline' };

async function readFramed(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  limitMs: number,
): Promise<{ body?: Uint8Array; ms: number; detail: string }> {
  const started = performance.now();
  let buf = new Uint8Array(0);
  let length: number | undefined;
  let expired = false;
  const deadline = new Promise<'deadline'>((resolve) =>
    setTimeout(() => {
      expired = true;
      resolve('deadline');
    }, limitMs),
  );
  for (;;) {
    if (length === undefined && buf.length >= 4) {
      length = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0, false);
    }
    if (length !== undefined && buf.length >= 4 + length) {
      return {
        body: buf.slice(4, 4 + length),
        ms: Math.round(performance.now() - started),
        detail: 'ok',
      };
    }
    if (expired) {
      return {
        ms: Math.round(performance.now() - started),
        detail: `timed out with ${buf.length} bytes buffered`,
      };
    }
    const step = await Promise.race([
      reader.read().then(
        (result): Step => ({ kind: 'read', result }),
        (error: unknown): Step => ({ kind: 'error', error }),
      ),
      deadline.then((): Step => ({ kind: 'deadline' })),
    ]);
    if (step.kind === 'deadline') {
      return {
        ms: Math.round(performance.now() - started),
        detail: `timed out with ${buf.length} bytes buffered`,
      };
    }
    if (step.kind === 'error') {
      return {
        ms: Math.round(performance.now() - started),
        detail: `read rejected: ${explain(step.error)}`,
      };
    }
    if (step.result.done || step.result.value === undefined) {
      return {
        ms: Math.round(performance.now() - started),
        detail: `stream ended with ${buf.length} bytes buffered`,
      };
    }
    const chunk = step.result.value;
    const merged = new Uint8Array(buf.length + chunk.length);
    merged.set(buf, 0);
    merged.set(chunk, buf.length);
    buf = merged;
  }
}

function sameBytes(a: Uint8Array | undefined, b: Uint8Array): boolean {
  if (!a || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

const rows: string[] = [];
function record(caseName: string, outcome: string, ms: number, detail: string) {
  const known = EXPECTED_FAIL[`${FAMILY}|${caseName}`];
  const mark = known ? ` [EXPECTED-FAIL: ${known}]` : '';
  const line = `MATRIX | ${caseName} | ${outcome} | ${ms}ms | ${detail}${mark}`;
  rows.push(line);
  console.log(line);
}

function browserName(): string {
  const ua = navigator.userAgent;
  if (/Firefox\//.test(ua)) return `firefox ${/Firefox\/([\d.]+)/.exec(ua)?.[1] ?? '?'}`;
  if (/Chrome\//.test(ua)) return `chrome ${/Chrome\/([\d.]+)/.exec(ua)?.[1] ?? '?'}`;
  return ua;
}

const FAMILY = /Firefox\//.test(navigator.userAgent) ? 'firefox' : 'chrome';

// Cells that do not hold today, per browser family. Mocha has no soft-fail, so an entry here
// inverts its case's assertion: the case asserts that the defect still reproduces, and goes red
// the day the browser fixes it.
const EXPECTED_FAIL: Record<string, string> = {
  // Firefox 153 never settles a stream write blocked on flow control when the page closes the
  // session: no rejection, no resolution, no timeout of its own. A write that fits the window
  // resolves normally under the same close, so the trigger is the backpressure, not the close.
  'firefox|1 user close vs send: write': 'write never settles after a user-initiated close',
};

function expectedFail(caseName: string): string | undefined {
  return EXPECTED_FAIL[`${FAMILY}|${caseName}`];
}

describe('veilid-wasm WebTransport write/close stress matrix', () => {
  after(() => {
    console.log(`\n===== WebTransport stress matrix: ${browserName()} =====`);
    for (const row of rows) console.log(row);
    console.log('===== end matrix =====\n');
  });

  it('runs in a secure context with WebTransport and a reachable stress server', async () => {
    expect(window.isSecureContext).toBe(true);
    expect(typeof (window as unknown as { WebTransport?: unknown }).WebTransport).toBe('function');
    console.log(`browser: ${browserName()}, stress server: ${url('/echo')}`);

    const wt = await openSession('/echo');
    try {
      const stream = await wt.createBidirectionalStream();
      const writer = stream.writable.getWriter();
      const reader = stream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
      const message = payloadOf(64);
      await writer.write(framed(message));
      const echo = await readFramed(reader, ECHO_READ_MS);
      record('0 baseline echo', echo.body ? 'echoed' : 'failed', echo.ms, echo.detail);
      expect(sameBytes(echo.body, message)).toBe(true);
    } finally {
      wt.close();
    }
  });

  it('case 1: settles a send that races a user-initiated close', async () => {
    const wt = await openSession('/park');
    const stream = await wt.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;

    const write = writer.write(payloadOf(BACKPRESSURE_BYTES));
    wt.close();

    const w = await settle(write, HANG_MS);
    record('1 user close vs send: write', w.outcome, w.ms, w.detail);
    const r = await settle(reader.read(), SILENT_READ_MS);
    record('1 user close vs send: read', r.outcome, r.ms, r.detail);
    const c = await settle(wt.closed, SILENT_READ_MS);
    record('1 user close vs send: session.closed', c.outcome, c.ms, c.detail);

    if (expectedFail('1 user close vs send: write')) {
      expect(w.outcome).toBe('pending');
    } else {
      expect(w.outcome).not.toBe('pending');
    }
  });

  it('case 2: settles a send that races a remote-initiated close', async () => {
    const wt = await openSession('/close-on-first-byte');
    const stream = await wt.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;

    await writer.write(new Uint8Array([0x01]));
    const write = writer.write(payloadOf(BACKPRESSURE_BYTES));

    const w = await settle(write, HANG_MS);
    record('2 remote close vs send: write', w.outcome, w.ms, w.detail);
    const r = await settle(reader.read(), SILENT_READ_MS);
    record('2 remote close vs send: read', r.outcome, r.ms, r.detail);
    const c = await settle(wt.closed, SILENT_READ_MS);
    record('2 remote close vs send: session.closed', c.outcome, c.ms, c.detail);

    expect(w.outcome).not.toBe('pending');
  });

  // An abandoned session can jam the browser's WebTransport pool, so the last arm here dials
  // again after the close.
  it('case 3: buffers a send with no matching receive and leaves the pool usable', async () => {
    const wt = await openSession('/park');
    const stream = await wt.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;

    const message = payloadOf(1024);
    const w = await settle(writer.write(framed(message)), HANG_MS);
    record('3 no receiver: write', w.outcome, w.ms, w.detail);
    expect(w.outcome).toBe('resolved');

    const r = await settle(reader.read(), SILENT_READ_MS);
    record('3 no receiver: read', r.outcome, r.ms, r.detail);
    expect(r.outcome).toBe('pending');

    wt.close();

    const started = performance.now();
    const next = await openSession('/echo');
    try {
      const nextStream = await next.createBidirectionalStream();
      const nextWriter = nextStream.writable.getWriter();
      const nextReader = nextStream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
      const probe = payloadOf(64, 0x11);
      await nextWriter.write(framed(probe));
      const echo = await readFramed(nextReader, ECHO_READ_MS);
      record(
        '3 no receiver: next session',
        echo.body ? 'echoed' : 'failed',
        Math.round(performance.now() - started),
        echo.detail,
      );
      expect(sameBytes(echo.body, probe)).toBe(true);
    } finally {
      next.close();
    }
  });

  it('case 4: chunking probe: two writes vs one buffer vs the historical JS bridge', async () => {
    const message = payloadOf(512, 0x77);

    async function twoWrites(): Promise<{ ok: boolean; ms: number; detail: string }> {
      const started = performance.now();
      const wt = await openSession('/echo');
      try {
        const stream = await wt.createBidirectionalStream();
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
        const p = await settle(writer.write(prefix(message.length)), HANG_MS);
        if (p.outcome !== 'resolved') {
          return {
            ok: false,
            ms: Math.round(performance.now() - started),
            detail: `prefix write ${p.outcome}`,
          };
        }
        const b = await settle(writer.write(message), HANG_MS);
        if (b.outcome !== 'resolved') {
          return {
            ok: false,
            ms: Math.round(performance.now() - started),
            detail: `payload write ${b.outcome}`,
          };
        }
        const echo = await readFramed(reader, ECHO_READ_MS);
        return {
          ok: sameBytes(echo.body, message),
          ms: Math.round(performance.now() - started),
          detail: echo.detail,
        };
      } finally {
        wt.close();
      }
    }

    async function oneBuffer(): Promise<{ ok: boolean; ms: number; detail: string }> {
      const started = performance.now();
      const wt = await openSession('/echo');
      try {
        const stream = await wt.createBidirectionalStream();
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
        const w = await settle(writer.write(framed(message)), HANG_MS);
        if (w.outcome !== 'resolved') {
          return {
            ok: false,
            ms: Math.round(performance.now() - started),
            detail: `write ${w.outcome}`,
          };
        }
        const echo = await readFramed(reader, ECHO_READ_MS);
        return {
          ok: sameBytes(echo.body, message),
          ms: Math.round(performance.now() - started),
          detail: echo.detail,
        };
      } finally {
        wt.close();
      }
    }

    async function bridgeShape(): Promise<{ ok: boolean; ms: number; detail: string }> {
      const started = performance.now();
      const wt = new WebTransport(url('/echo'), {
        serverCertificateHashes: [{ algorithm: 'sha-256', value: STRESS_HASH }],
      });
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error(`timed out after ${ECHO_READ_MS}ms`)),
          ECHO_READ_MS,
        );
      });
      const work = (async () => {
        await wt.ready;
        const stream = await wt.createBidirectionalStream();
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
        await writer.write(framed(message));
        let buf = new Uint8Array(0);
        let length: number | undefined;
        for (;;) {
          if (length === undefined && buf.length >= 4) {
            length = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0, false);
            if (length > MAX_MESSAGE_BYTES) throw new Error(`response too large: ${length}`);
          }
          if (length !== undefined && buf.length >= 4 + length) {
            return buf.slice(4, 4 + length);
          }
          const r = await reader.read();
          if (r.done || r.value === undefined) throw new Error('stream closed early');
          const merged = new Uint8Array(buf.length + r.value.length);
          merged.set(buf, 0);
          merged.set(r.value, buf.length);
          buf = merged;
        }
      })();
      try {
        const body = await Promise.race([work, deadline]);
        return {
          ok: sameBytes(body, message),
          ms: Math.round(performance.now() - started),
          detail: `${body.length} bytes`,
        };
      } catch (e) {
        return { ok: false, ms: Math.round(performance.now() - started), detail: explain(e) };
      } finally {
        clearTimeout(timer);
        wt.close();
      }
    }

    const a = await twoWrites();
    record(
      '4a chunking: two writes (current Rust path)',
      a.ok ? 'echoed' : 'failed',
      a.ms,
      a.detail,
    );
    const b = await oneBuffer();
    record('4b chunking: one combined buffer', b.ok ? 'echoed' : 'failed', b.ms, b.detail);
    const c = await bridgeShape();
    record('4c chunking: historical JS bridge shape', c.ok ? 'echoed' : 'failed', c.ms, c.detail);

    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    expect(c.ok).toBe(true);
  });

  it('case 5: reports how promptly a read settles when the peer closes', async () => {
    const wt = await openSession('/close-mid-read');
    const stream = await wt.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;

    const message = payloadOf(128, 0x33);
    await writer.write(framed(message));
    const echo = await readFramed(reader, ECHO_READ_MS);
    record(
      '5 recv close: echo before close',
      echo.body ? 'echoed' : 'failed',
      echo.ms,
      echo.detail,
    );
    expect(sameBytes(echo.body, message)).toBe(true);

    const r = await settle(reader.read(), RECV_CLOSE_MS);
    const latency = Math.max(0, r.ms - SERVER_CLOSE_DELAY_MS);
    record(
      '5 recv close: read after peer close',
      r.outcome,
      r.ms,
      `${latency}ms after the close: ${r.detail}`,
    );
    const c = await settle(wt.closed, SILENT_READ_MS);
    record('5 recv close: session.closed', c.outcome, c.ms, c.detail);

    expect(r.outcome).not.toBe('pending');
  });

  it('case 6: measures how long a WebTransport options object costs to build', () => {
    const hashes = [STRESS_HASH, new Uint8Array(STRESS_HASH)];
    const ITERATIONS = 1_000_000;
    let entries = 0;

    for (let i = 0; i < 10_000; i++) {
      entries += hashes.map((h) => ({ algorithm: 'sha-256', value: h })).length;
    }
    entries = 0;

    const started = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
      const options = {
        serverCertificateHashes: hashes.map((h) => ({ algorithm: 'sha-256', value: h })),
      };
      entries += options.serverCertificateHashes.length;
    }
    const elapsed = performance.now() - started;
    const nsPerOp = (elapsed * 1e6) / ITERATIONS;
    record(
      '6 options construction',
      `${nsPerOp.toFixed(1)} ns/op`,
      Math.round(elapsed),
      `${ITERATIONS} options objects, 2 hashes each`,
    );

    expect(entries).toBe(ITERATIONS * 2);
    expect(nsPerOp).toBeLessThan(10_000);
  });
});
