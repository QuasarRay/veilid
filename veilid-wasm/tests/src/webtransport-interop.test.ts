import { expect } from '@wdio/globals';

const env: Record<string, string | undefined> =
  typeof process !== 'undefined' && process.env ? process.env : {};

function requireInteropEnv(): { port: number; hash: Uint8Array<ArrayBuffer> } {
  const required = { WT_BROWSER_PORT: env.WT_BROWSER_PORT, WT_BROWSER_HASH: env.WT_BROWSER_HASH };
  const missing = Object.entries(required)
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(
      `webtransport-interop.test.ts requires the environment variable(s) ${missing.join(', ')}, ` +
        `which ${missing.length === 1 ? 'is' : 'are'} not set. WT_BROWSER_PORT is the port the ` +
        `native echo server (veilid-core's #[ignore]d serve_wt_echo_for_browser test) bound on ` +
        `127.0.0.1, and WT_BROWSER_HASH is the 64-character hex SHA-256 that server wrote to ` +
        `WT_BROWSER_HASH_FILE. There is no default, so this spec cannot run without them.`,
    );
  }
  const port = Number(required.WT_BROWSER_PORT);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(
      `WT_BROWSER_PORT must be a TCP/UDP port number, got "${required.WT_BROWSER_PORT}"`,
    );
  }
  const hex = required.WT_BROWSER_HASH!.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`WT_BROWSER_HASH must be 64 hex characters (a SHA-256), got "${hex}"`);
  }
  const hash = new Uint8Array(new ArrayBuffer(32));
  for (let i = 0; i < 32; i++) {
    hash[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return { port, hash };
}

const { port: ECHO_PORT, hash: ECHO_HASH } = requireInteropEnv();

const ECHO_READ_MS = 15_000;

function framed(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + payload.length);
  new DataView(out.buffer).setUint32(0, payload.length, false);
  out.set(payload, 4);
  return out;
}

async function readFramed(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  limitMs: number,
): Promise<Uint8Array | undefined> {
  let buf = new Uint8Array(0);
  let length: number | undefined;
  const deadline = new Promise<undefined>((resolve) =>
    setTimeout(() => resolve(undefined), limitMs),
  );
  for (;;) {
    if (length === undefined && buf.length >= 4) {
      length = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0, false);
    }
    if (length !== undefined && buf.length >= 4 + length) {
      return buf.slice(4, 4 + length);
    }
    const result = await Promise.race([reader.read().catch(() => undefined), deadline]);
    if (result === undefined || result.done || result.value === undefined) {
      return undefined;
    }
    const merged = new Uint8Array(buf.length + result.value.length);
    merged.set(buf, 0);
    merged.set(result.value, buf.length);
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

describe('veilid-wasm WebTransport browser ↔ native interop', () => {
  it('runs in a secure context with WebTransport available', () => {
    expect(window.isSecureContext).toBe(true);
    expect(typeof (window as unknown as { WebTransport?: unknown }).WebTransport).toBe('function');
  });

  it('round-trips a message to a native echo server pinned by certificate hash', async () => {
    const url = `https://127.0.0.1:${ECHO_PORT}/`;
    console.log(`connecting to ${url} with a pinned certificate hash`);
    const wt = new WebTransport(url, {
      serverCertificateHashes: [{ algorithm: 'sha-256', value: ECHO_HASH }],
    });
    await wt.ready;
    try {
      const stream = await wt.createBidirectionalStream();
      const writer = stream.writable.getWriter();
      const reader = stream.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
      const message = new TextEncoder().encode('hello from the browser');
      await writer.write(framed(message));
      const echo = await readFramed(reader, ECHO_READ_MS);
      expect(sameBytes(echo, message)).toBe(true);
    } finally {
      wt.close();
    }
  });
});
