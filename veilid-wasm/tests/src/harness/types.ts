import type { expect } from './expect.js';

// What a test case is handed. Suites import veilid-wasm directly; only a worker *entry* module
// must avoid a static import of it (that hangs wasm instantiation in vite-bundled workers), so
// entries pull this graph in dynamically.
export interface CaseContext {
  expect: typeof expect;
  context: ContextName;
}

export interface TestCase {
  name: string;
  // Needs an attached node. Defaults to the suite's setting.
  requiresNetwork?: boolean;
  // Why this build or context cannot run the case; reported as skipped.
  skipReason?: (context: ContextName) => string | undefined;
  run: (c: CaseContext) => Promise<void> | void;
}

export interface Suite {
  name: string;
  // Default for this suite's cases.
  requiresNetwork?: boolean;
  cases: () => TestCase[];
}

export type ContextName = 'window' | 'dedicated' | 'shared' | 'service' | 'extension';

export const ALL_CONTEXTS: ContextName[] = [
  'window',
  'dedicated',
  'shared',
  'service',
  'extension',
];

// Contexts with no usable WebSocket, so no attached node.
const NO_NETWORK_CONTEXTS: ContextName[] = ['service', 'extension'];

export function contextSupportsNetwork(context: ContextName): boolean {
  return !NO_NETWORK_CONTEXTS.includes(context);
}

export const NETWORK_SKIP_NOTICE =
  'needs an attached node, and this context has no usable WebSocket. ' +
  'These require a secure context and will be enabled when WebTransport support lands.';

export function caseSelected(c: TestCase, caseFilter?: string): boolean {
  return caseFilter === undefined || c.name.includes(caseFilter);
}

export function caseRequiresNetwork(suite: Suite, c: TestCase): boolean {
  return c.requiresNetwork ?? suite.requiresNetwork ?? false;
}

export interface CaseResult {
  suite: string;
  name: string;
  ok: boolean;
  skipped?: string;
  error?: string;
}
