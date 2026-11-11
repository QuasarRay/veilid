const BOOTSTRAP_PROTOCOLS = ['UDP', 'TCP', 'WS', 'WSS', 'WTS'] as const;
export type BootstrapProtocol = (typeof BOOTSTRAP_PROTOCOLS)[number];

export interface TestEnvironment {
  description?: string;
  networkKey?: string;
  bootstrap?: string[];
  bootstrapProtocols?: BootstrapProtocol[];
  bootstrapKeys?: string[];
}

export const TEST_ENVIRONMENT_VAR = 'VEILID_TEST_ENVIRONMENT';

const KNOWN_FIELDS = [
  'description',
  'networkKey',
  'bootstrap',
  'bootstrapProtocols',
  'bootstrapKeys',
];

// `process` is undefined in worker/service-worker bundles; fall back to an empty env there.
const env: Record<string, string | undefined> =
  typeof process !== 'undefined' && process.env ? process.env : {};

function asString(value: unknown, field: string, source: string): string {
  if (typeof value !== 'string') {
    throw new Error(`${source}: "${field}" must be a string`);
  }
  return value;
}

function asStringArray(value: unknown, field: string, source: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`${source}: "${field}" must be an array of strings`);
  }
  return value as string[];
}

export function parseTestEnvironment(text: string, source: string): TestEnvironment {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`${source}: not valid JSON (${e instanceof Error ? e.message : String(e)})`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${source}: must hold a JSON object`);
  }

  const fields = parsed as Record<string, unknown>;
  const unknown = Object.keys(fields).filter((name) => !KNOWN_FIELDS.includes(name));
  if (unknown.length > 0) {
    throw new Error(
      `${source}: unknown field(s) ${unknown.join(', ')}. The fields are ${KNOWN_FIELDS.join(', ')}`,
    );
  }

  const environment: TestEnvironment = {};
  if (fields.description !== undefined) {
    environment.description = asString(fields.description, 'description', source);
  }
  if (fields.networkKey !== undefined) {
    environment.networkKey = asString(fields.networkKey, 'networkKey', source);
  }
  if (fields.bootstrap !== undefined) {
    environment.bootstrap = asStringArray(fields.bootstrap, 'bootstrap', source);
  }
  if (fields.bootstrapProtocols !== undefined) {
    const protocols = asStringArray(fields.bootstrapProtocols, 'bootstrapProtocols', source);
    const unknownProtocols = protocols.filter(
      (protocol) => !(BOOTSTRAP_PROTOCOLS as readonly string[]).includes(protocol),
    );
    if (unknownProtocols.length > 0) {
      throw new Error(
        `${source}: "bootstrapProtocols" holds ${unknownProtocols.join(', ')}. The protocols are ${BOOTSTRAP_PROTOCOLS.join(', ')}`,
      );
    }
    environment.bootstrapProtocols = protocols as BootstrapProtocol[];
  }
  if (fields.bootstrapKeys !== undefined) {
    environment.bootstrapKeys = asStringArray(fields.bootstrapKeys, 'bootstrapKeys', source);
  }
  return environment;
}

export function configuredTestEnvironment(): TestEnvironment | undefined {
  const published = env[TEST_ENVIRONMENT_VAR];
  return published ? parseTestEnvironment(published, TEST_ENVIRONMENT_VAR) : undefined;
}
