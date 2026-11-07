import { expect } from '@wdio/globals';

import init, { veilidClient, VeilidWASMConfig } from 'veilid-wasm';
import { configuredTestEnvironment, type TestEnvironment } from './utils/test-environment.js';
import { veilidCoreStartupConfig } from './utils/veilid-config.js';
import {
  asyncCallWithTimeout,
  getLogTimestamp,
  waitForMs,
  waitForShutdown,
} from './utils/wait-utils.js';

const debugInitConfig: VeilidWASMConfig = {
  logging: {
    api: { enabled: true, level: 'Debug' },
    performance: { enabled: false, level: 'Info', console: { enabled: false } },
  },
};

function requireTestEnvironment(): TestEnvironment {
  const environment = configuredTestEnvironment();
  if (!environment) {
    throw new Error(
      `webtransport-network.test.ts requires TEST_ENVIRONMENT to name an environment file, ` +
        `relative to veilid-wasm/tests or absolute, carrying the network key, the wts:// ` +
        `bootstrap URLs, and the matching bootstrap node keys; ` +
        `veilid-wasm/tests/environments/example.json is the template. There is no default, ` +
        `so this test cannot run without one.`,
    );
  }
  return environment;
}

const TEST_ENVIRONMENT = requireTestEnvironment();

const ATTACH_TIMEOUT_MS = 150_000;

function isAttached(state: string) {
  return !['Detached', 'Detaching', 'Attaching'].includes(state);
}

function webTransportOnlyConfig() {
  const config = veilidCoreStartupConfig();
  config.namespace = 'webtransport-network';

  config.network.protocol.ws.connect = false;
  config.network.protocol.wss!.connect = false;
  config.network.protocol.webtransport!.connect = true;

  return config;
}

describe('veilid-wasm WebTransport', () => {
  before('veilid startup', async () => {
    console.log(`environment: ${TEST_ENVIRONMENT.description ?? '(no description)'}`);
    // The `--target web` build does not instantiate the wasm module on import.
    await init();
    await veilidClient.initializeCore(debugInitConfig);
    await veilidClient.startupCore((_update) => {
      if (_update.kind === 'Log') {
        if (
          /webtransport|wts|wtd|bootstrap|relay|attach|dial_?info|reachab|public_?internet|quic/i.test(
            _update.message ?? '',
          )
        ) {
          console.log(`${getLogTimestamp()}: ${_update.message}`);
        }
      }
    }, webTransportOnlyConfig());
  });

  after('veilid shutdown', async () => {
    await veilidClient.shutdownCore();
    await asyncCallWithTimeout(waitForShutdown(), 10_000);
  });

  it('was built with the WebTransport protocol feature', () => {
    const features = veilidClient.features();
    console.log('veilid-wasm features:', features.join(', '));
    expect(features).toContain('enable-protocol-webtransport');
  });

  it('runs in a browser secure context (required for WebTransport)', () => {
    expect(window.isSecureContext).toBe(true);
    expect(typeof (window as unknown as { WebTransport?: unknown }).WebTransport).toBe('function');
  });

  it('attaches to the configured network over WebTransport (WebTransport-only node)', async () => {
    await veilidClient.attach();

    const start = Date.now();
    let lastState = '';
    let attachedSeen = false;
    let publicReady = false;
    while (Date.now() - start < ATTACH_TIMEOUT_MS) {
      const s = await veilidClient.getState();
      const st = s.attachment.state;
      if (st !== lastState) {
        console.log(
          `${getLogTimestamp()}: attachment=${st} publicInternetReady=${s.attachment.publicInternetReady}`,
        );
        lastState = st;
      }
      if (isAttached(st)) attachedSeen = true;
      if (s.attachment.publicInternetReady && isAttached(st)) {
        publicReady = true;
        break;
      }
      if (attachedSeen && Date.now() - start > 60_000) break;
      await waitForMs(1000);
    }

    console.log(
      `RESULT: attachedSeen=${attachedSeen} publicInternetReady=${publicReady} after ${Math.round(
        (Date.now() - start) / 1000,
      )}s`,
    );

    expect(attachedSeen).toBe(true);

    if (publicReady) {
      console.log('BONUS: node reached publicInternetReady over WebTransport');
    } else {
      console.log(
        'NOTE: publicInternetReady not reached within budget (safety-route allocation needs a pool of route-capable nodes); WebTransport attachment itself succeeded',
      );
    }

    await veilidClient.detach();
    await veilidClient.waitForAttachmentCondition({ optMaxState: 'Detached' }, 20_000);
  });
});
