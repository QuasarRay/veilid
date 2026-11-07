// The bootstraps are IP literals rather than the staging hostname because wasm has no DNS
// resolver: the browser resolves a hostname `wts://` itself, and Firefox before 154 has no
// WebTransport Happy-Eyeballs, so it picks IPv6 first and stalls on networks that blackhole
// IPv6-UDP. The staging bootstrap serves a matching IP-SAN Let's Encrypt certificate per family,
// so an IP-literal dial still validates against the system roots.

// The wasm-bindgen web-target package does not instantiate the module on import: the default
// export is an `init()` that must be awaited before any `veilidClient` call.
import init, { veilidClient, type VeilidWASMConfig } from 'veilid-wasm';

function requireStagingEnv(): {
  networkKey: string;
  bootstrap: string[];
  bootstrapKeys: string[];
} {
  const required = {
    VITE_NETWORK_KEY: import.meta.env.VITE_NETWORK_KEY,
    VITE_BOOTSTRAP: import.meta.env.VITE_BOOTSTRAP,
    VITE_BOOTSTRAP_KEYS: import.meta.env.VITE_BOOTSTRAP_KEYS,
  };
  const missing = Object.entries(required)
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(
      `missing environment variable(s) ${missing.join(', ')}. VITE_NETWORK_KEY, VITE_BOOTSTRAP, ` +
        `and VITE_BOOTSTRAP_KEYS must carry the staging network's WebTransport bootstrap ` +
        `configuration (the network key, a comma-separated list of wts:// bootstrap URLs, and a ` +
        `comma-separated list of the matching bootstrap node keys); set them before running the ` +
        `dev server, e.g. in an untracked .env.local file (see README.md).`,
    );
  }
  return {
    networkKey: required.VITE_NETWORK_KEY!,
    bootstrap: required.VITE_BOOTSTRAP!.split(','),
    bootstrapKeys: required.VITE_BOOTSTRAP_KEYS!.split(','),
  };
}

const $ = (id: string) => document.getElementById(id)!;
function set(id: string, text: string, cls?: 'ok' | 'bad' | 'pending') {
  const el = $(id);
  el.textContent = text;
  el.className = 'v' + (cls ? ' ' + cls : '');
}

const logEl = $('log');
function log(line: string) {
  logEl.textContent += line + '\n';
  logEl.scrollTop = logEl.scrollHeight;
}

const initConfig: VeilidWASMConfig = {
  logging: {
    api: { enabled: true, level: 'Info' },
    performance: { enabled: false, level: 'Info', console: { enabled: false } },
  },
};

function stagingWebTransportConfig(
  networkKey: string,
  bootstrap: string[],
  bootstrapKeys: string[],
) {
  const config = veilidClient.defaultConfig();
  config.programName = 'veilid-wasm-webtransport-bench';
  config.namespace = 'wt-staging-bench';
  config.network.networkKeyPassword = networkKey;
  config.network.routingTable.bootstrap = bootstrap;
  config.network.routingTable.bootstrapKeys = bootstrapKeys;
  config.network.protocol.ws.connect = false;
  config.network.protocol.wss!.connect = false;
  config.network.protocol.webtransport!.connect = true;
  config.tableStore.delete = true;
  config.protectedStore.delete = true;
  config.blockStore.delete = true;
  return config;
}

async function main() {
  const { networkKey, bootstrap, bootstrapKeys } = requireStagingEnv();

  set('secure', window.isSecureContext ? 'yes' : 'no', window.isSecureContext ? 'ok' : 'bad');
  const hasWT =
    typeof (window as unknown as { WebTransport?: unknown }).WebTransport === 'function';
  set('wtapi', hasWT ? 'available' : 'missing', hasWT ? 'ok' : 'bad');
  set('bootstrap', bootstrap.join(', '));
  set('booted', 'waiting…', 'pending');
  set('attach', 'loading wasm…', 'pending');
  set('public', '—', 'pending');
  set('relay', '—');

  await init();

  const features = veilidClient.features();
  const hasFeature = features.includes('enable-protocol-webtransport');
  set('feature', hasFeature ? 'yes' : 'NO, rebuild with the feature', hasFeature ? 'ok' : 'bad');
  log(`veilid ${veilidClient.versionString()} features: ${features.join(', ')}`);

  await veilidClient.initializeCore(initConfig);
  await veilidClient.startupCore(
    (update) => {
      if (update.kind === 'Log') {
        const msg = update.message ?? '';
        if (/Direct bootstrap with: wts/i.test(msg)) set('booted', 'yes ✓', 'ok');
        if (/relays changed: \[\] ->/i.test(msg))
          set('relay', msg.split('->')[1]?.trim() ?? 'set', 'ok');
        if (/webtransport|wts|wtd|bootstrap|relay|attach|public_?internet/i.test(msg)) {
          log(msg);
        }
      }
    },
    stagingWebTransportConfig(networkKey, bootstrap, bootstrapKeys),
  );

  set('attach', 'attaching…', 'pending');
  await veilidClient.attach();

  for (;;) {
    const s = await veilidClient.getState();
    const st = s.attachment.state;
    const attached = !['Detached', 'Detaching', 'Attaching'].includes(st);
    set('attach', st, attached ? 'ok' : 'pending');
    set(
      'public',
      String(s.attachment.publicInternetReady),
      s.attachment.publicInternetReady ? 'ok' : 'pending',
    );
    await new Promise((r) => setTimeout(r, 1000));
  }
}

main().catch((e) => {
  log('ERROR: ' + (e?.stack ?? e));
  set('attach', 'error', 'bad');
});
