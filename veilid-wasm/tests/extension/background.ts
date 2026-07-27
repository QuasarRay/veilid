// MV3 background service worker. Same constraints as a page service worker: static imports only
// (dynamic import is disallowed) and no top-level await, so this bundle is built ahead of time
// with vite-plugin-top-level-await.
//
// In this context veilid-core's runtime detection sees chrome.runtime.id and selects the
// extension-storage ProtectedStore backend (chrome.storage.local), not localStorage/IndexedDB.
import { runSuites } from '../src/harness/run-suites.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const chrome: any;

chrome.runtime.onMessageExternal.addListener(
  (
    message: { type?: string; suites?: string[] },
    _sender: unknown,
    sendResponse: (r: unknown) => void,
  ) => {
    if (message?.type === 'ping') {
      sendResponse({ type: 'pong' });
      return false;
    }
    if (message?.type !== 'run') {
      return false;
    }
    (async () => {
      try {
        const results = await runSuites(message.suites ?? [], 'extension');
        sendResponse({ type: 'done', ok: true, results });
      } catch (err) {
        sendResponse({ type: 'done', ok: false, error: String(err) });
      }
    })();
    // Keep the message channel open for the async response.
    return true;
  },
);
