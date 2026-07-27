import {
  CryptoKind,
  DHTRecordDescriptor,
  KeyPair,
  RecordKey,
  VeilidRoutingContext,
  veilidCrypto,
} from 'veilid-wasm';
import { textEncoder, textDecoder } from '../utils/marshalling-utils.js';
import { waitForOfflineSubkeyWrite } from '../utils/wait-utils.js';
import { dhtRetry } from '../utils/dht-retry.js';
import type { CaseContext, Suite, TestCase } from '../harness/types.js';

const data = '🚀 This example DHT data with unicode a Ā 𐀀 文 🚀';

export const dhtSuite: Suite = {
  name: 'dht',
  requiresNetwork: true,
  cases: (): TestCase[] => {
    const cases: TestCase[] = [];

    // Stands in for the create/delete record hooks the describe block used.
    const withRecord = (
      cryptoKind: CryptoKind,
      body: (c: CaseContext, rc: VeilidRoutingContext, rec: DHTRecordDescriptor) => Promise<void>,
    ) => async (c: CaseContext) => {
      const routingContext = VeilidRoutingContext.create();
      const dhtRecord = await routingContext.createDHTRecord(cryptoKind, {
        DFLT: { oCnt: 1 },
      });
      c.expect(dhtRecord.key).toBeInstanceOf(RecordKey);
      c.expect(dhtRecord.owner).toBeInstanceOf(KeyPair);
      c.expect(dhtRecord.schema).toEqual({ DFLT: { oCnt: 1 } });

      try {
        await body(c, routingContext, dhtRecord);
      } finally {
        await routingContext.deleteDHTRecord(dhtRecord.key);
      }
    };

    for (const cryptoKind of veilidCrypto.VALID_CRYPTO_KINDS) {
      cases.push({
        name: `should set value for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          const setValueRes = await dhtRetry(
            () => rc.setDHTValue(rec.key, 0, textEncoder.encode(data)),
            { label: 'setDHTValue' },
          );
          expect(setValueRes).toBeUndefined();
        }),
      });

      cases.push({
        name: `should get value with force refresh for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          const setValueRes = await dhtRetry(
            () => rc.setDHTValue(rec.key, 0, textEncoder.encode(data)),
            { label: 'setDHTValue' },
          );
          expect(setValueRes).toBeUndefined();

          await waitForOfflineSubkeyWrite(rc, rec.key);

          const getValueRes = await dhtRetry(() => rc.getDHTValue(rec.key, 0, true), {
            label: 'getDHTValue forceRefresh',
          });
          expect(getValueRes?.data).toBeDefined();
          expect(textDecoder.decode(getValueRes?.data)).toBe(data);
          expect(getValueRes?.writer.isEqual((rec.owner as KeyPair).key)).toEqual(true);
          expect(getValueRes?.seq).toBe(0);
        }),
      });

      cases.push({
        name: `should open readonly record for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          await rc.closeDHTRecord(rec.key);

          const readonlyDhtRecord = await dhtRetry(() => rc.openDHTRecord(rec.key), {
            label: 'openDHTRecord readonly',
          });
          expect(readonlyDhtRecord).toBeDefined();

          // No retry: we're asserting the not-writable rejection.
          await expect(
            rc.setDHTValue(rec.key, 0, textEncoder.encode(data)),
          ).rejects.toEqual({ kind: 'Generic', message: 'value is not writable' });
        }),
      });

      cases.push({
        name: `should open writable record for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          await rc.closeDHTRecord(rec.key);

          const writeableDhtRecord = await dhtRetry(
            () => rc.openDHTRecord(rec.key, rec.owner as KeyPair),
            { label: 'openDHTRecord writable' },
          );
          expect(writeableDhtRecord).toBeDefined();

          const setValueRes = await dhtRetry(
            () => rc.setDHTValue(rec.key, 0, textEncoder.encode(`${data}👋`)),
            { label: 'setDHTValue' },
          );
          expect(setValueRes).toBeUndefined();
        }),
      });

      cases.push({
        name: `should open readonly record and specify writer during the set for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          await rc.closeDHTRecord(rec.key);

          const writeableDhtRecord = await dhtRetry(() => rc.openDHTRecord(rec.key), {
            label: 'openDHTRecord',
          });
          expect(writeableDhtRecord).toBeDefined();

          // No retry: we're asserting the not-writable rejection.
          await expect(
            rc.setDHTValue(rec.key, 0, textEncoder.encode(`${data}👋`)),
          ).rejects.toEqual({ kind: 'Generic', message: 'value is not writable' });

          const setValueRes = await dhtRetry(
            () =>
              rc.setDHTValue(rec.key, 0, textEncoder.encode(`${data}👋`), {
                writer: rec.owner as KeyPair,
                allowOffline: undefined,
              }),
            { label: 'setDHTValue with writer' },
          );
          expect(setValueRes).toBeUndefined();
        }),
      });

      cases.push({
        name: `should watch value and cancel watch for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          const setValueRes = await dhtRetry(
            () => rc.setDHTValue(rec.key, 0, textEncoder.encode(data)),
            { label: 'setDHTValue' },
          );
          expect(setValueRes).toBeUndefined();

          const watchValueRes = await dhtRetry(
            () => rc.watchDhtValues(rec.key, [[0, 0]], '0', 0xffffffff),
            { label: 'watchDhtValues' },
          );
          expect(watchValueRes).toEqual(true);

          const cancelValueRes = await dhtRetry(() => rc.cancelDHTWatch(rec.key, []), {
            label: 'cancelDHTWatch',
          });
          expect(cancelValueRes).toEqual(false);
        }),
      });

      cases.push({
        name: `should watch value and cancel watch with default values for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          const setValueRes = await dhtRetry(
            () => rc.setDHTValue(rec.key, 0, textEncoder.encode(data)),
            { label: 'setDHTValue' },
          );
          expect(setValueRes).toBeUndefined();

          const watchValueRes = await dhtRetry(() => rc.watchDhtValues(rec.key), {
            label: 'watchDhtValues default',
          });
          expect(watchValueRes).toEqual(true);

          const cancelValueRes = await dhtRetry(() => rc.cancelDHTWatch(rec.key), {
            label: 'cancelDHTWatch default',
          });
          expect(cancelValueRes).toEqual(false);
        }),
      });

      cases.push({
        name: `should set a value and inspect it for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          const setValueRes = await dhtRetry(
            () => rc.setDHTValue(rec.key, 0, textEncoder.encode(data)),
            { label: 'setDHTValue' },
          );
          expect(setValueRes).toBeUndefined();

          const inspectRes = await dhtRetry(
            () => rc.inspectDHTRecord(rec.key, [[0, 0]], 'Local'),
            { label: 'inspectDHTRecord Local' },
          );
          expect(inspectRes).toBeDefined();
          expect(inspectRes.subkeys).toEqual([[0, 0]]);
          expect(inspectRes.localSeqs).toEqual([0]);
          expect(inspectRes.networkSeqs).toEqual([undefined]);

          await waitForOfflineSubkeyWrite(rc, rec.key);

          const inspectRes2 = await dhtRetry(
            () => rc.inspectDHTRecord(rec.key, [[0, 0]], 'SyncGet'),
            { label: 'inspectDHTRecord SyncGet' },
          );
          expect(inspectRes2).toBeDefined();
          expect(inspectRes2.subkeys).toEqual([[0, 0]]);
          expect(inspectRes2.offlineSubkeys).toEqual([]);
          expect(inspectRes2.localSeqs).toEqual([0]);
          expect(inspectRes2.networkSeqs).toEqual([0]);
        }),
      });

      cases.push({
        name: `should set a value and inspect it with defaults for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          const setValueRes = await dhtRetry(
            () => rc.setDHTValue(rec.key, 0, textEncoder.encode(data)),
            { label: 'setDHTValue' },
          );
          expect(setValueRes).toBeUndefined();

          await waitForOfflineSubkeyWrite(rc, rec.key);

          const inspectRes = await dhtRetry(() => rc.inspectDHTRecord(rec.key), {
            label: 'inspectDHTRecord default',
          });
          expect(inspectRes).toBeDefined();
          expect(inspectRes.offlineSubkeys).toEqual([]);
          expect(inspectRes.localSeqs).toEqual([0]);
          expect(inspectRes.networkSeqs).toEqual([undefined]);
        }),
      });

      cases.push({
        name: `should flush a record and confirm no offline subkeys remain for ${cryptoKind}`,
        run: withRecord(cryptoKind, async ({ expect }, rc, rec) => {
          const setValueRes = await rc.setDHTValue(rec.key, 0, textEncoder.encode(data));
          expect(setValueRes).toBeUndefined();

          // flush with no timeout should wait until writes drain and return true
          expect(await rc.flushDHTRecord(rec.key)).toBe(true);
          // no pending writes, tight timeout should still return true immediately
          expect(await rc.flushDHTRecord(rec.key, 10)).toBe(true);
        }),
      });
    }

    return cases;
  },
};
