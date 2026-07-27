import { driveContext } from './harness/drive.js';
import { selectedContext, selectedSuiteNames } from './harness/select.js';
import { suitesByName } from './suites/registry.js';
import type { CaseResult } from './harness/types.js';

// One run = one context. The whole selection executes once, in that context, and each case is
// then reported as its own mocha test so the spec reporter shows what actually ran where.
const context = selectedContext();
const suiteNames = selectedSuiteNames();
const suites = suitesByName(suiteNames);

let resultsPromise: Promise<CaseResult[]>;
let results: CaseResult[] | undefined;
let runError: unknown;

async function ensureRun(): Promise<CaseResult[]> {
  if (!results && !runError) {
    try {
      results = await resultsPromise;
    } catch (e) {
      runError = e;
    }
  }
  if (runError) {
    throw runError;
  }
  return results!;
}

describe(`veilid-wasm [${context}]`, () => {
  before('run selected suites in context', () => {
    // Kick the run off once; each case below waits on it and reports its own outcome.
    resultsPromise = driveContext(context, suiteNames);
  });

  for (const suite of suites) {
    describe(suite.name, () => {
      for (const testCase of suite.cases()) {
        it(testCase.name, async function () {
          const all = await ensureRun();
          const result = all.find(
            (r) => r.suite === suite.name && r.name === testCase.name,
          );

          if (!result) {
            throw new Error(`no result reported for ${suite.name}: ${testCase.name}`);
          }
          if (result.skipped) {
            console.log(`SKIPPED [${context}] ${suite.name}: ${result.skipped}`);
            this.skip();
          }
          if (!result.ok) {
            throw new Error(result.error ?? 'case failed');
          }
        });
      }
    });
  }
});
