'use strict';

/**
 * electron/first-run.preservation.property.test.js
 *
 * PRESERVATION property tests (design Property 3) — written BEFORE the fix.
 *
 * **METHODOLOGY**: Observation-first. Each property below encodes the CURRENT
 * (unfixed) behavior of the orchestrator `electron/first-run.js` so the tests
 * PASS on unfixed code and act as a regression guard after the fix lands.
 *
 * The PowerShell runner (`defender/ps-runner.js`) and the shared database
 * singleton (`../database`) are MOCKED so nothing real executes and no host
 * Defender / registry state is touched.
 *
 * Preservation requirements (bugfix.md "Unchanged Behavior"):
 *   3.1 uninstall/restore path is NOT touched by first-run setup.
 *   3.2 setup CONTINUES to perform best-effort WSC registration (register-wsc.ps1).
 *   3.4 first-run completion bookkeeping: mark first_run_complete='1',
 *       push defender:setup-result, support manual re-trigger via defender:runSetup.
 *   3.5 already-completed installs skip the disable/consent steps on later launches.
 *
 * **NOTE on the consent gate (3.5 / design note)**: the consent gate does NOT
 * exist on unfixed code. These tests therefore capture the ACTUAL observed gating
 * — which is driven solely by `first_run_complete` via `isFirstRun()` — and
 * deliberately do NOT assert any future consent behavior that would fail now.
 *
 * **Validates: Requirements 3.1, 3.2, 3.4, 3.5**
 */

// ── Mock the PowerShell runner so nothing real executes ─────────────────────────
jest.mock('../defender/ps-runner', () => ({
  runScript: jest.fn(),
}));

// ── Mock the database singleton so first_run_complete is fully controllable ─────
const mockDbStore = {};
jest.mock('../database', () => ({
  getDb: jest.fn(() => ({
    prepare: (sql) => {
      if (/SELECT value FROM settings WHERE key/.test(sql)) {
        return {
          get: (key) =>
            mockDbStore[key] !== undefined ? { value: mockDbStore[key] } : undefined,
        };
      }
      if (/UPDATE settings SET value/.test(sql)) {
        return {
          run: (value, key) => {
            mockDbStore[key] = value;
          },
        };
      }
      return { get: () => undefined, run: () => {} };
    },
  })),
}), { virtual: true });

const fc = require('fast-check');
const { runScript } = require('../defender/ps-runner');
const firstRun = require('./first-run');

// ── Helpers ─────────────────────────────────────────────────────────────────

function scriptWasInvoked(needle) {
  return runScript.mock.calls.some((call) => String(call[0]).includes(needle));
}

function resetDbStore(next = {}) {
  Object.keys(mockDbStore).forEach((k) => delete mockDbStore[k]);
  Object.assign(mockDbStore, next);
}

function makeCapturingWindow() {
  const captured = { payload: null, channel: null };
  return {
    win: {
      isDestroyed: () => false,
      webContents: {
        send: (channel, payload) => {
          captured.channel = channel;
          captured.payload = payload;
        },
      },
    },
    captured,
  };
}

beforeEach(() => {
  runScript.mockReset();
  runScript.mockResolvedValue({ exitCode: 0, stdout: 'OK', stderr: '' });
  resetDbStore();
});

// ─────────────────────────────────────────────────────────────────────────────

describe('Preservation: first-run skip gating (Requirement 3.5)', () => {
  /**
   * Observed baseline: `isFirstRun()` returns false ONLY when
   * first_run_complete === '1'. The consent value is IGNORED on unfixed code.
   * This is the gate main.js uses to decide whether to run setup.
   */
  it('PRESERVE 3.5: isFirstRun() reflects ONLY first_run_complete (consent ignored on unfixed code)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          first_run_complete: fc.constantFrom('1', '0', '', undefined),
          defender_consent: fc.constantFrom('1', '0', '', undefined),
        }),
        async (settings) => {
          const next = {};
          if (settings.first_run_complete !== undefined) next.first_run_complete = settings.first_run_complete;
          if (settings.defender_consent !== undefined) next.defender_consent = settings.defender_consent;
          resetDbStore(next);

          const result = await firstRun.isFirstRun();

          // Observed model: setup is skipped iff first_run_complete === '1',
          // regardless of the (non-existent) consent gate.
          const expectedFirstRun = settings.first_run_complete !== '1';
          expect(result).toBe(expectedFirstRun);
        }
      ),
      { numRuns: 40 }
    );
  });

  it('PRESERVE 3.5: completed install (first_run_complete=1) is treated as NOT first run', () => {
    // Observed: isFirstRun() is synchronous and returns a boolean.
    resetDbStore({ first_run_complete: '1' });
    expect(firstRun.isFirstRun()).toBe(false);
  });

  it('PRESERVE 3.5: fresh install (no first_run_complete) is treated as first run', () => {
    resetDbStore({});
    expect(firstRun.isFirstRun()).toBe(true);
  });
});

describe('Preservation: setup step composition — WSC kept, restore untouched (Requirements 3.1, 3.2)', () => {
  /**
   * Observed baseline: runFirstRunSetup runs disable-defender.ps1 then
   * register-wsc.ps1, and NEVER touches restore-defender.ps1 (restore is
   * uninstall-only). This holds for any step exit codes the runner returns.
   */
  it('PRESERVE 3.2: register-wsc.ps1 is always invoked by first-run setup', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        async (disableExit, wscExit) => {
          runScript.mockReset();
          // Return per-call exit codes for the two ordered steps.
          runScript
            .mockResolvedValueOnce({ exitCode: disableExit, stdout: 'disable', stderr: '' })
            .mockResolvedValueOnce({ exitCode: wscExit, stdout: 'wsc', stderr: '' });

          await firstRun.runFirstRunSetup(null);

          // WSC registration step is preserved regardless of the disable outcome.
          expect(scriptWasInvoked('register-wsc.ps1')).toBe(true);
        }
      ),
      { numRuns: 20 }
    );
  });

  it('PRESERVE 3.1: first-run setup NEVER invokes restore-defender.ps1', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: -1, max: 255 }),
        async (exitCode) => {
          runScript.mockReset();
          runScript.mockResolvedValue({ exitCode, stdout: '', stderr: '' });

          await firstRun.runFirstRunSetup(null);

          // Restore is uninstall-only — the setup path must not reverse Defender.
          expect(scriptWasInvoked('restore-defender.ps1')).toBe(false);
        }
      ),
      { numRuns: 15 }
    );
  });

  it('PRESERVE 3.2: setup invokes disable-defender before register-wsc (observed order)', async () => {
    await firstRun.runFirstRunSetup(null);
    const disableIdx = runScript.mock.calls.findIndex((c) => String(c[0]).includes('disable-defender.ps1'));
    const wscIdx = runScript.mock.calls.findIndex((c) => String(c[0]).includes('register-wsc.ps1'));
    expect(disableIdx).toBeGreaterThanOrEqual(0);
    expect(wscIdx).toBeGreaterThan(disableIdx);
  });
});

describe('Preservation: first-run bookkeeping and IPC (Requirement 3.4)', () => {
  /**
   * Observed baseline: after running setup, first_run_complete is set to '1'
   * and a defender:setup-result payload is pushed to the renderer. This holds
   * for any combination of per-step exit codes.
   */
  it('PRESERVE 3.4: setup sets first_run_complete=1 and pushes defender:setup-result for any step outcomes', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        async (disableExit, wscExit) => {
          runScript.mockReset();
          runScript
            .mockResolvedValueOnce({ exitCode: disableExit, stdout: 'disable', stderr: '' })
            .mockResolvedValueOnce({ exitCode: wscExit, stdout: 'wsc', stderr: '' });
          resetDbStore({});

          const { win, captured } = makeCapturingWindow();
          await firstRun.runFirstRunSetup(win);

          // Bookkeeping: completion flag written.
          expect(mockDbStore.first_run_complete).toBe('1');

          // IPC: setup-result pushed with the observed payload shape.
          expect(captured.channel).toBe('defender:setup-result');
          expect(captured.payload).toBeDefined();
          expect(captured.payload).toHaveProperty('success');
          expect(Array.isArray(captured.payload.steps)).toBe(true);
          expect(captured.payload.steps.length).toBe(2);
          expect(captured.payload).toHaveProperty('failureCount');

          // Observed success classification: true iff BOTH steps exited 0.
          const expectedSuccess = disableExit === 0 && wscExit === 0;
          expect(captured.payload.success).toBe(expectedSuccess);
        }
      ),
      { numRuns: 25 }
    );
  });

  it('PRESERVE 3.4: defender:runSetup IPC handler re-runs setup and reports started', async () => {
    // Emulate the minimal ipcMain contract used by first-run.register().
    const handlers = new Map();
    const ipcMain = { handle: (channel, fn) => handlers.set(channel, fn) };
    const { win, captured } = makeCapturingWindow();

    firstRun.register(ipcMain, { getMainWindow: () => win });

    expect(handlers.has('defender:runSetup')).toBe(true);

    resetDbStore({}); // simulate a manual re-trigger
    const ret = await handlers.get('defender:runSetup')();

    // Handler acknowledges start and setup actually ran.
    expect(ret).toEqual({ started: true });
    expect(scriptWasInvoked('disable-defender.ps1')).toBe(true);
    expect(scriptWasInvoked('register-wsc.ps1')).toBe(true);
    // Bookkeeping + IPC preserved on re-trigger.
    expect(mockDbStore.first_run_complete).toBe('1');
    expect(captured.channel).toBe('defender:setup-result');
  });

  it('PRESERVE 3.4: re-trigger sets first_run_complete=1 across arbitrary prior states', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('1', '0', '', undefined),
        async (prior) => {
          runScript.mockReset();
          runScript.mockResolvedValue({ exitCode: 0, stdout: 'OK', stderr: '' });
          resetDbStore(prior === undefined ? {} : { first_run_complete: prior });

          const handlers = new Map();
          const ipcMain = { handle: (channel, fn) => handlers.set(channel, fn) };
          firstRun.register(ipcMain, { getMainWindow: () => null });

          await handlers.get('defender:runSetup')();

          // Re-trigger always completes bookkeeping regardless of prior state.
          expect(mockDbStore.first_run_complete).toBe('1');
        }
      ),
      { numRuns: 12 }
    );
  });
});
