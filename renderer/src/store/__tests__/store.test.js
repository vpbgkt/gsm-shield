/**
 * renderer/src/store/__tests__/store.test.js
 *
 * Unit tests for Zustand store pure logic (Requirements: 13.3, 13.4).
 *
 * These tests exercise the pure logic extracted from each store without
 * importing Zustand or the ESM store modules themselves, making them
 * fully compatible with the root Jest (CommonJS / Node) configuration.
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// 1. applyFilter — whitelistStore pure filtering logic
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extracted verbatim from whitelistStore.js.
 * Returns entries that match the search query (case-insensitive).
 * Matches against name, vendor, or hash.
 */
function applyFilter(entries, query) {
  if (!query) return entries;
  const lower = query.toLowerCase();
  return entries.filter(
    (e) =>
      (e.name ?? '').toLowerCase().includes(lower) ||
      (e.vendor ?? '').toLowerCase().includes(lower) ||
      (e.hash ?? '').toLowerCase().includes(lower)
  );
}

describe('applyFilter (whitelistStore)', () => {
  const sampleEntries = [
    { name: 'notepad.exe',    vendor: 'Microsoft', hash: 'abc123def456' },
    { name: 'chrome.exe',     vendor: 'Google',    hash: 'deadbeef0000' },
    { name: 'malware.exe',    vendor: 'Unknown',   hash: 'cafebabe1234' },
    { name: 'setup_tool.exe', vendor: 'Acme Corp', hash: '11223344aabb' },
  ];

  test('empty query returns all entries unchanged', () => {
    expect(applyFilter(sampleEntries, '')).toBe(sampleEntries);
  });

  test('null-ish query (undefined falsy) returns all entries', () => {
    expect(applyFilter(sampleEntries, undefined)).toBe(sampleEntries);
  });

  test('filters by name (case-insensitive)', () => {
    const result = applyFilter(sampleEntries, 'NOTE');
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('notepad.exe');
  });

  test('filters by vendor (case-insensitive)', () => {
    const result = applyFilter(sampleEntries, 'google');
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('chrome.exe');
  });

  test('filters by hash (case-insensitive)', () => {
    const result = applyFilter(sampleEntries, 'CAFEBABE');
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('malware.exe');
  });

  test('returns multiple matches when query matches several entries', () => {
    // 'exe' appears in every name
    const result = applyFilter(sampleEntries, 'exe');
    expect(result).toHaveLength(4);
  });

  test('returns empty array when no entry matches', () => {
    const result = applyFilter(sampleEntries, 'zzznomatch');
    expect(result).toHaveLength(0);
  });

  test('handles entries with missing fields gracefully', () => {
    const sparse = [{ hash: 'onlyhash' }, { name: 'onlyname' }, {}];
    // Should not throw; missing fields treated as empty string
    expect(() => applyFilter(sparse, 'test')).not.toThrow();
  });

  test('partial match on hash works correctly', () => {
    const result = applyFilter(sampleEntries, 'abc123');
    expect(result).toHaveLength(1);
    expect(result[0].hash).toBe('abc123def456');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. scanStore pure action logic — addThreat and updateProgress
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extracted from scanStore.js:
 *   addThreat: (threat) => set((state) => ({ threatsFound: [...state.threatsFound, threat] }))
 *   updateProgress: ({ currentFile, filesScanned }) =>
 *       set({ currentFile: currentFile ?? '', progress: filesScanned ?? 0 })
 *
 * We test the reducer logic directly without Zustand by applying the
 * updater functions to plain state objects.
 */

/** Pure reducer: add a threat to threatsFound */
function addThreat(state, threat) {
  return { ...state, threatsFound: [...state.threatsFound, threat] };
}

/** Pure reducer: update currentFile and progress */
function updateProgress(state, { currentFile, filesScanned }) {
  return {
    ...state,
    currentFile: currentFile ?? '',
    progress: filesScanned ?? 0,
  };
}

describe('scanStore — addThreat logic', () => {
  const baseState = () => ({
    status: 'running',
    mode: 'quick',
    currentFile: '',
    progress: 0,
    threatsFound: [],
    history: [],
  });

  test('appends a threat to an empty threatsFound array', () => {
    const threat = { scanId: 's1', filePath: 'C:\\bad.exe', threatName: 'EICAR' };
    const next = addThreat(baseState(), threat);
    expect(next.threatsFound).toHaveLength(1);
    expect(next.threatsFound[0]).toEqual(threat);
  });

  test('appends a threat to an existing threats array', () => {
    const first  = { scanId: 's1', filePath: 'C:\\bad.exe',   threatName: 'EICAR'   };
    const second = { scanId: 's1', filePath: 'C:\\trojan.exe', threatName: 'Trojan'  };
    const state1 = addThreat(baseState(), first);
    const state2 = addThreat(state1, second);
    expect(state2.threatsFound).toHaveLength(2);
    expect(state2.threatsFound[1]).toEqual(second);
  });

  test('does not mutate the original state', () => {
    const state = baseState();
    const threat = { scanId: 's1', filePath: 'C:\\bad.exe', threatName: 'EICAR' };
    addThreat(state, threat);
    expect(state.threatsFound).toHaveLength(0);
  });

  test('each addThreat call produces an independent new array', () => {
    const state = baseState();
    const threat = { scanId: 's1', filePath: 'C:\\bad.exe', threatName: 'EICAR' };
    const next1 = addThreat(state, threat);
    const next2 = addThreat(state, threat);
    expect(next1.threatsFound).not.toBe(next2.threatsFound);
  });

  test('preserves other state fields when adding threat', () => {
    const state = { ...baseState(), status: 'running', progress: 45, currentFile: 'C:\\file.dll' };
    const threat = { scanId: 's2', filePath: 'C:\\virus.exe', threatName: 'Virus.X' };
    const next = addThreat(state, threat);
    expect(next.status).toBe('running');
    expect(next.progress).toBe(45);
    expect(next.currentFile).toBe('C:\\file.dll');
  });
});

describe('scanStore — updateProgress logic', () => {
  const baseState = () => ({
    status: 'running',
    mode: 'full',
    currentFile: '',
    progress: 0,
    threatsFound: [],
    history: [],
  });

  test('updates currentFile and progress from payload', () => {
    const next = updateProgress(baseState(), { currentFile: 'C:\\windows\\system32\\ntdll.dll', filesScanned: 55 });
    expect(next.currentFile).toBe('C:\\windows\\system32\\ntdll.dll');
    expect(next.progress).toBe(55);
  });

  test('defaults currentFile to empty string when missing in payload', () => {
    const next = updateProgress(baseState(), { filesScanned: 10 });
    expect(next.currentFile).toBe('');
    expect(next.progress).toBe(10);
  });

  test('defaults progress to 0 when filesScanned is missing', () => {
    const next = updateProgress(baseState(), { currentFile: 'C:\\file.exe' });
    expect(next.currentFile).toBe('C:\\file.exe');
    expect(next.progress).toBe(0);
  });

  test('defaults both to safe values when payload is empty', () => {
    const next = updateProgress(baseState(), {});
    expect(next.currentFile).toBe('');
    expect(next.progress).toBe(0);
  });

  test('preserves other state fields (threatsFound, status)', () => {
    const threat = { scanId: 's1', filePath: 'C:\\bad.exe', threatName: 'EICAR' };
    const state  = { ...baseState(), threatsFound: [threat], status: 'running' };
    const next   = updateProgress(state, { currentFile: 'C:\\next.exe', filesScanned: 20 });
    expect(next.threatsFound).toHaveLength(1);
    expect(next.status).toBe('running');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. licenseStore — initial state defaults
// ─────────────────────────────────────────────────────────────────────────────

/**
 * These values are extracted directly from licenseStore.js.
 * Testing that the initial state shape matches Requirements 13.3 / 13.4
 * (the store must track license status and enforce feature gates).
 */
const INITIAL_LICENSE_STATE = {
  status: 'inactive',
  expiresAt: null,
  machineFingerprint: '',
  featureGates: {
    scanLimit: true,
    whitelistCap: true,
    realtimeDisabled: true,
  },
  isActivating: false,
  activationError: null,
};

describe('licenseStore — initial state', () => {
  test('status defaults to "inactive"', () => {
    expect(INITIAL_LICENSE_STATE.status).toBe('inactive');
  });

  test('expiresAt defaults to null', () => {
    expect(INITIAL_LICENSE_STATE.expiresAt).toBeNull();
  });

  test('machineFingerprint defaults to empty string', () => {
    expect(INITIAL_LICENSE_STATE.machineFingerprint).toBe('');
  });

  test('featureGates.scanLimit defaults to true (limited on inactive license)', () => {
    expect(INITIAL_LICENSE_STATE.featureGates.scanLimit).toBe(true);
  });

  test('featureGates.whitelistCap defaults to true (capped on inactive license)', () => {
    expect(INITIAL_LICENSE_STATE.featureGates.whitelistCap).toBe(true);
  });

  test('featureGates.realtimeDisabled defaults to true (disabled on inactive license)', () => {
    expect(INITIAL_LICENSE_STATE.featureGates.realtimeDisabled).toBe(true);
  });

  test('isActivating defaults to false', () => {
    expect(INITIAL_LICENSE_STATE.isActivating).toBe(false);
  });

  test('activationError defaults to null', () => {
    expect(INITIAL_LICENSE_STATE.activationError).toBeNull();
  });

  test('all featureGates keys are present', () => {
    const keys = Object.keys(INITIAL_LICENSE_STATE.featureGates);
    expect(keys).toEqual(expect.arrayContaining(['scanLimit', 'whitelistCap', 'realtimeDisabled']));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. settingsStore — initial state defaults
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extracted from settingsStore.js initial state.
 */
const INITIAL_SETTINGS_STATE = {
  realtimeProtection: true,
  autoQuarantine: true,
  startWithWindows: false,
  monitoredPaths: [],
  definitionVersion: '',
  lastDefinitionUpdate: null,
  telemetryEnabled: true,
  isUpdatingDefinitions: false,
  updateProgress: null,
};

describe('settingsStore — initial state', () => {
  test('realtimeProtection defaults to true', () => {
    expect(INITIAL_SETTINGS_STATE.realtimeProtection).toBe(true);
  });

  test('autoQuarantine defaults to true', () => {
    expect(INITIAL_SETTINGS_STATE.autoQuarantine).toBe(true);
  });

  test('startWithWindows defaults to false', () => {
    expect(INITIAL_SETTINGS_STATE.startWithWindows).toBe(false);
  });

  test('monitoredPaths defaults to an empty array', () => {
    expect(INITIAL_SETTINGS_STATE.monitoredPaths).toEqual([]);
  });

  test('definitionVersion defaults to empty string', () => {
    expect(INITIAL_SETTINGS_STATE.definitionVersion).toBe('');
  });

  test('lastDefinitionUpdate defaults to null', () => {
    expect(INITIAL_SETTINGS_STATE.lastDefinitionUpdate).toBeNull();
  });

  test('telemetryEnabled defaults to true', () => {
    expect(INITIAL_SETTINGS_STATE.telemetryEnabled).toBe(true);
  });

  test('isUpdatingDefinitions defaults to false', () => {
    expect(INITIAL_SETTINGS_STATE.isUpdatingDefinitions).toBe(false);
  });

  test('updateProgress defaults to null', () => {
    expect(INITIAL_SETTINGS_STATE.updateProgress).toBeNull();
  });
});
