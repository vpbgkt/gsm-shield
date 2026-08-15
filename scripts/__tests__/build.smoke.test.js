'use strict';

/**
 * Build pipeline smoke tests
 * Validates Requirements 23.1, 23.2, 23.3
 *
 * These tests verify the build pipeline logic without actually running
 * Vite, electron-builder, or Inno Setup.
 */

const path = require('path');
const fs = require('fs');

const ROOT_DIR = path.resolve(__dirname, '..', '..');
const SCRIPTS_DIR = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. scripts/build.js can be required without error
// ---------------------------------------------------------------------------
describe('scripts/build.js module', () => {
  let buildModule;

  test('can be required without throwing', () => {
    expect(() => {
      buildModule = require(path.join(SCRIPTS_DIR, 'build.js'));
    }).not.toThrow();
  });

  // ---------------------------------------------------------------------------
  // 2. Exports stage1, stage2, stage3, isOnPath as functions
  // ---------------------------------------------------------------------------
  test('exports stage1 as a function', () => {
    const mod = require(path.join(SCRIPTS_DIR, 'build.js'));
    expect(typeof mod.stage1).toBe('function');
  });

  test('exports stage2 as a function', () => {
    const mod = require(path.join(SCRIPTS_DIR, 'build.js'));
    expect(typeof mod.stage2).toBe('function');
  });

  test('exports stage3 as a function', () => {
    const mod = require(path.join(SCRIPTS_DIR, 'build.js'));
    expect(typeof mod.stage3).toBe('function');
  });

  test('exports isOnPath as a function', () => {
    const mod = require(path.join(SCRIPTS_DIR, 'build.js'));
    expect(typeof mod.isOnPath).toBe('function');
  });
});

// ---------------------------------------------------------------------------
// 3. isOnPath('node') returns true — Node.js is always available
// ---------------------------------------------------------------------------
describe('isOnPath()', () => {
  let isOnPath;

  beforeAll(() => {
    ({ isOnPath } = require(path.join(SCRIPTS_DIR, 'build.js')));
  });

  test("isOnPath('node') returns true", () => {
    expect(isOnPath('node')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 4. isOnPath('nonexistent-binary-xyz') returns false
  // ---------------------------------------------------------------------------
  test("isOnPath('nonexistent-binary-xyz') returns false", () => {
    expect(isOnPath('nonexistent-binary-xyz')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 5. stage3 skips gracefully (no process.exit) when iscc is not on PATH
// ---------------------------------------------------------------------------
describe('stage3() graceful skip', () => {
  test('does not throw and does not call process.exit when iscc is absent', () => {
    // Isolate the module so we can inject a patched isOnPath
    jest.resetModules();

    const buildPath = path.join(SCRIPTS_DIR, 'build.js');

    // Patch child_process.spawnSync so that `where iscc` / `which iscc` reports not-found
    jest.mock('child_process', () => {
      const actual = jest.requireActual('child_process');
      return {
        ...actual,
        spawnSync: (cmd, args, opts) => {
          // Simulate "iscc not found" for the PATH probe
          const isBinaryProbe = (cmd === 'where' || cmd === 'which');
          if (isBinaryProbe && args && args[0] === 'iscc') {
            return { status: 1, stdout: '', stderr: '' };
          }
          return actual.spawnSync(cmd, args, opts);
        },
      };
    });

    const { stage3 } = require(buildPath);

    const exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit must NOT be called when iscc is absent');
    });

    try {
      expect(() => stage3()).not.toThrow();
    } finally {
      exitSpy.mockRestore();
      jest.resetModules();
      jest.unmock('child_process');
    }
  });
});

// ---------------------------------------------------------------------------
// 6. package.json contains all four expected build scripts
// ---------------------------------------------------------------------------
describe('package.json build scripts', () => {
  let scripts;

  beforeAll(() => {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(ROOT_DIR, 'package.json'), 'utf8')
    );
    scripts = pkg.scripts || {};
  });

  const expectedScripts = ['build:full', 'build:stage1', 'build:stage2', 'build:stage3'];

  test.each(expectedScripts)('contains script "%s"', (scriptName) => {
    expect(scripts).toHaveProperty(scriptName);
  });
});

// ---------------------------------------------------------------------------
// 7. electron-builder.yml exists and contains appId: com.gsmshield.av
// ---------------------------------------------------------------------------
describe('electron-builder.yml', () => {
  const ymlPath = path.join(ROOT_DIR, 'electron-builder.yml');

  test('file exists', () => {
    expect(fs.existsSync(ymlPath)).toBe(true);
  });

  test('contains appId: com.gsmshield.av', () => {
    const content = fs.readFileSync(ymlPath, 'utf8');
    expect(content).toMatch(/appId:\s*com\.gsmshield\.av/);
  });
});

// ---------------------------------------------------------------------------
// 8. installer/setup.iss exists and contains PrivilegesRequired=admin
// ---------------------------------------------------------------------------
describe('installer/setup.iss', () => {
  const issPath = path.join(ROOT_DIR, 'installer', 'setup.iss');

  test('file exists', () => {
    expect(fs.existsSync(issPath)).toBe(true);
  });

  test('contains PrivilegesRequired=admin', () => {
    const content = fs.readFileSync(issPath, 'utf8');
    expect(content).toMatch(/PrivilegesRequired\s*=\s*admin/);
  });
});

// ---------------------------------------------------------------------------
// 9. installer/license.txt exists
// ---------------------------------------------------------------------------
describe('installer/license.txt', () => {
  test('file exists', () => {
    const licensePath = path.join(ROOT_DIR, 'installer', 'license.txt');
    expect(fs.existsSync(licensePath)).toBe(true);
  });
});
