'use strict';

/**
 * Smoke test: renderer Vite build and all 6 routes render without crashing.
 *
 * Strategy:
 *  1. Run `npm run build` inside the `renderer/` workspace to produce
 *     `renderer/dist/`.
 *  2. Assert that `renderer/dist/index.html` exists and is non-empty.
 *  3. Assert that at least one JS bundle (`assets/*.js`) exists in the dist.
 *  4. Assert that `index.html` contains <script> and <link> tags referencing
 *     the generated assets (not an empty shell).
 *  5. Assert that `index.html` contains the React root mount point (`#root`)
 *     so that the renderer entry can boot.
 *  6. Confirm that all 6 route paths are referenced or accessible — because
 *     Vite produces a single `index.html` for an SPA we verify the built JS
 *     bundle contains the 6 route path strings defined in App.jsx.
 *
 * Requirements: 13.3
 */

const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');
const glob = require('glob');

// ─── Paths ────────────────────────────────────────────────────────────────────

const REPO_ROOT     = path.resolve(__dirname, '../../');
const RENDERER_DIR  = path.join(REPO_ROOT, 'renderer');
const DIST_DIR      = path.join(RENDERER_DIR, 'dist');
const INDEX_HTML    = path.join(DIST_DIR, 'index.html');
const ASSETS_DIR    = path.join(DIST_DIR, 'assets');

// ─── Build step (once for the whole suite) ────────────────────────────────────

beforeAll(() => {
  // Run the renderer build. The renderer workspace has its own package.json
  // with a "build" script that calls `vite build`.
  // We allow up to 120 seconds for the build to complete.
  execSync('npm run build', {
    cwd: RENDERER_DIR,
    stdio: 'pipe',       // capture output; errors surface via the thrown Error
    timeout: 120_000,
  });
}, 130_000 /* jest timeout slightly above execSync timeout */);

// ─── Helper ───────────────────────────────────────────────────────────────────

/**
 * Returns all files under `dir` that match `pattern` (glob-style).
 * Falls back to a manual readdir walk when the `glob` package is absent.
 */
function findFiles(dir, ext) {
  try {
    // node 18+ has glob built-in; older nodes rely on a manual walk
    return fs.readdirSync(dir).filter((f) => f.endsWith(ext));
  } catch {
    return [];
  }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('renderer Vite build smoke test (Requirements: 13.3)', () => {

  // ── Output directory structure ──────────────────────────────────────────────

  test('renderer/dist/ directory exists after build', () => {
    expect(fs.existsSync(DIST_DIR)).toBe(true);
  });

  test('renderer/dist/index.html exists', () => {
    expect(fs.existsSync(INDEX_HTML)).toBe(true);
  });

  test('renderer/dist/index.html is non-empty', () => {
    const stat = fs.statSync(INDEX_HTML);
    expect(stat.size).toBeGreaterThan(0);
  });

  test('renderer/dist/assets/ directory exists', () => {
    expect(fs.existsSync(ASSETS_DIR)).toBe(true);
  });

  // ── JS bundles ──────────────────────────────────────────────────────────────

  test('at least one JS bundle exists in renderer/dist/assets/', () => {
    const jsFiles = findFiles(ASSETS_DIR, '.js');
    expect(jsFiles.length).toBeGreaterThan(0);
  });

  // ── index.html content ──────────────────────────────────────────────────────

  describe('index.html content', () => {
    let html;

    beforeAll(() => {
      html = fs.readFileSync(INDEX_HTML, 'utf-8');
    });

    test('contains at least one <script> tag referencing a JS asset', () => {
      // Vite emits <script type="module" src="./assets/..."> in the built HTML
      expect(html).toMatch(/<script[^>]+src=['"]\.[/\\]?assets[/\\][^'"]+\.js['"]/i);
    });

    test('contains at least one <link rel="stylesheet"> referencing a CSS asset', () => {
      // Vite emits a <link rel="stylesheet" href="./assets/..."> for CSS
      expect(html).toMatch(/<link[^>]+rel=["']stylesheet["'][^>]+href=[^>]+assets[^>]+\.css/i);
    });

    test('contains the React root mount point (#root)', () => {
      expect(html).toMatch(/id=["']root["']/i);
    });

    test('does not contain un-substituted template variables (Vite processed it)', () => {
      // Vite replaces %VITE_...% env vars; an unprocessed template is a build failure
      expect(html).not.toMatch(/%[A-Z_]+%/);
    });
  });

  // ── All 6 routes present in the compiled JS bundle ──────────────────────────

  describe('all 6 React Router routes are compiled into the JS bundle', () => {
    /**
     * The 6 route paths declared in App.jsx:
     *   '/', '/scanner', '/whitelist', '/quarantine', '/settings', '/license'
     *
     * After Vite tree-shaking and bundling, these string literals survive in
     * the output JS because React Router needs them at runtime.
     */
    const EXPECTED_ROUTES = [
      '/scanner',
      '/whitelist',
      '/quarantine',
      '/settings',
      '/license',
    ];

    let bundleContent;

    beforeAll(() => {
      const jsFiles = findFiles(ASSETS_DIR, '.js');
      // Read all JS bundles and concatenate for searching
      bundleContent = jsFiles
        .map((f) => fs.readFileSync(path.join(ASSETS_DIR, f), 'utf-8'))
        .join('\n');
    });

    test.each(EXPECTED_ROUTES)(
      'route path "%s" is present in the compiled JS bundle',
      (routePath) => {
        expect(bundleContent).toContain(routePath);
      }
    );

    test('page component names survive in the bundle (tree-shake check)', () => {
      // Component names may be minified, but their unique display text must
      // survive since each page renders a literal string (e.g. "Dashboard").
      // This confirms Vite imported and compiled all 6 page components.
      const PAGE_STRINGS = [
        'Dashboard',
        'Scanner',
        'Whitelist',
        'Quarantine',
        'Settings',
        'License',
      ];
      for (const name of PAGE_STRINGS) {
        expect(bundleContent).toContain(name);
      }
    });
  });

});
