import React from 'react';
import { HashRouter as Router, Routes, Route } from 'react-router-dom';

import Sidebar from './components/Sidebar.jsx';
import TitleBar from './components/TitleBar.jsx';
import DefenderConsentDialog from './components/DefenderConsentDialog.jsx';

import Dashboard  from './pages/Dashboard.jsx';
import Scanner    from './pages/Scanner.jsx';
import Whitelist  from './pages/Whitelist.jsx';
import Quarantine from './pages/Quarantine.jsx';
import Settings   from './pages/Settings.jsx';
import License    from './pages/License.jsx';

/**
 * App — root React Router shell (Requirements 13.1, 13.2, 13.3, 13.4).
 *
 * Layout structure:
 *   ┌──────────────────────────────────────────────┐
 *   │  TitleBar  (fixed, top-0, left-56, right-0)  │
 *   ├────────────┬─────────────────────────────────┤
 *   │  Sidebar   │  <Routes> — page content         │
 *   │  (w-56)    │  (flex-1, pt-10 for title bar)   │
 *   └────────────┴─────────────────────────────────┘
 *
 * - BrowserRouter drives client-side navigation without reloading the window.
 * - Sidebar provides the six persistent navigation links.
 * - TitleBar provides the drag region and window controls.
 * - The main content area has pt-10 (40 px) top padding to sit below the fixed TitleBar.
 */
export default function App() {
  return (
    <Router>
      <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden">
        {/* First-run consent gate + Tamper Protection guidance overlay.
            Renders nothing unless setup requires consent or is tamper-blocked. */}
        <DefenderConsentDialog />

        {/* Persistent sidebar navigation */}
        <Sidebar />

        {/* Right-hand column: title bar + page content */}
        <div className="flex flex-col flex-1 min-w-0">
          {/* Custom frameless title bar */}
          <TitleBar />

          {/* Page content — offset by title bar height (h-10 = 40 px) */}
          <main className="flex-1 overflow-y-auto mt-10 bg-slate-950">
            <Routes>
              <Route path="/"           element={<Dashboard  />} />
              <Route path="/scanner"    element={<Scanner    />} />
              <Route path="/whitelist"  element={<Whitelist  />} />
              <Route path="/quarantine" element={<Quarantine />} />
              <Route path="/settings"   element={<Settings   />} />
              <Route path="/license"    element={<License    />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}
