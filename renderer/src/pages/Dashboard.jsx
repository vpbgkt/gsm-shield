/**
 * renderer/src/pages/Dashboard.jsx
 *
 * Dashboard page — Requirements 14.1, 14.2, 14.3
 *
 * Displays:
 *  - Status card: real-time protection state, last scan time, threat count
 *  - Recent threats list: 5 most recent quarantine entries
 *  - Quick Scan button: navigates to /scanner
 */

import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  ShieldAlert,
  ShieldOff,
  Clock,
  AlertTriangle,
  Zap,
} from 'lucide-react';

import useScanStore       from '../store/scanStore';
import useQuarantineStore from '../store/quarantineStore';
import useSettingsStore   from '../store/settingsStore';

// ── helpers ──────────────────────────────────────────────────────────────────

/**
 * Format an ISO timestamp into a readable "Jan 15, 2025 · 14:32" string.
 * Returns '—' if the value is falsy.
 */
function formatDateTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: 'short',
      day:   'numeric',
      year:  'numeric',
      hour:  '2-digit',
      minute:'2-digit',
    });
  } catch (_) {
    return iso;
  }
}

/**
 * Truncate a long file path so it fits in one line of the threats list.
 * Keeps the filename and a leading "…/" prefix.
 */
function shortPath(fullPath) {
  if (!fullPath) return '—';
  const sep = fullPath.includes('\\') ? '\\' : '/';
  const parts = fullPath.split(sep);
  if (parts.length <= 2) return fullPath;
  return `…${sep}${parts.slice(-2).join(sep)}`;
}

// ── component ─────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate();

  // Store slices
  const realtimeProtection = useSettingsStore((s) => s.realtimeProtection);
  const loadSettings        = useSettingsStore((s) => s.loadSettings);

  const threatsFound  = useScanStore((s) => s.threatsFound);
  const history       = useScanStore((s) => s.history);
  const loadHistory   = useScanStore((s) => s.loadHistory);

  const entries     = useQuarantineStore((s) => s.entries);
  const loadEntries = useQuarantineStore((s) => s.loadEntries);

  // Load data on mount
  useEffect(() => {
    loadEntries();
    loadSettings();
    loadHistory();
  }, [loadEntries, loadSettings, loadHistory]);

  // Derived values
  const lastScan       = history.length > 0 ? history[history.length - 1]?.started_at : null;
  const threatCount    = threatsFound.length;
  const recentThreats  = entries.slice(0, 5);

  // ── status card config ───────────────────────────────────────────────────
  const ProtectionIcon = realtimeProtection ? Shield : ShieldOff;
  const protectionLabel = realtimeProtection ? 'Protected' : 'Protection Off';
  const protectionColor = realtimeProtection
    ? 'text-emerald-400'
    : 'text-red-400';
  const protectionBg = realtimeProtection
    ? 'bg-emerald-500/10 border-emerald-500/30'
    : 'bg-red-500/10 border-red-500/30';

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <div className="p-6 space-y-6">
      {/* Page title */}
      <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
        Dashboard
      </h1>

      {/* ── Status card ───────────────────────────────────────────────── */}
      <div className={`rounded-xl border p-6 ${protectionBg}`}>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          {/* Protection status */}
          <div className="flex items-center gap-3">
            <ProtectionIcon className={`w-10 h-10 ${protectionColor}`} />
            <div>
              <p className="text-xs uppercase tracking-widest text-slate-400 mb-0.5">
                Real-Time Protection
              </p>
              <p className={`text-xl font-bold ${protectionColor}`}>
                {protectionLabel}
              </p>
            </div>
          </div>

          {/* Stats row */}
          <div className="flex gap-8 flex-wrap">
            {/* Last scan */}
            <div className="flex items-center gap-2">
              <Clock className="w-5 h-5 text-slate-400 shrink-0" />
              <div>
                <p className="text-xs text-slate-400">Last Scan</p>
                <p className="text-sm font-medium text-slate-200">
                  {formatDateTime(lastScan)}
                </p>
              </div>
            </div>

            {/* Threats found this session */}
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0" />
              <div>
                <p className="text-xs text-slate-400">Threats (session)</p>
                <p className="text-sm font-medium text-slate-200">
                  {threatCount}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Bottom row: recent threats + quick scan ───────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent threats list — spans 2 of 3 columns on large screens */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-widest mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Recent Threats
          </h2>

          {recentThreats.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-slate-500">
              <Shield className="w-10 h-10 mb-3 opacity-30" />
              <p className="text-sm">No threats detected</p>
            </div>
          ) : (
            <ul className="divide-y divide-slate-800">
              {recentThreats.map((entry) => (
                <li key={entry.id} className="py-3 flex items-start gap-3">
                  <ShieldAlert className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-slate-200 truncate">
                      {entry.threat_name ?? 'Unknown Threat'}
                    </p>
                    <p className="text-xs text-slate-500 truncate mt-0.5">
                      {shortPath(entry.original_path)}
                    </p>
                  </div>
                  <span className="text-xs text-slate-500 shrink-0 mt-0.5">
                    {formatDateTime(entry.detected_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Quick Scan card */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-widest mb-2 flex items-center gap-2">
              <Zap className="w-4 h-4 text-sky-400" />
              Quick Actions
            </h2>
            <p className="text-xs text-slate-500 leading-relaxed">
              Run a Quick Scan to check your most vulnerable locations for
              threats in seconds.
            </p>
          </div>

          <button
            onClick={() => navigate('/scanner')}
            className="mt-6 w-full flex items-center justify-center gap-2 rounded-lg bg-sky-600 hover:bg-sky-500 active:bg-sky-700 transition-colors py-3 px-4 text-sm font-semibold text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            <Zap className="w-4 h-4" />
            Quick Scan
          </button>
        </div>
      </div>
    </div>
  );
}
