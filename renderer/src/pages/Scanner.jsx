/**
 * Scanner page — renderer/src/pages/Scanner.jsx
 *
 * Requirements: 15.1, 15.2, 15.3, 15.4
 *
 * - Four scan-trigger buttons (quick, full, folder, file)
 * - Progress bar + current file + Cancel while scan is running
 * - Threats found list on completion
 * - Scan history (last 10 records)
 */

import React, { useEffect } from 'react';
import {
  Zap,
  Search,
  FolderOpen,
  File,
  X,
  Play,
  AlertTriangle,
  Clock,
} from 'lucide-react';
import useScanStore from '../store/scanStore';

// ── Scan mode configuration ───────────────────────────────────────────────────

const SCAN_MODES = [
  {
    mode: 'quick',
    label: 'Quick Scan',
    description: 'Common threat locations',
    Icon: Zap,
    color: 'text-yellow-400',
    border: 'border-yellow-500/30 hover:border-yellow-400/60',
    bg: 'hover:bg-yellow-500/10',
  },
  {
    mode: 'full',
    label: 'Full Scan',
    description: 'Entire file system',
    Icon: Search,
    color: 'text-blue-400',
    border: 'border-blue-500/30 hover:border-blue-400/60',
    bg: 'hover:bg-blue-500/10',
  },
  {
    mode: 'folder',
    label: 'Folder Scan',
    description: 'Select a folder to scan',
    Icon: FolderOpen,
    color: 'text-green-400',
    border: 'border-green-500/30 hover:border-green-400/60',
    bg: 'hover:bg-green-500/10',
  },
  {
    mode: 'file',
    label: 'File Scan',
    description: 'Select a single file',
    Icon: File,
    color: 'text-purple-400',
    border: 'border-purple-500/30 hover:border-purple-400/60',
    bg: 'hover:bg-purple-500/10',
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Compute a human-readable duration from two ISO date strings.
 * Returns "—" if either value is missing.
 */
function formatDuration(startedAt, endedAt) {
  if (!startedAt || !endedAt) return '—';
  const ms = new Date(endedAt) - new Date(startedAt);
  if (isNaN(ms) || ms < 0) return '—';
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const rem = secs % 60;
  return rem > 0 ? `${mins}m ${rem}s` : `${mins}m`;
}

/**
 * Format an ISO timestamp to a readable local date/time string.
 */
function formatTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

/**
 * Capitalise the first letter of a string.
 */
function capitalize(str) {
  if (!str) return '—';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// ── Sub-components ────────────────────────────────────────────────────────────

/** Single scan-trigger card button (Requirement 15.1) */
function ScanButton({ mode, label, description, Icon, color, border, bg, disabled, onStart }) {
  return (
    <button
      onClick={() => onStart(mode)}
      disabled={disabled}
      className={[
        'flex flex-col items-center justify-center gap-3 p-6 rounded-xl border',
        'bg-slate-900/60 backdrop-blur transition-all duration-200',
        border,
        bg,
        disabled
          ? 'opacity-40 cursor-not-allowed'
          : 'cursor-pointer active:scale-95',
      ].join(' ')}
    >
      <Icon className={`w-8 h-8 ${color}`} strokeWidth={1.5} />
      <div className="text-center">
        <p className="text-sm font-semibold text-slate-100">{label}</p>
        <p className="text-xs text-slate-400 mt-0.5">{description}</p>
      </div>
    </button>
  );
}

/** Format elapsed milliseconds as m:ss or s. */
function formatElapsed(ms) {
  if (!ms || ms < 0) return '0s';
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  return `${mins}m ${secs % 60}s`;
}

/** Live scan progress panel — shows phase, current file, counts, elapsed. */
function ProgressBar({ phase, currentFile, filesScanned, threatsCount, elapsedMs, onCancel }) {
  const isLoading = phase === 'loading';

  return (
    <div className="bg-slate-900/60 border border-slate-700/50 rounded-xl p-6 space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${isLoading ? 'bg-amber-400' : 'bg-blue-400'} opacity-75`} />
            <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${isLoading ? 'bg-amber-500' : 'bg-blue-500'}`} />
          </span>
          <span className="text-sm font-medium text-slate-200">
            {isLoading ? 'Loading virus definitions…' : 'Scanning…'}
          </span>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400 font-mono tabular-nums">{formatElapsed(elapsedMs)}</span>
          <button
            onClick={onCancel}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-red-500/40 text-red-400 text-xs font-medium hover:bg-red-500/10 hover:border-red-400/60 transition-colors"
          >
            <X className="w-3.5 h-3.5" />
            Cancel
          </button>
        </div>
      </div>

      {/* Indeterminate progress bar */}
      <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden relative">
        <div
          className={`h-2 rounded-full ${isLoading ? 'bg-gradient-to-r from-amber-600 to-amber-400' : 'bg-gradient-to-r from-blue-600 to-blue-400'} animate-pulse`}
          style={{ width: '100%' }}
        />
      </div>

      {isLoading ? (
        <p className="text-xs text-amber-300/80">
          Preparing the scan engine (one-time, ~15s). This is normal.
        </p>
      ) : (
        <>
          {/* Live counters */}
          <div className="flex items-center gap-6">
            <div>
              <p className="text-lg font-semibold text-slate-100 tabular-nums">{filesScanned}</p>
              <p className="text-[11px] uppercase tracking-wider text-slate-500">Files scanned</p>
            </div>
            <div>
              <p className={`text-lg font-semibold tabular-nums ${threatsCount > 0 ? 'text-red-400' : 'text-green-400'}`}>{threatsCount}</p>
              <p className="text-[11px] uppercase tracking-wider text-slate-500">Threats</p>
            </div>
          </div>

          {/* Current file being scanned */}
          <div className="min-w-0">
            <p className="text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">Now scanning</p>
            <p className="text-xs text-slate-300 font-mono truncate" title={currentFile}>
              {currentFile || '…'}
            </p>
          </div>
        </>
      )}
    </div>
  );
}

/** Status badge for a completed/cancelled result */
function StatusBadge({ status }) {
  if (status === 'complete') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/25">
        Complete
      </span>
    );
  }
  if (status === 'cancelled') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-500/15 text-yellow-400 border border-yellow-500/25">
        Cancelled
      </span>
    );
  }
  return null;
}

/** Threats found list (Requirement 15.3) */
function ThreatsPanel({ threats }) {
  if (!threats || threats.length === 0) {
    return (
      <div className="bg-slate-900/60 border border-green-500/25 rounded-xl p-6 flex items-center gap-3">
        <div className="w-9 h-9 rounded-full bg-green-500/15 flex items-center justify-center flex-shrink-0">
          <Play className="w-4 h-4 text-green-400" />
        </div>
        <div>
          <p className="text-sm font-semibold text-slate-100">No threats found</p>
          <p className="text-xs text-slate-400 mt-0.5">Your system looks clean.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/60 border border-red-500/30 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-5 py-4 border-b border-red-500/20">
        <AlertTriangle className="w-4 h-4 text-red-400" />
        <span className="text-sm font-semibold text-red-300">
          {threats.length} threat{threats.length !== 1 ? 's' : ''} found
        </span>
      </div>

      {/* Threat rows */}
      <ul className="divide-y divide-slate-800/70">
        {threats.map((threat, i) => (
          <li key={i} className="flex items-start gap-3 px-5 py-3">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400 mt-0.5 flex-shrink-0" />
            <div className="min-w-0 flex-1">
              <p className="text-xs font-mono text-slate-300 truncate" title={threat.filePath}>
                {threat.filePath}
              </p>
              <p className="text-xs text-red-400 mt-0.5">{threat.threatName}</p>
            </div>
            {/* Quarantine status badge */}
            {threat.quarantined && (
              <span className="shrink-0 inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-green-500/15 text-green-400 border border-green-500/25">
                Quarantined
              </span>
            )}
            {threat.quarantineFailed && (
              <span
                className="shrink-0 inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-amber-500/15 text-amber-400 border border-amber-500/25"
                title={threat.quarantineError || 'Quarantine failed'}
              >
                Quarantine failed
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Scan history table (Requirement 15.4) */
function HistoryPanel({ history }) {
  // Show at most last 10 records (Requirement 15.4)
  const records = history.slice(0, 10);

  return (
    <div className="bg-slate-900/60 border border-slate-700/50 rounded-xl overflow-hidden">
      {/* Panel header */}
      <div className="flex items-center gap-2 px-5 py-4 border-b border-slate-700/50">
        <Clock className="w-4 h-4 text-slate-400" />
        <span className="text-sm font-semibold text-slate-200">Scan History</span>
        {records.length > 0 && (
          <span className="ml-auto text-xs text-slate-500">{records.length} record{records.length !== 1 ? 's' : ''}</span>
        )}
      </div>

      {records.length === 0 ? (
        <p className="px-5 py-6 text-sm text-slate-500 text-center">No scan history yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-400 border-b border-slate-800">
                <th className="text-left px-5 py-2.5 font-medium">Mode</th>
                <th className="text-left px-4 py-2.5 font-medium">Started</th>
                <th className="text-left px-4 py-2.5 font-medium">Duration</th>
                <th className="text-right px-4 py-2.5 font-medium">Files</th>
                <th className="text-right px-5 py-2.5 font-medium">Threats</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {records.map((rec, i) => (
                <tr
                  key={rec.id ?? i}
                  className="hover:bg-slate-800/30 transition-colors"
                >
                  <td className="px-5 py-3 font-medium text-slate-200">
                    {capitalize(rec.mode)}
                  </td>
                  <td className="px-4 py-3 text-slate-400">
                    {formatTime(rec.started_at)}
                  </td>
                  <td className="px-4 py-3 text-slate-400">
                    {formatDuration(rec.started_at, rec.ended_at)}
                  </td>
                  <td className="px-4 py-3 text-right text-slate-300 font-mono">
                    {rec.files_scanned ?? '—'}
                  </td>
                  <td className="px-5 py-3 text-right">
                    <span
                      className={
                        rec.threats_found > 0
                          ? 'text-red-400 font-semibold'
                          : 'text-slate-400'
                      }
                    >
                      {rec.threats_found ?? 0}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

/**
 * Scanner — main scan UI page.
 *
 * Orchestrates the four scan-trigger buttons, running state (progress bar +
 * cancel), results panel, and history table.
 *
 * Requirements: 15.1, 15.2, 15.3, 15.4
 */
export default function Scanner() {
  const status = useScanStore((s) => s.status);
  const phase = useScanStore((s) => s.phase);
  const mode = useScanStore((s) => s.mode);
  const currentFile = useScanStore((s) => s.currentFile);
  const filesScanned = useScanStore((s) => s.filesScanned);
  const startedAt = useScanStore((s) => s.startedAt);
  const endedAt = useScanStore((s) => s.endedAt);
  const errorMessage = useScanStore((s) => s.errorMessage);
  const threatsFound = useScanStore((s) => s.threatsFound);
  const history = useScanStore((s) => s.history);
  const startScan = useScanStore((s) => s.startScan);
  const cancelScan = useScanStore((s) => s.cancelScan);
  const loadHistory = useScanStore((s) => s.loadHistory);

  // Load scan history once on mount (Requirement 15.4)
  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const isRunning = status === 'running';
  const isDone = status === 'complete' || status === 'cancelled';

  // Live elapsed-time ticker while a scan is running.
  const [now, setNow] = React.useState(Date.now());
  useEffect(() => {
    if (!isRunning) return undefined;
    const id = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(id);
  }, [isRunning]);

  // Reload history when a scan finishes so the table reflects the new record.
  useEffect(() => {
    if (isDone) loadHistory();
  }, [isDone, loadHistory]);

  const elapsedMs = startedAt ? (endedAt || now) - startedAt : 0;

  return (
    <div className="min-h-full bg-slate-950 text-slate-100 px-6 py-6 space-y-6">

      {/* ── Page header ───────────────────────────────────────────────────── */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Scanner</h1>
        <p className="text-sm text-slate-400 mt-0.5">
          Choose a scan type to inspect your system for threats.
        </p>
      </div>

      {/* ── Scan trigger buttons (Requirement 15.1) ───────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {SCAN_MODES.map((cfg) => (
          <ScanButton
            key={cfg.mode}
            {...cfg}
            disabled={isRunning}
            onStart={startScan}
          />
        ))}
      </div>

      {/* ── Running state: live progress + cancel (Requirement 15.2) ─────── */}
      {isRunning && (
        <ProgressBar
          phase={phase}
          currentFile={currentFile}
          filesScanned={filesScanned}
          threatsCount={threatsFound.length}
          elapsedMs={elapsedMs}
          onCancel={cancelScan}
        />
      )}

      {/* ── Completed / cancelled state ───────────────────────────────────── */}
      {isDone && (
        <div className="space-y-3">
          {/* Status summary row */}
          <div className="flex items-center gap-3 flex-wrap">
            <StatusBadge status={status} />
            {mode && (
              <span className="text-xs text-slate-400">
                {capitalize(mode)} scan — {filesScanned} file{filesScanned !== 1 ? 's' : ''} scanned in {formatElapsed(elapsedMs)}
              </span>
            )}
          </div>

          {/* Error banner if the scan engine failed */}
          {errorMessage && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-xs text-red-300">
              {errorMessage}
            </div>
          )}

          {/* Threats found list (Requirement 15.3) */}
          <ThreatsPanel threats={threatsFound} />
        </div>
      )}

      {/* ── Scan history (Requirement 15.4) ──────────────────────────────── */}
      <HistoryPanel history={history} />
    </div>
  );
}
