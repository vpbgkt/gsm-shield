/**
 * renderer/src/pages/Quarantine.jsx
 *
 * Quarantine page — Requirements 17.1, 17.2, 17.3
 *
 * Displays:
 *  - Persistent amber warning banner (Req 17.3)
 *  - Table of quarantined files: name, threat, detected date, size (Req 17.1)
 *  - "Restore" and "Delete Permanently" actions per row (Req 17.2)
 *  - Modal prompt for alternate restore destination when needsPath === true
 *  - Empty state with shield icon when no entries exist
 */

import React, { useEffect, useState, useCallback } from 'react';
import {
  AlertTriangle,
  RotateCcw,
  Trash2,
  ShieldAlert,
  FolderOpen,
  Shield,
} from 'lucide-react';

import useQuarantineStore from '../store/quarantineStore';

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Return just the file name from a full path (handles both / and \ separators).
 */
function basename(fullPath) {
  if (!fullPath) return '—';
  return fullPath.replace(/.*[/\\]/, '') || fullPath;
}

/**
 * Format an ISO timestamp into a readable local date/time string.
 * Returns '—' if the value is falsy.
 */
function formatDateTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      year:   'numeric',
      month:  'short',
      day:    'numeric',
      hour:   '2-digit',
      minute: '2-digit',
    });
  } catch (_) {
    return iso;
  }
}

/**
 * Convert a byte count to a human-readable KB / MB string.
 */
function formatSize(bytes) {
  if (bytes == null || bytes < 0) return '—';
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

// ── RestorePathModal ──────────────────────────────────────────────────────────

/**
 * Modal that prompts the user for an alternative destination path when
 * restoreEntry() returns { needsPath: true }.
 */
function RestorePathModal({ entryId, onConfirm, onCancel }) {
  const [destPath, setDestPath] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const handleConfirm = async () => {
    const trimmed = destPath.trim();
    if (!trimmed) {
      setError('Please enter a destination path.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      await onConfirm(entryId, trimmed);
    } catch (err) {
      setError(err?.message ?? 'Restore failed.');
      setBusy(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleConfirm();
    if (e.key === 'Escape') onCancel();
  };

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => e.target === e.currentTarget && onCancel()}
    >
      {/* Dialog */}
      <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        {/* Header */}
        <div className="flex items-center gap-3 mb-4">
          <FolderOpen className="w-5 h-5 text-amber-400 shrink-0" />
          <h2 className="text-base font-semibold text-slate-100">
            Choose Restore Destination
          </h2>
        </div>

        <p className="text-sm text-slate-400 mb-4 leading-relaxed">
          The original location is unavailable. Enter an alternative path where
          the file should be restored.
        </p>

        {/* Input */}
        <input
          type="text"
          value={destPath}
          onChange={(e) => setDestPath(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="C:\Users\…\Documents"
          autoFocus
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-500"
        />

        {error && (
          <p className="mt-2 text-xs text-red-400">{error}</p>
        )}

        {/* Buttons */}
        <div className="mt-5 flex justify-end gap-3">
          <button
            onClick={onCancel}
            disabled={busy}
            className="px-4 py-2 rounded-lg border border-slate-700 text-sm text-slate-300 hover:bg-slate-800 transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={busy || !destPath.trim()}
            className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 active:bg-sky-700 text-sm font-semibold text-white transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            {busy ? 'Restoring…' : 'Restore Here'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Quarantine ────────────────────────────────────────────────────────────────

export default function Quarantine() {
  const entries     = useQuarantineStore((s) => s.entries);
  const loadEntries = useQuarantineStore((s) => s.loadEntries);
  const restoreEntry = useQuarantineStore((s) => s.restoreEntry);
  const deleteEntry  = useQuarantineStore((s) => s.deleteEntry);

  // Per-row action state: { [id]: 'restoring' | 'deleting' | undefined }
  const [busyMap, setBusyMap] = useState({});

  // When not null, shows the restore-path modal for the given entry id
  const [needsPathId, setNeedsPathId] = useState(null);

  // Inline status messages per row: { [id]: { type: 'error'|'success', text: string } }
  const [statusMap, setStatusMap] = useState({});

  useEffect(() => {
    loadEntries();
  }, [loadEntries]);

  // ── action helpers ──────────────────────────────────────────────────────

  const setBusy = (id, action) =>
    setBusyMap((prev) => ({ ...prev, [id]: action }));
  const clearBusy = (id) =>
    setBusyMap((prev) => { const n = { ...prev }; delete n[id]; return n; });

  const setStatus = (id, type, text) =>
    setStatusMap((prev) => ({ ...prev, [id]: { type, text } }));
  const clearStatus = (id) =>
    setStatusMap((prev) => { const n = { ...prev }; delete n[id]; return n; });

  const handleRestore = useCallback(async (id) => {
    clearStatus(id);
    setBusy(id, 'restoring');
    try {
      const result = await restoreEntry(id);
      if (result?.needsPath) {
        // Show path modal — entry list is NOT reloaded yet
        setNeedsPathId(id);
      } else if (result?.success) {
        setStatus(id, 'success', 'Restored successfully.');
        setTimeout(() => clearStatus(id), 3000);
      } else {
        setStatus(id, 'error', result?.error ?? 'Restore failed.');
      }
    } catch (err) {
      setStatus(id, 'error', err?.message ?? 'Restore failed.');
    } finally {
      clearBusy(id);
    }
  }, [restoreEntry]);

  const handleRestoreTo = useCallback(async (id, destPath) => {
    setBusy(id, 'restoring');
    try {
      const result = await window.electronAPI.quarantineRestoreTo({ id, destPath });
      setNeedsPathId(null);
      if (result?.success) {
        // Reload list since the entry should now be gone
        await loadEntries();
        setStatus(id, 'success', 'Restored to alternate location.');
        setTimeout(() => clearStatus(id), 3000);
      } else {
        setStatus(id, 'error', result?.error ?? 'Restore failed.');
      }
    } catch (err) {
      setStatus(id, 'error', err?.message ?? 'Restore failed.');
      throw err; // let modal surface the error
    } finally {
      clearBusy(id);
    }
  }, [loadEntries]);

  const handleDelete = useCallback(async (id) => {
    clearStatus(id);
    setBusy(id, 'deleting');
    try {
      const result = await deleteEntry(id);
      if (!result?.success) {
        setStatus(id, 'error', result?.error ?? 'Delete failed.');
      }
    } catch (err) {
      setStatus(id, 'error', err?.message ?? 'Delete failed.');
    } finally {
      clearBusy(id);
    }
  }, [deleteEntry]);

  // ── render ────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-5">
      {/* ── Page title ──────────────────────────────────────────────────── */}
      <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
        Quarantine
      </h1>

      {/* ── Warning banner (Req 17.3) ────────────────────────────────────
          Persistent amber banner informing the user of the restore risk.
      ──────────────────────────────────────────────────────────────────── */}
      <div className="flex items-start gap-3 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3">
        <AlertTriangle className="w-5 h-5 text-amber-400 mt-0.5 shrink-0" />
        <p className="text-sm text-amber-200 leading-snug">
          <span className="font-semibold">Warning:</span> Restoring files may
          expose the system to malware. Only restore files you are certain are
          safe.
        </p>
      </div>

      {/* ── Quarantine table / empty state ──────────────────────────────── */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
        {entries.length === 0 ? (
          /* Empty state */
          <div className="flex flex-col items-center justify-center py-16 text-slate-500">
            <Shield className="w-12 h-12 mb-4 opacity-30" />
            <p className="text-sm font-medium">No quarantined files</p>
            <p className="text-xs mt-1 text-slate-600">
              Files detected as threats will appear here.
            </p>
          </div>
        ) : (
          /* Table (Req 17.1, 17.2) */
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-xs uppercase tracking-widest text-slate-500">
                  <th className="px-5 py-3 text-left font-medium">File Name</th>
                  <th className="px-5 py-3 text-left font-medium">Threat</th>
                  <th className="px-5 py-3 text-left font-medium">Detected</th>
                  <th className="px-5 py-3 text-left font-medium">Size</th>
                  <th className="px-5 py-3 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {entries.map((entry) => {
                  const busy   = busyMap[entry.id];
                  const status = statusMap[entry.id];

                  return (
                    <tr
                      key={entry.id}
                      className="hover:bg-slate-800/40 transition-colors"
                    >
                      {/* File name */}
                      <td className="px-5 py-4 max-w-[200px]">
                        <div className="flex items-center gap-2 min-w-0">
                          <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                          <span
                            className="truncate font-medium text-slate-200"
                            title={entry.original_path}
                          >
                            {basename(entry.original_path)}
                          </span>
                        </div>
                      </td>

                      {/* Threat name */}
                      <td className="px-5 py-4 max-w-[180px]">
                        <span
                          className="truncate block text-red-300"
                          title={entry.threat_name}
                        >
                          {entry.threat_name ?? '—'}
                        </span>
                      </td>

                      {/* Detection date */}
                      <td className="px-5 py-4 whitespace-nowrap text-slate-400">
                        {formatDateTime(entry.detected_at)}
                      </td>

                      {/* File size */}
                      <td className="px-5 py-4 whitespace-nowrap text-slate-400">
                        {formatSize(entry.file_size)}
                      </td>

                      {/* Actions + inline status */}
                      <td className="px-5 py-4">
                        <div className="flex flex-col items-end gap-1.5">
                          <div className="flex items-center gap-2 justify-end">
                            {/* Restore button */}
                            <button
                              onClick={() => handleRestore(entry.id)}
                              disabled={!!busy}
                              title="Restore file"
                              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                            >
                              <RotateCcw className={`w-3.5 h-3.5 ${busy === 'restoring' ? 'animate-spin' : ''}`} />
                              {busy === 'restoring' ? 'Restoring…' : 'Restore'}
                            </button>

                            {/* Delete permanently button */}
                            <button
                              onClick={() => handleDelete(entry.id)}
                              disabled={!!busy}
                              title="Delete permanently"
                              className="flex items-center gap-1.5 rounded-lg border border-red-800/60 bg-red-900/30 hover:bg-red-800/50 active:bg-red-700/50 px-3 py-1.5 text-xs font-medium text-red-300 transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                            >
                              <Trash2 className={`w-3.5 h-3.5 ${busy === 'deleting' ? 'animate-pulse' : ''}`} />
                              {busy === 'deleting' ? 'Deleting…' : 'Delete Permanently'}
                            </button>
                          </div>

                          {/* Inline status feedback */}
                          {status && (
                            <span
                              className={`text-xs ${
                                status.type === 'error'
                                  ? 'text-red-400'
                                  : 'text-emerald-400'
                              }`}
                            >
                              {status.text}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Restore-path modal ───────────────────────────────────────────── */}
      {needsPathId !== null && (
        <RestorePathModal
          entryId={needsPathId}
          onConfirm={handleRestoreTo}
          onCancel={() => setNeedsPathId(null)}
        />
      )}
    </div>
  );
}
