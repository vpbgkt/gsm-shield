/**
 * renderer/src/pages/Whitelist.jsx
 *
 * Whitelist management page — Requirements 16.1, 16.2, 16.3, 16.4, 16.5
 *
 * Features:
 *  - Table of all whitelist entries with name, vendor, verified badge, remove action
 *  - Real-time search bar filtering by name or vendor (16.2)
 *  - "Add File" button — opens file picker via IPC then adds to whitelist (16.3)
 *  - "Sync from Cloud" button — shows progress indicator during sync (16.4)
 *  - "Submit a Tool" button — opens inline modal form (16.5)
 */

import React, { useEffect, useState } from 'react';
import {
  Search,
  Plus,
  RefreshCw,
  Upload,
  CheckCircle,
  X,
  Shield,
  Trash2,
} from 'lucide-react';

import useWhitelistStore from '../store/whitelistStore';

// ── helpers ──────────────────────────────────────────────────────────────────

/** Format an ISO timestamp into a short readable string. */
function formatDate(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch (_) {
    return iso;
  }
}

// ── SubmitModal ───────────────────────────────────────────────────────────────

/**
 * Inline modal for submitting a tool to the cloud whitelist.
 * Requirement 16.5
 */
function SubmitModal({ onClose }) {
  const [hash, setHash] = useState('');
  const [name, setName] = useState('');
  const [vendor, setVendor] = useState('');
  const [status, setStatus] = useState(null); // null | 'submitting' | 'success' | 'error'
  const [errorMsg, setErrorMsg] = useState('');

  const isValidHash = /^[0-9a-fA-F]{64}$/.test(hash.trim());
  const canSubmit = isValidHash && name.trim().length > 0 && status !== 'submitting';

  async function handleSubmit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setStatus('submitting');
    setErrorMsg('');
    try {
      await window.electronAPI.whitelistSubmit({
        hash: hash.trim().toLowerCase(),
        name: name.trim(),
        vendor: vendor.trim(),
      });
      setStatus('success');
    } catch (err) {
      setStatus('error');
      setErrorMsg(err?.message ?? 'Submission failed. Please try again.');
    }
  }

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="submit-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="relative w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl mx-4">
        {/* Header */}
        <div className="flex items-start justify-between mb-5">
          <div className="flex items-center gap-2">
            <Upload className="w-5 h-5 text-sky-400" />
            <h2
              id="submit-modal-title"
              className="text-base font-semibold text-slate-100"
            >
              Submit a Tool
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {status === 'success' ? (
          <div className="flex flex-col items-center gap-3 py-6 text-center">
            <CheckCircle className="w-10 h-10 text-emerald-400" />
            <p className="text-sm font-medium text-slate-200">
              Tool submitted successfully!
            </p>
            <p className="text-xs text-slate-400">
              It will be reviewed and added to the cloud whitelist.
            </p>
            <button
              onClick={onClose}
              className="mt-3 px-5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm text-slate-200 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              Close
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* SHA-256 Hash */}
            <div>
              <label
                htmlFor="submit-hash"
                className="block text-xs font-medium text-slate-400 mb-1.5"
              >
                SHA-256 Hash <span className="text-red-400">*</span>
              </label>
              <input
                id="submit-hash"
                type="text"
                value={hash}
                onChange={(e) => setHash(e.target.value)}
                placeholder="64-character hex string"
                maxLength={64}
                className="w-full rounded-lg bg-slate-800 border border-slate-700 text-slate-100 placeholder-slate-500 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-sky-500 transition font-mono"
                autoComplete="off"
                spellCheck={false}
              />
              {hash.length > 0 && !isValidHash && (
                <p className="mt-1 text-xs text-red-400">
                  Must be exactly 64 hexadecimal characters.
                </p>
              )}
            </div>

            {/* Name */}
            <div>
              <label
                htmlFor="submit-name"
                className="block text-xs font-medium text-slate-400 mb-1.5"
              >
                Tool Name <span className="text-red-400">*</span>
              </label>
              <input
                id="submit-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Nmap"
                className="w-full rounded-lg bg-slate-800 border border-slate-700 text-slate-100 placeholder-slate-500 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-sky-500 transition"
              />
            </div>

            {/* Vendor */}
            <div>
              <label
                htmlFor="submit-vendor"
                className="block text-xs font-medium text-slate-400 mb-1.5"
              >
                Vendor
              </label>
              <input
                id="submit-vendor"
                type="text"
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                placeholder="e.g. Nmap Project"
                className="w-full rounded-lg bg-slate-800 border border-slate-700 text-slate-100 placeholder-slate-500 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-sky-500 transition"
              />
            </div>

            {/* Error feedback */}
            {status === 'error' && (
              <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                {errorMsg}
              </p>
            )}

            {/* Actions */}
            <div className="flex gap-3 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm text-slate-300 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!canSubmit}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 active:bg-sky-700 disabled:opacity-40 disabled:cursor-not-allowed text-sm font-semibold text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
              >
                {status === 'submitting' ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Submitting…
                  </>
                ) : (
                  <>
                    <Upload className="w-4 h-4" />
                    Submit
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Whitelist() {
  // Store bindings
  const filteredEntries = useWhitelistStore((s) => s.filteredEntries);
  const searchQuery     = useWhitelistStore((s) => s.searchQuery);
  const setSearch       = useWhitelistStore((s) => s.setSearch);
  const isSyncing       = useWhitelistStore((s) => s.isSyncing);
  const lastSyncAt      = useWhitelistStore((s) => s.lastSyncAt);
  const loadEntries     = useWhitelistStore((s) => s.loadEntries);
  const addEntry        = useWhitelistStore((s) => s.addEntry);
  const removeEntry     = useWhitelistStore((s) => s.removeEntry);
  const startSync       = useWhitelistStore((s) => s.startSync);

  // Local UI state
  const [feedback, setFeedback]             = useState(null); // { type: 'success'|'error'|'warn', message }
  const [removingHash, setRemovingHash]     = useState(null); // hash currently being removed
  const [showSubmitModal, setShowSubmitModal] = useState(false);

  // Load entries on mount (Requirement 16.1)
  useEffect(() => {
    loadEntries();
  }, [loadEntries]);

  /** Show a timed feedback banner then auto-dismiss after 4 s. */
  function showFeedback(type, message) {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 4000);
  }

  // ── Add File handler (Requirement 16.3) ──────────────────────────────────
  async function handleAddFile() {
    try {
      const result = await window.electronAPI.showOpenDialog({
        properties: ['openFile'],
      });
      // result is typically { canceled, filePaths }
      if (!result || result.canceled || !result.filePaths?.length) return;

      const filePath = result.filePaths[0];
      const res = await addEntry(filePath);

      if (res?.duplicate) {
        showFeedback('warn', 'This file is already in the whitelist.');
      } else if (res?.capReached) {
        showFeedback('error', 'Whitelist capacity reached. Remove entries to add new ones.');
      } else if (res?.success) {
        showFeedback('success', 'File added to whitelist successfully.');
      } else {
        showFeedback('error', res?.error ?? 'Failed to add file.');
      }
    } catch (err) {
      showFeedback('error', err?.message ?? 'An unexpected error occurred.');
    }
  }

  // ── Remove handler (Requirement 16.1) ────────────────────────────────────
  async function handleRemove(hash) {
    setRemovingHash(hash);
    try {
      const res = await removeEntry(hash);
      if (res?.forbidden) {
        showFeedback('error', 'This entry cannot be removed (cloud-verified entries are protected).');
      } else if (!res?.success) {
        showFeedback('error', res?.error ?? 'Failed to remove entry.');
      }
    } finally {
      setRemovingHash(null);
    }
  }

  // ── Sync handler (Requirement 16.4) ──────────────────────────────────────
  function handleSync() {
    if (!isSyncing) startSync();
  }

  // ── Feedback banner color mapping ────────────────────────────────────────
  const feedbackStyles = {
    success: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300',
    error:   'bg-red-500/10 border-red-500/30 text-red-300',
    warn:    'bg-amber-500/10 border-amber-500/30 text-amber-300',
  };

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <>
      <div className="p-6 space-y-6">
        {/* ── Page header ─────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-slate-100 tracking-tight flex items-center gap-2">
              <Shield className="w-6 h-6 text-sky-400" />
              Whitelist
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Trusted files and tools that are excluded from scanning.
            </p>
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Add File (16.3) */}
            <button
              onClick={handleAddFile}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 active:bg-sky-700 text-sm font-medium text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <Plus className="w-4 h-4" />
              Add File
            </button>

            {/* Sync from Cloud (16.4) */}
            <button
              onClick={handleSync}
              disabled={isSyncing}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 active:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed border border-slate-700 text-sm font-medium text-slate-200 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <RefreshCw className={`w-4 h-4 ${isSyncing ? 'animate-spin' : ''}`} />
              {isSyncing ? 'Syncing…' : 'Sync from Cloud'}
            </button>

            {/* Submit a Tool (16.5) */}
            <button
              onClick={() => setShowSubmitModal(true)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 active:bg-slate-600 border border-slate-700 text-sm font-medium text-slate-200 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <Upload className="w-4 h-4" />
              Submit a Tool
            </button>
          </div>
        </div>

        {/* ── Last sync info ───────────────────────────────────────────── */}
        {lastSyncAt && (
          <p className="text-xs text-slate-500">
            Last synced: {formatDate(lastSyncAt)}
          </p>
        )}

        {/* ── Sync progress indicator (16.4) ──────────────────────────── */}
        {isSyncing && (
          <div className="flex items-center gap-3 rounded-lg border border-sky-500/30 bg-sky-500/10 px-4 py-3">
            <RefreshCw className="w-4 h-4 text-sky-400 animate-spin shrink-0" />
            <p className="text-sm text-sky-300">
              Syncing whitelist from cloud…
            </p>
          </div>
        )}

        {/* ── Feedback banner ──────────────────────────────────────────── */}
        {feedback && (
          <div
            className={`flex items-start justify-between gap-3 rounded-lg border px-4 py-3 text-sm ${feedbackStyles[feedback.type]}`}
            role="alert"
          >
            <span>{feedback.message}</span>
            <button
              onClick={() => setFeedback(null)}
              className="shrink-0 opacity-70 hover:opacity-100 transition-opacity focus:outline-none"
              aria-label="Dismiss"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* ── Search bar (Requirement 16.2) ────────────────────────────── */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name or vendor…"
            className="w-full rounded-lg bg-slate-900 border border-slate-800 text-slate-100 placeholder-slate-500 text-sm pl-9 pr-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent transition"
          />
        </div>

        {/* ── Whitelist table (Requirement 16.1) ──────────────────────── */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
          {filteredEntries.length === 0 ? (
            /* Empty state */
            <div className="flex flex-col items-center justify-center py-16 text-slate-500">
              <Shield className="w-12 h-12 mb-3 opacity-20" />
              <p className="text-sm font-medium">
                {searchQuery ? 'No entries match your search.' : 'No whitelist entries yet.'}
              </p>
              {!searchQuery && (
                <p className="text-xs mt-1 text-slate-600">
                  Click "Add File" to trust a file, or "Sync from Cloud" to pull the latest list.
                </p>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm" role="table">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/50">
                    <th
                      scope="col"
                      className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider"
                    >
                      Name
                    </th>
                    <th
                      scope="col"
                      className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider"
                    >
                      Vendor
                    </th>
                    <th
                      scope="col"
                      className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider"
                    >
                      Status
                    </th>
                    <th
                      scope="col"
                      className="px-4 py-3 text-right text-xs font-semibold text-slate-400 uppercase tracking-wider"
                    >
                      Action
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {filteredEntries.map((entry) => (
                    <WhitelistRow
                      key={entry.hash}
                      entry={entry}
                      isRemoving={removingHash === entry.hash}
                      onRemove={handleRemove}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Entry count */}
        {filteredEntries.length > 0 && (
          <p className="text-xs text-slate-500 text-right">
            {filteredEntries.length} {filteredEntries.length === 1 ? 'entry' : 'entries'}
            {searchQuery && ' matching'}
          </p>
        )}
      </div>

      {/* ── Submit a Tool modal (Requirement 16.5) ───────────────────────── */}
      {showSubmitModal && (
        <SubmitModal onClose={() => setShowSubmitModal(false)} />
      )}
    </>
  );
}

// ── WhitelistRow ──────────────────────────────────────────────────────────────

/**
 * Single row in the whitelist table.
 * Shows name, vendor, verified/source badge, and a remove button.
 */
function WhitelistRow({ entry, isRemoving, onRemove }) {
  const isVerified = entry.verified === 1 || entry.verified === true;
  const isUserEntry = entry.source === 'user';

  return (
    <tr className="hover:bg-slate-800/50 transition-colors">
      {/* Name + hash sub-text */}
      <td className="px-4 py-3">
        <p className="font-medium text-slate-200 truncate max-w-[200px]">
          {entry.name || '—'}
        </p>
        {entry.hash && (
          <p
            className="text-xs text-slate-500 font-mono truncate max-w-[200px] mt-0.5"
            title={entry.hash}
          >
            {entry.hash.slice(0, 16)}…
          </p>
        )}
      </td>

      {/* Vendor */}
      <td className="px-4 py-3 text-slate-400 truncate max-w-[160px]">
        {entry.vendor || '—'}
      </td>

      {/* Status badge */}
      <td className="px-4 py-3">
        {isVerified ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium px-2.5 py-0.5">
            <CheckCircle className="w-3 h-3" />
            Verified
          </span>
        ) : isUserEntry ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-slate-700/60 border border-slate-600 text-slate-400 text-xs font-medium px-2.5 py-0.5">
            <Shield className="w-3 h-3" />
            User
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded-full bg-slate-700/60 border border-slate-600 text-slate-400 text-xs font-medium px-2.5 py-0.5">
            Cloud
          </span>
        )}
      </td>

      {/* Remove action */}
      <td className="px-4 py-3 text-right">
        <button
          onClick={() => onRemove(entry.hash)}
          disabled={isRemoving}
          aria-label={`Remove ${entry.name || entry.hash} from whitelist`}
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium text-slate-400 hover:text-red-400 hover:bg-red-500/10 disabled:opacity-40 disabled:cursor-not-allowed transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-400"
        >
          {isRemoving ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <Trash2 className="w-3.5 h-3.5" />
          )}
          Remove
        </button>
      </td>
    </tr>
  );
}
