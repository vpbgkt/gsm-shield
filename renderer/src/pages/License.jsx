/**
 * renderer/src/pages/License.jsx
 *
 * License management page — Requirements 19.1, 19.2, 19.3, 19.4, 19.5, 19.6
 *
 * Displays:
 *  - Status card: license status (active/grace/inactive), expiry date, machine fingerprint (19.1)
 *  - Activation form: license key input + Activate button (19.2)
 *  - Activation feedback: success/failure messages via IPC (19.3, 19.4)
 *  - Deactivate link: removes machine from license (19.5)
 *  - Purchase link: opens https://gsmshield.app/pricing in browser (19.6)
 *  - Feature gates: shows which features are locked when inactive (19.1)
 */

import React, { useEffect, useState } from 'react';
import {
  Key,
  CheckCircle,
  XCircle,
  AlertCircle,
  ExternalLink,
  Copy,
  Shield,
} from 'lucide-react';

import useLicenseStore from '../store/licenseStore';

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Format an ISO date string into a readable "Jan 15, 2026" format.
 * Returns '—' for falsy values.
 */
function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      month: 'short',
      day:   'numeric',
      year:  'numeric',
    });
  } catch (_) {
    return iso;
  }
}

/**
 * Open a URL in the system browser via Electron's shell.openExternal,
 * exposed through the contextBridge as window.electronAPI.openExternal.
 */
function openExternal(url) {
  if (typeof window !== 'undefined' && window.electronAPI?.openExternal) {
    window.electronAPI.openExternal(url);
  } else {
    // Fallback for dev / non-Electron environments
    window.open(url, '_blank', 'noopener,noreferrer');
  }
}

// ── Status badge config ───────────────────────────────────────────────────────

const STATUS_CONFIG = {
  active: {
    label:     'Active',
    Icon:      CheckCircle,
    iconClass: 'text-emerald-400',
    cardClass: 'bg-emerald-500/10 border-emerald-500/30',
    textClass: 'text-emerald-400',
  },
  grace: {
    label:     'Grace Period',
    Icon:      AlertCircle,
    iconClass: 'text-yellow-400',
    cardClass: 'bg-yellow-500/10 border-yellow-500/30',
    textClass: 'text-yellow-400',
  },
  inactive: {
    label:     'Inactive',
    Icon:      XCircle,
    iconClass: 'text-slate-400',
    cardClass: 'bg-slate-800/60 border-slate-700',
    textClass: 'text-slate-400',
  },
};

// ── component ─────────────────────────────────────────────────────────────────

export default function License() {
  // Store slices
  const status            = useLicenseStore((s) => s.status);
  const expiresAt         = useLicenseStore((s) => s.expiresAt);
  const machineFingerprint = useLicenseStore((s) => s.machineFingerprint);
  const featureGates      = useLicenseStore((s) => s.featureGates);
  const isActivating      = useLicenseStore((s) => s.isActivating);
  const activationError   = useLicenseStore((s) => s.activationError);
  const loadLicense       = useLicenseStore((s) => s.loadLicense);
  const activateLicense   = useLicenseStore((s) => s.activateLicense);
  const deactivateLicense = useLicenseStore((s) => s.deactivateLicense);

  // Local state
  const [licenseKey, setLicenseKey]         = useState('');
  const [activationSuccess, setActivationSuccess] = useState(false);
  const [copied, setCopied]                 = useState(false);
  const [deactivating, setDeactivating]     = useState(false);
  const [deactivateError, setDeactivateError] = useState(null);

  // Load license on mount (Req 19.1)
  useEffect(() => {
    loadLicense();
  }, [loadLicense]);

  // Reset success banner when status changes away from active
  useEffect(() => {
    if (status !== 'active') setActivationSuccess(false);
  }, [status]);

  // ── handlers ─────────────────────────────────────────────────────────────

  /** Copy machine fingerprint to clipboard */
  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(machineFingerprint);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (_) {
      // Clipboard not available — silently ignore
    }
  }

  /** Submit activation form (Req 19.2, 19.3, 19.4) */
  async function handleActivate(e) {
    e.preventDefault();
    const trimmedKey = licenseKey.trim();
    if (!trimmedKey) return;

    setActivationSuccess(false);
    const result = await activateLicense(trimmedKey);
    if (result?.success) {
      setActivationSuccess(true);
      setLicenseKey('');
    }
  }

  /** Deactivate license (Req 19.5) */
  async function handleDeactivate() {
    setDeactivating(true);
    setDeactivateError(null);
    const result = await deactivateLicense();
    setDeactivating(false);
    if (!result?.success) {
      setDeactivateError(result?.error ?? 'Deactivation failed');
    }
  }

  // ── derived ──────────────────────────────────────────────────────────────

  const cfg         = STATUS_CONFIG[status] ?? STATUS_CONFIG.inactive;
  const { Icon }    = cfg;
  const isActive    = status === 'active';
  const isInactive  = status === 'inactive';

  // Locked features list for inactive/grace states
  const lockedFeatures = [];
  if (featureGates?.scanLimit)        lockedFeatures.push('Scan count limited');
  if (featureGates?.whitelistCap)     lockedFeatures.push('Whitelist entries capped');
  if (featureGates?.realtimeDisabled) lockedFeatures.push('Real-time protection disabled');

  // ── render ────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      {/* Page title */}
      <h1 className="text-2xl font-semibold text-slate-100 tracking-tight flex items-center gap-2">
        <Key className="w-6 h-6 text-sky-400" />
        License
      </h1>

      {/* ── Status card (Req 19.1) ─────────────────────────────────────── */}
      <div className={`rounded-xl border p-6 space-y-4 ${cfg.cardClass}`}>
        {/* Status row */}
        <div className="flex items-center gap-3">
          <Icon className={`w-8 h-8 shrink-0 ${cfg.iconClass}`} />
          <div>
            <p className="text-xs uppercase tracking-widest text-slate-400 mb-0.5">
              License Status
            </p>
            <p className={`text-xl font-bold ${cfg.textClass}`}>
              {cfg.label}
            </p>
          </div>
        </div>

        {/* Expiry + fingerprint row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
          {/* Expiry date */}
          <div>
            <p className="text-xs text-slate-400 mb-1">Expires</p>
            <p className="text-sm font-medium text-slate-200">
              {formatDate(expiresAt)}
            </p>
          </div>

          {/* Machine fingerprint — copyable monospace field */}
          <div>
            <p className="text-xs text-slate-400 mb-1">Machine ID</p>
            <div className="flex items-center gap-2">
              <code className="text-xs font-mono text-slate-300 bg-slate-800 rounded px-2 py-1 truncate flex-1 min-w-0">
                {machineFingerprint || '—'}
              </code>
              {machineFingerprint && (
                <button
                  onClick={handleCopy}
                  title={copied ? 'Copied!' : 'Copy to clipboard'}
                  className="shrink-0 p-1.5 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-700 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  aria-label="Copy machine fingerprint"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
            {copied && (
              <p className="text-xs text-emerald-400 mt-1">Copied!</p>
            )}
          </div>
        </div>

        {/* Feature gates — shown when not fully active (Req 19.1) */}
        {lockedFeatures.length > 0 && (
          <div className="pt-2 border-t border-slate-700/50">
            <p className="text-xs text-slate-400 mb-2 flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-slate-500" />
              Locked features
            </p>
            <ul className="space-y-1">
              {lockedFeatures.map((feature) => (
                <li
                  key={feature}
                  className="flex items-center gap-2 text-xs text-slate-400"
                >
                  <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                  {feature}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Deactivate link — shown only when active (Req 19.5) */}
        {isActive && (
          <div className="pt-2 border-t border-slate-700/50 flex items-center justify-between">
            <p className="text-xs text-slate-500">
              Remove this machine from the license
            </p>
            <button
              onClick={handleDeactivate}
              disabled={deactivating}
              className="text-xs text-red-400 hover:text-red-300 underline underline-offset-2 transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-400 rounded"
            >
              {deactivating ? 'Deactivating…' : 'Deactivate'}
            </button>
          </div>
        )}

        {/* Deactivation error */}
        {deactivateError && (
          <p className="text-xs text-red-400 flex items-center gap-1.5">
            <XCircle className="w-3.5 h-3.5 shrink-0" />
            {deactivateError}
          </p>
        )}
      </div>

      {/* ── Activation form (Req 19.2, 19.3, 19.4) ────────────────────── */}
      {!isActive && (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 space-y-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-widest">
            Activate License
          </h2>

          {/* Success banner (Req 19.4) */}
          {activationSuccess && (
            <div className="flex items-center gap-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 px-4 py-3">
              <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
              <p className="text-sm text-emerald-300">
                License activated successfully. All features are now unlocked.
              </p>
            </div>
          )}

          {/* Error banner (Req 19.3) */}
          {activationError && !activationSuccess && (
            <div className="flex items-center gap-2 rounded-lg bg-red-500/10 border border-red-500/30 px-4 py-3">
              <XCircle className="w-4 h-4 text-red-400 shrink-0" />
              <p className="text-sm text-red-300">{activationError}</p>
            </div>
          )}

          <form onSubmit={handleActivate} className="space-y-3">
            <div>
              <label
                htmlFor="license-key-input"
                className="block text-xs text-slate-400 mb-1.5"
              >
                License Key
              </label>
              <input
                id="license-key-input"
                type="text"
                value={licenseKey}
                onChange={(e) => setLicenseKey(e.target.value)}
                placeholder="XXXX-XXXX-XXXX-XXXX"
                spellCheck={false}
                autoComplete="off"
                disabled={isActivating}
                className="w-full rounded-lg bg-slate-800 border border-slate-700 text-slate-100 placeholder-slate-500 text-sm font-mono px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent disabled:opacity-50 transition"
              />
            </div>

            <button
              type="submit"
              disabled={isActivating || !licenseKey.trim()}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-sky-600 hover:bg-sky-500 active:bg-sky-700 transition-colors py-2.5 px-4 text-sm font-semibold text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Key className="w-4 h-4" />
              {isActivating ? 'Activating…' : 'Activate'}
            </button>
          </form>
        </div>
      )}

      {/* ── Purchase link (Req 19.6) ───────────────────────────────────── */}
      {isInactive && (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 flex items-center justify-between gap-4 flex-wrap">
          <div>
            <p className="text-sm font-medium text-slate-200">
              Don't have a license?
            </p>
            <p className="text-xs text-slate-500 mt-0.5">
              Purchase a license to unlock all features including real-time
              protection, unlimited scans, and whitelist management.
            </p>
          </div>
          <button
            onClick={() => openExternal('https://gsmshield.app/pricing')}
            className="shrink-0 flex items-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 transition-colors py-2 px-4 text-sm font-semibold text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            Get a License
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
