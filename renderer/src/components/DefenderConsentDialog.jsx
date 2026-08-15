/**
 * renderer/src/components/DefenderConsentDialog.jsx
 *
 * First-run consent gate + Tamper Protection guidance UI.
 *
 * Rendered at the App shell level so it can appear over any page on first run.
 *
 * Two responsibilities (Requirements 2.3, 2.4):
 *  - Consent gate (2.3): show an in-app dialog explaining that Windows Defender
 *    will be disabled and require the user to click "Agree" before ANY disable
 *    step runs. On Agree → record consent then run setup. On Decline → record the
 *    decline and dismiss (no disable step runs).
 *  - Tamper Protection guidance (2.4): when the `defender:setup-result` push
 *    reports `tamperBlocked`, show the exact Windows Security settings path and a
 *    Retry action that re-runs setup after the user turns Tamper Protection off.
 *
 * All window.electronAPI access is guarded so the renderer still works when
 * electronAPI is undefined (e.g. in a browser/test context).
 *
 * Preservation: this component only reacts to the first-run setup surface. It
 * does not alter any non-setup UI flow — when there is nothing to show it renders
 * nothing.
 */

import React, { useEffect, useRef, useState } from 'react';
import { ShieldAlert, ShieldOff, AlertTriangle, RefreshCw, X } from 'lucide-react';

/**
 * The exact Windows Security settings path the user must follow to turn Tamper
 * Protection off. Used as a fallback when the push payload omits it.
 */
const TAMPER_SETTINGS_PATH =
  'Settings > Windows Security > Virus & threat protection > ' +
  'Virus & threat protection settings > Tamper Protection > Off';

/**
 * View modes for the dialog.
 * @typedef {'hidden' | 'consent' | 'tamper'} DialogMode
 */

export default function DefenderConsentDialog() {
  /** @type {[DialogMode, Function]} */
  const [mode, setMode] = useState('hidden');
  /** Exact settings path to display in the tamper view (from payload or fallback). */
  const [tamperPath, setTamperPath] = useState(TAMPER_SETTINGS_PATH);
  /** Whether a setup/consent request is in flight (disables buttons). */
  const [busy, setBusy] = useState(false);

  const dialogRef = useRef(null);

  // ── Decide whether to present the consent dialog on first mount ────────────
  useEffect(() => {
    let cancelled = false;

    async function checkConsent() {
      const api = window.electronAPI;
      if (!api?.defenderGetConsent) return;
      try {
        const res = await api.defenderGetConsent();
        // res may be { consent: boolean } or a raw boolean.
        const consent = typeof res === 'object' && res !== null ? res.consent : res;
        if (!cancelled && !consent) {
          setMode('consent');
        }
      } catch (_) {
        // If we cannot determine consent, do not force a dialog.
      }
    }

    checkConsent();
    return () => {
      cancelled = true;
    };
  }, []);

  // ── Subscribe to setup-result pushes to drive tamper / re-consent views ────
  useEffect(() => {
    const api = window.electronAPI;
    if (!api?.onDefenderSetupResult) return undefined;

    const handler = (payload) => {
      if (!payload || typeof payload !== 'object') return;

      if (payload.tamperBlocked) {
        setTamperPath(payload.tamperSettingsPath || TAMPER_SETTINGS_PATH);
        setBusy(false);
        setMode('tamper');
        return;
      }

      if (payload.needsConsent) {
        setBusy(false);
        setMode('consent');
        return;
      }

      // Success (or any non-blocking result): clear the dialog.
      if (payload.success) {
        setBusy(false);
        setMode('hidden');
      }
    };

    api.onDefenderSetupResult(handler);
    return () => {
      if (api.offDefenderSetupResult) {
        api.offDefenderSetupResult(handler);
      }
    };
  }, []);

  // ── Move focus into the dialog when it opens (accessibility) ───────────────
  useEffect(() => {
    if (mode !== 'hidden' && dialogRef.current) {
      const focusable = dialogRef.current.querySelector(
        'button:not([disabled])'
      );
      if (focusable) focusable.focus();
    }
  }, [mode]);

  // ── Handlers ───────────────────────────────────────────────────────────────

  async function handleAgree() {
    const api = window.electronAPI;
    setBusy(true);
    try {
      if (api?.defenderConsent) {
        await api.defenderConsent(true);
      }
      if (api?.defenderRunSetup) {
        await api.defenderRunSetup();
      }
      // Keep the dialog visible until a setup-result push resolves the outcome
      // (success hides it; tamper-blocked switches to the tamper view).
    } catch (_) {
      setBusy(false);
    }
  }

  async function handleDecline() {
    const api = window.electronAPI;
    setBusy(true);
    try {
      if (api?.defenderConsent) {
        await api.defenderConsent(false);
      }
    } catch (_) {
      /* best-effort — dismiss regardless */
    } finally {
      setBusy(false);
      setMode('hidden');
    }
  }

  async function handleRetry() {
    const api = window.electronAPI;
    setBusy(true);
    try {
      if (api?.defenderRunSetup) {
        await api.defenderRunSetup();
      }
      // Await the next setup-result push to update the view.
    } catch (_) {
      setBusy(false);
    }
  }

  function handleDismissTamper() {
    setMode('hidden');
  }

  // ── Render ───────────────────────────────────────────────────────────────

  if (mode === 'hidden') return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
      role="presentation"
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="defender-dialog-title"
        aria-describedby="defender-dialog-body"
        className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden"
      >
        {mode === 'consent' ? (
          // ── Consent gate (Requirement 2.3) ──────────────────────────────
          <>
            <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-800 bg-slate-950/40">
              <ShieldAlert className="w-5 h-5 text-sky-400 shrink-0" />
              <h2
                id="defender-dialog-title"
                className="text-base font-semibold text-slate-100"
              >
                Disable Windows Defender?
              </h2>
            </div>

            <div id="defender-dialog-body" className="px-6 py-5 space-y-4">
              <p className="text-sm text-slate-300 leading-relaxed">
                To make GSM Shield your active real-time protection, Windows
                Defender's real-time scanning and the Defender antivirus service
                will be disabled on this PC.
              </p>
              <ul className="text-sm text-slate-400 space-y-1.5 list-disc pl-5">
                <li>No disable step runs until you click Agree.</li>
                <li>
                  Windows Defender is fully restored if you uninstall GSM Shield.
                </li>
                <li>
                  You can re-run setup later from Settings if you decline now.
                </li>
              </ul>
            </div>

            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-800 bg-slate-950/40">
              <button
                type="button"
                onClick={handleDecline}
                disabled={busy}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm text-slate-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
              >
                Decline
              </button>
              <button
                type="button"
                onClick={handleAgree}
                disabled={busy}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 active:bg-sky-700 text-sm font-semibold text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
              >
                {busy ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <ShieldOff className="w-4 h-4" />
                )}
                {busy ? 'Working…' : 'Agree'}
              </button>
            </div>
          </>
        ) : (
          // ── Tamper Protection guidance (Requirement 2.4) ────────────────
          <>
            <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-800 bg-slate-950/40">
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
              <h2
                id="defender-dialog-title"
                className="text-base font-semibold text-slate-100"
              >
                Turn off Tamper Protection to continue
              </h2>
              <button
                type="button"
                onClick={handleDismissTamper}
                aria-label="Dismiss"
                className="ml-auto text-slate-500 hover:text-slate-300 rounded p-1 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div id="defender-dialog-body" className="px-6 py-5 space-y-4">
              <p className="text-sm text-slate-300 leading-relaxed">
                Windows Tamper Protection is on, which silently blocks changes to
                Defender. Turn it off, then retry setup.
              </p>

              <div className="rounded-lg bg-slate-800/60 border border-slate-700/60 px-4 py-3">
                <p className="text-xs uppercase tracking-wider text-slate-500 mb-1.5">
                  Settings path
                </p>
                <p className="text-sm text-slate-200 font-mono break-words leading-relaxed">
                  {tamperPath}
                </p>
              </div>

              <p className="text-xs text-slate-500">
                After turning Tamper Protection off, click Retry below.
              </p>
            </div>

            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-800 bg-slate-950/40">
              <button
                type="button"
                onClick={handleDismissTamper}
                disabled={busy}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm text-slate-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
              >
                Later
              </button>
              <button
                type="button"
                onClick={handleRetry}
                disabled={busy}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 active:bg-sky-700 text-sm font-semibold text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
              >
                <RefreshCw className={`w-4 h-4 ${busy ? 'animate-spin' : ''}`} />
                {busy ? 'Retrying…' : 'Retry'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
