import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  FolderOpen,
  FileCode,
  AlertTriangle,
  Play,
  RotateCcw,
  Sparkles,
  CheckCircle2,
  Cpu,
  Loader2,
  X,
} from 'lucide-react';
import useExpiroStore from '../store/expiroStore';

export default function ExpiroScannerPanel() {
  const {
    status,
    currentFile,
    scannedCount,
    totalCount,
    threshold,
    detections,
    stats,
    disinfecting,
    disinfectingPath,
    disinfectionNotice,
    lastScanDuration,
    errorMessage,
    loadConfig,
    loadStats,
    setThreshold,
    scanDirectory,
    scanFile,
    disinfectFile,
    disinfectAll,
    clearNotice,
    resetScan,
    cancelScan,
  } = useExpiroStore();

  const [inputPath, setInputPath] = useState('C:\\Program Files\\Git');
  const [targetType, setTargetType] = useState('dir'); // 'dir' | 'file'

  useEffect(() => {
    loadConfig();
    loadStats();
  }, [loadConfig, loadStats]);

  const isScanning = status === 'scanning';

  const handleStartScan = async () => {
    if (!inputPath.trim()) return;
    if (targetType === 'dir') {
      await scanDirectory(inputPath.trim());
    } else {
      await scanFile(inputPath.trim());
    }
  };

  const handleQuickSystemScan = async () => {
    setInputPath('C:\\Windows\\System32');
    setTargetType('dir');
    await scanDirectory('C:\\Windows\\System32');
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Engine Status */}
      <div className="rounded-xl border border-indigo-500/30 bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 shadow-inner">
              <Cpu className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold text-slate-100">
                  Expiro PE Heuristic Engine v2
                </h3>
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2.5 py-0.5 text-xs font-medium text-emerald-400 border border-emerald-500/25">
                  <CheckCircle2 className="h-3 w-3" />
                  Calibrated
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Structural PE header inspection, Entry Point tracking, W^X violations, and encrypted overlay heuristics.
              </p>
            </div>
          </div>

          {/* Sensitivity Selector */}
          <div className="flex items-center gap-2 self-start sm:self-auto bg-slate-900/80 p-1.5 rounded-lg border border-slate-800">
            <span className="text-xs text-slate-400 px-2 font-medium">Threshold:</span>
            {[
              { label: 'Aggressive', value: 50 },
              { label: 'Balanced (Rec)', value: 60 },
              { label: 'Strict', value: 75 },
            ].map((option) => (
              <button
                key={option.value}
                onClick={() => setThreshold(option.value)}
                className={`px-2.5 py-1 text-xs rounded-md font-medium transition-colors ${
                  threshold === option.value
                    ? 'bg-indigo-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Target Input & Scan Controls */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-slate-200">Scan Target Path</span>
          <div className="flex items-center gap-3 text-xs">
            <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
              <input
                type="radio"
                name="targetType"
                checked={targetType === 'dir'}
                onChange={() => setTargetType('dir')}
                className="text-indigo-600 focus:ring-indigo-500"
              />
              Directory (Recursive)
            </label>
            <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
              <input
                type="radio"
                name="targetType"
                checked={targetType === 'file'}
                onChange={() => setTargetType('file')}
                className="text-indigo-600 focus:ring-indigo-500"
              />
              Single PE File
            </label>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              value={inputPath}
              onChange={(e) => setInputPath(e.target.value)}
              placeholder={targetType === 'dir' ? 'e.g. C:\\Program Files\\Git' : 'e.g. C:\\path\\to\\app.exe'}
              disabled={isScanning}
              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3.5 py-2.5 text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition"
            />
          </div>

          {isScanning ? (
            <button
              onClick={cancelScan}
              className="flex items-center gap-2 rounded-lg bg-rose-600 hover:bg-rose-500 active:bg-rose-700 text-white px-5 py-2.5 text-sm font-medium shadow-md transition-colors"
            >
              <X className="h-4 w-4" />
              Cancel Scan
            </button>
          ) : (
            <button
              onClick={handleStartScan}
              disabled={!inputPath.trim()}
              className="flex items-center gap-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 disabled:opacity-50 text-white px-5 py-2.5 text-sm font-medium shadow-md transition-colors"
            >
              <Search className="h-4 w-4" />
              Run Expiro Scan
            </button>
          )}
        </div>

        {/* Quick Location Shortcuts */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-slate-400">
          <span className="text-slate-500 font-medium">Quick locations:</span>
          <button
            onClick={() => { setInputPath('C:\\Program Files\\Git'); setTargetType('dir'); }}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            Git Binaries
          </button>
          <button
            onClick={() => { setInputPath('C:\\Program Files\\nodejs'); setTargetType('dir'); }}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            Node.js
          </button>
          <button
            onClick={handleQuickSystemScan}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            System32
          </button>
        </div>
      </div>

      {/* Progress View */}
      {isScanning && (
        <div className="rounded-xl border border-indigo-500/40 bg-slate-900/90 p-5 space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span className="font-medium text-indigo-400 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-indigo-400 animate-ping" />
              PE Structural Analysis in Progress (Worker Thread)...
            </span>
            <div className="flex items-center gap-3">
              <span className="font-mono tabular-nums text-slate-300 font-medium">
                {scannedCount} PE files analyzed
              </span>
              <button
                onClick={cancelScan}
                className="text-xs text-rose-400 hover:text-rose-300 hover:underline font-medium px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 transition-colors"
              >
                Stop Scan
              </button>
            </div>
          </div>

          <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
            <div className="h-full bg-gradient-to-r from-indigo-500 to-sky-400 w-full animate-indeterminate" />
          </div>

          <p className="text-xs font-mono text-slate-400 truncate" title={currentFile}>
            Current: {currentFile || 'Scanning files...'}
          </p>
        </div>
      )}

      {/* Results View */}
      {status === 'complete' && (
        <div className="space-y-4">
          {/* Disinfection Result Notice */}
          {disinfectionNotice && (
            <div
              className={`rounded-xl border p-4 flex items-center justify-between gap-3 animate-fade-in ${
                disinfectionNotice.type === 'success'
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                  : 'border-red-500/30 bg-red-500/10 text-red-300'
              }`}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                {disinfectionNotice.type === 'success' ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                )}
                <span className="text-xs font-medium truncate">{disinfectionNotice.message}</span>
              </div>
              <button
                onClick={clearNotice}
                className="text-slate-400 hover:text-slate-200 transition shrink-0"
                title="Dismiss"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          )}

          {detections.length === 0 ? (
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-5 flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/20 text-emerald-400 shrink-0">
                <ShieldCheck className="h-7 w-7" />
              </div>
              <div className="flex-1 min-w-0">
                <h4 className="text-sm font-semibold text-emerald-300">
                  Target Clean — No Expiro Infections Detected
                </h4>
                <p className="text-xs text-slate-300 mt-0.5">
                  Analyzed {scannedCount} executable(s) at {threshold}% threshold in {lastScanDuration ?? 1}s. All section headers, entry points, and overlays match known-good patterns.
                </p>
              </div>
              <button
                onClick={resetScan}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 transition"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                Reset
              </button>
            </div>
          ) : (
            <div className="rounded-xl border border-red-500/40 bg-slate-900 overflow-hidden shadow-xl">
              <div className="flex items-center justify-between bg-red-950/40 border-b border-red-500/30 px-5 py-3.5">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-red-400" />
                  <span className="text-sm font-semibold text-red-200">
                    {detections.length} Potential Infection(s) Identified
                  </span>
                </div>
                <button
                  onClick={disinfectAll}
                  disabled={disinfecting}
                  className="flex items-center gap-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white px-3 py-1.5 text-xs font-semibold shadow transition disabled:opacity-50"
                >
                  {disinfecting && disinfectingPath === 'ALL' ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>Disinfecting All...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="h-3.5 w-3.5" />
                      <span>Disinfect & Quarantine All</span>
                    </>
                  )}
                </button>
              </div>

              <div className="divide-y divide-slate-800 max-h-[460px] overflow-y-auto pr-1">
                {detections.map((det, idx) => (
                  <div key={idx} className="p-4 space-y-2 hover:bg-slate-800/40 transition">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-mono text-slate-200 truncate select-all" title={det.filePath}>
                          {det.filePath}
                        </p>
                        <div className="flex flex-wrap gap-1.5 mt-2">
                          {(det.reasons || []).map((reason, rIdx) => (
                            <span
                              key={rIdx}
                              className="inline-flex items-center rounded bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-300 border border-red-500/20"
                            >
                              {String(reason).replace(/[^\x20-\x7E]/g, ' ')}
                            </span>
                          ))}
                        </div>
                      </div>

                      <div className="flex flex-col items-end gap-2 shrink-0">
                        <span className="rounded-full bg-red-500/20 px-2.5 py-0.5 text-xs font-bold text-red-400 border border-red-500/30">
                          {det.confidence}% Confidence
                        </span>
                        <button
                          onClick={() => disinfectFile(det.filePath, det)}
                          disabled={disinfecting}
                          className="inline-flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 hover:underline font-medium disabled:opacity-50"
                        >
                          {disinfecting && disinfectingPath === det.filePath ? (
                            <>
                              <Loader2 className="h-3 w-3 animate-spin text-indigo-400" />
                              <span>Fixing...</span>
                            </>
                          ) : (
                            <span>Disinfect</span>
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Error View */}
      {status === 'error' && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-red-400 shrink-0" />
          <p className="text-xs text-red-300 font-mono flex-1">
            Scan Error: {errorMessage || 'An error occurred during PE analysis.'}
          </p>
          <button
            onClick={resetScan}
            className="text-xs text-slate-400 hover:text-slate-200 underline"
          >
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
}
