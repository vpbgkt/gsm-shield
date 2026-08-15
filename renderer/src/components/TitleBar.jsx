import React from 'react';
import { ShieldCheck, Minus, Square, X } from 'lucide-react';

/**
 * TitleBar — custom frameless window chrome (Requirements 13.1, 13.2).
 *
 * Layout:
 *   [drag region: logo + app name]  [no-drag: window controls]
 *
 * The drag-region uses -webkit-app-region: drag (via .drag-region CSS class)
 * so the user can reposition the frameless window by clicking and dragging
 * anywhere on the bar except the control buttons (Requirement 13.2).
 *
 * Window controls call window.electronAPI.* IPC methods exposed by preload.js
 * (Requirement 13.1).
 */
export default function TitleBar() {
  const handleMinimize = () => {
    window.electronAPI?.windowMinimize?.();
  };

  const handleMaximize = () => {
    window.electronAPI?.windowMaximize?.();
  };

  const handleClose = () => {
    window.electronAPI?.windowClose?.();
  };

  return (
    <header
      className="drag-region fixed top-0 left-56 right-0 h-10 z-50 flex items-center justify-between bg-slate-950 border-b border-slate-800"
    >
      {/* Left side — app identity (draggable) */}
      <div className="flex items-center gap-2 pl-4">
        <ShieldCheck size={16} className="text-emerald-400 shrink-0" />
        <span className="text-xs font-semibold tracking-wider text-slate-300 uppercase">
          GSM Shield AV
        </span>
      </div>

      {/* Right side — window controls (NOT draggable) */}
      <div className="no-drag flex items-center">
        {/* Minimize */}
        <button
          onClick={handleMinimize}
          aria-label="Minimize window"
          className="w-11 h-10 flex items-center justify-center text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors duration-100"
        >
          <Minus size={14} />
        </button>

        {/* Maximize / restore */}
        <button
          onClick={handleMaximize}
          aria-label="Maximize window"
          className="w-11 h-10 flex items-center justify-center text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors duration-100"
        >
          <Square size={13} />
        </button>

        {/* Close */}
        <button
          onClick={handleClose}
          aria-label="Close window"
          className="w-11 h-10 flex items-center justify-center text-slate-400 hover:bg-red-600 hover:text-white transition-colors duration-100"
        >
          <X size={15} />
        </button>
      </div>
    </header>
  );
}
