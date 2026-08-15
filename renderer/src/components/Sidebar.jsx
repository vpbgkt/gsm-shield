import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ScanLine,
  ShieldCheck,
  Archive,
  Settings,
  KeyRound,
} from 'lucide-react';

/**
 * Navigation items for the six required pages (Requirement 13.3).
 * Each item maps a label to its route path and a lucide-react icon.
 */
const NAV_ITEMS = [
  { label: 'Dashboard',  to: '/',            icon: LayoutDashboard },
  { label: 'Scanner',    to: '/scanner',     icon: ScanLine         },
  { label: 'Whitelist',  to: '/whitelist',   icon: ShieldCheck      },
  { label: 'Quarantine', to: '/quarantine',  icon: Archive          },
  { label: 'Settings',   to: '/settings',    icon: Settings         },
  { label: 'License',    to: '/license',     icon: KeyRound         },
];

/**
 * Sidebar — persistent vertical navigation panel.
 * Uses React Router <NavLink> for client-side navigation (Requirement 13.4).
 * Styled with the dark slate-900 / slate-950 palette (Requirement 13.1).
 */
export default function Sidebar() {
  return (
    <aside className="flex flex-col w-56 shrink-0 bg-slate-900 border-r border-slate-800 pt-10 pb-4 select-none">
      {/* Logo / brand mark */}
      <div className="px-5 mb-8 flex items-center gap-3">
        <div className="flex items-center justify-center w-8 h-8 rounded-md bg-emerald-600 shrink-0">
          <ShieldCheck size={18} className="text-white" />
        </div>
        <span className="text-sm font-semibold tracking-wide text-slate-100">
          GSM Shield AV
        </span>
      </div>

      {/* Navigation links */}
      <nav className="flex-1 flex flex-col gap-1 px-3">
        {NAV_ITEMS.map(({ label, to, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}   // exact match for root so it doesn't stay active on sub-routes
            className={({ isActive }) =>
              [
                'flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors duration-150',
                isActive
                  ? 'bg-emerald-600/20 text-emerald-400'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100',
              ].join(' ')
            }
          >
            <Icon size={17} className="shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Version footer */}
      <div className="px-5 pt-4 border-t border-slate-800">
        <p className="text-xs text-slate-600">v1.0.0</p>
      </div>
    </aside>
  );
}
