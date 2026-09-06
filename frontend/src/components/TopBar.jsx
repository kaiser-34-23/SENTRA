import { Link, useLocation } from "react-router-dom";
import { ShieldAlert, Radio } from "lucide-react";

export const SyntheticBadge = ({ testId = "synthetic-badge", size = "sm" }) => (
  <span
    data-testid={testId}
    className={`inline-flex items-center gap-2 rounded-full border border-amber-400/40 bg-amber-400/10 font-mono uppercase tracking-[0.16em] text-amber-300 ${
      size === "sm" ? "px-2.5 py-1 text-[10px]" : "px-3 py-1.5 text-xs"
    }`}
  >
    <span className="relative flex h-1.5 w-1.5">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-75" />
      <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-amber-400" />
    </span>
    Synthetic environment
  </span>
);

export const TopBar = ({ environment, status }) => {
  const { pathname } = useLocation();
  return (
    <header data-testid="app-header" className="sticky top-0 z-40 border-b border-white/[0.08] bg-[#07090E]/85 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-[1600px] items-center justify-between px-4 md:px-8">
        <div className="flex items-center gap-6">
          <Link to="/" data-testid="wordmark-link" className="group flex items-center gap-2.5">
            <ShieldAlert className="h-5 w-5 text-cyan transition-transform group-hover:scale-110" strokeWidth={2.2} />
            <span className="font-mono text-base font-bold tracking-[0.22em] text-white">SENTRA</span>
            <span className="hidden font-mono text-[10px] uppercase tracking-[0.18em] text-slate-500 md:inline">Autonomous Security Intelligence</span>
          </Link>
          {environment && (
            <div data-testid="topbar-environment" className="hidden items-center gap-2 border-l border-white/10 pl-6 font-mono text-xs text-slate-300 lg:flex">
              <span className="text-slate-500">target</span>
              <span className="text-white">{environment.name}</span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-3">
          {status && (
            <span data-testid="topbar-scan-status" className="hidden items-center gap-2 font-mono text-[10px] uppercase tracking-[0.16em] text-cyan md:flex">
              <Radio className="h-3.5 w-3.5 animate-pulse" /> {status}
            </span>
          )}
          <Link
            to="/incident"
            data-testid="nav-incident-link"
            className={`hidden rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors md:inline ${
              pathname === "/incident" ? "border-cyan/60 text-cyan" : "border-white/10 text-slate-400 hover:border-white/30 hover:text-white"
            }`}
          >
            Incident mode
          </Link>
          <SyntheticBadge testId="synthetic-badge-topbar" />
        </div>
      </div>
    </header>
  );
};
