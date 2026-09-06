import { Link } from "react-router-dom";
import { ShieldAlert, Radio } from "lucide-react";

export const TopBar = ({ environment, status }) => {
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
          <span data-testid="live-engine-badge" className="hidden items-center gap-2 rounded-full border border-emerald-400/30 bg-emerald-400/[0.06] px-3 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-emerald-300 md:inline-flex">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Live assessment engine
          </span>
        </div>
      </div>
    </header>
  );
};
