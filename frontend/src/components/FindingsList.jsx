import { useState } from "react";
import { ChevronDown, Crosshair } from "lucide-react";
import { SEV, SEVERITIES, SeverityPill } from "@/lib/severity";

const FindingCard = ({ f, assetName, onLocate, onPath }) => {
  const [open, setOpen] = useState(f.severity === "critical");
  const s = SEV[f.severity];
  return (
    <div data-testid={`finding-card-${f.id}`} className={`panel overflow-hidden border-l-2 transition-colors ${s.border}`} style={{ borderLeftColor: s.hex }}>
      <button type="button" data-testid={`finding-toggle-${f.id}`} onClick={() => setOpen(!open)} className="flex w-full items-start justify-between gap-4 p-4 text-left">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityPill severity={f.severity} />
            <span className="font-mono text-[10px] text-slate-500">{f.id}</span>
            <span className="font-mono text-[10px] text-slate-500">· {assetName}</span>
            {onPath && <span className="rounded-sm border border-cyan/40 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider text-cyan">on attack path</span>}
          </div>
          <h4 className="mt-1.5 text-sm font-medium text-white">{f.title}</h4>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          <span className="font-mono text-[11px] text-slate-400">{Math.round(f.confidence * 100)}% conf</span>
          <ChevronDown className={`h-4 w-4 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`} />
        </div>
      </button>
      {open && (
        <div className="grid gap-4 border-t border-white/[0.06] p-4 lg:grid-cols-2">
          <div>
            <p className="eyebrow mb-2">Observed evidence</p>
            <pre data-testid={`finding-evidence-${f.id}`} className="overflow-x-auto rounded-md border border-white/[0.06] bg-[#04060A] p-3 font-mono text-[11.5px] leading-relaxed text-slate-300 whitespace-pre-wrap">
              {f.evidence}
            </pre>
          </div>
          <div className="space-y-4">
            <div>
              <p className="eyebrow mb-1.5">Why it matters</p>
              <p className="text-sm leading-relaxed text-slate-300">{f.why_it_matters}</p>
            </div>
            <div>
              <p className="eyebrow mb-1.5">Recommended action</p>
              <p className="text-sm leading-relaxed text-slate-200">{f.recommended_action}</p>
            </div>
            {f.mitre?.length > 0 && (
              <div data-testid={`finding-mitre-${f.id}`}>
                <p className="eyebrow mb-1.5">MITRE ATT&amp;CK context</p>
                <div className="flex flex-wrap gap-1.5">
                  {f.mitre.map((technique) => (
                    <span key={technique.id} title={technique.name} className="rounded-sm border border-cyan/25 bg-cyan/[0.04] px-2 py-1 font-mono text-[10px] text-cyan">
                      {technique.id} · {technique.tactic}
                    </span>
                  ))}
                </div>
              </div>
            )}
            <button
              type="button"
              data-testid={`finding-locate-${f.id}`}
              onClick={() => onLocate(f.id)}
              className="inline-flex items-center gap-2 rounded-md border border-cyan/40 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-cyan hover:bg-cyan/10"
            >
              <Crosshair className="h-3.5 w-3.5" /> Locate in attack graph
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export const FindingsList = ({ findings, assets, pathNodeIds, onLocate }) => {
  const [filter, setFilter] = useState("all");
  const assetName = (id) => assets.find((a) => a.id === id)?.name || id;
  const visible = findings.filter((f) => filter === "all" || f.severity === filter);
  const grouped = SEVERITIES.map((s) => [s, visible.filter((f) => f.severity === s)]).filter(([, l]) => l.length);

  return (
    <div data-testid="findings-list-container">
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {["all", ...SEVERITIES].map((s) => {
          const n = s === "all" ? findings.length : findings.filter((f) => f.severity === s).length;
          return (
            <button
              key={s}
              type="button"
              data-testid={`findings-severity-filter-${s}`}
              onClick={() => setFilter(s)}
              className={`rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors ${
                filter === s ? "border-cyan/60 bg-cyan/10 text-cyan" : "border-white/10 text-slate-400 hover:border-white/30"
              }`}
            >
              {s} <span className="text-slate-500">{n}</span>
            </button>
          );
        })}
      </div>
      <div className="space-y-6">
        {grouped.map(([sev, list]) => (
          <section key={sev} data-testid={`findings-group-${sev}`}>
            <h3 className={`mb-2 font-mono text-xs uppercase tracking-[0.18em] ${SEV[sev].text}`}>
              {SEV[sev].label} · {list.length}
            </h3>
            <div className="space-y-2">
              {list.map((f) => (
                <FindingCard key={f.id} f={f} assetName={assetName(f.asset_id)} onLocate={onLocate} onPath={pathNodeIds.has(f.id)} />
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
};
