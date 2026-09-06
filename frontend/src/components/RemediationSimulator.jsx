import { CheckCircle2, RotateCcw, ShieldCheck } from "lucide-react";

export const RemediationSimulator = ({ items, fixedIds, comparison, busyFindingId, onToggle, onReset }) => {
  const selected = new Set(fixedIds);
  const fixedOnPath = new Set(comparison?.fixed_on_path_ids || []);

  return (
    <section data-testid="remediation-simulator" className={`panel overflow-hidden ${comparison ? "border-emerald-400/30" : "border-cyan/20"}`}>
      <div className="grid gap-5 p-5 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <div>
          <div className="flex items-center gap-2">
            {comparison ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <ShieldCheck className="h-4 w-4 text-cyan" />}
            <p className={`font-mono text-[11px] uppercase tracking-[0.18em] ${comparison ? "text-emerald-300" : "text-cyan"}`}>
              {comparison ? "Security state updated" : "Test remediation"}
            </p>
          </div>

          {comparison ? (
            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-3 gap-2">
                <Metric label="Risk" before={comparison.risk_before} after={comparison.risk_after} />
                <Metric label="Security score" before={comparison.baseline_score} after={comparison.simulated_score} positive />
                <Metric label="Attack paths" before={comparison.baseline_path_count} after={comparison.remaining_path_count} />
              </div>
              {fixedOnPath.size > 0 && (
                <div data-testid="remediation-blocked-at" className="rounded-md border border-emerald-400/20 bg-emerald-400/[0.05] p-3">
                  <p className="eyebrow text-emerald-300">Blocked at</p>
                  <p className="mt-1 text-sm text-white">
                    {items.filter((item) => fixedOnPath.has(item.finding_id)).map((item) => item.title).join(" · ")}
                  </p>
                  <p className="mt-1 font-mono text-[10px] text-slate-400">
                    {comparison.removed_edge_ids.length} relationship{comparison.removed_edge_ids.length === 1 ? "" : "s"} removed from the graph
                  </p>
                </div>
              )}
              <p data-testid="remediation-state-explanation" className="text-sm leading-relaxed text-slate-300">{comparison.explanation}</p>
              <button type="button" data-testid="remediation-reset" onClick={onReset} disabled={Boolean(busyFindingId)} className="flex items-center gap-1.5 rounded-md border border-white/15 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-slate-300 hover:border-white/30 hover:text-white disabled:opacity-50">
                <RotateCcw className="h-3 w-3" /> Reset original state
              </button>
            </div>
          ) : (
            <div className="mt-4">
              <h2 className="font-mono text-xl font-semibold text-white">What if we fix this first?</h2>
              <p className="mt-2 max-w-xl text-sm leading-relaxed text-slate-400">
                Toggle controls to remove their findings from the model. SENTRA recalculates the graph, reachable attack paths, and risk without touching the target.
              </p>
            </div>
          )}
        </div>

        <div>
          <div className="mb-2 flex items-center justify-between gap-3">
            <p className="eyebrow">Simulated controls</p>
            <span className="font-mono text-[10px] text-slate-500">{selected.size} selected · reversible</span>
          </div>
          <div className="max-h-[260px] space-y-1.5 overflow-y-auto pr-1">
            {items.map((item) => {
              const checked = selected.has(item.finding_id);
              return (
                <label key={item.finding_id} data-testid={`remediation-control-${item.finding_id}`} className={`flex cursor-pointer items-start gap-3 rounded-md border px-3 py-2.5 transition-colors ${checked ? "border-emerald-400/30 bg-emerald-400/[0.06]" : "border-white/[0.07] bg-[#080B12] hover:border-cyan/25"}`}>
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={Boolean(busyFindingId)}
                    onChange={() => onToggle(item.finding_id)}
                    className="mt-0.5 h-4 w-4 accent-[#00F0FF]"
                  />
                  <span className="min-w-0 flex-1">
                    <span className={`block text-sm ${checked ? "text-emerald-100" : "text-slate-200"}`}>{item.title}</span>
                    <span className="mt-0.5 block font-mono text-[10px] text-slate-500">{item.finding_id} · {item.priority}{item.on_path ? " · breaks a current path" : ""}</span>
                  </span>
                  {busyFindingId === item.finding_id && <span className="font-mono text-[9px] uppercase text-cyan">calculating…</span>}
                </label>
              );
            })}
          </div>
        </div>
      </div>
      <div className="border-t border-white/[0.06] bg-[#080B12]/70 px-5 py-2.5 font-mono text-[10px] text-slate-500">
        Simulation only · observed evidence and the original assessment remain unchanged
      </div>
    </section>
  );
};

const Metric = ({ label, before, after, positive = false }) => {
  const improved = positive ? after >= before : after <= before;
  return (
    <div className="rounded-md border border-white/[0.07] bg-[#080B12] p-2.5">
      <p className="font-mono text-[9px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className="mt-1 font-mono text-lg font-semibold tabular-nums text-slate-400">
        {before} <span className={improved ? "text-emerald-300" : "text-sev-high"}>→ {after}</span>
      </p>
    </div>
  );
};
