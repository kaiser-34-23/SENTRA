import { Brain, RefreshCw, Sparkles } from "lucide-react";

const Section = ({ title, children, testId }) => (
  <div data-testid={testId}>
    <p className="eyebrow mb-1.5">{title}</p>
    {children}
  </div>
);

export const AIAnalyst = ({ analysis, loading, error, onRetry, paths, findings, compact = false }) => {
  const byId = Object.fromEntries(findings.map((f) => [f.id, f]));
  const top = paths[0];

  return (
    <div data-testid="ai-analyst-panel" className="panel flex h-full flex-col p-5">
      <div className="flex items-center justify-between">
        <p className="eyebrow flex items-center gap-2">
          <Brain className="h-3.5 w-3.5 text-cyan" /> AI security analyst
        </p>
        <span className="font-mono text-[10px] text-slate-500">gemini-3-flash · narrative only</span>
      </div>

      <div data-testid="ai-analyst-observed-evidence" className="mt-4 rounded-md border border-white/[0.08] bg-[#04060A]/70 p-3">
        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-emerald-400">Observed evidence · deterministic</p>
        <ul className="space-y-1 font-mono text-[11.5px] text-slate-300">
          <li>
            {findings.length} findings · {paths.length} validated attack path{paths.length === 1 ? "" : "s"}
          </li>
          {top && (
            <li className="truncate">
              Top chain: {top.node_ids.map((n) => byId[n]?.id || n).join(" → ")} · likelihood {top.likelihood}
            </li>
          )}
        </ul>
      </div>

      <div data-testid="ai-analyst-ai-narrative" className="mt-3 flex-1 rounded-md border border-cyan/25 bg-cyan/[0.04] p-3">
        <p className="mb-2 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-cyan">
          <Sparkles className="h-3 w-3" /> AI interpretation
        </p>
        {loading && (
          <div data-testid="ai-analyst-loading" className="flex items-center gap-3 py-6 text-sm text-slate-400">
            <RefreshCw className="spin-slow h-4 w-4 text-cyan" /> Analyst is reading the validated graph…
          </div>
        )}
        {!loading && error && (
          <div data-testid="ai-analyst-error" className="py-4 text-sm text-slate-400">
            {error}
            <button type="button" data-testid="ai-analyst-retry" onClick={onRetry} className="ml-3 rounded-sm border border-cyan/50 px-2 py-0.5 font-mono text-[10px] uppercase text-cyan hover:bg-cyan/10">
              retry
            </button>
          </div>
        )}
        {!loading && analysis && (
          <div className="space-y-4">
            <p data-testid="ai-summary" className="text-sm leading-relaxed text-slate-100">{analysis.summary}</p>
            <Section title="Business impact" testId="ai-business-impact">
              <p className="text-sm leading-relaxed text-slate-300">{analysis.business_impact}</p>
            </Section>
            {!compact && (
              <>
                <Section title="Likely attacker objective" testId="ai-attacker-objective">
                  <p className="text-sm leading-relaxed text-slate-300">{analysis.attacker_objective}</p>
                </Section>
                {analysis.path_narratives?.length > 0 && (
                  <Section title="Attack path narratives" testId="ai-path-narratives">
                    <div className="space-y-2">
                      {analysis.path_narratives.map((n) => (
                        <div key={n.path_id} data-testid={`ai-path-narrative-${n.path_id}`} className="rounded-md border border-white/[0.06] p-3">
                          <p className="font-mono text-[10px] text-cyan">
                            {n.path_id} · {n.title}
                          </p>
                          <p className="mt-1 text-sm leading-relaxed text-slate-300">{n.narrative}</p>
                        </div>
                      ))}
                    </div>
                  </Section>
                )}
                {analysis.remediation?.length > 0 && (
                  <Section title="Analyst priority order" testId="ai-remediation">
                    <ol className="space-y-1.5">
                      {analysis.remediation.map((r, i) => (
                        <li key={r.finding_id + i} className="flex gap-2 text-sm text-slate-300">
                          <span className="font-mono text-slate-500">{i + 1}.</span>
                          <span>
                            <span className="font-mono text-[11px] text-cyan">{r.finding_id}</span> {r.action} <span className="text-slate-500">— {r.reason}</span>
                          </span>
                        </li>
                      ))}
                    </ol>
                  </Section>
                )}
              </>
            )}
            <div className="flex flex-wrap items-center gap-2 border-t border-white/[0.06] pt-3 font-mono text-[10px] text-slate-500">
              <span>priority: <span className="text-slate-300">{analysis.priority}</span></span>
              <span>· confidence: <span className="text-slate-300">{Math.round(analysis.confidence * 100)}%</span></span>
              <span>· cites: {analysis.evidence_cited?.slice(0, 8).join(", ")}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
