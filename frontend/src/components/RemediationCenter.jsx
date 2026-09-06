import { SeverityPill } from "@/lib/severity";
import { CodeSnippet } from "@/components/CodeSnippet";

const PRIORITY = { P0: "text-sev-critical border-sev-critical/50", P1: "text-sev-high border-sev-high/50", P2: "text-sev-medium border-sev-medium/50", P3: "text-slate-400 border-white/20" };

export const RemediationCenter = ({ items, assets }) => {
  const assetName = (id) => assets.find((a) => a.id === id)?.name || id;
  return (
    <div data-testid="remediation-center-container" className="space-y-3">
      <p className="text-sm text-slate-400">
        Ordered by priority, then severity. Fixes that break a validated attack path are flagged. Snippets are starting points, not drop-in patches.
      </p>
      {items.map((r, i) => (
        <div key={r.finding_id} data-testid={`remediation-item-${r.finding_id}`} className="panel fade-up grid gap-4 p-4 lg:grid-cols-12" style={{ animationDelay: `${i * 40}ms` }}>
          <div className="lg:col-span-5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-2xl font-bold tabular-nums text-slate-600">{String(i + 1).padStart(2, "0")}</span>
              <span data-testid={`remediation-priority-${r.finding_id}`} className={`rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${PRIORITY[r.priority]}`}>
                {r.priority}
              </span>
              <SeverityPill severity={r.severity} />
              {r.on_path && <span className="rounded-sm border border-cyan/40 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider text-cyan">breaks attack path</span>}
            </div>
            <h4 className="mt-2 text-sm font-medium text-white">{r.title}</h4>
            <p className="mt-1 font-mono text-[11px] text-slate-500">
              {r.finding_id} · {assetName(r.asset_id)}
            </p>
            <p className="mt-3 text-sm leading-relaxed text-slate-300">{r.explanation}</p>
          </div>
          <div className="lg:col-span-7">{r.snippet ? <CodeSnippet code={r.snippet} language={r.snippet_language} testId={`remediation-code-snippet-${r.finding_id}`} /> : <p className="text-sm text-slate-500">No snippet — process change.</p>}</div>
        </div>
      ))}
    </div>
  );
};
