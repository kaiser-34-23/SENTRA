import { X, ArrowRight } from "lucide-react";
import { SeverityPill } from "@/lib/severity";

const Relation = ({ edge, dir, label, onSelect }) => (
  <button type="button" data-testid={`node-panel-edge-${edge.id}`} onClick={() => onSelect(dir === "in" ? edge.source : edge.target)} className="w-full rounded-md border border-white/[0.06] p-2.5 text-left hover:border-cyan/40">
    <p className="flex items-center gap-1.5 font-mono text-[10px] text-cyan">
      {dir === "in" ? <>{edge.source} <ArrowRight className="h-3 w-3" /> this</> : <>this <ArrowRight className="h-3 w-3" /> {edge.target}</>}
      <span className="text-slate-500">· {edge.relation}</span>
    </p>
    <p className="mt-1 text-xs text-slate-300">{label}</p>
    <p className="mt-1 text-[11px] leading-relaxed text-slate-500">{edge.explanation}</p>
  </button>
);

export const NodePanel = ({ nodeId, graph, findings, paths, assets, rules, onClose, onSelect }) => {
  const node = graph.nodes.find((n) => n.id === nodeId);
  const finding = findings.find((f) => f.id === nodeId);
  const asset = assets.find((a) => a.id === (finding?.asset_id || node?.asset_id));
  const incoming = graph.edges.filter((e) => e.target === nodeId);
  const outgoing = graph.edges.filter((e) => e.source === nodeId);
  const inPaths = paths.filter((p) => p.node_ids.includes(nodeId) || `asset:${p.impact_asset_id}` === nodeId);
  const ruleName = (id) => rules.find((r) => r.id === id)?.name;
  const nodeLabel = (id) => graph.nodes.find((n) => n.id === id)?.label || id;

  return (
    <aside data-testid="attack-graph-side-panel" className="hidden h-[560px] w-[38%] flex-col overflow-y-auto border-l border-white/[0.08] bg-[#0D111A] lg:flex">
      <div className="sticky top-0 flex items-start justify-between gap-3 border-b border-white/[0.08] bg-[#0D111A] p-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {finding && <SeverityPill severity={finding.severity} />}
            <span className="font-mono text-[10px] uppercase tracking-wider text-slate-500">{node?.type}</span>
            <span className="font-mono text-[10px] text-slate-500">{nodeId}</span>
          </div>
          <h4 data-testid="node-panel-title" className="mt-1.5 text-sm font-medium text-white">{node?.label}</h4>
          {asset && <p className="font-mono text-[10px] text-slate-500">{asset.name} · {asset.exposure}</p>}
        </div>
        <button type="button" data-testid="node-panel-close" onClick={onClose} className="rounded-sm border border-white/10 p-1 text-slate-400 hover:text-white">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="space-y-5 p-4">
        {finding && (
          <>
            <div>
              <p className="eyebrow mb-1.5">Observed evidence</p>
              <pre data-testid="node-panel-evidence" className="overflow-x-auto whitespace-pre-wrap rounded-md border border-white/[0.06] bg-[#04060A] p-3 font-mono text-[11px] leading-relaxed text-slate-300">{finding.evidence}</pre>
            </div>
            <div>
              <p className="eyebrow mb-1.5">Why it matters</p>
              <p className="text-sm leading-relaxed text-slate-300">{finding.why_it_matters}</p>
            </div>
            <div className="flex gap-4 font-mono text-[11px] text-slate-400">
              <span>confidence {Math.round(finding.confidence * 100)}%</span>
              <span>tags: {finding.tags.join(", ")}</span>
            </div>
          </>
        )}
        {node?.type === "attacker" && <p className="text-sm text-slate-300">Anonymous internet position. Every chain begins here, at an internet-facing weakness.</p>}
        {node?.type === "asset" && <p className="text-sm text-slate-300">Terminal asset for {inPaths.length} validated path{inPaths.length === 1 ? "" : "s"}. Reaching this node is the attacker's objective.</p>}

        {(incoming.length > 0 || outgoing.length > 0) && (
          <div>
            <p className="eyebrow mb-2">Relationships · {incoming.length + outgoing.length}</p>
            <div className="space-y-2">
              {incoming.map((e) => <Relation key={e.id} edge={e} dir="in" label={ruleName(e.rule_id) || e.relation} onSelect={onSelect} />)}
              {outgoing.map((e) => <Relation key={e.id} edge={e} dir="out" label={ruleName(e.rule_id) || e.relation} onSelect={onSelect} />)}
            </div>
          </div>
        )}

        {inPaths.length > 0 && (
          <div>
            <p className="eyebrow mb-2">Why this chain matters</p>
            <div className="space-y-2">
              {inPaths.map((p) => (
                <div key={p.id} data-testid={`node-panel-path-${p.id}`} className="rounded-md border border-cyan/25 bg-cyan/[0.04] p-3">
                  <p className="font-mono text-[10px] text-cyan">{p.id} · likelihood {Math.round(p.likelihood * 100)}% · {p.hops} hops</p>
                  <p className="mt-1.5 font-mono text-[11px] leading-relaxed text-slate-300">{p.node_ids.map(nodeLabel).join(" → ")}</p>
                  <p className="mt-1.5 text-xs text-slate-400">
                    Ends at <span className="text-slate-200">{assets.find((a) => a.id === p.impact_asset_id)?.name}</span>. Break any single link and the chain collapses.
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};
