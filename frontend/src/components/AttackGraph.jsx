import { useEffect, useMemo, useState } from "react";
import { ReactFlow, Background, Controls, Handle, Position, MarkerType } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Database, Skull } from "lucide-react";
import { SEV } from "@/lib/severity";
import { NodePanel } from "@/components/NodePanel";

const AttackerNode = ({ data }) => (
  <div data-testid="attack-graph-node-attacker" className="flex items-center gap-2 rounded-md border border-white/30 bg-[#131826] px-3 py-2 font-mono text-xs text-white">
    <Skull className="h-4 w-4 text-slate-300" /> {data.label}
    <Handle type="source" position={Position.Right} className="!bg-slate-400 !border-0 !w-1.5 !h-1.5" />
  </div>
);

const FindingNode = ({ data, selected }) => {
  const s = SEV[data.severity];
  return (
    <div
      data-testid={`attack-graph-node-${data.id}`}
      className={`w-[210px] rounded-md border bg-[#0D111A] px-3 py-2 transition-shadow ${selected ? "ring-1 ring-cyan" : ""} ${data.severity === "critical" && data.on_path ? "pulse-critical" : ""}`}
      style={{ borderColor: data.on_path ? s.hex : "rgba(255,255,255,0.15)", boxShadow: data.on_path ? `0 0 14px ${s.hex}33` : "none" }}
    >
      <Handle type="target" position={Position.Left} className="!bg-slate-500 !border-0 !w-1.5 !h-1.5" />
      <div className="flex items-center justify-between">
        <span className="font-mono text-[9px] uppercase tracking-wider" style={{ color: s.hex }}>
          {data.severity}
        </span>
        <span className="font-mono text-[9px] text-slate-500">{data.id}</span>
      </div>
      <p className="mt-1 text-[11.5px] leading-snug text-slate-100">{data.label}</p>
      <p className="mt-1 truncate font-mono text-[9px] text-slate-500">{data.assetName}</p>
      <Handle type="source" position={Position.Right} className="!bg-slate-500 !border-0 !w-1.5 !h-1.5" />
    </div>
  );
};

const AssetNode = ({ data }) => (
  <div data-testid={`attack-graph-node-${data.id}`} className="flex items-center gap-2 rounded-md border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 font-mono text-xs text-white">
    <Handle type="target" position={Position.Left} className="!bg-sev-critical !border-0 !w-1.5 !h-1.5" />
    <Database className="h-4 w-4 text-sev-critical" />
    <div>
      <p className="text-[9px] uppercase tracking-wider text-sev-critical">crown jewel</p>
      <p>{data.label}</p>
    </div>
  </div>
);

const nodeTypes = { attacker: AttackerNode, finding: FindingNode, asset: AssetNode };

const layout = (graph, assets) => {
  const byLayer = {};
  graph.nodes.forEach((n) => (byLayer[n.layer] = [...(byLayer[n.layer] || []), n]));
  const maxRows = Math.max(...Object.values(byLayer).map((l) => l.length));
  return graph.nodes.map((n) => {
    const col = byLayer[n.layer];
    const idx = col.indexOf(n);
    const y = (idx - (col.length - 1) / 2) * 118 + (maxRows * 118) / 2;
    return {
      id: n.id,
      type: n.type,
      position: { x: n.layer * 290, y },
      data: { ...n, assetName: assets.find((a) => a.id === n.asset_id)?.name },
      draggable: true,
    };
  });
};

export const AttackGraph = ({ graph, findings, paths, assets, rules, focusId, onFocusHandled }) => {
  const [selected, setSelected] = useState(null);
  const [activePath, setActivePath] = useState(null);

  useEffect(() => {
    if (focusId) {
      setSelected(focusId);
      onFocusHandled?.();
    }
  }, [focusId, onFocusHandled]);

  const highlight = useMemo(() => {
    if (!activePath) return null;
    const p = paths.find((x) => x.id === activePath);
    return p ? { nodes: new Set([...p.node_ids, "attacker", `asset:${p.impact_asset_id}`]), edges: new Set([...p.edge_ids, `attacker->${p.node_ids[0]}`, `${p.node_ids.at(-1)}->asset:${p.impact_asset_id}`]) } : null;
  }, [activePath, paths]);

  const nodes = useMemo(
    () => layout(graph, assets).map((n) => ({ ...n, selected: n.id === selected, className: highlight && !highlight.nodes.has(n.id) ? "dim" : "" })),
    [graph, assets, selected, highlight],
  );

  const edges = useMemo(
    () =>
      graph.edges.map((e, i) => {
        const dim = highlight && !highlight.edges.has(e.id);
        const color = e.kind === "impact" ? "#FF3B30" : e.on_path ? "#00F0FF" : "rgba(148,163,184,0.5)";
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: "smoothstep",
          label: e.relation,
          labelStyle: { fill: "#94A3B8", fontFamily: "JetBrains Mono", fontSize: 9 },
          labelBgStyle: { fill: "#07090E", fillOpacity: 0.9 },
          labelBgPadding: [4, 2],
          className: `sentra-edge ${dim ? "dim" : ""}`,
          style: { stroke: color, strokeWidth: e.on_path ? 2 : 1.2, animationDelay: `${i * 90}ms` },
          markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
          data: e,
        };
      }),
    [graph, highlight],
  );

  return (
    <div data-testid="attack-graph-container" className="panel relative overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] px-5 py-3">
        <div>
          <p className="eyebrow">Show me the attack</p>
          <p className="text-sm text-slate-400">Edges are deterministic correlation rules. Click a node for evidence.</p>
        </div>
        <div className="flex flex-wrap gap-1.5" data-testid="attack-path-selector">
          <button
            type="button"
            data-testid="attack-path-all"
            onClick={() => setActivePath(null)}
            className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider ${!activePath ? "border-cyan/60 text-cyan" : "border-white/10 text-slate-400 hover:border-white/30"}`}
          >
            all
          </button>
          {paths.map((p) => (
            <button
              key={p.id}
              type="button"
              data-testid={`attack-path-${p.id}`}
              onClick={() => setActivePath(activePath === p.id ? null : p.id)}
              className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider ${activePath === p.id ? "border-cyan/60 bg-cyan/10 text-cyan" : "border-white/10 text-slate-400 hover:border-white/30"}`}
            >
              {p.id} · {p.hops} hops · {Math.round(p.likelihood * 100)}%
            </button>
          ))}
        </div>
      </div>
      <div className="flex">
        <div className={`h-[560px] transition-[width] duration-300 ${selected ? "w-full lg:w-[62%]" : "w-full"}`}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.3}
            onNodeClick={(_, n) => setSelected(n.id)}
            onPaneClick={() => setSelected(null)}
            proOptions={{ hideAttribution: true }}
            colorMode="dark"
          >
            <Background color="rgba(255,255,255,0.06)" gap={24} />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
        {selected && <NodePanel nodeId={selected} graph={graph} findings={findings} paths={paths} assets={assets} rules={rules} onClose={() => setSelected(null)} onSelect={setSelected} />}
      </div>
    </div>
  );
};
