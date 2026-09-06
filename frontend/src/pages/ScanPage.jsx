import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { Loader2, CheckCircle2 } from "lucide-react";
import { streamUrl } from "@/lib/api";
import { TopBar } from "@/components/TopBar";

const STAGES = [
  ["init", "Init"],
  ["tls", "TLS"],
  ["headers", "Headers"],
  ["endpoints", "Endpoints"],
  ["auth", "Auth"],
  ["correlate", "Correlate"],
  ["graph", "Attack paths"],
  ["score", "Score"],
  ["ai", "AI analyst"],
  ["done", "Done"],
];
const LEVEL = { info: "text-slate-300", ok: "text-emerald-400", warn: "text-amber-300", crit: "text-sev-critical" };

const LogLine = ({ entry }) => (
  <div data-testid="terminal-log-line" className="fade-up flex gap-3 font-mono text-[12.5px] leading-6">
    <span className="w-16 shrink-0 text-slate-600">{entry.t.toFixed(2)}s</span>
    <span className={`w-24 shrink-0 ${LEVEL[entry.level]}`}>[{entry.tag}]</span>
    <span className="text-slate-200">{entry.message}</span>
  </div>
);

export default function ScanPage() {
  const { scanId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const [lines, setLines] = useState([]);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("init");
  const [done, setDone] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    const es = new EventSource(streamUrl(scanId));
    es.onmessage = (ev) => {
      const data = JSON.parse(ev.data);
      if (data.type === "log") {
        setLines((l) => [...l, data]);
        setProgress(data.progress);
        setStage(data.stage);
      } else if (data.type === "complete") {
        setDone(true);
        es.close();
        setTimeout(() => navigate(`/results/${scanId}`), 900);
      }
    };
    es.onerror = () => es.close();
    return () => es.close();
  }, [scanId, navigate]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  const stageIdx = STAGES.findIndex(([k]) => k === stage);
  const activeMode = location.state?.assessment_mode === "active";

  return (
    <div className="min-h-screen">
      <TopBar status={done ? "complete" : "scanning"} />
      <main className="mx-auto max-w-5xl px-4 pt-12 md:px-8">
        <p className="eyebrow">Live scan · {activeMode ? "bounded active staging checks" : "authorized read-only checks"}</p>
        <h1 className="mt-3 font-mono text-3xl font-bold tracking-tight text-white sm:text-4xl">
          {done ? "Scan complete." : "Scanning…"}
        </h1>
        <p data-testid="scan-target" className="mt-2 break-all font-mono text-xs text-cyan">{location.state?.target || "Target supplied by the assessor"}</p>

        <div className="mt-8 flex flex-wrap gap-2" data-testid="scan-stage-indicators">
          {STAGES.map(([key, label], i) => {
            const state = i < stageIdx || done ? "done" : i === stageIdx ? "active" : "todo";
            return (
              <div
                key={key}
                data-testid={`scan-stage-${key}`}
                data-state={state}
                className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors ${
                  state === "done" ? "border-cyan/40 text-cyan" : state === "active" ? "border-white/40 text-white" : "border-white/10 text-slate-600"
                }`}
              >
                {state === "done" ? <CheckCircle2 className="h-3 w-3" /> : state === "active" ? <Loader2 className="h-3 w-3 animate-spin" /> : <span className="h-3 w-3 rounded-full border border-current" />}
                {label}
              </div>
            );
          })}
        </div>

        <div data-testid="streaming-terminal-container" className="scanline relative mt-6 overflow-hidden rounded-md border border-white/[0.1] bg-[#04060A]">
          <div className="flex items-center justify-between border-b border-white/[0.08] px-4 py-2">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-sev-critical/80" />
              <span className="h-2.5 w-2.5 rounded-full bg-sev-medium/80" />
              <span className="h-2.5 w-2.5 rounded-full bg-sev-low/80" />
              <span className="ml-3 font-mono text-[11px] text-slate-500">sentra — scan {scanId.slice(0, 8)}</span>
            </div>
            <span data-testid="scan-progress" className="font-mono text-[11px] text-cyan">{progress}%</span>
          </div>
          <div className="h-[3px] w-full bg-white/[0.04]">
            <div className="h-full bg-cyan transition-[width] duration-500 ease-out" style={{ width: `${progress}%` }} />
          </div>
          <div data-testid="terminal-log-output" className="h-[380px] overflow-y-auto px-4 py-4">
            {lines.map((l, i) => (
              <LogLine key={i} entry={l} />
            ))}
            {!done && (
              <div className="flex gap-3 font-mono text-[12.5px] leading-6">
                <span className="w-16 shrink-0" />
                <span className="caret text-cyan">▍</span>
              </div>
            )}
            <div ref={bottomRef} />
          </div>
        </div>
        {done && (
          <button
            type="button"
            data-testid="view-results-button"
            onClick={() => navigate(`/results/${scanId}`)}
            className="mt-6 rounded-md bg-cyan px-5 py-3 font-mono text-xs font-semibold uppercase tracking-[0.14em] text-[#07090E] hover:bg-cyan-hover"
          >
            Open results →
          </button>
        )}
      </main>
    </div>
  );
}
