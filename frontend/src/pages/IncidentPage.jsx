import { useEffect, useState } from "react";
import { Pause, Play, RotateCcw, ChevronRight, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { fetchDemoIncident } from "@/lib/api";
import { TopBar, SyntheticBadge } from "@/components/TopBar";
import { SEV, SeverityPill } from "@/lib/severity";
import { CodeSnippet } from "@/components/CodeSnippet";

const FindingChips = ({ ids, findings }) => (
  <div className="flex flex-wrap gap-1.5">
    {ids.map((id) => {
      const f = findings[id];
      return (
        <span key={id} data-testid={`incident-finding-chip-${id}`} className="inline-flex items-center gap-1.5 rounded-sm border border-white/10 bg-[#04060A] px-2 py-1 font-mono text-[10px] text-slate-300">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV[f.severity].hex }} /> {id} · {f.title}
        </span>
      );
    })}
  </div>
);

const StepBody = ({ step, findings }) => (
  <div className="space-y-5">
    {step.evidence && (
      <div>
        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-emerald-400">Observed evidence</p>
        <pre className="whitespace-pre-wrap rounded-md border border-white/[0.06] bg-[#04060A] p-3 font-mono text-[11.5px] leading-relaxed text-slate-300">{step.evidence.join("\n")}</pre>
      </div>
    )}
    {step.path_node_ids && (
      <div data-testid="incident-path-chain" className="flex flex-wrap items-center gap-2">
        {step.path_node_ids.map((id, i) => (
          <span key={id} className="flex items-center gap-2">
            <span className="rounded-md border px-3 py-2 font-mono text-[11px] text-white" style={{ borderColor: SEV[findings[id].severity].hex, boxShadow: `0 0 12px ${SEV[findings[id].severity].hex}33` }}>
              {id}
              <span className="block text-[10px] text-slate-400">{findings[id].title}</span>
            </span>
            {i < step.path_node_ids.length - 1 && <ChevronRight className="h-4 w-4 text-cyan" />}
          </span>
        ))}
      </div>
    )}
    {step.observed_evidence && (
      <div className="grid gap-3 lg:grid-cols-2">
        <div data-testid="incident-observed-evidence" className="rounded-md border border-white/[0.08] bg-[#04060A]/70 p-3">
          <p className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-emerald-400">Observed evidence · deterministic</p>
          <ul className="space-y-1.5 text-sm text-slate-300">{step.observed_evidence.map((e) => <li key={e}>· {e}</li>)}</ul>
        </div>
        <div data-testid="incident-ai-interpretation" className="rounded-md border border-cyan/25 bg-cyan/[0.04] p-3">
          <p className="mb-1.5 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-cyan"><Sparkles className="h-3 w-3" /> AI interpretation · pre-generated for replay</p>
          <p className="text-sm leading-relaxed text-slate-100">{step.ai_interpretation}</p>
          <p className="mt-2 font-mono text-[10px] text-slate-500">confidence {Math.round(step.confidence * 100)}%</p>
        </div>
      </div>
    )}
    {step.actions && (
      <div className="space-y-2">
        {step.actions.map((a, i) => (
          <div key={a.title} data-testid={`incident-action-${i + 1}`} className="grid gap-3 rounded-md border border-white/[0.06] p-3 lg:grid-cols-12">
            <div className="lg:col-span-5">
              <div className="flex items-center gap-2">
                <span className={`rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${a.priority === "P0" ? "border-sev-critical/50 text-sev-critical" : "border-sev-high/50 text-sev-high"}`}>{a.priority}</span>
                <SeverityPill severity={findings[a.finding_id].severity} />
                <span className="font-mono text-[10px] text-slate-500">{a.finding_id}</span>
              </div>
              <p className="mt-1.5 text-sm font-medium text-white">{a.title}</p>
              <p className="mt-1 text-sm text-slate-400">{a.detail}</p>
            </div>
            <div className="lg:col-span-7"><CodeSnippet code={a.snippet} language={a.snippet_language} testId={`incident-snippet-${i + 1}`} /></div>
          </div>
        ))}
      </div>
    )}
    {step.finding_ids && !step.actions && (
      <div>
        <p className="eyebrow mb-1.5">Referenced findings</p>
        <FindingChips ids={step.finding_ids} findings={findings} />
      </div>
    )}
  </div>
);

export default function IncidentPage() {
  const [inc, setInc] = useState(null);
  const [idx, setIdx] = useState(0);
  const [playing, setPlaying] = useState(true);

  useEffect(() => {
    fetchDemoIncident().then(setInc).catch(() => toast.error("Could not load incident"));
  }, []);

  useEffect(() => {
    if (!inc || !playing) return undefined;
    if (idx >= inc.steps.length - 1) {
      setPlaying(false);
      return undefined;
    }
    const t = setTimeout(() => setIdx((i) => i + 1), inc.steps[idx].duration_ms + 1200);
    return () => clearTimeout(t);
  }, [inc, idx, playing]);

  if (!inc) {
    return (
      <div className="min-h-screen">
        <TopBar />
        <div className="mx-auto max-w-[1600px] px-8 pt-16 font-mono text-sm text-slate-400">Loading incident…</div>
      </div>
    );
  }

  const step = inc.steps[idx];

  return (
    <div className="min-h-screen">
      <TopBar environment={inc.environment} status={playing ? "replaying" : "paused"} />
      <main className="mx-auto max-w-6xl px-4 pb-24 pt-10 md:px-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="eyebrow">Demo incident mode · {inc.id} · {inc.environment.name}</p>
            <h1 data-testid="incident-title" className="mt-2 font-mono text-3xl font-bold tracking-tight text-white sm:text-4xl">{inc.title}</h1>
            <p className="mt-2 max-w-2xl text-sm text-slate-400">{inc.summary}</p>
          </div>
          <div className="flex items-center gap-2">
            <SyntheticBadge testId="incident-synthetic-badge" size="md" />
            <button type="button" data-testid="incident-play-pause" onClick={() => setPlaying(!playing)} className="rounded-md border border-white/10 p-2 text-slate-300 hover:border-white/30 hover:text-white">
              {playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            </button>
            <button type="button" data-testid="incident-restart" onClick={() => { setIdx(0); setPlaying(true); }} className="rounded-md border border-white/10 p-2 text-slate-300 hover:border-white/30 hover:text-white">
              <RotateCcw className="h-4 w-4" />
            </button>
          </div>
        </div>

        <ol data-testid="demo-incident-stepper" className="mt-10 grid grid-cols-5 gap-2">
          {inc.steps.map((s, i) => {
            const state = i < idx ? "done" : i === idx ? "active" : "todo";
            return (
              <li key={s.key}>
                <button
                  type="button"
                  data-testid={`demo-incident-step-${s.index}`}
                  data-state={state}
                  onClick={() => { setIdx(i); setPlaying(false); }}
                  className={`w-full rounded-md border p-3 text-left transition-colors ${state === "active" ? "border-cyan/70 bg-cyan/[0.06] glow-cyan" : state === "done" ? "border-cyan/30 bg-[#0D111A]" : "border-white/[0.08] bg-[#0D111A]/60"}`}
                >
                  <p className={`font-mono text-[10px] uppercase tracking-[0.16em] ${state === "todo" ? "text-slate-600" : "text-cyan"}`}>0{s.index}</p>
                  <p className={`mt-1 font-mono text-sm font-semibold ${state === "todo" ? "text-slate-500" : "text-white"}`}>{s.name}</p>
                  <div className="mt-2 h-[2px] w-full bg-white/[0.06]">
                    <div className={`h-full bg-cyan ${state === "done" ? "w-full" : state === "active" ? "w-1/2 animate-pulse" : "w-0"}`} />
                  </div>
                </button>
              </li>
            );
          })}
        </ol>

        <section key={step.key} data-testid={`incident-step-content-${step.key}`} className="panel fade-up mt-6 p-6">
          <p className="eyebrow">Step {step.index} · {step.name}</p>
          <h2 className="mt-2 text-base font-semibold text-white md:text-lg">{step.headline}</h2>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-300">{step.description}</p>
          <div className="mt-6"><StepBody step={step} findings={inc.findings} /></div>
          <div className="mt-6 flex justify-end">
            <button
              type="button"
              data-testid="incident-next-step"
              disabled={idx >= inc.steps.length - 1}
              onClick={() => { setIdx((i) => Math.min(i + 1, inc.steps.length - 1)); setPlaying(false); }}
              className="rounded-md bg-cyan px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-[#07090E] hover:bg-cyan-hover disabled:opacity-30"
            >
              Next step →
            </button>
          </div>
        </section>
      </main>
    </div>
  );
}
