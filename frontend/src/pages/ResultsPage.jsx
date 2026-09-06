import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { fetchResults, requestAiAnalysis, simulateRemediation } from "@/lib/api";
import { TopBar } from "@/components/TopBar";
import { ScoreGauge } from "@/components/ScoreGauge";
import { CategoryBars } from "@/components/CategoryBars";
import { AIAnalyst } from "@/components/AIAnalyst";
import { AttackGraph } from "@/components/AttackGraph";
import { FindingsList } from "@/components/FindingsList";
import { RemediationCenter } from "@/components/RemediationCenter";
import { RemediationSimulator } from "@/components/RemediationSimulator";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

export default function ResultsPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [simulation, setSimulation] = useState(null);
  const [busyFindingId, setBusyFindingId] = useState(null);
  const [ai, setAi] = useState({ analysis: null, loading: false, error: null });
  const [focusId, setFocusId] = useState(null);
  const [tab, setTab] = useState("findings");
  const graphRef = useRef(null);
  const simulatorRef = useRef(null);
  const simulationRequestRef = useRef(0);

  const runAi = useCallback(async () => {
    setAi({ analysis: null, loading: true, error: null });
    try {
      const res = await requestAiAnalysis(scanId);
      setAi({ analysis: res.analysis, loading: false, error: null });
    } catch (e) {
      setAi({ analysis: null, loading: false, error: "AI analyst unavailable right now. The deterministic results above are unaffected." });
    }
  }, [scanId]);

  useEffect(() => {
    fetchResults(scanId)
      .then((d) => {
        if (d.status !== "complete") {
          navigate(`/scan/${scanId}`);
          return;
        }
        setData(d);
        if (d.ai_analysis) setAi({ analysis: d.ai_analysis, loading: false, error: null });
        else runAi();
      })
      .catch(() => toast.error("Scan not found"));
  }, [scanId, navigate, runAi]);

  const view = simulation || data;
  const pathNodeIds = useMemo(() => new Set((view?.attack_paths || []).flatMap((p) => p.node_ids)), [view]);

  const locate = (id) => {
    setFocusId(id);
    graphRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const simulateFix = async (findingId) => {
    const fixedIds = simulation?.fixed_finding_ids || [];
    const nextIds = fixedIds.includes(findingId)
      ? fixedIds.filter((id) => id !== findingId)
      : [...fixedIds, findingId];
    const requestId = ++simulationRequestRef.current;
    if (nextIds.length === 0) {
      setSimulation(null);
      setBusyFindingId(null);
      return;
    }
    setBusyFindingId(findingId);
    try {
      const result = await simulateRemediation(scanId, nextIds);
      if (requestId !== simulationRequestRef.current) return;
      setSimulation(result);
      toast.success(`Security state updated: risk ${result.comparison.risk_before} → ${result.comparison.risk_after}`);
    } catch (e) {
      if (requestId !== simulationRequestRef.current) return;
      toast.error(e?.response?.data?.detail || "Could not simulate that remediation");
    } finally {
      if (requestId === simulationRequestRef.current) setBusyFindingId(null);
    }
  };

  const resetSimulation = () => {
    simulationRequestRef.current += 1;
    setSimulation(null);
    setBusyFindingId(null);
  };

  if (!data) {
    return (
      <div className="min-h-screen">
        <TopBar />
        <div data-testid="results-loading" className="mx-auto max-w-[1600px] px-8 pt-16 font-mono text-sm text-slate-400">Loading results…</div>
      </div>
    );
  }

  const env = data.environment;
  const displayed = view || data;

  return (
    <div className="min-h-screen">
      <TopBar environment={env} status="results" />
      <main data-testid="results-dashboard" className="mx-auto max-w-[1600px] space-y-6 px-4 pb-24 pt-8 md:px-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="eyebrow">Results · {env.name} · {env.sector} · {data.assessment_mode === "active" ? "BOUNDED ACTIVE" : "READ-ONLY"}</p>
            <h1 className="mt-2 font-mono text-3xl font-bold tracking-tight text-white sm:text-4xl">
              {displayed.attack_paths.length > 0
                ? `${displayed.attack_paths.length} validated attack path${displayed.attack_paths.length === 1 ? "" : "s"} to sensitive data.`
                : simulation
                  ? "All validated attack paths are blocked."
                  : displayed.findings.length > 0
                  ? "Observed controls, prioritized by risk."
                  : "No validated attack path was observed."}
            </h1>
            {env.target && <p data-testid="results-target" className="mt-2 break-all font-mono text-xs text-cyan">{env.target}</p>}
          </div>
          <div className="flex gap-2">
            <button type="button" data-testid="results-test-remediation" onClick={() => simulatorRef.current?.scrollIntoView({ behavior: "smooth", block: "center" })} className="rounded-md border border-cyan/40 px-4 py-2 font-mono text-[11px] uppercase tracking-wider text-cyan hover:bg-cyan/10">
              Test remediation
            </button>
            <button type="button" data-testid="results-new-scan" onClick={() => navigate("/")} className="rounded-md border border-white/10 px-4 py-2 font-mono text-[11px] uppercase tracking-wider text-slate-300 hover:border-white/30 hover:text-white">
              New scan
            </button>
          </div>
        </div>

        <section className="grid gap-4 lg:grid-cols-12">
          <div className="fade-up lg:col-span-3"><ScoreGauge score={displayed.score} /></div>
          <div className="fade-up lg:col-span-4" style={{ animationDelay: "80ms" }}><CategoryBars categories={displayed.score.categories} /></div>
          <div className="fade-up lg:col-span-5" style={{ animationDelay: "160ms" }}>
            <AIAnalyst analysis={ai.analysis} loading={ai.loading} error={ai.error} onRetry={runAi} paths={displayed.attack_paths} findings={displayed.findings} compact stateUpdate={simulation?.comparison} />
          </div>
        </section>

        <div ref={simulatorRef} className="scroll-mt-20">
          <RemediationSimulator items={data.remediation.map((item) => ({ ...item, ...(displayed.remediation.find((current) => current.finding_id === item.finding_id) || {}) }))} fixedIds={simulation?.fixed_finding_ids || []} comparison={simulation?.comparison} busyFindingId={busyFindingId} onToggle={simulateFix} onReset={resetSimulation} />
        </div>

        <section ref={graphRef} className="fade-up scroll-mt-20" style={{ animationDelay: "240ms" }}>
          <AttackGraph graph={displayed.graph} findings={displayed.findings} paths={displayed.attack_paths} assets={env.assets} rules={displayed.rules} focusId={focusId} onFocusHandled={() => setFocusId(null)} onRemediate={simulateFix} busyFindingId={busyFindingId} comparison={simulation?.comparison} />
        </section>

        <Tabs value={tab} onValueChange={setTab} className="fade-up" style={{ animationDelay: "320ms" }}>
          <TabsList className="h-auto gap-1 rounded-md border border-white/[0.08] bg-[#0D111A] p-1">
            {[
              ["findings", `Findings · ${displayed.findings.length}`],
              ["remediation", `Remediation · ${displayed.remediation.length}`],
              ["analyst", "AI analyst · full"],
            ].map(([k, l]) => (
              <TabsTrigger key={k} value={k} data-testid={`results-tab-${k}`} className="rounded-sm px-4 py-2 font-mono text-[11px] uppercase tracking-wider text-slate-400 data-[state=active]:bg-cyan/10 data-[state=active]:text-cyan">
                {l}
              </TabsTrigger>
            ))}
          </TabsList>
          <TabsContent value="findings" className="mt-4">
            <FindingsList findings={displayed.findings} assets={env.assets} pathNodeIds={pathNodeIds} onLocate={locate} />
          </TabsContent>
          <TabsContent value="remediation" className="mt-4">
            <RemediationCenter items={displayed.remediation} assets={env.assets} onFix={simulateFix} busyFindingId={busyFindingId} />
          </TabsContent>
          <TabsContent value="analyst" className="mt-4">
            <AIAnalyst analysis={ai.analysis} loading={ai.loading} error={ai.error} onRetry={runAi} paths={displayed.attack_paths} findings={displayed.findings} stateUpdate={simulation?.comparison} />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
