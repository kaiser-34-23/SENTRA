import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { fetchResults, requestAiAnalysis } from "@/lib/api";
import { TopBar } from "@/components/TopBar";
import { ScoreGauge } from "@/components/ScoreGauge";
import { CategoryBars } from "@/components/CategoryBars";
import { AIAnalyst } from "@/components/AIAnalyst";
import { AttackGraph } from "@/components/AttackGraph";
import { FindingsList } from "@/components/FindingsList";
import { RemediationCenter } from "@/components/RemediationCenter";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

export default function ResultsPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [ai, setAi] = useState({ analysis: null, loading: false, error: null });
  const [focusId, setFocusId] = useState(null);
  const [tab, setTab] = useState("findings");
  const graphRef = useRef(null);

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

  const pathNodeIds = useMemo(() => new Set((data?.attack_paths || []).flatMap((p) => p.node_ids)), [data]);

  const locate = (id) => {
    setFocusId(id);
    graphRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
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

  return (
    <div className="min-h-screen">
      <TopBar environment={env} status="results" />
      <main data-testid="results-dashboard" className="mx-auto max-w-[1600px] space-y-6 px-4 pb-24 pt-8 md:px-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="eyebrow">Results · {env.name} · {env.sector}</p>
            <h1 className="mt-2 font-mono text-3xl font-bold tracking-tight text-white sm:text-4xl">
              {data.attack_paths.length} validated attack path{data.attack_paths.length === 1 ? "" : "s"} to sensitive data.
            </h1>
          </div>
          <div className="flex gap-2">
            <button type="button" data-testid="results-new-scan" onClick={() => navigate("/")} className="rounded-md border border-white/10 px-4 py-2 font-mono text-[11px] uppercase tracking-wider text-slate-300 hover:border-white/30 hover:text-white">
              New scan
            </button>
            <button type="button" data-testid="results-incident-link" onClick={() => navigate("/incident")} className="rounded-md border border-cyan/40 px-4 py-2 font-mono text-[11px] uppercase tracking-wider text-cyan hover:bg-cyan/10">
              Replay incident
            </button>
          </div>
        </div>

        <section className="grid gap-4 lg:grid-cols-12">
          <div className="fade-up lg:col-span-3"><ScoreGauge score={data.score} /></div>
          <div className="fade-up lg:col-span-4" style={{ animationDelay: "80ms" }}><CategoryBars categories={data.score.categories} /></div>
          <div className="fade-up lg:col-span-5" style={{ animationDelay: "160ms" }}>
            <AIAnalyst analysis={ai.analysis} loading={ai.loading} error={ai.error} onRetry={runAi} paths={data.attack_paths} findings={data.findings} compact />
          </div>
        </section>

        <section ref={graphRef} className="fade-up scroll-mt-20" style={{ animationDelay: "240ms" }}>
          <AttackGraph graph={data.graph} findings={data.findings} paths={data.attack_paths} assets={env.assets} rules={data.rules} focusId={focusId} onFocusHandled={() => setFocusId(null)} />
        </section>

        <Tabs value={tab} onValueChange={setTab} className="fade-up" style={{ animationDelay: "320ms" }}>
          <TabsList className="h-auto gap-1 rounded-md border border-white/[0.08] bg-[#0D111A] p-1">
            {[
              ["findings", `Findings · ${data.findings.length}`],
              ["remediation", `Remediation · ${data.remediation.length}`],
              ["analyst", "AI analyst · full"],
            ].map(([k, l]) => (
              <TabsTrigger key={k} value={k} data-testid={`results-tab-${k}`} className="rounded-sm px-4 py-2 font-mono text-[11px] uppercase tracking-wider text-slate-400 data-[state=active]:bg-cyan/10 data-[state=active]:text-cyan">
                {l}
              </TabsTrigger>
            ))}
          </TabsList>
          <TabsContent value="findings" className="mt-4">
            <FindingsList findings={data.findings} assets={env.assets} pathNodeIds={pathNodeIds} onLocate={locate} />
          </TabsContent>
          <TabsContent value="remediation" className="mt-4">
            <RemediationCenter items={data.remediation} assets={env.assets} />
          </TabsContent>
          <TabsContent value="analyst" className="mt-4">
            <AIAnalyst analysis={ai.analysis} loading={ai.loading} error={ai.error} onRetry={runAi} paths={data.attack_paths} findings={data.findings} />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
