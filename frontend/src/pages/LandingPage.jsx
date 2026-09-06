import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, Boxes, Building2, HeartPulse, Landmark, ShoppingBag } from "lucide-react";
import { toast } from "sonner";
import { fetchEnvironments, startScan } from "@/lib/api";
import { TopBar, SyntheticBadge } from "@/components/TopBar";
import { Checkbox } from "@/components/ui/checkbox";

const ICONS = { "acme-retail": ShoppingBag, "fincorp-bank": Landmark, healthops: HeartPulse };

const TargetCard = ({ env, selected, onSelect, index }) => {
  const Icon = ICONS[env.id] || Building2;
  return (
    <button
      type="button"
      data-testid={`target-card-${env.id}`}
      onClick={() => onSelect(env.id)}
      style={{ animationDelay: `${index * 90}ms` }}
      className={`fade-up group relative flex flex-col items-start gap-4 rounded-md border p-6 text-left transition-all duration-300 ${
        selected ? "border-cyan/70 bg-[#0D111A] glow-cyan" : "border-white/[0.08] bg-[#0D111A]/70 hover:border-white/25 hover:bg-[#0D111A]"
      }`}
    >
      <div className="flex w-full items-start justify-between">
        <div className={`rounded-md border p-2 ${selected ? "border-cyan/50 text-cyan" : "border-white/10 text-slate-300"}`}>
          <Icon className="h-5 w-5" />
        </div>
        <SyntheticBadge testId={`synthetic-badge-${env.id}`} />
      </div>
      <div>
        <h3 className="font-mono text-lg font-semibold text-white">{env.name}</h3>
        <p className="text-sm text-slate-400">{env.tagline}</p>
      </div>
      <p className="text-sm leading-relaxed text-slate-400">{env.description}</p>
      <div className="mt-auto w-full space-y-1.5 border-t border-white/[0.06] pt-4 font-mono text-[11px] text-slate-500">
        <div className="flex items-center gap-2">
          <Boxes className="h-3.5 w-3.5" /> {env.infra}
        </div>
        <div>
          {env.assets.length} assets · {env.endpoint_count} endpoints · {env.finding_count} seeded findings
        </div>
      </div>
      {selected && <span className="absolute right-4 bottom-4 font-mono text-[10px] uppercase tracking-widest text-cyan">selected</span>}
    </button>
  );
};

export default function LandingPage() {
  const [envs, setEnvs] = useState([]);
  const [selected, setSelected] = useState(null);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    fetchEnvironments().then(setEnvs).catch(() => toast.error("Could not load environments"));
  }, []);

  const launch = async () => {
    if (!selected || !authorized) return;
    setBusy(true);
    try {
      const run = await startScan(selected, true);
      navigate(`/scan/${run.scan_id}`);
    } catch (e) {
      toast.error("Failed to start scan");
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen">
      <TopBar />
      <main className="mx-auto max-w-[1600px] px-4 pb-24 pt-14 md:px-8">
        <section className="max-w-3xl">
          <p className="eyebrow fade-up">Autonomous security intelligence · demo build</p>
          <h1 className="fade-up mt-4 font-mono text-4xl font-bold leading-[1.05] tracking-tight text-white sm:text-5xl lg:text-6xl" style={{ animationDelay: "60ms" }}>
            Show me the attack,<br />
            <span className="text-cyan">not the alert list.</span>
          </h1>
          <p className="fade-up mt-6 max-w-2xl text-base leading-relaxed text-slate-400" style={{ animationDelay: "120ms" }}>
            SENTRA correlates findings into validated attack paths, explains the business impact in plain language and hands you an ordered fix list.
            Every environment below is synthetic. Nothing here touches a real system.
          </p>
        </section>

        <section className="mt-14">
          <div className="mb-5 flex items-baseline justify-between">
            <h2 className="font-mono text-base text-slate-200 md:text-lg">01 · Select a synthetic target</h2>
            <span className="font-mono text-[11px] text-slate-500">{envs.length} environments seeded</span>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            {envs.map((env, i) => (
              <TargetCard key={env.id} env={env} index={i} selected={selected === env.id} onSelect={setSelected} />
            ))}
          </div>
        </section>

        <section className="mt-12 grid gap-6 lg:grid-cols-12">
          <div className="lg:col-span-8">
            <h2 className="mb-4 font-mono text-base text-slate-200 md:text-lg">02 · Confirm authorization</h2>
            <label
              htmlFor="authorization-checkbox"
              className={`panel flex cursor-pointer items-start gap-4 p-5 transition-colors ${authorized ? "border-cyan/40" : ""}`}
            >
              <Checkbox
                id="authorization-checkbox"
                data-testid="authorization-checkbox"
                checked={authorized}
                onCheckedChange={(v) => setAuthorized(Boolean(v))}
                className="mt-0.5 border-white/30 data-[state=checked]:border-cyan data-[state=checked]:bg-cyan data-[state=checked]:text-[#07090E]"
              />
              <span className="text-sm leading-relaxed text-slate-300">
                I am authorized to run non-destructive security analysis against this isolated <span className="text-amber-300">synthetic</span> environment.
                <span className="mt-1 block font-mono text-[11px] text-slate-500">Kept for muscle memory. Real scans would require domain ownership verification.</span>
              </span>
            </label>
          </div>
          <div className="flex flex-col justify-end gap-3 lg:col-span-4">
            <button
              type="button"
              data-testid="start-scan-button"
              disabled={!selected || !authorized || busy}
              onClick={launch}
              className="group inline-flex h-14 items-center justify-between rounded-md bg-cyan px-6 font-mono text-sm font-semibold uppercase tracking-[0.14em] text-[#07090E] transition-all hover:bg-cyan-hover disabled:cursor-not-allowed disabled:opacity-30"
            >
              {busy ? "Provisioning…" : "Launch autonomous scan"}
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
            </button>
            <button
              type="button"
              data-testid="landing-incident-link"
              onClick={() => navigate("/incident")}
              className="h-11 rounded-md border border-white/10 font-mono text-xs uppercase tracking-[0.14em] text-slate-300 transition-colors hover:border-white/30 hover:text-white"
            >
              Replay demo incident instead
            </button>
          </div>
        </section>
      </main>
    </div>
  );
}
