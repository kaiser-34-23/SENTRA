import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, Check, Globe2, LockKeyhole, Radar } from "lucide-react";
import { toast } from "sonner";
import { startScan } from "@/lib/api";
import { TopBar } from "@/components/TopBar";

const GOALS = [
  ["surface", "Attack surface discovery"],
  ["headers", "Security control analysis"],
  ["correlation", "Finding correlation"],
  ["impact", "Business-impact analysis"],
  ["remediation", "Remediation prioritization"],
];

const PROFILES = [
  ["safe", "Safe", "Read-only HTTP checks. No crawling or state changes."],
  ["standard", "Standard", "Recommended · response-control checks on the supplied URL."],
  ["deep", "Deep", "Include the declared scope in the assessment record for follow-up checks."],
];

const ACTIVE_METHOD_OPTIONS = [
  ["POST", "Create canary"],
  ["PUT", "Update canary"],
];

export default function LandingPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    target: "",
    target_type: "web",
    scope: "",
    profile: "standard",
    goals: GOALS.map(([key]) => key),
    authorized: false,
    assessment_mode: "read_only",
    active_methods: ["POST"],
    active_paths: "/sentra-test",
    active_confirmed: false,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));
  const toggleGoal = (key, checked) => setForm((current) => ({
    ...current,
    goals: checked ? [...new Set([...current.goals, key])] : current.goals.filter((goal) => goal !== key),
  }));
  const toggleActiveMethod = (method, checked) => setForm((current) => ({
    ...current,
    active_methods: checked ? [...new Set([...current.active_methods, method])] : current.active_methods.filter((item) => item !== method),
  }));

  const launch = async (event) => {
    event.preventDefault();
    setError("");
    if (!form.target.trim()) return setError("Enter a hostname, IP address, or http(s) URL.");
    if (!form.authorized) return setError("Confirm that you are authorized to test this target.");
    if (form.assessment_mode === "active") {
      const paths = form.active_paths.split(/[\n,]+/).map((path) => path.trim()).filter(Boolean);
      if (!form.active_confirmed) return setError("Confirm that this is a disposable staging target before using active checks.");
      if (!form.active_methods.length) return setError("Choose at least one approved active method.");
      if (!paths.length) return setError("Enter at least one approved active path.");
    }
    setBusy(true);
    try {
      const run = await startScan({
        ...form,
        target: form.target.trim(),
        active_paths: form.active_paths.split(/[\n,]+/).map((path) => path.trim()).filter(Boolean),
      });
      navigate(`/scan/${run.scan_id}`, { state: { target: run.target || form.target.trim(), assessment_mode: form.assessment_mode } });
    } catch (e) {
      const message = e?.response?.data?.detail
        || (!e?.response ? "SENTRA API is unreachable. Refresh the preview and try again." : "The assessment could not be started. Check the target and try again.");
      setError(message);
      toast.error(message);
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen">
      <TopBar />
      <main className="mx-auto max-w-[1180px] px-4 pb-24 pt-14 md:px-8">
        <section className="max-w-3xl">
          <div className="fade-up flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.18em] text-cyan">
            <Radar className="h-3.5 w-3.5" /> Autonomous security intelligence
          </div>
          <h1 className="fade-up mt-4 font-mono text-4xl font-bold leading-[1.05] tracking-tight text-white sm:text-5xl lg:text-6xl" style={{ animationDelay: "60ms" }}>
            Show me the attack,<br />
            <span className="text-cyan">not the alert list.</span>
          </h1>
          <p className="fade-up mt-6 max-w-2xl text-base leading-relaxed text-slate-400" style={{ animationDelay: "120ms" }}>
            SENTRA checks the target you provide, records what it actually observes, correlates related security controls, and turns the evidence into an ordered fix list.
          </p>
        </section>

        <form onSubmit={launch} className="mt-12 space-y-6">
          <section className="panel p-5 md:p-7">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="eyebrow">01 · Target setup</p>
                <h2 className="mt-2 font-mono text-xl font-semibold text-white">Define the system you own</h2>
                <p className="mt-1 text-sm text-slate-400">One target per assessment. SENTRA sends bounded, non-destructive requests only.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <div className="flex items-center gap-2 rounded-full border border-emerald-400/25 bg-emerald-400/[0.06] px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-emerald-300">
                  <LockKeyhole className="h-3.5 w-3.5" /> Read-only checks
                </div>
              </div>
            </div>

            <div className="mt-7 grid gap-5 md:grid-cols-12">
              <label className="md:col-span-8">
                <span className="eyebrow mb-2 block">Target URL or IP</span>
                <div className="relative">
                  <Globe2 className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                  <input
                    data-testid="target-input"
                    value={form.target}
                    onChange={(event) => update("target", event.target.value)}
                    placeholder="https://your-domain.com or 192.168.1.100"
                    autoComplete="url"
                    className="h-12 w-full rounded-md border border-white/10 bg-[#07090E] pl-10 pr-3 font-mono text-sm text-white outline-none transition-colors placeholder:text-slate-600 focus:border-cyan/60 focus:ring-1 focus:ring-cyan/30"
                  />
                </div>
              </label>
              <label className="md:col-span-4">
                <span className="eyebrow mb-2 block">Target type</span>
                <select
                  data-testid="target-type-select"
                  value={form.target_type}
                  onChange={(event) => update("target_type", event.target.value)}
                  className="h-12 w-full rounded-md border border-white/10 bg-[#07090E] px-3 font-mono text-sm text-white outline-none focus:border-cyan/60"
                >
                  <option value="web">Web application</option>
                  <option value="api">API</option>
                  <option value="network">Network host</option>
                  <option value="cloud">Cloud endpoint</option>
                </select>
              </label>
              <label className="md:col-span-8">
                <span className="eyebrow mb-2 block">Scope <span className="normal-case tracking-normal text-slate-600">optional</span></span>
                <input
                  data-testid="scope-input"
                  value={form.scope}
                  onChange={(event) => update("scope", event.target.value)}
                  placeholder="api.your-domain.com or /api/*"
                  className="h-11 w-full rounded-md border border-white/10 bg-[#07090E] px-3 font-mono text-sm text-white outline-none transition-colors placeholder:text-slate-600 focus:border-cyan/60 focus:ring-1 focus:ring-cyan/30"
                />
              </label>
            </div>

          </section>

          <section className="panel p-5 md:p-7">
            <p className="eyebrow">02 · Assessment configuration</p>
            <h2 className="mt-2 font-mono text-xl font-semibold text-white">Choose how SENTRA should analyze it</h2>
            <div className="mt-6 grid gap-3 md:grid-cols-3">
              {PROFILES.map(([key, title, description]) => (
                <label key={key} className={`cursor-pointer rounded-md border p-4 transition-colors ${form.profile === key ? "border-cyan/60 bg-cyan/[0.05]" : "border-white/[0.08] hover:border-white/25"}`}>
                  <input className="sr-only" type="radio" name="profile" value={key} checked={form.profile === key} onChange={() => update("profile", key)} />
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm font-semibold text-white">{title}</span>
                    {form.profile === key && <Check className="h-4 w-4 text-cyan" />}
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-slate-400">{description}</p>
                </label>
              ))}
            </div>
            <div className="mt-7">
              <p className="eyebrow mb-3">Analysis goals</p>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {GOALS.map(([key, label]) => (
                  <label key={key} className="flex cursor-pointer items-center gap-2 rounded-md border border-white/[0.06] px-3 py-2.5 text-sm text-slate-300 hover:border-white/20">
                    <input
                      type="checkbox"
                      checked={form.goals.includes(key)}
                      onChange={(event) => toggleGoal(key, event.target.checked)}
                      className="h-4 w-4 shrink-0 cursor-pointer"
                      style={{ accentColor: "#00F0FF" }}
                    />
                    {label}
                  </label>
                ))}
              </div>
            </div>
            <div className="mt-7 border-t border-white/[0.08] pt-6">
              <p className="eyebrow mb-3">Assessment mode</p>
              <div className="grid gap-3 md:grid-cols-2">
                <label className={`cursor-pointer rounded-md border p-4 transition-colors ${form.assessment_mode === "read_only" ? "border-cyan/60 bg-cyan/[0.05]" : "border-white/[0.08] hover:border-white/25"}`}>
                  <input className="sr-only" type="radio" name="assessment_mode" value="read_only" checked={form.assessment_mode === "read_only"} onChange={() => update("assessment_mode", "read_only")} />
                  <div className="flex items-center justify-between"><span className="font-mono text-sm font-semibold text-white">Read-only</span>{form.assessment_mode === "read_only" && <Check className="h-4 w-4 text-cyan" />}</div>
                  <p className="mt-2 text-xs leading-relaxed text-slate-400">Inspect response controls with bounded GET requests. Recommended default.</p>
                </label>
                <label className={`cursor-pointer rounded-md border p-4 transition-colors ${form.assessment_mode === "active" ? "border-amber-300/60 bg-amber-300/[0.05]" : "border-white/[0.08] hover:border-white/25"}`}>
                  <input className="sr-only" type="radio" name="assessment_mode" value="active" checked={form.assessment_mode === "active"} onChange={() => update("assessment_mode", "active")} />
                  <div className="flex items-center justify-between"><span className="font-mono text-sm font-semibold text-white">Active staging checks</span>{form.assessment_mode === "active" && <Check className="h-4 w-4 text-amber-300" />}</div>
                  <p className="mt-2 text-xs leading-relaxed text-slate-400">Opt-in canary writes only after the endpoint advertises cleanup support.</p>
                </label>
              </div>
              {form.assessment_mode === "active" && (
                <div className="mt-4 space-y-4 rounded-md border border-amber-300/25 bg-amber-300/[0.04] p-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <label>
                      <span className="eyebrow mb-2 block">Approved active paths</span>
                      <textarea data-testid="active-paths-input" value={form.active_paths} onChange={(event) => update("active_paths", event.target.value)} placeholder="/sentra-test" rows={2} className="w-full rounded-md border border-white/10 bg-[#07090E] px-3 py-2 font-mono text-sm text-white outline-none placeholder:text-slate-600 focus:border-amber-300/60" />
                      <span className="mt-1 block text-[11px] text-slate-500">Comma or newline separated; no wildcards.</span>
                    </label>
                    <div>
                      <span className="eyebrow mb-2 block">Approved methods</span>
                      <div className="space-y-2">
                        {ACTIVE_METHOD_OPTIONS.map(([method, label]) => <label key={method} className="flex cursor-pointer items-center gap-2 text-sm text-slate-300"><input data-testid={`active-method-${method.toLowerCase()}`} type="checkbox" checked={form.active_methods.includes(method)} onChange={(event) => toggleActiveMethod(method, event.target.checked)} className="h-4 w-4" style={{ accentColor: "#FCD34D" }} /> <span className="font-mono text-xs text-amber-200">{method}</span> {label}</label>)}
                      </div>
                    </div>
                  </div>
                  <label className="flex cursor-pointer items-start gap-3 text-sm leading-relaxed text-slate-300"><input data-testid="active-confirmation-checkbox" type="checkbox" checked={form.active_confirmed} onChange={(event) => update("active_confirmed", event.target.checked)} className="mt-1 h-4 w-4 shrink-0" style={{ accentColor: "#FCD34D" }} /><span>I confirm this is a disposable staging environment and the approved endpoint will return an <code className="text-amber-200">X-SENTRA-Active-Contract: true</code> header plus a same-origin cleanup path. SENTRA will rate-limit requests and clean up each canary.</span></label>
                </div>
              )}
            </div>
          </section>

          <section className="panel p-5 md:p-6">
            <div>
              <div>
                <p className="eyebrow">03 · Check target</p>
                <h2 className="mt-2 font-mono text-lg font-semibold text-white">Run the assessment</h2>
                <label htmlFor="authorization-checkbox" className="mt-3 flex max-w-3xl cursor-pointer items-start gap-3 text-sm leading-relaxed text-slate-300">
                  <input
                    type="checkbox"
                    id="authorization-checkbox"
                    data-testid="authorization-checkbox"
                    checked={form.authorized}
                    onChange={(event) => update("authorized", event.target.checked)}
                    className="mt-1 h-4 w-4 shrink-0 cursor-pointer"
                    style={{ accentColor: "#00F0FF" }}
                  />
                  <span>
                    I confirm that I am authorized to test this target. {form.assessment_mode === "active" ? "I have approved the bounded active checks configured above." : "SENTRA will make read-only requests only."}
                    <span className="mt-1 block font-mono text-[11px] text-slate-500">Only assess systems you own or have written permission to test.</span>
                  </span>
                </label>
              </div>
              <button type="submit" data-testid="start-scan-button" disabled={busy} style={{ backgroundColor: "#00F0FF", color: "#07090E", borderColor: "#FFFFFF", boxShadow: "0 0 0 2px #00F0FF, 0 8px 28px rgba(0, 240, 255, 0.28)" }} className="group mt-5 flex h-14 w-full items-center justify-center gap-3 rounded-md border-2 px-5 font-mono text-sm font-bold uppercase tracking-[0.16em] transition-all hover:brightness-110 disabled:cursor-wait disabled:opacity-60">
                {busy ? "Checking target…" : "CHECK TARGET"}
                <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
              </button>
            </div>
          </section>

          {error && <p data-testid="launch-error" className="rounded-md border border-sev-critical/30 bg-sev-critical/10 px-4 py-3 font-mono text-xs text-red-200">{error}</p>}
        </form>
      </main>
    </div>
  );
}
