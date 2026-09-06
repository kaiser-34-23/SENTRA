import { scoreColor } from "@/lib/severity";

const KEYS = { web: "web", transport: "transport", auth: "auth", config: "config", exposure: "exposure" };

export const CategoryBars = ({ categories }) => (
  <div data-testid="category-breakdown" className="panel flex h-full flex-col p-5">
    <div className="flex items-baseline justify-between">
      <p className="eyebrow">Category breakdown</p>
      <span className="font-mono text-[10px] text-slate-500">5 domains</span>
    </div>
    <div className="mt-5 flex flex-1 flex-col justify-between gap-4">
      {categories.map((c, i) => {
        const color = scoreColor(c.score);
        return (
          <div key={c.key} data-testid={`category-breakdown-${KEYS[c.key]}`} className="fade-up" style={{ animationDelay: `${i * 80}ms` }}>
            <div className="mb-1.5 flex items-center justify-between font-mono text-xs">
              <span className="text-slate-200">{c.label}</span>
              <span className="flex items-center gap-3">
                <span className="text-[10px] text-slate-500">{c.finding_count} finding{c.finding_count === 1 ? "" : "s"}</span>
                <span className="w-8 text-right tabular-nums" style={{ color }}>
                  {c.score}
                </span>
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/[0.05]">
              <div
                className="h-full rounded-full transition-[width] duration-[1200ms] ease-out"
                style={{ width: `${c.score}%`, background: color, boxShadow: `0 0 10px ${color}66` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  </div>
);
