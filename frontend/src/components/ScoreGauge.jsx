import { useEffect, useState } from "react";
import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer } from "recharts";
import { scoreColor } from "@/lib/severity";

export const ScoreGauge = ({ score }) => {
  const [value, setValue] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setValue(score.overall), 150);
    return () => clearTimeout(t);
  }, [score.overall]);
  const color = scoreColor(score.overall);
  const c = score.severity_counts;

  return (
    <div data-testid="security-score-gauge" className="panel flex h-full flex-col p-5">
      <div className="flex items-baseline justify-between">
        <p className="eyebrow">Security score</p>
        <span className="font-mono text-[10px] text-slate-500">deterministic · not AI</span>
      </div>
      <div className="relative mx-auto mt-2 h-[190px] w-full min-w-[200px] max-w-[260px]">
        <ResponsiveContainer width="100%" height={190} minWidth={200}>
          <RadialBarChart innerRadius="78%" outerRadius="100%" data={[{ value }]} startAngle={220} endAngle={-40} barSize={12}>
            <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
            <RadialBar dataKey="value" cornerRadius={6} fill={color} background={{ fill: "rgba(255,255,255,0.05)" }} isAnimationActive animationDuration={1400} animationEasing="ease-out" />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pt-2">
          <span data-testid="security-score-value" className="font-mono text-5xl font-bold tabular-nums tracking-tight" style={{ color }}>
            {score.overall}
          </span>
          <span className="font-mono text-[11px] text-slate-500">/ 100</span>
          <span data-testid="security-score-grade" className="mt-1 rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest" style={{ color, borderColor: `${color}66` }}>
            {score.grade}
          </span>
        </div>
      </div>
      <div className="mt-2 grid grid-cols-5 gap-1 border-t border-white/[0.06] pt-4">
        {[
          ["critical", c.critical],
          ["high", c.high],
          ["medium", c.medium],
          ["low", c.low],
          ["info", c.info],
        ].map(([k, n]) => (
          <div key={k} data-testid={`severity-count-${k}`} className="text-center">
            <div className={`font-mono text-lg font-semibold text-sev-${k}`}>{n}</div>
            <div className="font-mono text-[9px] uppercase tracking-wider text-slate-500">{k}</div>
          </div>
        ))}
      </div>
    </div>
  );
};
