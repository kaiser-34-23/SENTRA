export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const SEV = {
  critical: { label: "Critical", hex: "#FF3B30", text: "text-sev-critical", bg: "bg-sev-critical/10", border: "border-sev-critical/40" },
  high: { label: "High", hex: "#FF9500", text: "text-sev-high", bg: "bg-sev-high/10", border: "border-sev-high/40" },
  medium: { label: "Medium", hex: "#FFCC00", text: "text-sev-medium", bg: "bg-sev-medium/10", border: "border-sev-medium/40" },
  low: { label: "Low", hex: "#30D158", text: "text-sev-low", bg: "bg-sev-low/10", border: "border-sev-low/40" },
  info: { label: "Info", hex: "#64D2FF", text: "text-sev-info", bg: "bg-sev-info/10", border: "border-sev-info/40" },
};

export const scoreColor = (s) => (s >= 80 ? "#30D158" : s >= 60 ? "#FFCC00" : s >= 40 ? "#FF9500" : "#FF3B30");

export const SeverityPill = ({ severity, className = "", testId }) => {
  const s = SEV[severity] || SEV.info;
  return (
    <span
      data-testid={testId}
      className={`inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${s.text} ${s.bg} ${s.border} ${className}`}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.hex }} />
      {s.label}
    </span>
  );
};
