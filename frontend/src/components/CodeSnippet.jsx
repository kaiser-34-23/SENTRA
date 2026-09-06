import { useState } from "react";
import { Check, Copy } from "lucide-react";

export const CodeSnippet = ({ code, language, testId = "remediation-code-snippet" }) => {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      /* clipboard unavailable */
    }
  };
  return (
    <div data-testid={testId} className="relative overflow-hidden rounded-md border border-white/[0.08] bg-[#04060A]">
      <div className="flex items-center justify-between border-b border-white/[0.06] px-3 py-1.5">
        <span className="font-mono text-[10px] uppercase tracking-wider text-slate-500">{language || "text"}</span>
        <button type="button" data-testid={`${testId}-copy`} onClick={copy} className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-wider text-slate-400 hover:text-cyan">
          {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
          {copied ? "copied" : "copy"}
        </button>
      </div>
      <pre className="overflow-x-auto px-3 py-3 font-mono text-[12px] leading-relaxed text-slate-200">
        <code>{code}</code>
      </pre>
    </div>
  );
};
