import { Sparkles, FileText } from 'lucide-react';

export default function ExplanationPanel({ explanation }) {
  if (!explanation) return null;
  const isAi = explanation.source === 'ai';

  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-6 " aria-labelledby="explanation-title">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] pb-3">
        <h2 id="explanation-title" className="font-display text-base font-bold text-white">
          Summary
        </h2>
        <span className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/[0.03] px-2.5 py-1 font-mono text-[10.5px] text-white/60">
          {isAi ? <Sparkles size={11} className="text-signal" /> : <FileText size={11} />}
          <span>{isAi ? 'AI explanation' : 'Rule-based explanation'}</span>
        </span>
      </div>

      <p className="text-sm leading-relaxed text-white/85">{explanation.summary}</p>

      {explanation.keyPoints?.length > 0 && (
        <div className="mt-4 space-y-2 border-t border-white/[0.04] pt-3">
          <div className="eyebrow mb-2">Key Observed Indicators</div>
          <ul className="space-y-2">
            {explanation.keyPoints.map((k, i) => (
              <li key={i} className="flex gap-2.5 text-xs text-white/70">
                <span className="font-mono text-signal font-semibold">•</span>
                <span className="leading-relaxed">{k}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {isAi && (
        <div className="mt-4 rounded glass-inset p-2.5 text-[10.5px] text-white/40 border border-white/[0.04]">
          Constraint: The AI engine provides contextual explanation exclusively from collected security indicators. It cannot invent results or modify deterministic risk classifications.
        </div>
      )}
    </section>
  );
}
