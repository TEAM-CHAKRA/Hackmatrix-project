import { AlertTriangle } from 'lucide-react';
import { cx } from '../../utils/format.js';

export default function RedirectChain({ chain }) {
  if (!chain) return null;

  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-6 " aria-labelledby="redirect-title">
      <div className="border-b border-white/[0.06] pb-3">
        <h2 id="redirect-title" className="font-display text-base font-bold text-white">
          Redirect chain
        </h2>
        <p className="mt-1 text-xs text-white/50">
          Sensitive URL values are redacted.
        </p>
      </div>

      {chain.length === 0 ? (
        <p className="mt-4 text-xs text-white/40">No intermediate redirects recorded.</p>
      ) : (
        <ol className="mt-5 space-y-3">
          {chain.map((hop, i) => {
            const isFirst = i === 0;
            const isLast = i === chain.length - 1;
            const label = isFirst ? 'Initial Submission' : isLast ? 'Final Resolution' : `Hop 0${i}`;

            return (
              <li
                key={i}
                className={cx(
                  'rounded-lg border p-3 text-xs font-mono transition-colors',
                  hop.suspicious
                    ? 'border-amber-400/30 bg-amber-400/[0.05]'
                    : 'border-white/[0.06] glass-inset'
                )}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.04] pb-1.5 mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10.5px] uppercase font-semibold text-white/40">{label}</span>
                    {hop.statusCode != null && (
                      <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[10.5px] text-white/70">
                        HTTP {hop.statusCode}
                      </span>
                    )}
                  </div>
                  {hop.suspicious && (
                    <span className="inline-flex items-center gap-1 text-[11px] text-amber-300 font-semibold">
                      <AlertTriangle size={12} /> Suspicious Hop
                    </span>
                  )}
                </div>
                <div className="break-all text-white/90 font-medium">{hop.url}</div>
                {hop.note && <div className="mt-1 text-[11px] text-white/45">{hop.note}</div>}
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
