import { HelpCircle } from 'lucide-react';
import { CLASSIFICATIONS } from '../../utils/constants.js';
import { cx } from '../../utils/format.js';

// Ordered severity scale. "Inconclusive" is deliberately NOT on the scale:
// it means "not enough evidence", not "somewhere between".
const SCALE = [
  { key: 'low_risk', bar: 'bg-signal', text: 'text-signal' },
  { key: 'suspicious', bar: 'bg-amber-400', text: 'text-amber-300' },
  { key: 'high_risk', bar: 'bg-orange-500', text: 'text-orange-300' },
  { key: 'confirmed_malicious', bar: 'bg-red-500', text: 'text-red-300' },
];

/** At-a-glance position of this report on the CYBERLENS risk scale, plus in-page section links. */
export default function RiskScale({ classification, sections = [] }) {
  const idx = SCALE.findIndex((s) => s.key === classification);
  const inconclusive = idx === -1;

  return (
    <div className="no-print grid gap-6 rounded-xl border border-white/[0.08] glass-card p-5 lg:grid-cols-[1.3fr_1fr] lg:items-center">
      <div>
        <div className="mb-3 flex items-center justify-between font-mono text-[10.5px] uppercase tracking-[0.18em] text-white/40">
          <span>Risk scale</span>
          {inconclusive && <span className="text-white/60">Not placed: insufficient evidence</span>}
        </div>
        <ol className="grid grid-cols-4 gap-1.5" aria-label="Risk classification scale">
          {SCALE.map((s, i) => {
            const active = i === idx;
            const passed = !inconclusive && i <= idx;
            return (
              <li key={s.key} aria-current={active ? 'true' : undefined}>
                <div
                  className={cx(
                    'h-1.5 rounded-full transition-all duration-700',
                    passed ? s.bar : 'bg-white/[0.08]',
                    inconclusive && 'bg-[repeating-linear-gradient(135deg,rgba(255,255,255,0.10)_0_4px,transparent_4px_8px)]'
                  )}
                />
                <div className={cx('mt-2 text-[11.5px] leading-tight', active ? cx('font-semibold', s.text) : 'text-white/40')}>
                  {CLASSIFICATIONS[s.key].label}
                  {active && <span className="sr-only"> (this report)</span>}
                </div>
              </li>
            );
          })}
        </ol>
        {inconclusive && (
          <p className="mt-3 flex items-center gap-2 text-xs text-white/55">
            <HelpCircle size={13} className="shrink-0" /> Inconclusive reports are not placed on the scale and must not be read as safe.
          </p>
        )}
      </div>

      {sections.length > 0 && (
        <nav aria-label="Report sections" className="lg:border-l lg:border-white/[0.08] lg:pl-6">
          <div className="mb-2.5 font-mono text-[10.5px] uppercase tracking-[0.18em] text-white/40">Jump to</div>
          <ul className="flex flex-wrap gap-1.5">
            {sections.map(([id, label]) => (
              <li key={id}>
                <a
                  href={`#${id}`}
                  onClick={(e) => {
                    e.preventDefault();
                    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                  }}
                  className="inline-flex rounded-md border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-[12px] text-white/65 transition hover:border-signal/40 hover:text-white"
                >
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
      )}
    </div>
  );
}
