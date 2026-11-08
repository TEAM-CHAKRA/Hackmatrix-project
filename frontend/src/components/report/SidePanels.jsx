import { CircleCheck, CircleAlert, ListChecks } from 'lucide-react';
import { CheckStatusPill } from '../ui/Badges.jsx';

export function CheckCoverage({ checks = [] }) {
  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-5 " aria-labelledby="coverage-title">
      <div className="border-b border-white/[0.06] pb-2.5">
        <h2 id="coverage-title" className="font-display text-sm font-bold text-white flex items-center gap-2">
          <ListChecks size={15} className="text-signal" />
          <span>Checks</span>
        </h2>
      </div>
      <ul className="mt-3.5 space-y-2">
        {checks.map((c) => (
          <li key={c.id} className="flex items-start justify-between gap-2.5 text-xs">
            <div className="min-w-0">
              <div className="text-white/85 font-medium">{c.name}</div>
              <div className="text-[10.5px] text-white/40">{c.source}</div>
            </div>
            <CheckStatusPill status={c.status} />
          </li>
        ))}
      </ul>
    </section>
  );
}

export function Recommendations({ items = [] }) {
  if (!items.length) return null;
  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-5 " aria-labelledby="rec-title">
      <div className="border-b border-white/[0.06] pb-2.5">
        <h2 id="rec-title" className="font-display text-sm font-bold text-white">
          What to do
        </h2>
      </div>
      <ul className="mt-3.5 space-y-2.5">
        {items.map((r, i) => (
          <li key={i} className="flex gap-2.5 text-xs leading-relaxed text-white/70">
            <CircleCheck size={14} className="mt-0.5 shrink-0 text-signal" />
            <span>{r}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function Limitations({ items = [] }) {
  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-5 " aria-labelledby="lim-title">
      <div className="border-b border-white/[0.06] pb-2.5">
        <h2 id="lim-title" className="font-display text-sm font-bold text-white">
          Limitations
        </h2>
        
      </div>
      {items.length ? (
        <ul className="mt-3 space-y-2">
          {items.map((r, i) => (
            <li key={i} className="flex gap-2 text-xs text-white/55">
              <CircleAlert size={13} className="mt-0.5 shrink-0 text-white/40" />
              <span>{r}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-xs text-white/40">None reported.</p>
      )}
    </section>
  );
}
