import { Check, Loader2, X, Minus } from 'lucide-react';
import { DEFAULT_STEPS } from '../../utils/constants.js';
import { cx } from '../../utils/format.js';
import { CheckStatusPill } from '../ui/Badges.jsx';

function StepIcon({ status }) {
  const base = 'flex h-7 w-7 shrink-0 items-center justify-center rounded-md border text-xs';
  if (status === 'completed') return <span className={cx(base, 'border-signal/50 bg-signal/15 text-signal')}><Check size={14} /></span>;
  if (status === 'running') return <span className={cx(base, 'border-signal bg-signal/10 text-signal')}><Loader2 size={14} className="animate-spin" /></span>;
  if (status === 'failed') return <span className={cx(base, 'border-red-400/50 bg-red-500/10 text-red-300')}><X size={14} /></span>;
  if (status === 'skipped') return <span className={cx(base, 'border-white/10 bg-white/[0.02] text-white/40')}><Minus size={14} /></span>;
  return <span className={cx(base, 'border-white/10 bg-white/[0.02] text-white/30')} />;
}

export default function ProgressStepper({ report }) {
  const steps = report?.steps?.length ? report.steps : DEFAULT_STEPS[report?.type || 'url'].map((s) => ({ ...s, status: 'pending' }));
  const checks = report?.checks || [];

  return (
    <div className="rounded-xl border border-white/[0.08] glass-card p-6 ">
      <div className="mb-6 flex items-center justify-between gap-4 border-b border-white/[0.06] pb-4">
        <div>
          <div className="font-mono text-xs uppercase tracking-wider text-signal font-medium">Investigating</div>
          <h2 className="font-display text-base font-bold text-white mt-1">Collecting evidence</h2>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs text-white/50">
          <Loader2 size={14} className="animate-spin text-signal" />
          <span>Active</span>
        </div>
      </div>

      <ol className="space-y-4">
        {steps.map((s, i) => (
          <li key={s.key} className="flex items-start gap-3.5">
            <StepIcon status={s.status} />
            <div className="pt-0.5">
              <div className={cx('text-xs font-semibold', s.status === 'pending' ? 'text-white/40' : 'text-white')}>
                {i + 1}. {s.label}
              </div>
              {s.detail && <div className="mt-0.5 text-[11px] text-white/45">{s.detail}</div>}
            </div>
          </li>
        ))}
      </ol>

      {checks.length > 0 && (
        <div className="mt-6 border-t border-white/[0.06] pt-4">
          <div className="eyebrow mb-2.5">Subordinate Verification Checks</div>
          <ul className="grid gap-2 sm:grid-cols-2">
            {checks.map((c) => (
              <li key={c.id} className="flex items-center justify-between gap-2 rounded-lg border border-white/[0.05] glass-inset px-3 py-2 text-xs">
                <span className="truncate text-white/70">{c.name}</span>
                <CheckStatusPill status={c.status} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
