import { useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { FINDING_CATEGORY, SEVERITY } from '../../utils/constants.js';
import { cx } from '../../utils/format.js';
import { tone } from '../../utils/tones.js';
import { CheckStatusPill, SeverityPill } from '../ui/Badges.jsx';

function EvidenceCard({ finding, checkStatus }) {
  const [open, setOpen] = useState(finding.severity === 'critical' || finding.severity === 'high');
  const t = tone(SEVERITY[finding.severity]?.tone);
  const evidence = finding.evidence;
  const hasEvidence = evidence && (typeof evidence === 'string' ? evidence : Object.keys(evidence).length);

  return (
    <article className={cx('rounded-lg border border-white/[0.08] glass-inset border-l-2 transition-colors', t.border)}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left"
      >
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityPill severity={finding.severity} />
            <h4 className="text-xs font-semibold text-white">{finding.title}</h4>
          </div>
          <p className="mt-1 text-xs leading-relaxed text-white/60">{finding.description}</p>
        </div>
        <ChevronDown size={14} className={cx('mt-0.5 shrink-0 text-white/40 transition-transform duration-150', open && 'rotate-180')} />
      </button>

      {open && (
        <div className="border-t border-white/[0.06] glass-inset px-4 py-3 text-xs">
          {hasEvidence ? (
            typeof evidence === 'string' ? (
              <pre className="whitespace-pre-wrap break-words font-mono text-[11px] text-white/70">{evidence}</pre>
            ) : (
              <dl className="grid gap-x-4 gap-y-1.5 text-[11px] sm:grid-cols-[auto_1fr]">
                {Object.entries(evidence).map(([k, v]) => (
                  <div key={k} className="contents">
                    <dt className="text-white/40 font-mono">{k}:</dt>
                    <dd className="break-all font-mono text-white/85">{String(v)}</dd>
                  </div>
                ))}
              </dl>
            )
          ) : (
            <p className="text-white/40 text-[11px]">No extra details.</p>
          )}

          <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 pt-2 border-t border-white/[0.04] text-[11px] text-white/45">
            <span>
              Source: <span className="text-white/70">{finding.source}</span>
            </span>
            {checkStatus && (
              <span className="flex items-center gap-1.5">
                Check: <CheckStatusPill status={checkStatus} />
              </span>
            )}
          </div>
        </div>
      )}
    </article>
  );
}

const GROUP_ORDER = ['confirmed', 'heuristic', 'weakness', 'informational'];

export default function EvidenceSection({ findings = [], checks = [] }) {
  const statusById = Object.fromEntries(checks.map((c) => [c.id, c.status]));
  const groups = GROUP_ORDER.map((key) => ({
    key,
    ...FINDING_CATEGORY[key],
    items: findings
      .filter((f) => (f.category || 'heuristic') === key)
      .sort((a, b) => (SEVERITY[b.severity]?.rank || 0) - (SEVERITY[a.severity]?.rank || 0)),
  })).filter((g) => g.items.length);

  const unavailable = checks.filter((c) => ['unavailable', 'error', 'not_checked'].includes(c.status));

  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-6 " aria-labelledby="evidence-title">
      <div className="border-b border-white/[0.06] pb-3">
        <h2 id="evidence-title" className="font-display text-base font-bold text-white">
          Evidence
        </h2>
        <p className="mt-1 text-xs text-white/50">
          Each finding shows its source.
        </p>
      </div>

      {groups.length === 0 && (
        <p className="mt-4 rounded-lg border border-dashed border-white/10 px-4 py-6 text-center text-xs text-white/45">
          No positive threat findings were triggered. Review the coverage ledger and limitations below.
        </p>
      )}

      <div className="mt-5 space-y-6">
        {groups.map((g) => (
          <div key={g.key}>
            <div className="mb-2.5 flex flex-wrap items-baseline justify-between gap-2">
              <h3 className="eyebrow text-white/70">
                {g.label} <span className="text-white/40 font-mono">({g.items.length})</span>
              </h3>
              <span className="text-[11px] text-white/40">{g.description}</span>
            </div>
            <div className="space-y-2">
              {g.items.map((f) => (
                <EvidenceCard key={f.id} finding={f} checkStatus={statusById[f.checkId]} />
              ))}
            </div>
          </div>
        ))}

        {unavailable.length > 0 && (
          <div className="border-t border-white/[0.06] pt-4">
            <h3 className="eyebrow mb-2.5 text-white/70">
              Unavailable or Skipped Checks <span className="text-white/40 font-mono">({unavailable.length})</span>
            </h3>
            <ul className="space-y-1.5">
              {unavailable.map((c) => (
                <li key={c.id} className="flex flex-col gap-1 rounded-lg border border-dashed border-white/10 px-3.5 py-2 sm:flex-row sm:items-center sm:justify-between text-xs">
                  <div>
                    <div className="text-white/70 font-medium">{c.name}</div>
                    {c.detail && <div className="text-[11px] text-white/40">{c.detail}</div>}
                  </div>
                  <CheckStatusPill status={c.status} />
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[11px] text-white/40">
              Checks that could not run are never counted as clean.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
