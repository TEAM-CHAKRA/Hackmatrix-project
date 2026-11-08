import { Link2, Mail, Phone, Globe } from 'lucide-react';
import { TACTICS } from '../../utils/constants.js';
import { cx } from '../../utils/format.js';

const TACTIC_TONE = {
  otp_request: 'bg-red-500/20 text-red-200 border-b border-red-400 font-semibold',
  password_request: 'bg-red-500/20 text-red-200 border-b border-red-400 font-semibold',
  payment_request: 'bg-red-500/20 text-red-200 border-b border-red-400 font-semibold',
  suspicious_link: 'bg-signal/15 text-signal border-b border-signal font-mono',
};
const DEFAULT_TONE = 'bg-amber-400/15 text-amber-100 border-b border-amber-400';

function HighlightedText({ text, highlights }) {
  const valid = (highlights || [])
    .filter((h) => h.start >= 0 && h.end <= text.length && h.end > h.start)
    .sort((a, b) => a.start - b.start);

  const parts = [];
  let cursor = 0;
  valid.forEach((h, i) => {
    if (h.start < cursor) return;
    if (h.start > cursor) parts.push(<span key={`t${i}`}>{text.slice(cursor, h.start)}</span>);
    parts.push(
      <mark
        key={`h${i}`}
        title={TACTICS[h.tactic] || h.tactic}
        className={cx('rounded-sm px-1 py-0.5', TACTIC_TONE[h.tactic] || DEFAULT_TONE)}
      >
        {text.slice(h.start, h.end)}
        <span className="sr-only"> (flagged: {TACTICS[h.tactic] || h.tactic})</span>
      </mark>
    );
    cursor = h.end;
  });
  if (cursor < text.length) parts.push(<span key="tail">{text.slice(cursor)}</span>);
  return <p className="whitespace-pre-wrap break-words text-sm leading-8 text-white/85 font-mono">{parts}</p>;
}

function IndicatorList({ icon: Icon, label, items }) {
  return (
    <div>
      <div className="mb-1.5 flex items-center gap-1.5 text-xs text-white/50">
        <Icon size={12} /> {label} <span className="text-white/30 font-mono">({items.length})</span>
      </div>
      {items.length ? (
        <ul className="space-y-1">
          {items.map((v) => (
            <li key={v} className="break-all rounded glass-inset px-2 py-1 font-mono text-xs text-white/85 border border-white/[0.04]">
              {v}
            </li>
          ))}
        </ul>
      ) : (
        <div className="text-[11px] text-white/30 font-mono">None isolated</div>
      )}
    </div>
  );
}

export default function MessageAnalysis({ message, text }) {
  if (!message) return null;
  const ind = message.indicators || {};

  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-6 " aria-labelledby="message-title">
      <div className="border-b border-white/[0.06] pb-3">
        <h2 id="message-title" className="font-display text-base font-bold text-white">
          Message analysis
        </h2>
        <p className="mt-1 text-xs text-white/50">
          Suspicious phrases are highlighted.
        </p>
      </div>

      <div className="mt-5">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <span className="eyebrow">Submitted Communication Text</span>
          <span className="flex flex-wrap gap-3 font-mono text-[10.5px] text-white/50">
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-red-500/60" /> Credential / Payment</span>
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-amber-400/60" /> Coercion</span>
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-signal/60" /> Endpoint</span>
          </span>
        </div>

        <div className="rounded-lg border border-white/[0.06] glass-inset p-4">
          {text ? (
            <HighlightedText text={text} highlights={message.highlights} />
          ) : (
            <p className="text-xs text-white/40">
              The original message isn't stored, so highlights can't be shown.
            </p>
          )}
        </div>
      </div>

      <div className="mt-6 grid gap-6 md:grid-cols-2 border-t border-white/[0.06] pt-4">
        <div>
          <div className="eyebrow mb-2.5">Adversary Tactics Detected</div>
          {message.tactics?.length ? (
            <ul className="flex flex-wrap gap-1.5">
              {message.tactics.map((t) => (
                <li key={t.key} className="rounded border border-amber-400/25 bg-amber-400/[0.08] px-2 py-0.5 text-xs text-amber-200">
                  <span>{TACTICS[t.key] || t.key}</span>
                  {t.count > 1 && <span className="ml-1 text-amber-300 font-mono font-semibold">×{t.count}</span>}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-white/40">No overt manipulation tactics detected.</p>
          )}
        </div>

        <div>
          <div className="eyebrow mb-2.5">Extracted Threat Indicators</div>
          <div className="grid gap-3 sm:grid-cols-2">
            <IndicatorList icon={Link2} label="URLs" items={ind.urls || []} />
            <IndicatorList icon={Globe} label="Domains" items={ind.domains || []} />
            <IndicatorList icon={Mail} label="Emails" items={ind.emails || []} />
            <IndicatorList icon={Phone} label="Phone Numbers" items={ind.phones || []} />
          </div>
        </div>
      </div>
    </section>
  );
}
