import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Copy, Check, Download, Printer, ShieldCheck, Link2, MessageSquareText } from 'lucide-react';
import { CLASSIFICATIONS } from '../../utils/constants.js';
import { tone } from '../../utils/tones.js';
import { copyToClipboard, cx, downloadJson, formatDateTime } from '../../utils/format.js';
import { RiskBadge } from '../ui/Badges.jsx';
import Tooltip from '../ui/Tooltip.jsx';

const CONFIDENCE = {
  high: { label: 'High', bars: 3 },
  medium: { label: 'Medium', bars: 2 },
  low: { label: 'Low', bars: 1 },
};

function Stat({ label, tip, children }) {
  return (
    <div className="min-w-0">
      <div className="eyebrow mb-1">{tip ? <Tooltip text={tip}>{label}</Tooltip> : label}</div>
      <div className="text-xs text-white/90">{children}</div>
    </div>
  );
}

export default function ReportHeader({ report, onExport }) {
  const [copied, setCopied] = useState(false);
  const c = CLASSIFICATIONS[report.classification] || CLASSIFICATIONS.inconclusive;
  const t = tone(c.tone);
  const conf = CONFIDENCE[report.confidence] || CONFIDENCE.low;
  const cov = report.coverage || { completed: 0, total: 0 };
  const covPct = cov.total ? Math.round((cov.completed / cov.total) * 100) : 0;
  const TypeIcon = report.type === 'message' ? MessageSquareText : Link2;

  async function copyId() {
    if (await copyToClipboard(report.id)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    }
  }

  return (
    <header className="rounded-xl border border-white/[0.08] glass-card overflow-hidden">
      {/* Top Banner with Risk Level */}
      <div className={cx('border-b px-5 py-4 sm:px-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between', t.border)}>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-white/50">
            <span>Report</span>
            <span className="text-white/20">/</span>
            <span className="text-white/90 font-medium">{report.id}</span>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-3">
            <RiskBadge classification={report.classification} size="lg" />
            <span className={cx('font-display text-xl font-bold tracking-tight sm:text-2xl', t.text)}>
              {c.headline}
            </span>
          </div>

          <p className="mt-2 max-w-2xl text-xs leading-relaxed text-white/60">{c.description}</p>

          <div className="mt-3.5 flex min-w-0 items-center gap-2 rounded-lg border border-white/[0.06] glass-inset px-3 py-2 font-mono text-xs">
            <TypeIcon size={14} className="shrink-0 text-white/40" />
            <span className="min-w-0 break-all text-white/90">{report.target?.display || '—'}</span>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="no-print grid shrink-0 grid-cols-2 gap-2 sm:flex sm:flex-wrap">
          <button onClick={copyId} className="btn-secondary px-3 py-2 text-xs">
            {copied ? <Check size={13} className="text-signal" /> : <Copy size={13} />}
            <span>{copied ? 'Copied' : 'Copy ID'}</span>
          </button>
          <button onClick={onExport} className="btn-secondary px-3 py-2 text-xs">
            <Download size={13} />
            <span>Export JSON</span>
          </button>
          <button onClick={() => window.print()} className="btn-secondary px-3 py-2 text-xs">
            <Printer size={13} />
            <span>Print / PDF</span>
          </button>
          <Link to={`/verify?id=${encodeURIComponent(report.id)}`} className="btn-secondary px-3 py-2 text-xs">
            <ShieldCheck size={13} className="text-signal" />
            <span>Verify Integrity</span>
          </Link>
        </div>
      </div>

      {/* Metadata Telemetry Grid */}
      <div className="grid grid-cols-2 gap-x-6 gap-y-4 border-t border-white/[0.06] glass-inset px-5 py-3.5 sm:px-6 md:grid-cols-5 text-xs">
        <Stat label="Type">
          <span className="font-mono">{report.type === 'message' ? 'Message Communication' : 'URL / Web Domain'}</span>
        </Stat>

        <Stat label="Date">
          <span className="font-mono">{formatDateTime(report.completedAt || report.createdAt)}</span>
        </Stat>

        <Stat label="Confidence" tip="How strongly the evidence supports the result. Separate from risk.">
          <div className="flex items-center gap-2">
            <span className="flex gap-0.5" aria-hidden>
              {[1, 2, 3].map((n) => (
                <span
                  key={n}
                  className={cx('h-2.5 w-1 rounded-sm', n <= conf.bars ? 'bg-signal' : 'bg-white/10')}
                />
              ))}
            </span>
            <span className="font-mono">{conf.label}</span>
          </div>
        </Stat>

        <Stat label="Coverage" tip="How many planned checks actually completed.">
          <div className="font-mono">
            {cov.completed} of {cov.total} checks ({covPct}%)
          </div>
          <div className="mt-1 h-1 w-full max-w-[120px] rounded-full bg-white/10 overflow-hidden">
            <div className="h-full rounded-full bg-signal" style={{ width: `${covPct}%` }} />
          </div>
        </Stat>

        <Stat label="Heuristic score" tip="Rule-based 0–100 score. Not a probability that the site is malicious.">
          <span className="font-mono">
            {report.heuristicScore != null ? `${report.heuristicScore} / 100` : 'Not Evaluated'}
          </span>
        </Stat>
      </div>
    </header>
  );
}

export function exportReport(report) {
  downloadJson(`cyberlens-${report.id}.json`, report);
}
