import { ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, HelpCircle } from 'lucide-react';
import { CHECK_STATUS, CLASSIFICATIONS, SEVERITY } from '../../utils/constants.js';
import { tone } from '../../utils/tones.js';
import { cx } from '../../utils/format.js';

const RISK_ICON = {
  low_risk: ShieldCheck,
  suspicious: AlertTriangle,
  high_risk: ShieldAlert,
  confirmed_malicious: ShieldX,
  inconclusive: HelpCircle,
};

export function RiskBadge({ classification, size = 'md' }) {
  const c = CLASSIFICATIONS[classification] || CLASSIFICATIONS.inconclusive;
  const t = tone(c.tone);
  const Icon = RISK_ICON[c.key];
  const sizes = {
    sm: 'px-2 py-0.5 text-[11px] gap-1',
    md: 'px-2.5 py-1 text-xs gap-1.5',
    lg: 'px-3 py-1.5 text-sm gap-2',
  };
  return (
    <span className={cx('inline-flex items-center rounded-md border font-semibold', t.bg, t.border, t.text, sizes[size])}>
      <Icon size={size === 'lg' ? 16 : 13} strokeWidth={2} />
      {c.label}
    </span>
  );
}

export function CheckStatusPill({ status }) {
  const s = CHECK_STATUS[status] || CHECK_STATUS.not_checked;
  const t = tone(s.tone);
  return (
    <span className={cx('inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-0.5 font-mono text-[11px]', t.border, t.text, t.bg)}>
      <span className={cx('h-1.5 w-1.5 rounded-full', t.dot)} />
      {s.label}
    </span>
  );
}

export function SeverityPill({ severity }) {
  const s = SEVERITY[severity] || SEVERITY.info;
  const t = tone(s.tone);
  return (
    <span className={cx('inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider', t.bg, t.text)}>
      {s.label}
    </span>
  );
}

export function Chip({ children, toneName = 'gray', className }) {
  const t = tone(toneName);
  return (
    <span className={cx('inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium', t.border, t.bg, t.text, className)}>
      {children}
    </span>
  );
}
