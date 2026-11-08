import { AlertOctagon, Inbox } from 'lucide-react';
import { cx } from '../../utils/format.js';

export function Skeleton({ className }) {
  return <div className={cx('animate-pulse rounded-md bg-ink-700/60', className)} />;
}

export function ErrorState({ title = 'Something went wrong', message, action }) {
  return (
    <div className="panel panel-pad flex flex-col items-start gap-3 border-red-500/30" role="alert">
      <div className="flex items-center gap-2 text-red-300">
        <AlertOctagon size={18} />
        <span className="font-semibold">{title}</span>
      </div>
      {message && <p className="text-sm text-white/70">{message}</p>}
      {action}
    </div>
  );
}

export function EmptyState({ icon: Icon = Inbox, title, message, action }) {
  return (
    <div className="panel flex flex-col items-center gap-3 px-6 py-14 text-center">
      <div className="rounded-full border border-white/10 bg-ink-800 p-3 text-white/55">
        <Icon size={22} strokeWidth={1.5} />
      </div>
      <div className="font-display text-base font-semibold text-white">{title}</div>
      {message && <p className="max-w-md text-sm text-white/55">{message}</p>}
      {action}
    </div>
  );
}

export function Notice({ children, toneClass = 'border-signal/25 bg-signal/[0.06] text-white/85', icon: Icon }) {
  return (
    <div className={cx('flex gap-3 rounded-lg border px-4 py-3 text-sm', toneClass)}>
      {Icon && <Icon size={16} className="mt-0.5 shrink-0" />}
      <div>{children}</div>
    </div>
  );
}
