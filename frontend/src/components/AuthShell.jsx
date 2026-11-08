import { useState } from 'react';
import { Eye, EyeOff, AlertTriangle, ServerOff } from 'lucide-react';
import { useAuth } from '../hooks/useAuth.jsx';
import { USE_MOCKS } from '../services/api.js';
import Logo from './ui/Logo.jsx';
import { cx } from '../utils/format.js';

export default function AuthShell({ title, subtitle, children, footer }) {
  const { status } = useAuth();

  return (
    <div className="relative mx-auto flex max-w-md flex-col px-4 pb-20 pt-12 sm:pt-16">
      <div className="rounded-xl border border-white/[0.08] glass-card p-6 sm:p-8 ">
        <div className="flex flex-col items-center text-center">
          <Logo size={36} animated={false} />
          <h1 className="font-display text-2xl font-bold text-white mt-4">{title}</h1>
          {subtitle && <p className="mt-1 text-xs text-white/50">{subtitle}</p>}
        </div>

        {(USE_MOCKS || status === 'unavailable') && (
          <div className="mt-5 flex items-start gap-2.5 rounded-lg border border-amber-400/25 bg-amber-400/[0.06] p-3 text-xs leading-relaxed text-amber-200">
            <ServerOff size={14} className="mt-0.5 shrink-0 text-amber-300" />
            <span>
              {USE_MOCKS
                ? 'Sign-in is off in demo mode.'
                : 'Sign-in service is offline right now.'}
            </span>
          </div>
        )}

        <div className="mt-6">{children}</div>
      </div>

      {footer && <div className="mt-5 text-center text-xs text-white/50">{footer}</div>}
    </div>
  );
}

export function AuthField({ id, label, error, hint, className, ...props }) {
  return (
    <div className={className}>
      <label htmlFor={id} className="eyebrow mb-1.5 block">
        {label}
      </label>
      <input
        id={id}
        className={cx('input text-xs py-2.5', error && 'border-red-400/60')}
        aria-invalid={!!error}
        aria-describedby={error ? `${id}-err` : hint ? `${id}-hint` : undefined}
        {...props}
      />
      {error ? (
        <p id={`${id}-err`} className="mt-1 text-xs text-red-300">
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="mt-1 text-[11px] text-white/40">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function PasswordField({ id, label, error, hint, value, onChange, autoComplete, className }) {
  const [show, setShow] = useState(false);
  return (
    <div className={className}>
      <label htmlFor={id} className="eyebrow mb-1.5 block">
        {label}
      </label>
      <div className="relative">
        <input
          id={id}
          type={show ? 'text' : 'password'}
          className={cx('input pr-10 text-xs py-2.5', error && 'border-red-400/60')}
          value={value}
          onChange={onChange}
          autoComplete={autoComplete}
          aria-invalid={!!error}
          aria-describedby={error ? `${id}-err` : hint ? `${id}-hint` : undefined}
        />
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-1 text-white/40 hover:text-white transition-colors"
          aria-label={show ? 'Hide password' : 'Show password'}
          aria-pressed={show}
        >
          {show ? <EyeOff size={15} /> : <Eye size={15} />}
        </button>
      </div>
      {error ? (
        <p id={`${id}-err`} className="mt-1 text-xs text-red-300">
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="mt-1 text-[11px] text-white/40">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function FormError({ children }) {
  if (!children) return null;
  return (
    <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-400/30 bg-red-500/10 p-3 text-xs text-red-200">
      <AlertTriangle size={14} className="mt-0.5 shrink-0 text-red-400" />
      <span>{children}</span>
    </div>
  );
}

export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
