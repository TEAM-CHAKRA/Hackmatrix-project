import { forwardRef, useImperativeHandle, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { Link2, MessageSquareText, ScanSearch, Loader2, Lock, AlertTriangle, FlaskConical, Terminal } from 'lucide-react';
import { createInvestigation, USE_MOCKS } from '../services/api.js';
import { validateInvestigationUrl, validateMessage } from '../utils/url.js';
import { PRIVACY_WARNING, SAMPLE_MESSAGES, SAMPLE_URLS } from '../utils/constants.js';
import { cx } from '../utils/format.js';
import { stashMessage } from '../utils/session.js';

const TABS = [
  { key: 'url', label: 'Link / Domain', icon: Link2 },
  { key: 'message', label: 'Message', icon: MessageSquareText },
];

function AnalyzeButton({ busy, label, className }) {
  return (
    <button
      type="submit"
      disabled={busy}
      className={cx('btn-primary px-5 py-3 text-sm font-semibold whitespace-nowrap', className)}
    >
      {busy ? (
        <Loader2 size={15} className="animate-spin" />
      ) : (
        <ScanSearch size={15} />
      )}
      <span>{busy ? 'Starting…' : label}</span>
    </button>
  );
}

const InvestigationConsole = forwardRef(function InvestigationConsole(_, ref) {
  const navigate = useNavigate();
  const [mode, setMode] = useState('url');
  const [url, setUrl] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [warning, setWarning] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [activeSample, setActiveSample] = useState(null);
  const urlRef = useRef(null);
  const msgRef = useRef(null);

  function switchMode(next) {
    setMode(next);
    setError('');
    setWarning('');
  }

  function loadSample(kind, value, id = null) {
    switchMode(kind);
    setActiveSample(id);
    if (kind === 'url') setUrl(value);
    else setMessage(value);
    setTimeout(() => (kind === 'url' ? urlRef.current : msgRef.current)?.focus({ preventScroll: true }), 50);
  }

  function focusInput() {
    (mode === 'url' ? urlRef.current : msgRef.current)?.focus({ preventScroll: true });
  }

  useImperativeHandle(ref, () => ({ loadSample, focusInput }));

  async function submit(e) {
    e.preventDefault();
    if (submitting) return;
    setError('');
    setWarning('');

    const raw = mode === 'url' ? url : message;
    const v = mode === 'url' ? validateInvestigationUrl(raw) : validateMessage(raw);
    if (!v.ok) {
      setError(v.error);
      return;
    }
    if (v.warning) setWarning(v.warning);

    setSubmitting(true);
    try {
      const payload = mode === 'url' ? { type: 'url', target: v.value } : { type: 'message', content: v.value };
      const res = await createInvestigation(payload);
      if (mode === 'message') stashMessage(res.investigationId, v.value);
      navigate(`/report/${encodeURIComponent(res.investigationId)}`);
    } catch (err) {
      setError(err.message || 'Could not start the investigation.');
      setSubmitting(false);
    }
  }

  const samples = mode === 'url' ? SAMPLE_URLS : SAMPLE_MESSAGES;

  return (
    <div className="rounded-xl border border-white/[0.1] glass-card overflow-hidden">
      {/* Console Header Bar */}
      <div className="flex flex-col gap-3 border-b border-white/[0.08] glass-inset px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div className="flex items-center gap-2.5">
          <span className="flex h-7 w-7 items-center justify-center rounded-md border border-white/10 bg-white/[0.04] text-signal">
            <Terminal size={14} />
          </span>
          <div>
            <div className="font-display text-sm font-bold text-white">New investigation</div>
          </div>
        </div>

        {/* Tab switcher */}
        <div role="tablist" aria-label="Investigation Mode" className="flex rounded-lg border border-white/10 glass-inset p-0.5">
          {TABS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              role="tab"
              type="button"
              aria-selected={mode === key}
              onClick={() => switchMode(key)}
              className={cx(
                'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
                mode === key
                  ? 'bg-signal text-midnight font-semibold shadow-sm'
                  : 'text-white/60 hover:text-white'
              )}
            >
              <Icon size={13} />
              <span>{label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Input Form */}
      <form onSubmit={submit} className="px-5 py-6 sm:px-6 sm:py-6" noValidate>
        <AnimatePresence mode="wait" initial={false}>
          {mode === 'url' ? (
            <motion.div
              key="url"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
            >
              <label htmlFor="url" className="eyebrow mb-2 block">
                Link or domain
              </label>
              <div className="flex flex-col gap-2.5 sm:flex-row">
                <div className="relative flex-1">
                  <Link2 size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-white/40" />
                  <input
                    ref={urlRef}
                    id="url"
                    type="url"
                    inputMode="url"
                    autoComplete="off"
                    spellCheck="false"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => {
                      setUrl(e.target.value);
                      setActiveSample(null);
                    }}
                    className="input pl-10 font-mono text-xs py-3.5 text-white"
                    aria-invalid={!!error}
                    aria-describedby={error ? 'form-error' : 'url-help'}
                  />
                </div>
                <AnalyzeButton busy={submitting} label="Analyze" className="sm:w-44" />
              </div>
              <p id="url-help" className="mt-2 text-[11px] text-white/45">
                http:// or https:// links only.
              </p>
            </motion.div>
          ) : (
            <motion.div
              key="message"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
            >
              <label htmlFor="message" className="eyebrow mb-2 block">
                Message
              </label>
              <textarea
                ref={msgRef}
                id="message"
                rows={5}
                maxLength={5000}
                placeholder="Paste the SMS, email or WhatsApp message…"
                value={message}
                onChange={(e) => {
                  setMessage(e.target.value);
                  setActiveSample(null);
                }}
                className="input resize-y text-xs leading-relaxed"
                aria-invalid={!!error}
                aria-describedby="privacy-warning"
              />
              <div className="mt-3.5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p id="privacy-warning" className="flex items-center gap-1.5 text-xs text-amber-200/90">
                  <Lock size={12} className="shrink-0 text-amber-300" />
                  <span>{PRIVACY_WARNING}</span>
                </p>
                <AnalyzeButton busy={submitting} label="Analyze Message" />
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Validation Errors & Notices */}
        <AnimatePresence>
          {error && (
            <motion.p
              key="err"
              id="form-error"
              role="alert"
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mt-3.5 flex items-start gap-2 rounded-lg border border-red-400/30 bg-red-500/10 px-3.5 py-2.5 text-xs text-red-200"
            >
              <AlertTriangle size={14} className="mt-0.5 shrink-0 text-red-400" />
              <span>{error}</span>
            </motion.p>
          )}
          {warning && !error && (
            <motion.p
              key="warn"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="mt-3.5 flex items-start gap-2 rounded-lg border border-amber-400/30 bg-amber-400/10 px-3.5 py-2.5 text-xs text-amber-200"
            >
              <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber-400" />
              <span>{warning}</span>
            </motion.p>
          )}
        </AnimatePresence>
      </form>

      {/* Preset Test Scenarios */}
      <div className="border-t border-white/[0.08] glass-inset px-5 py-4 sm:px-6">
        <div className="mb-2.5 flex flex-wrap items-center gap-2">
          <FlaskConical size={13} className="text-signal" />
          <span className="font-mono text-[11px] uppercase tracking-wider text-white/50">Try a sample</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {samples.map((s) => (
            <button
              key={s.id}
              type="button"
              disabled={submitting}
              onClick={() => loadSample(mode, s.value, s.id)}
              className={cx(
                'rounded-md border px-3 py-1.5 text-left text-xs font-medium transition-colors disabled:opacity-50',
                activeSample === s.id
                  ? 'border-signal/60 bg-signal/15 text-signal'
                  : 'border-white/10 glass-inset text-white/70 hover:border-white/20 hover:text-white'
              )}
            >
              <span>{s.label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
});

export default InvestigationConsole;
