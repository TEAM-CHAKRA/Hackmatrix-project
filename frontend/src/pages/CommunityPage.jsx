import { PageHeader } from '../components/ui/Glass.jsx';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { Users, Send, Loader2, AlertTriangle, CheckCircle2, Lock, Link2, Globe, Phone, Mail, ShieldAlert, Blocks, Scale, RefreshCw, ThumbsUp, ThumbsDown, ShieldCheck } from 'lucide-react';
import { listCommunityReports, submitCommunityReport, voteCommunityReport, updateCommunityReportStatus, registerCommunityReport } from '../services/api.js';
import { useAuth } from '../hooks/useAuth.jsx';
import { Chip } from '../components/ui/Badges.jsx';
import { EmptyState, Skeleton } from '../components/ui/States.jsx';
import { COMMUNITY_STATUS, THREAT_CATEGORIES, PRIVACY_WARNING } from '../utils/constants.js';
import { validateInvestigationUrl } from '../utils/url.js';
import { cx, formatDateTime, titleCase } from '../utils/format.js';

const TARGET_TYPES = [
  { key: 'url', label: 'URL', icon: Link2, placeholder: 'https://suspicious.example/login' },
  { key: 'domain', label: 'Domain', icon: Globe, placeholder: 'suspicious.example' },
  { key: 'phone', label: 'Phone', icon: Phone, placeholder: '+91 98765 43210' },
  { key: 'email', label: 'Email', icon: Mail, placeholder: 'alerts@suspicious.example' },
];

const DOMAIN_RE = /^(?=.{3,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;
const PHONE_RE = /^\+?[0-9][0-9\s-]{6,16}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function validate(form) {
  const errors = {};
  const t = form.target.trim();
  if (!t) errors.target = 'Enter the suspicious target.';
  else if (form.targetType === 'url' && !validateInvestigationUrl(t).ok) errors.target = validateInvestigationUrl(t).error;
  else if (form.targetType === 'domain' && !DOMAIN_RE.test(t)) errors.target = 'Enter a valid domain, e.g. suspicious.example';
  else if (form.targetType === 'phone' && !PHONE_RE.test(t)) errors.target = 'Enter a valid phone number.';
  else if (form.targetType === 'email' && !EMAIL_RE.test(t)) errors.target = 'Enter a valid email address.';
  if (!form.category) errors.category = 'Choose a category.';
  const d = form.description.trim();
  if (d.length < 20) errors.description = 'Describe what happened in at least 20 characters.';
  else if (d.length > 1000) errors.description = 'Keep the description under 1000 characters.';
  if (!form.confirm) errors.confirm = 'Please confirm before submitting.';
  return errors;
}

const EMPTY = { targetType: 'url', target: '', category: '', description: '', confirm: false };

function FieldError({ id, children }) {
  if (!children) return null;
  return (
    <p id={id} className="mt-1.5 text-xs text-red-300">
      {children}
    </p>
  );
}

function SubmitForm({ onSubmitted }) {
  const [form, setForm] = useState(EMPTY);
  const [errors, setErrors] = useState({});
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState(null);
  const [success, setSuccess] = useState(null);

  const set = (k, v) => {
    setForm((f) => ({ ...f, [k]: v }));
    if (errors[k]) setErrors((e) => ({ ...e, [k]: undefined }));
  };
  const type = TARGET_TYPES.find((t) => t.key === form.targetType);

  async function submit(e) {
    e.preventDefault();
    setServerError(null);
    setSuccess(null);
    const errs = validate(form);
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setBusy(true);
    try {
      const res = await submitCommunityReport({
        targetType: form.targetType,
        target: form.target.trim(),
        category: form.category,
        description: form.description.trim(),
      });
      setSuccess(res.report || { id: res.reportId, status: 'pending_review' });
      setForm(EMPTY);
      onSubmitted?.();
    } catch (err) {
      setServerError({ message: err.message || 'Submission failed.', status: err.status });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} noValidate className="rounded-xl border border-white/[0.08] glass-card p-6 ">
      <div className="flex items-center gap-3 border-b border-white/[0.06] pb-4">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 glass-inset text-signal">
          <ShieldAlert size={18} />
        </span>
        <div>
          <h2 className="font-display text-base font-bold text-white">Submit a Threat Report</h2>
          
        </div>
      </div>

      {/* Target Type Selector */}
      <fieldset className="mt-5">
        <legend className="eyebrow mb-2">What are you reporting?</legend>
        <div className="grid grid-cols-4 gap-1 rounded-lg border border-white/10 glass-inset p-1" role="radiogroup">
          {TARGET_TYPES.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              type="button"
              role="radio"
              aria-checked={form.targetType === key}
              onClick={() => {
                set('targetType', key);
                setErrors((e) => ({ ...e, target: undefined }));
              }}
              className={cx(
                'flex items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-medium transition-colors',
                form.targetType === key ? 'bg-signal text-midnight font-semibold' : 'text-white/60 hover:text-white'
              )}
            >
              <Icon size={13} className="hidden sm:block" />
              <span>{label}</span>
            </button>
          ))}
        </div>
      </fieldset>

      {/* Target input */}
      <div className="mt-4">
        <label htmlFor="cr-target" className="eyebrow mb-2 block">
          Suspicious {type.label}
        </label>
        <input
          id="cr-target"
          className={cx('input font-mono text-xs', errors.target && 'border-red-400/60')}
          placeholder={type.placeholder}
          value={form.target}
          onChange={(e) => set('target', e.target.value)}
          autoComplete="off"
          spellCheck="false"
          aria-invalid={!!errors.target}
          aria-describedby="cr-target-err"
        />
        <FieldError id="cr-target-err">{errors.target}</FieldError>
      </div>

      {/* Category selector */}
      <div className="mt-4">
        <label htmlFor="cr-category" className="eyebrow mb-2 block">
          Category
        </label>
        <select
          id="cr-category"
          className={cx('input appearance-none text-xs [&>option]:glass-card', errors.category && 'border-red-400/60')}
          value={form.category}
          onChange={(e) => set('category', e.target.value)}
          aria-invalid={!!errors.category}
          aria-describedby="cr-category-err"
        >
          <option value="">Select a category...</option>
          {Object.entries(THREAT_CATEGORIES).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <FieldError id="cr-category-err">{errors.category}</FieldError>
      </div>

      {/* Description textarea */}
      <div className="mt-4">
        <div className="mb-2 flex items-baseline justify-between">
          <label htmlFor="cr-desc" className="eyebrow">
            What happened?
          </label>
          <span className={cx('font-mono text-[10px]', form.description.length > 1000 ? 'text-red-300' : 'text-white/40')}>
            {form.description.length}/1000
          </span>
        </div>
        <textarea
          id="cr-desc"
          rows={4}
          className={cx('input resize-y text-xs leading-relaxed', errors.description && 'border-red-400/60')}
          placeholder="Describe how the target was received, claimed organization, or observed threat behavior..."
          value={form.description}
          onChange={(e) => set('description', e.target.value)}
          aria-invalid={!!errors.description}
          aria-describedby="cr-desc-err cr-privacy"
        />
        <FieldError id="cr-desc-err">{errors.description}</FieldError>
        <p id="cr-privacy" className="mt-2 flex items-center gap-1.5 text-xs text-amber-200/90">
          <Lock size={12} className="shrink-0 text-amber-300" />
          <span>{PRIVACY_WARNING}</span>
        </p>
      </div>

      {/* Confirmation checkbox */}
      <label className="mt-4 flex cursor-pointer items-start gap-2.5 text-xs text-white/70">
        <input
          type="checkbox"
          checked={form.confirm}
          onChange={(e) => set('confirm', e.target.checked)}
          className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-[#00D1B2]"
          aria-invalid={!!errors.confirm}
        />
        <span>
          This report is accurate and contains no personal data or passwords.
          {errors.confirm && <span className="mt-1 block text-red-300 font-medium">{errors.confirm}</span>}
        </span>
      </label>

      {/* Server Feedback */}
      <AnimatePresence>
        {serverError && (
          <motion.div
            key="err"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            role="alert"
            className="mt-4 flex items-start gap-2 rounded-lg border border-red-400/30 bg-red-500/10 p-3 text-xs text-red-200"
          >
            <AlertTriangle size={14} className="mt-0.5 shrink-0 text-red-400" />
            <span>{serverError.message}</span>
          </motion.div>
        )}
        {success && (
          <motion.div
            key="ok"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            role="status"
            className="mt-4 flex items-start gap-2 rounded-lg border border-signal/30 bg-signal/10 p-3 text-xs text-white"
          >
            <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-signal" />
            <span>
              Report submitted successfully{success.id ? <> (<span className="font-mono">{success.id}</span>)</> : ''}. Status: {COMMUNITY_STATUS[success.status]?.label || 'Pending Review'}.
            </span>
          </motion.div>
        )}
      </AnimatePresence>

      <button type="submit" disabled={busy} className="btn-primary mt-5 w-full py-3 text-xs font-semibold">
        {busy ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />}
        <span>{busy ? 'Submitting Report...' : 'Submit Threat Report'}</span>
      </button>
    </form>
  );
}

const MOD_ACTIONS = [
  { status: 'validated', label: 'Validate' },
  { status: 'disputed', label: 'Mark disputed' },
  { status: 'rejected', label: 'Reject' },
];

/** Vote buttons for everyone; moderation + on-chain anchoring for admins. */
function ReportActions({ r, onChange }) {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [myVote, setMyVote] = useState(null);

  async function run(key, fn) {
    setBusy(key);
    setError('');
    try {
      await fn();
    } catch (err) {
      setError(err.message || 'Something went wrong.');
    } finally {
      setBusy('');
    }
  }

  const vote = (voteType) =>
    run(voteType, async () => {
      const res = await voteCommunityReport(r.id, voteType);
      setMyVote(voteType);
      onChange({ validation: res.report.validation, status: res.report.status });
    });

  const moderate = (status) =>
    run(status, async () => {
      const res = await updateCommunityReportStatus(r.id, status);
      onChange(res.report);
    });

  const anchor = () =>
    run('anchor', async () => {
      const res = await registerCommunityReport(r.id);
      onChange({ registry: res.registry });
    });

  const canAnchor = isAdmin && r.status === 'validated' && r.registry?.status !== 'registered';

  return (
    <div className="mt-3 border-t border-white/[0.06] pt-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="mr-1 text-[11px] text-white/45">Seen this too?</span>
        {[
          { type: 'confirm', label: 'Confirm', Icon: ThumbsUp, on: 'border-signal/50 bg-signal/15 text-signal' },
          { type: 'dispute', label: 'Dispute', Icon: ThumbsDown, on: 'border-orange-400/50 bg-orange-500/15 text-orange-200' },
        ].map(({ type, label, Icon, on }) => (
          <button
            key={type}
            type="button"
            onClick={() => vote(type)}
            disabled={Boolean(busy)}
            aria-pressed={myVote === type}
            className={cx(
              'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-[11px] font-medium transition',
              myVote === type ? on : 'border-white/10 text-white/65 hover:border-white/25 hover:text-white'
            )}
          >
            {busy === type ? <Loader2 size={12} className="animate-spin" /> : <Icon size={12} />}
            {label}
          </button>
        ))}

        {isAdmin && (
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <span className="text-[10.5px] font-mono uppercase tracking-wider text-white/40">Admin</span>
            {MOD_ACTIONS.filter((a) => a.status !== r.status).map((a) => (
              <button
                key={a.status}
                type="button"
                onClick={() => moderate(a.status)}
                disabled={Boolean(busy) || r.registry?.status === 'registered'}
                className="rounded-full border border-white/10 px-3 py-1 text-[11px] text-white/70 transition hover:border-white/25 hover:text-white disabled:opacity-40"
              >
                {busy === a.status ? <Loader2 size={12} className="inline animate-spin" /> : a.label}
              </button>
            ))}
            {canAnchor && (
              <button type="button" onClick={anchor} disabled={Boolean(busy)} className="btn-primary px-3 py-1 text-[11px] font-semibold">
                {busy === 'anchor' ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
                Anchor on-chain
              </button>
            )}
          </div>
        )}
      </div>
      {error && (
        <p role="alert" className="mt-2 flex items-center gap-1.5 text-[11px] text-red-300">
          <AlertTriangle size={12} /> {error}
        </p>
      )}
    </div>
  );
}

function ReportItem({ r: initial }) {
  const [r, setR] = useState(initial);
  const st = COMMUNITY_STATUS[r.status] || { label: titleCase(r.status || 'pending_review'), tone: 'gray' };
  return (
    <li className="rounded-xl border border-white/[0.08] glass-card p-5 shadow-sm transition-colors hover:border-white/20">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded bg-amber-400/10 px-2 py-0.5 font-mono text-[10.5px] font-semibold text-amber-300 border border-amber-400/20">
              <Users size={11} /> COMMUNITY REPORT
            </span>
            {r.category && (
              <span className="rounded bg-white/[0.06] px-2 py-0.5 font-mono text-[10.5px] text-white/70">
                {THREAT_CATEGORIES[r.category] || titleCase(r.category)}
              </span>
            )}
          </div>
          <div className="mt-2 font-mono text-sm font-semibold text-white/90">{r.id}</div>
          {r.targetDisplay && <div className="mt-0.5 break-all font-mono text-xs text-white/50">{r.targetDisplay}</div>}
        </div>
        <Chip toneName={st.tone}>{st.label}</Chip>
      </div>

      {r.description && (
        <p className="mt-3 text-xs leading-relaxed text-white/65 line-clamp-3 glass-inset p-3 rounded-lg border border-white/[0.04]">
          {r.description}
        </p>
      )}

      <div className="mt-3.5 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-white/[0.06] pt-3 text-xs text-white/50">
        <span className="font-mono text-[11px]">{formatDateTime(r.submittedAt)}</span>
        {r.validation && (
          <span className="inline-flex items-center gap-1 font-mono text-[11px]">
            <Scale size={11} />
            <span className="text-signal">{r.validation.confirms ?? 0} confirms</span> ·{' '}
            <span className="text-orange-300">{r.validation.disputes ?? 0} disputes</span>
          </span>
        )}
        <span className="inline-flex items-center gap-1 font-mono text-[11px]">
          <Blocks size={11} />
          {r.registry?.status === 'registered' ? (
            r.registry.explorerUrl ? (
              <a href={r.registry.explorerUrl} target="_blank" rel="noopener noreferrer" className="text-signal hover:underline">
                On-Chain
              </a>
            ) : (
              <span className="text-signal">On-Chain</span>
            )
          ) : (
            'Unregistered'
          )}
        </span>
        {r.linkedInvestigationId && (
          <Link to={`/report/${encodeURIComponent(r.linkedInvestigationId)}`} className="text-signal hover:underline ml-auto">
            View Investigation →
          </Link>
        )}
      </div>
      {r.status !== 'rejected' && <ReportActions r={r} onChange={(patch) => setR((cur) => ({ ...cur, ...patch }))} />}
    </li>
  );
}

export default function CommunityPage() {
  const [state, setState] = useState({ loading: true, items: [], error: null, demo: false });

  async function load() {
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const res = await listCommunityReports();
      setState({ loading: false, items: res.items || [], error: null, demo: !!res.demo });
    } catch (err) {
      setState({ loading: false, items: [], error: err.message, demo: false });
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="mx-auto max-w-7xl px-4 pb-24 pt-12 sm:px-6 sm:pt-16">
      <PageHeader eyebrow="Community" title="Report a" accent="threat.">
        Seen a scam link or message? Report it. Reports stay marked unverified until reviewed.
      </PageHeader>

      <div className="mt-10 grid items-start gap-8 lg:grid-cols-[1.1fr_1.3fr]">
        {/* Left: Form & Explanations */}
        <div className="space-y-6 lg:sticky lg:top-20">
          <SubmitForm onSubmitted={load} />
        </div>

        {/* Right: Existing Reports */}
        <div>
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="font-display text-base font-bold text-white flex items-center gap-2">
              <Users size={16} className="text-signal" />
              <span>Reported Threats</span>
              <span className="font-mono text-xs text-white/40">({state.items.length})</span>
            </h2>
            <button onClick={load} disabled={state.loading} className="btn-secondary px-3 py-1.5 text-xs">
              <RefreshCw size={12} className={state.loading ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>

          {state.loading && (
            <div className="space-y-3">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-32 w-full rounded-xl" />
              ))}
            </div>
          )}

          {!state.loading && state.error && (
            <EmptyState
              icon={AlertTriangle}
              title="Failed to retrieve community reports"
              message={state.error}
              action={
                <button onClick={load} className="btn-secondary mt-2 text-xs">
                  Retry
                </button>
              }
            />
          )}

          {!state.loading && !state.error && state.items.length === 0 && (
            <EmptyState
              icon={Users}
              title="No community reports on record"
              message={
                state.demo
                  ? 'Demo mode doesn\'t store reports.'
                  : 'Be the first to submit a newly observed scam or suspicious domain.'
              }
            />
          )}

          {!state.loading && state.items.length > 0 && (
            <ul className="space-y-3">
              {state.items.map((r) => (
                <ReportItem key={r.id} r={r} />
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
