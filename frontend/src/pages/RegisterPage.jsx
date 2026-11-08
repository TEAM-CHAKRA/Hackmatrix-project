import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Loader2, UserPlus } from 'lucide-react';
import { useAuth } from '../hooks/useAuth.jsx';
import AuthShell, { AuthField, PasswordField, FormError, EMAIL_RE } from '../components/AuthShell.jsx';
import { cx } from '../utils/format.js';

function strength(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(s, 4);
}
const STRENGTH = [
  ['Too weak', 'bg-red-500'],
  ['Weak', 'bg-orange-400'],
  ['Fair', 'bg-amber-400'],
  ['Good', 'bg-signal/70'],
  ['Strong', 'bg-signal'],
];

export default function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ fullName: '', email: '', password: '', confirm: '', accept: false });
  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState('');
  const [busy, setBusy] = useState(false);
  const s = useMemo(() => strength(form.password), [form.password]);

  const set = (k) => (e) => {
    const v = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
    setForm((f) => ({ ...f, [k]: v }));
    if (errors[k]) setErrors((x) => ({ ...x, [k]: undefined }));
  };

  async function submit(e) {
    e.preventDefault();
    setServerError('');
    const errs = {};
    if (form.fullName.trim().length < 2) errs.fullName = 'Enter your full name.';
    if (!EMAIL_RE.test(form.email.trim())) errs.email = 'Enter a valid email address.';
    if (form.password.length < 8) errs.password = 'Use at least 8 characters.';
    else if (!/[A-Za-z]/.test(form.password) || !/\d/.test(form.password)) errs.password = 'Include at least one letter and one number.';
    if (form.confirm !== form.password) errs.confirm = 'Passwords do not match.';
    if (!form.accept) errs.accept = 'You need to accept the terms and privacy notice.';
    setErrors(errs);
    if (Object.keys(errs).length) return;

    setBusy(true);
    try {
      const res = await register({ fullName: form.fullName.trim(), email: form.email.trim(), password: form.password, acceptTerms: true });
      setForm((f) => ({ ...f, password: '', confirm: '' }));
      if (res.user) navigate('/', { replace: true });
      else navigate('/login', { replace: true, state: { registered: true, email: form.email.trim() } });
    } catch (err) {
      setServerError(err.status === 409 ? 'An account with this email already exists.' : err.message || 'Registration failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Create your account"
      subtitle="Save scans and report threats"
      footer={
        <>
          Already have an account?{' '}
          <Link to="/login" className="font-medium text-signal hover:underline">
            Log in
          </Link>
        </>
      }
    >
      <form onSubmit={submit} noValidate className="space-y-4">
        <AuthField id="reg-name" label="Full name" autoComplete="name" placeholder="Your name" value={form.fullName} onChange={set('fullName')} error={errors.fullName} />
        <AuthField
          id="reg-email"
          label="Email"
          type="email"
          inputMode="email"
          autoComplete="email"
          placeholder="you@example.com"
          value={form.email}
          onChange={set('email')}
          error={errors.email}
        />
        <div>
          <PasswordField
            id="reg-password"
            label="Password"
            autoComplete="new-password"
            value={form.password}
            onChange={set('password')}
            error={errors.password}
            hint={!errors.password ? 'At least 8 characters, with a letter and a number.' : undefined}
          />
          {form.password && (
            <div className="mt-2 flex items-center gap-3" aria-live="polite">
              <div className="flex flex-1 gap-1">
                {[0, 1, 2, 3].map((i) => (
                  <span key={i} className={cx('h-1 flex-1 rounded-full transition-colors', i < Math.max(1, s) ? STRENGTH[s][1] : 'bg-white/10')} />
                ))}
              </div>
              <span className="w-14 text-right font-mono text-[10px] uppercase tracking-wider text-white/50">{STRENGTH[s][0]}</span>
            </div>
          )}
        </div>
        <PasswordField id="reg-confirm" label="Confirm password" autoComplete="new-password" value={form.confirm} onChange={set('confirm')} error={errors.confirm} />

        <label className="flex cursor-pointer items-start gap-2.5 text-xs text-white/65">
          <input type="checkbox" checked={form.accept} onChange={set('accept')} className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-[#00D1B2]" aria-invalid={!!errors.accept} />
          <span>
            I agree to the terms and privacy notice.
            {errors.accept && <span className="mt-1 block text-red-300 font-medium">{errors.accept}</span>}
          </span>
        </label>

        <FormError>{serverError}</FormError>
        <button type="submit" disabled={busy} className="btn-primary w-full py-2.5 text-xs font-semibold">
          {busy ? <Loader2 size={14} className="animate-spin" /> : <UserPlus size={14} />}
          <span>{busy ? 'Creating account...' : 'Create Account'}</span>
        </button>
      </form>
    </AuthShell>
  );
}
