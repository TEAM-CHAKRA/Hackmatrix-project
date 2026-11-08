import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Loader2, LogIn, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../hooks/useAuth.jsx';
import AuthShell, { AuthField, PasswordField, FormError, EMAIL_RE } from '../components/AuthShell.jsx';

export default function LoginPage() {
  const { login, user, status, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState(location.state?.email || '');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState('');
  const [busy, setBusy] = useState(false);
  const justRegistered = location.state?.registered;

  async function submit(e) {
    e.preventDefault();
    setServerError('');
    const errs = {};
    if (!EMAIL_RE.test(email.trim())) errs.email = 'Enter a valid email address.';
    if (!password) errs.password = 'Enter your password.';
    setErrors(errs);
    if (Object.keys(errs).length) return;

    setBusy(true);
    try {
      await login({ email: email.trim(), password });
      setPassword('');
      navigate(location.state?.from || '/', { replace: true });
    } catch (err) {
      setServerError(err.status === 401 ? 'Incorrect email or password.' : err.message || 'Login failed.');
    } finally {
      setBusy(false);
    }
  }

  if (status === 'authenticated' && user) {
    return (
      <AuthShell title="You're signed in" subtitle={user.email}>
        <div className="space-y-3">
          <Link to="/scanner" className="btn-primary w-full py-2.5 text-xs">
            Go to Scanner
          </Link>
          <button onClick={logout} className="btn-secondary w-full py-2.5 text-xs">
            Log out
          </button>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Welcome back"
      
      footer={
        <>
          New to CYBERLENS?{' '}
          <Link to="/register" className="font-medium text-signal hover:underline">
            Create an account
          </Link>
        </>
      }
    >
      <form onSubmit={submit} noValidate className="space-y-4">
        {justRegistered && (
          <p className="flex items-start gap-2 rounded-lg border border-signal/30 bg-signal/10 p-2.5 text-xs text-white">
            <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-signal" /> Account created. Log in to continue.
          </p>
        )}
        <AuthField
          id="login-email"
          label="Email"
          type="email"
          autoComplete="email"
          inputMode="email"
          placeholder="you@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          error={errors.email}
        />
        <PasswordField
          id="login-password"
          label="Password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={errors.password}
        />
        <FormError>{serverError}</FormError>
        <button type="submit" disabled={busy} className="btn-primary w-full py-2.5 text-xs font-semibold">
          {busy ? <Loader2 size={14} className="animate-spin" /> : <LogIn size={14} />}
          <span>{busy ? 'Logging in...' : 'Login'}</span>
        </button>
      </form>
    </AuthShell>
  );
}
