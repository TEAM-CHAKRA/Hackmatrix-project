import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { AnimatePresence, motion, useReducedMotion, useScroll, useSpring } from 'framer-motion';
import { Menu, X, ArrowRight, ArrowUpRight, LogOut, UserRound, Home, ScanSearch, Radio, Users, ShieldCheck } from 'lucide-react';
import { getHealth } from '../services/api.js';
import { useAuth } from '../hooks/useAuth.jsx';
import { useScanNow } from '../hooks/useScanNow.js';
import { cx } from '../utils/format.js';

export const NAV = [
  { to: '/', label: 'Home', icon: Home, end: true },
  { to: '/scanner', label: 'Scanner', icon: ScanSearch },
  { to: '/threat-feed', label: 'Threat Feed', icon: Radio },
  { to: '/community', label: 'Community', icon: Users },
  { to: '/verify', label: 'Verify', icon: ShieldCheck },
];

const STATUS = {
  checking: { dot: 'bg-white/50', ring: '', label: 'Checking backend' },
  online: { dot: 'bg-signal', ring: 'bg-signal', label: 'Backend online' },
  degraded: { dot: 'bg-amber-400', ring: 'bg-amber-400', label: 'Backend degraded' },
  offline: { dot: 'bg-red-500', ring: '', label: 'Backend offline' },
  demo: { dot: 'bg-amber-400', ring: 'bg-amber-400', label: 'Demo mode' },
};

function useBackendStatus() {
  const [status, setStatus] = useState('checking');
  useEffect(() => {
    let alive = true;
    getHealth()
      .then((h) => alive && setStatus(h.demo ? 'demo' : h.status === 'ok' ? 'online' : 'degraded'))
      .catch(() => alive && setStatus('offline'));
    return () => {
      alive = false;
    };
  }, []);
  return status;
}

function StatusDot({ status, size = 'h-2 w-2' }) {
  const s = STATUS[status];
  return (
    <span className={cx('relative flex', size)} title={s.label}>
      {s.ring && <span className={cx('absolute inline-flex h-full w-full animate-ping rounded-full opacity-60', s.ring)} />}
      <span className={cx('relative inline-flex rounded-full', size, s.dot, status === 'checking' && 'animate-pulse')} />
      <span className="sr-only">{s.label}</span>
    </span>
  );
}

/** Live backend connection indicator (used on the Scanner page and in the mobile menu). */
export function BackendStatus({ className }) {
  const status = useBackendStatus();
  return (
    <span
      className={cx('inline-flex items-center gap-2 rounded-full border border-white/[0.1] bg-white/[0.04] px-3 py-1 font-mono text-[11px] text-white/70 backdrop-blur-md', className)}
      role="status"
    >
      <StatusDot status={status} size="h-1.5 w-1.5" />
      {STATUS[status].label}
    </span>
  );
}

/* ---------------------------------------------------------------------------
 * Building blocks
 * ------------------------------------------------------------------------- */

/** A floating frosted-glass capsule. Tracks the cursor for a soft spotlight. */
function Island({ children, className, spotlight = false, ...rest }) {
  const ref = useRef(null);
  const onMove = useCallback((e) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', `${e.clientX - r.left}px`);
    el.style.setProperty('--my', `${e.clientY - r.top}px`);
  }, []);
  return (
    <div
      ref={ref}
      onMouseMove={spotlight ? onMove : undefined}
      className={cx(
        'nav-island group/island relative flex items-center rounded-full border border-white/[0.12] bg-[#001a36]/35 shadow-[inset_0_1px_0_rgba(255,255,255,0.10),0_12px_40px_-12px_rgba(0,0,0,0.7)] backdrop-blur-2xl backdrop-saturate-150',
        className
      )}
      {...rest}
    >
      {spotlight && (
        <span
          aria-hidden
          className="pointer-events-none absolute inset-0 rounded-full opacity-0 transition-opacity duration-300 group-hover/island:opacity-100"
          style={{ background: 'radial-gradient(140px circle at var(--mx, 50%) var(--my, 50%), rgba(0,209,178,0.16), transparent 70%)' }}
        />
      )}
      {children}
    </div>
  );
}

/** Animated lens mark: rotating reticle ring around a glowing core. */
function LensMark({ status }) {
  const reduce = useReducedMotion();
  return (
    <span className="relative flex h-8 w-8 shrink-0 items-center justify-center">
      <svg viewBox="0 0 40 40" className="absolute inset-0 h-full w-full" aria-hidden>
        <circle cx="20" cy="20" r="18" fill="none" stroke="rgba(255,255,255,0.16)" strokeWidth="1" />
        <g style={{ transformOrigin: '20px 20px' }} className={reduce ? '' : 'animate-[spin_9s_linear_infinite]'}>
          <circle cx="20" cy="20" r="13" fill="none" stroke="#00D1B2" strokeWidth="1.6" strokeDasharray="5 4" opacity="0.9" />
        </g>
        <g style={{ transformOrigin: '20px 20px' }} className={reduce ? '' : 'animate-[spin_5s_linear_infinite_reverse]'}>
          <path d="M20 2 A18 18 0 0 1 38 20" fill="none" stroke="#00D1B2" strokeWidth="1.8" strokeLinecap="round" opacity="0.7" />
        </g>
        <path d="M20 4v4M20 32v4M4 20h4M32 20h4" stroke="#fff" strokeWidth="1.4" strokeLinecap="round" opacity="0.85" />
      </svg>
      <span className="h-2.5 w-2.5 rounded-full bg-white shadow-[0_0_12px_3px_rgba(0,209,178,0.85)]" />
      {/* Backend status pip */}
      <span className="absolute -bottom-0.5 -right-0.5 rounded-full bg-[#001428] p-[2px]">
        <StatusDot status={status} size="h-1.5 w-1.5" />
      </span>
    </span>
  );
}

function ScanNowButton({ compact = false }) {
  const scanNow = useScanNow();
  return (
    <button
      onClick={scanNow}
      aria-keyshortcuts="/"
      title="Scan Now (press /)"
      className={cx(
        'group/scan relative isolate inline-flex items-center gap-2 overflow-hidden whitespace-nowrap rounded-full bg-signal font-semibold text-midnight shadow-[0_0_0_1px_rgba(0,209,178,0.6),0_8px_24px_-6px_rgba(0,209,178,0.7)] transition-all duration-200 hover:shadow-[0_0_0_1px_rgba(0,209,178,0.9),0_10px_32px_-4px_rgba(0,209,178,0.9)] active:scale-[0.97]',
        compact ? 'h-9 px-3.5 text-[13px]' : 'h-10 px-4 text-[13px] xl:pl-4 xl:pr-2'
      )}
    >
      {/* Scanning shimmer */}
      <span aria-hidden className="nav-shimmer pointer-events-none absolute inset-y-0 -left-1/2 -z-10 w-1/2 skew-x-[-20deg] bg-gradient-to-r from-transparent via-white/55 to-transparent" />
      <span className={cx(compact && 'max-[359px]:sr-only')}>Scan Now</span>
      {compact ? (
        <ArrowRight size={15} className="transition-transform group-hover/scan:translate-x-0.5" />
      ) : (
        <kbd className="hidden h-6 min-w-6 items-center xl:flex justify-center rounded-full bg-midnight/15 px-1.5 font-mono text-[11px] font-semibold">/</kbd>
      )}
    </button>
  );
}

function AccountActions({ mobile = false }) {
  const { user, status, logout } = useAuth();

  if (status === 'authenticated' && user) {
    return (
      <div className={cx('flex items-center gap-1', mobile && 'w-full gap-2')}>
        <span className={cx('inline-flex min-w-0 items-center gap-2 rounded-full px-3 py-1.5 text-[13px] text-white/85', mobile && 'flex-1 border border-white/10 bg-white/[0.04] py-3')}>
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-signal/15 text-signal">
            <UserRound size={13} />
          </span>
          <span className="max-w-[9rem] truncate">{user.fullName || user.name || user.email}</span>
        </span>
        <button onClick={logout} className={cx('inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] text-white/60 transition hover:bg-white/[0.06] hover:text-white', mobile && 'border border-white/10 py-3')} title="Log out">
          <LogOut size={14} />
          <span className={mobile ? '' : 'sr-only'}>Logout</span>
        </button>
      </div>
    );
  }

  return (
    <div className={cx('flex items-center gap-1', mobile && 'grid w-full grid-cols-2 gap-2')}>
      <NavLink
        to="/login"
        className={({ isActive }) =>
          cx(
            'inline-flex items-center justify-center rounded-full px-3.5 py-2 text-[13px] font-medium transition-colors',
            isActive ? 'text-signal' : 'text-white/70 hover:text-white',
            mobile && 'border border-white/10 bg-white/[0.04] py-3.5 text-[15px]'
          )
        }
      >
        Login
      </NavLink>
      <NavLink
        to="/register"
        className={({ isActive }) =>
          cx(
            'inline-flex items-center justify-center rounded-full border px-3.5 py-2 text-[13px] font-medium transition-all',
            isActive
              ? 'border-signal/60 bg-signal/15 text-white'
              : 'border-white/[0.16] bg-white/[0.05] text-white hover:border-signal/50 hover:bg-signal/10',
            mobile && 'py-3.5 text-[15px]'
          )
        }
      >
        Register
      </NavLink>
    </div>
  );
}

/* ---------------------------------------------------------------------------
 * Navbar
 * ------------------------------------------------------------------------- */

export default function GlassNavbar() {
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const location = useLocation();
  const status = useBackendStatus();
  const scanNow = useScanNow();
  const reduce = useReducedMotion();
  const headerRef = useRef(null);
  const [menuTop, setMenuTop] = useState(65);
  useEffect(() => {
    if (open && headerRef.current) setMenuTop(Math.round(headerRef.current.getBoundingClientRect().bottom));
  }, [open]);

  // Scroll progress line along the bottom of the dock.
  const { scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 140, damping: 30, mass: 0.3 });

  useEffect(() => setOpen(false), [location.pathname, location.key]);
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  // Keyboard: "/" opens the scanner (when not typing); Esc closes the menu.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') setOpen(false);
      const t = e.target;
      const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
      if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        scanNow();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [scanNow]);

  // Lock page scroll behind the full-screen mobile menu.
  useEffect(() => {
    document.body.style.overflow = open ? 'hidden' : '';
    return () => {
      document.body.style.overflow = '';
    };
  }, [open]);

  return (
    <header ref={headerRef} className="no-print pointer-events-none sticky top-0 z-50 h-[65px]">
      <div
        className={cx(
          'relative z-10 mx-auto flex h-full max-w-7xl items-center justify-between gap-3 px-3 transition-[padding] duration-500 sm:px-6',
          scrolled ? 'pt-1' : 'pt-2'
        )}
      >
        {/* Island 1 — brand */}
        <Island className={cx('pointer-events-auto shrink-0 transition-all duration-500', scrolled ? 'h-11 pl-1.5 pr-3.5' : 'h-12 pl-2 pr-4')}>
          <Link to="/" className="flex items-center gap-2.5" aria-label="CYBERLENS — Home">
            <LensMark status={status} />
            <span className="font-display text-[15px] font-bold tracking-[0.16em] text-white">
              CYBER<span className="text-signal">LENS</span>
            </span>
          </Link>
        </Island>

        {/* Island 2 — navigation dock (desktop) */}
        <Island spotlight className={cx('pointer-events-auto hidden overflow-hidden p-1 transition-all duration-500 lg:flex', scrolled ? 'h-11' : 'h-12')}>
          <nav aria-label="Primary" className="relative flex items-center">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink key={to} to={to} end={end} className="group/link relative block rounded-full outline-none">
                {({ isActive }) => (
                  <span
                    className={cx(
                      'relative z-10 flex items-center gap-2 whitespace-nowrap rounded-full px-3 transition-colors duration-200 xl:px-4',
                      scrolled ? 'py-2' : 'py-2.5',
                      isActive ? 'text-white' : 'text-white/60 group-hover/link:text-white'
                    )}
                  >
                    {isActive && (
                      <motion.span
                        layoutId="nav-lens"
                        transition={reduce ? { duration: 0 } : { type: 'spring', stiffness: 420, damping: 34 }}
                        className="absolute inset-0 -z-10 rounded-full border border-signal/40 bg-gradient-to-b from-signal/25 to-signal/[0.08] shadow-[inset_0_1px_0_rgba(255,255,255,0.18),0_0_22px_-4px_rgba(0,209,178,0.65)]"
                      >
                        {/* Lens glint */}
                        <span className="absolute left-1/2 top-0 h-px w-1/2 -translate-x-1/2 bg-gradient-to-r from-transparent via-white/80 to-transparent" />
                      </motion.span>
                    )}
                    <Icon
                      size={15}
                      strokeWidth={1.9}
                      className={cx('hidden transition-all duration-200 xl:block', isActive ? 'text-signal' : 'text-white/45 group-hover/link:-translate-y-px group-hover/link:text-signal')}
                    />
                    <span className="text-[13px] font-medium">{label}</span>
                  </span>
                )}
              </NavLink>
            ))}
          </nav>
          {/* Scroll progress */}
          <motion.span aria-hidden style={{ scaleX: progress }} className="absolute inset-x-5 bottom-0 h-[2px] origin-left rounded-full bg-gradient-to-r from-signal/0 via-signal to-signal/0" />
        </Island>

        {/* Island 3 — account + CTA (desktop) */}
        <Island className={cx('pointer-events-auto hidden shrink-0 gap-1 p-1 transition-all duration-500 lg:flex', scrolled ? 'h-11' : 'h-12')}>
          <AccountActions />
          <ScanNowButton />
        </Island>

        {/* Compact island (tablet / mobile) */}
        <Island className="pointer-events-auto flex h-12 gap-1 p-1 lg:hidden">
          <ScanNowButton compact />
          <button
            className="flex h-10 w-10 items-center justify-center rounded-full text-white/80 transition hover:bg-white/[0.08] hover:text-white"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-controls="mobile-nav"
            aria-label={open ? 'Close menu' : 'Open menu'}
          >
            <AnimatePresence mode="wait" initial={false}>
              <motion.span key={open ? 'x' : 'm'} initial={{ rotate: -90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: 90, opacity: 0 }} transition={{ duration: 0.15 }}>
                {open ? <X size={19} /> : <Menu size={19} />}
              </motion.span>
            </AnimatePresence>
          </button>
        </Island>
      </div>

      {/* Full-screen glass menu (tablet / mobile) */}
      <AnimatePresence>
        {open && (
          <motion.div
            id="mobile-nav"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            style={{ paddingTop: menuTop }}
            className="pointer-events-auto fixed inset-0 z-0 overflow-y-auto bg-[#001428]/60 backdrop-blur-3xl backdrop-saturate-150 lg:hidden"
          >
            <div className="mx-auto flex min-h-full max-w-lg flex-col px-5 pb-8 pt-6">
              <nav aria-label="Mobile">
                <ul className="space-y-1">
                  {NAV.map(({ to, label, icon: Icon, end }, i) => (
                    <motion.li key={to} initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.04 + i * 0.05, duration: 0.3 }}>
                      <NavLink
                        to={to}
                        end={end}
                        className={({ isActive }) =>
                          cx(
                            'group flex items-center justify-between rounded-2xl border px-4 py-4 transition',
                            isActive ? 'border-signal/35 bg-signal/10' : 'border-transparent hover:border-white/10 hover:bg-white/[0.04]'
                          )
                        }
                      >
                        {({ isActive }) => (
                          <>
                            <span className="flex items-center gap-4">
                              <span className={cx('flex h-10 w-10 items-center justify-center rounded-xl border', isActive ? 'border-signal/40 bg-signal/15 text-signal' : 'border-white/10 bg-white/[0.04] text-white/60')}>
                                <Icon size={18} />
                              </span>
                              <span className={cx('font-display text-2xl font-semibold tracking-tight', isActive ? 'text-white' : 'text-white/80')}>{label}</span>
                            </span>
                            <ArrowUpRight size={18} className={cx('transition', isActive ? 'text-signal' : 'text-white/30 group-hover:text-white/70')} />
                          </>
                        )}
                      </NavLink>
                    </motion.li>
                  ))}
                </ul>
              </nav>
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }} className="mt-auto space-y-4 pt-8">
                <AccountActions mobile />
                <div className="flex justify-center">
                  <BackendStatus />
                </div>
              </motion.div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
