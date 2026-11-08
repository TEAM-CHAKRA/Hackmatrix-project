import { Link } from 'react-router-dom';
import Logo from '../components/ui/Logo.jsx';

const LINKS = [
  { to: '/', label: 'Home' },
  { to: '/scanner', label: 'Scanner' },
  { to: '/threat-feed', label: 'Threat Feed' },
  { to: '/community', label: 'Community' },
  { to: '/verify', label: 'Verify' },
  { to: '/#how-it-works', label: 'How it works' },
  { to: '/login', label: 'Login' },
  { to: '/register', label: 'Register' },
];

export default function Footer() {
  return (
    <footer className="no-print relative border-t border-white/[0.1] bg-[#000b1b]/35 backdrop-blur-2xl backdrop-saturate-150">
      <div className="mx-auto flex max-w-7xl flex-col gap-8 px-4 py-12 sm:px-6 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <Link to="/" className="inline-flex items-center gap-2.5" aria-label="CYBERLENS — Home">
            <Logo size={28} />
            <span className="font-display text-base font-bold tracking-[0.14em] text-white">
              CYBER<span className="text-signal">LENS</span>
            </span>
          </Link>
          <p className="mt-3 text-sm text-white/55">See the Threat. Trust the Web.</p>
        </div>

        <nav aria-label="Footer">
          <ul className="grid grid-cols-2 gap-x-10 gap-y-2.5 text-sm sm:grid-cols-4">
            {LINKS.map(({ to, label }) => (
              <li key={to}>
                <Link to={to} className="text-white/60 transition-colors hover:text-white">
                  {label}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
      </div>

      <div className="border-t border-white/[0.06]">
        <div className="mx-auto flex max-w-7xl flex-col gap-2 px-4 py-5 text-xs text-white/40 sm:flex-row sm:justify-between sm:px-6">
          <span>© {new Date().getFullYear()} CYBERLENS · TEAM CHAKRA</span>
          <span>Never share passwords, OTPs or private keys.</span>
        </div>
      </div>
    </footer>
  );
}
