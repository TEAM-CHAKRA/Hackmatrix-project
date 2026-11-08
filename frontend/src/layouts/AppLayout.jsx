import { useEffect } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { FlaskConical } from 'lucide-react';
import { USE_MOCKS } from '../services/api.js';
import AnimatedBackground from './AnimatedBackground.jsx';
import GlassNavbar from './GlassNavbar.jsx';
import Footer from './Footer.jsx';

const TITLES = {
  '/': 'CYBERLENS · See the Threat. Trust the Web.',
  '/scanner': 'Scanner · CYBERLENS',
  '/threat-feed': 'Threat Feed · CYBERLENS',
  '/community': 'Community · CYBERLENS',
  '/verify': 'Verify a Report · CYBERLENS',
  '/login': 'Login · CYBERLENS',
  '/register': 'Create Account · CYBERLENS',
};

export default function AppLayout() {
  const location = useLocation();

  // Browser-tab title per page.
  useEffect(() => {
    const p = location.pathname;
    document.title = TITLES[p] || (p.startsWith('/report/') ? `Report ${decodeURIComponent(p.split('/')[2] || '')} · CYBERLENS` : 'Page not found · CYBERLENS');
  }, [location.pathname]);

  // Scroll to top on route change; for #hash links (e.g. /#how-it-works) scroll to
  // the section once the page transition has rendered it.
  useEffect(() => {
    if (!location.hash) {
      window.scrollTo({ top: 0 });
      return undefined;
    }
    const id = decodeURIComponent(location.hash.slice(1));
    let tries = 0;
    const timer = setInterval(() => {
      const el = document.getElementById(id);
      if (el || ++tries > 20) {
        clearInterval(timer);
        el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }, 100);
    return () => clearInterval(timer);
  }, [location.pathname, location.hash, location.key]);

  return (
    <div className="relative flex min-h-screen flex-col text-white">
      <AnimatedBackground />

      <a
        href="#main"
        className="sr-only z-[60] rounded-md bg-signal px-4 py-2 text-sm font-semibold text-midnight focus:not-sr-only focus:fixed focus:left-4 focus:top-4"
      >
        Skip to content
      </a>

      {USE_MOCKS && (
        <div className="no-print relative z-50 flex items-center justify-center gap-2 border-b border-amber-400/20 bg-amber-400/[0.06] px-4 py-1.5 text-center font-mono text-[11px] text-amber-200">
          <FlaskConical size={12} className="shrink-0 text-amber-300" />
          <span>
            <strong className="font-semibold text-amber-300">Demo mode</strong> · sample data only, no live checks or transactions
          </span>
        </div>
      )}

      <GlassNavbar />

      <AnimatePresence mode="wait">
        <motion.main
          key={location.pathname}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          id="main"
          tabIndex={-1}
          className="relative flex-1 outline-none"
        >
          <Outlet />
        </motion.main>
      </AnimatePresence>

      <Footer />
    </div>
  );
}
