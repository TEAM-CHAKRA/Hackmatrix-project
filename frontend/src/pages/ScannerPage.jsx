import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { PageHeader } from '../components/ui/Glass.jsx';
import InvestigationConsole from '../components/InvestigationConsole.jsx';
import { BackendStatus } from '../layouts/GlassNavbar.jsx';

export default function ScannerPage() {
  const location = useLocation();
  const consoleRef = useRef(null);
  const anchorRef = useRef(null);
  const focusAt = location.state?.focusScanner;

  useEffect(() => {
    const touch = typeof window !== 'undefined' && window.matchMedia?.('(pointer: coarse)').matches;
    if (!focusAt && touch) return undefined;
    const t = setTimeout(() => {
      if (focusAt) anchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      consoleRef.current?.focusInput();
    }, focusAt ? 120 : 400);
    return () => clearTimeout(t);
  }, [focusAt]);


  return (
    <div className="pb-28">
      {/* Scanner Header */}
      <section className="relative mx-auto max-w-4xl px-4 pt-12 sm:px-6 sm:pt-16">
        <PageHeader align="center" eyebrow="Scanner" title="Investigate a" accent="link or message.">
          Get an evidence-based risk report in seconds.
        </PageHeader>
        <div className="mt-5 flex justify-center">
          <BackendStatus />
        </div>

        {/* Console Container */}
        <div ref={anchorRef} className="mt-8 scroll-mt-24">
          <InvestigationConsole ref={consoleRef} />
        </div>
      </section>
    </div>
  );
}
