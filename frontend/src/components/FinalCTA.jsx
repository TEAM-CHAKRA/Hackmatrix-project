import { ArrowRight, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useScanNow } from '../hooks/useScanNow.js';
import { Reveal } from './ui/Glass.jsx';
import LensRings from './ui/LensRings.jsx';

/** Closing band: glass panel over scroll-driven lens rings. */
export default function FinalCTA() {
  const scanNow = useScanNow();

  return (
    <section className="relative isolate overflow-hidden border-t border-white/[0.08]">
      <div className="absolute inset-0 -z-10" aria-hidden>
        <div className="absolute inset-0 bg-[radial-gradient(60%_70%_at_75%_50%,rgba(0,110,130,0.28),transparent_70%)]" />
        <div className="absolute right-[-30%] top-1/2 w-[min(1000px,130vw)] -translate-y-1/2 opacity-60 sm:right-[-8%] sm:opacity-90">
          <LensRings className="w-full" />
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-4 py-28 sm:px-6 sm:py-36">
        <Reveal className="glass-strong max-w-3xl rounded-3xl p-8 sm:p-12">
          <div className="mb-6 flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.22em] text-white/60">
            <span className="h-px w-8 bg-signal" />
            Start an investigation
          </div>
          <h2 className="font-display text-4xl font-semibold leading-[1.05] tracking-[-0.03em] text-white sm:text-6xl">
            Don't Trust the Link.
            <br />
            <span className="text-signal">Investigate It.</span>
          </h2>
          <p className="mt-6 max-w-xl text-[17px] leading-relaxed text-white/70">
            Make informed decisions with evidence-backed digital trust intelligence, before you click, reply or pay.
          </p>
          <div className="mt-10 flex flex-col gap-3 sm:flex-row">
            <button onClick={scanNow} className="btn-primary group px-7 py-3.5 text-[15px] font-semibold">
              Scan Now
              <ArrowRight size={17} className="transition-transform group-hover:translate-x-0.5" />
            </button>
            <Link to="/verify" className="btn-secondary px-7 py-3.5 text-[15px]">
              <ShieldCheck size={17} className="text-signal" />
              Verify a report
            </Link>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
