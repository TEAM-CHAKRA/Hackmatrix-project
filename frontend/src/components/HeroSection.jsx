import { useEffect, useState } from 'react';
import { useReducedMotion } from 'framer-motion';
import { ArrowRight, ChevronDown, Database, Lock, FileCode, ShieldCheck, Globe, Loader2, FlaskConical } from 'lucide-react';
import { useScanNow } from '../hooks/useScanNow.js';
import { cx } from '../utils/format.js';
import ThreatGlobe from './ThreatGlobe.jsx';

// Illustrative preview rows (clearly labelled as an example in the UI).
const ROWS = [
  { icon: Globe, label: 'URL & domain structure', result: 'Look-alike token found', tone: 'amber' },
  { icon: Database, label: 'Threat intelligence (GSB · URLhaus)', result: 'No match', tone: 'muted' },
  { icon: Lock, label: 'TLS certificate & chain', result: 'Valid · hostname match', tone: 'ok' },
  { icon: FileCode, label: 'HTTP security headers', result: 'CSP missing', tone: 'amber' },
];

const SOURCES = ['Google Safe Browsing', 'URLhaus', 'crt.sh', 'TLS inspection', 'HTTP headers', 'SHA-256', 'EVM testnet'];

function ReportPreview() {
  const reduce = useReducedMotion();
  // Rows "complete" one after another, then the verdict appears; loops gently.
  const [step, setStep] = useState(reduce ? ROWS.length + 1 : 0);
  useEffect(() => {
    if (reduce) return undefined;
    const t = setTimeout(() => setStep((s) => (s > ROWS.length + 4 ? 0 : s + 1)), step === 0 ? 900 : 700);
    return () => clearTimeout(t);
  }, [step, reduce]);

  return (
    <div className="relative w-full max-w-[460px] overflow-hidden glass-strong rounded-2xl">
      <div className="flex items-center justify-between border-b border-white/[0.08] px-4 py-3">
        <div className="flex items-center gap-2 font-mono text-[11px] text-white/55">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-signal/60" />
            <span className="relative h-2 w-2 rounded-full bg-signal" />
          </span>
          Investigation · INV-EXAMPLE
        </div>
        <span className="inline-flex items-center gap-1 rounded border border-white/10 px-1.5 py-0.5 font-mono text-[9.5px] uppercase tracking-wider text-white/45">
          <FlaskConical size={10} /> Example
        </span>
      </div>

      <div className="px-4 pb-4 pt-3.5">
        <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-white/35">Target</div>
        <div className="mt-1 truncate font-mono text-[12.5px] text-white/90">http://paypa1-account-verify.example/signin</div>

        <ul className="mt-4 divide-y divide-white/[0.06] border-y border-white/[0.06]">
          {ROWS.map((r, i) => {
            const done = step > i;
            const running = step === i;
            return (
              <li key={r.label} className="flex items-center justify-between gap-3 py-2.5 text-[12px]">
                <span className={cx('flex items-center gap-2.5 transition-colors', done || running ? 'text-white/80' : 'text-white/35')}>
                  <r.icon size={14} className={done ? 'text-signal' : 'text-white/30'} />
                  {r.label}
                </span>
                <span className="shrink-0 font-mono text-[11px]">
                  {running ? (
                    <Loader2 size={13} className="animate-spin text-signal" />
                  ) : done ? (
                    <span className={r.tone === 'amber' ? 'text-amber-300' : r.tone === 'ok' ? 'text-signal' : 'text-white/50'}>{r.result}</span>
                  ) : (
                    <span className="text-white/20">pending</span>
                  )}
                </span>
              </li>
            );
          })}
        </ul>

        <div className={cx('mt-4 flex items-center justify-between transition-opacity duration-500', step > ROWS.length ? 'opacity-100' : 'opacity-0')}>
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-white/35">Classification</div>
            <div className="mt-1 inline-flex items-center gap-1.5 rounded-md border border-amber-400/35 bg-amber-400/10 px-2 py-1 text-[12px] font-semibold text-amber-300">
              <ShieldCheck size={13} /> Suspicious
            </div>
          </div>
          <div className="text-right">
            <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-white/35">Coverage</div>
            <div className="mt-1 font-mono text-[12px] text-white/80">4 of 4 checks</div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function HeroSection() {
  const scanNow = useScanNow();
  const exploreHow = () => document.getElementById('how-it-works')?.scrollIntoView({ behavior: 'smooth', block: 'start' });

  return (
    // Pulled up under the (transparent) navbar so the globe runs edge to edge.
    <section className="relative -mt-[65px] overflow-hidden pt-[65px]" aria-label="Introduction">
      {/* Live threat globe (canvas) */}
      <div className="absolute inset-0" aria-hidden>
        <ThreatGlobe />
        {/* Readability on the text side */}
        <div className="absolute inset-0 bg-[linear-gradient(90deg,rgba(0,18,38,0.7)_0%,rgba(0,22,46,0.35)_38%,transparent_60%)]" />
        <div className="absolute inset-x-0 bottom-0 h-40 bg-gradient-to-b from-transparent to-[#001a36]/70" />
        <div className="cl-rail absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-signal/50 to-transparent" />
      </div>

      <div className="relative mx-auto grid min-h-[min(860px,calc(100svh-30px))] max-w-7xl items-center gap-14 px-4 pb-28 pt-16 sm:px-6 lg:grid-cols-[1.15fr_0.85fr] lg:pb-36">
        <div>
          <div className="cl-rise mb-7 flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.22em] text-white/60">
            <span className="h-px w-8 bg-signal" />
            Digital trust intelligence
          </div>

          <h1 className="cl-rise font-display text-[2.75rem] font-semibold leading-[1.02] tracking-[-0.035em] text-white [animation-delay:80ms] sm:text-6xl lg:text-[4.75rem]">
            See the Threat.
            <br />
            <span className="text-white/55">Trust the </span>
            <span className="text-signal">Web.</span>
          </h1>

          <p className="cl-rise mt-7 max-w-[34rem] text-[17px] leading-relaxed text-white/70 [animation-delay:160ms] sm:text-lg">
            Investigate suspicious links and messages. Uncover hidden threats, inspect digital trust signals, and verify evidence through
            blockchain.
          </p>

          <div className="cl-rise mt-10 flex flex-col gap-3 [animation-delay:240ms] sm:flex-row sm:items-center">
            <button onClick={scanNow} className="btn-primary group px-7 py-3.5 text-[15px] font-semibold">
              Scan Now
              <ArrowRight size={17} className="transition-transform group-hover:translate-x-0.5" />
            </button>
            <button onClick={exploreHow} className="btn-secondary px-7 py-3.5 text-[15px]">
              Explore How It Works
              <ChevronDown size={17} className="text-white/60" />
            </button>
          </div>
        </div>

        <div className="cl-rise hidden justify-end [animation-delay:300ms] lg:flex">
          <ReportPreview />
        </div>
      </div>

      {/* Evidence sources strip */}
      <div className="relative border-t border-white/[0.1] bg-[#001a36]/25 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 px-4 py-5 sm:px-6 md:flex-row md:items-center md:gap-8">
          <span className="shrink-0 font-mono text-[10.5px] uppercase tracking-[0.2em] text-white/40">Evidence sources</span>
          <ul className="flex flex-wrap gap-x-7 gap-y-2">
            {SOURCES.map((s) => (
              <li key={s} className="font-display text-[14px] font-medium tracking-tight text-white/60">
                {s}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
