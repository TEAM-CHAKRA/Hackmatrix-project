import { ScanSearch, FileText, ShieldCheck } from 'lucide-react';
import { Reveal } from './ui/Glass.jsx';

const PILLARS = [
  { icon: ScanSearch, title: 'Investigate', text: 'Check a link or message against real evidence.' },
  { icon: FileText, title: 'Explain', text: 'Get a clear report with what to do next.' },
  { icon: ShieldCheck, title: 'Verify', text: 'Prove the report was never altered.' },
];

/** About CYBERLENS — short and direct. */
export default function PlatformIntro() {
  return (
    <section id="welcome" className="relative isolate overflow-x-clip mx-auto max-w-7xl px-4 py-24 sm:px-6 sm:py-32" aria-labelledby="welcome-title">
      <div className="glass-light right-[5%] top-1/3 h-72 w-[38rem] bg-signal/20" aria-hidden />
      <div className="glass-light right-[30%] bottom-10 h-56 w-80 bg-[#1e5287]/50" aria-hidden />
      <div className="grid gap-12 lg:grid-cols-[1fr_1.1fr] lg:items-end lg:gap-20">
        <Reveal>
          <div className="mb-6 flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.22em] text-white/55">
            <span className="h-px w-8 bg-signal" />
            About CYBERLENS
          </div>
          <h2 id="welcome-title" className="font-display text-4xl font-semibold leading-[1.06] tracking-[-0.03em] text-white sm:text-5xl">
            Digital trust starts with <span className="text-signal">evidence.</span>
          </h2>
          <p className="mt-6 max-w-lg text-[17px] leading-relaxed text-white/65">
            Scam links and phishing messages are built to look real. CYBERLENS shows you what's actually behind them.
          </p>
        </Reveal>

        <Reveal delay={0.1}>
          <ul className="grid gap-4 sm:grid-cols-3">
            {PILLARS.map((p) => (
              <li key={p.title} className="glass-card glass-hover rounded-2xl p-6">
                <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-signal/30 bg-signal/10 text-signal">
                  <p.icon size={19} strokeWidth={1.75} />
                </span>
                <div className="mt-4 font-display text-lg font-semibold text-white">{p.title}</div>
                <p className="mt-1.5 text-sm leading-relaxed text-white/55">{p.text}</p>
              </li>
            ))}
          </ul>
        </Reveal>
      </div>
    </section>
  );
}
