import { Crosshair, Radio, ShieldCheck, ServerCog, Sparkles, Blocks } from 'lucide-react';
import { motion, useReducedMotion } from 'framer-motion';
import LensRings from './ui/LensRings.jsx';

const ENGINES = [
  { icon: Crosshair, name: 'Threat Detection', text: 'Spots look-alike domains, hidden redirects and risky URL patterns.' },
  { icon: Radio, name: 'Threat Intelligence', text: 'Checks Google Safe Browsing and URLhaus, with the source shown.' },
  { icon: ServerCog, name: 'Website Security Audit', text: 'Reviews HTTPS, HSTS, CSP and other security headers.' },
  { icon: ShieldCheck, name: 'TLS Certificate Trust', text: 'Validates the certificate chain, hostname and expiry.' },
  { icon: Sparkles, name: 'AI-Powered Analysis', text: 'Explains the findings in plain language. It never invents results.' },
  { icon: Blocks, name: 'Community & Blockchain Registry', text: 'Community reports, kept separate, plus on-chain report integrity.' },
];

export default function IntelligenceSection() {
  const reduce = useReducedMotion();
  return (
    <section id="engines" className="relative isolate overflow-x-clip mx-auto max-w-7xl scroll-mt-24 px-4 py-24 sm:px-6 sm:py-32" aria-labelledby="intel-title">
      <div className="glass-light left-[40%] top-[20%] h-96 w-[36rem] bg-signal/15" aria-hidden />
      <div className="glass-light right-0 bottom-[10%] h-72 w-96 bg-[#1e5287]/50" aria-hidden />
      <div className="grid gap-14 lg:grid-cols-[0.8fr_1.2fr] lg:gap-20">
        {/* Left: editorial heading, sticky on desktop */}
        <div className="lg:sticky lg:top-28 lg:self-start">
          <div className="mb-6 flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.22em] text-white/55">
            <span className="h-px w-8 bg-signal" />
            Intelligence engines
          </div>
          <h2 id="intel-title" className="font-display text-4xl font-semibold leading-[1.06] tracking-[-0.03em] text-white sm:text-5xl">
            Six engines.
            <br />
            <span className="text-white/50">One evidence trail.</span>
          </h2>

          {/* Lens rings focus as the engine list scrolls past */}
          <LensRings className="mt-12 hidden w-full max-w-[22rem] lg:block" />
        </div>

        {/* Right: index of engines */}
        <ol className="glass-strong rounded-2xl px-5 sm:px-8">
          {ENGINES.map((e, i) => (
            <motion.li
              key={e.name}
              initial={reduce ? false : { opacity: 0, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-60px' }}
              transition={{ duration: 0.5, delay: 0.04 * i }}
              className="group grid grid-cols-[auto_1fr] gap-x-5 border-b border-white/[0.08] py-6 last:border-0 sm:grid-cols-[3.5rem_1fr] sm:gap-x-6"
            >
              <span className="font-mono text-sm text-white/35 transition-colors group-hover:text-signal">0{i + 1}</span>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <e.icon size={18} className="text-signal" strokeWidth={1.75} />
                  <h3 className="font-display text-xl font-semibold tracking-tight text-white">{e.name}</h3>
                </div>
                <p className="mt-2 max-w-xl text-[15px] leading-relaxed text-white/60">{e.text}</p>
              </div>
            </motion.li>
          ))}
        </ol>
      </div>
    </section>
  );
}
