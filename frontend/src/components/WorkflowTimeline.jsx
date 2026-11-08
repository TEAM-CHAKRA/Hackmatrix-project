import { useRef, useState } from 'react';
import { motion, useMotionValueEvent, useReducedMotion, useScroll, useSpring } from 'framer-motion';
import { SectionHeading } from './ui/Glass.jsx';
import CircuitField from './CircuitField.jsx';
import { cx } from '../utils/format.js';

const STEPS = [
  { n: '01', title: 'Submit', text: 'Paste a link or message.' },
  { n: '02', title: 'Investigate', text: 'URL, redirects and wording are checked.' },
  { n: '03', title: 'Analyse', text: 'Threat intel, TLS and headers are inspected.' },
  { n: '04', title: 'Assess Risk', text: 'Evidence becomes one of five risk levels.' },
  { n: '05', title: 'Report & Verify', text: 'Get the report and anchor it on-chain.' },
];

export default function WorkflowTimeline() {
  const reduce = useReducedMotion();
  const ref = useRef(null);

  // Whole-section progress drives the background; a tighter window drives the timeline.
  const { scrollYProgress: section } = useScroll({ target: ref, offset: ['start end', 'end start'] });
  const { scrollYProgress: line } = useScroll({ target: ref, offset: ['start 75%', 'center 45%'] });
  const fill = useSpring(line, { stiffness: 120, damping: 26, mass: 0.3 });

  // Steps light up as the line reaches them.
  const [active, setActive] = useState(reduce ? STEPS.length : 0);
  useMotionValueEvent(line, 'change', (v) => {
    if (!reduce) setActive(Math.min(STEPS.length, Math.floor(v * STEPS.length + 0.35)));
  });

  return (
    <section
      ref={ref}
      id="how-it-works"
      className="relative isolate overflow-hidden"
      aria-labelledby="workflow-title"
    >
      <CircuitField progress={section} />
      <div className="mx-auto max-w-7xl px-4 py-24 sm:px-6 sm:py-32">
        <SectionHeading id="workflow-title" eyebrow="How it works" title="Five steps." accent="Every time." />

        <ol className="relative grid gap-8 md:grid-cols-5 md:gap-6">
          {/* Connector: horizontal on desktop, vertical on mobile; fills with scroll */}
          <div className="absolute left-0 right-0 top-[7px] hidden h-px bg-white/15 md:block" aria-hidden>
            <motion.div
              style={{ scaleX: reduce ? 1 : fill }}
              className="h-px origin-left bg-signal shadow-[0_0_12px_rgba(0,209,178,0.9)]"
            />
          </div>
          <div className="absolute bottom-0 left-[7px] top-0 w-px bg-white/15 md:hidden" aria-hidden>
            <motion.div style={{ scaleY: reduce ? 1 : fill }} className="h-full w-px origin-top bg-signal" />
          </div>

          {STEPS.map((s, i) => {
            const on = i < active;
            return (
              <li key={s.n} className="relative flex gap-4 md:block">
                <span
                  className={cx(
                    'relative z-10 mt-1 block h-[15px] w-[15px] shrink-0 rounded-full border-2 transition-all duration-500 md:mt-0',
                    on ? 'border-signal bg-signal shadow-[0_0_18px_rgba(0,209,178,0.9)]' : 'border-white/30 bg-[#001a36]'
                  )}
                />
                <div
                  className={cx(
                    'glass-card glass-hover flex-1 rounded-xl p-4 transition-all duration-500 md:mt-6',
                    on ? 'translate-y-0 border-signal/35 opacity-100' : 'translate-y-2 opacity-60'
                  )}
                >
                  <div className="font-mono text-xs text-signal">{s.n}</div>
                  <div className="mt-1 font-display text-lg font-semibold text-white">{s.title}</div>
                  <p className="mt-1.5 text-sm leading-relaxed text-white/55">{s.text}</p>
                </div>
              </li>
            );
          })}
        </ol>
      </div>
    </section>
  );
}
