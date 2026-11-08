import { Link } from 'react-router-dom';
import { FileText, Hash, Blocks, ShieldCheck, ArrowRight } from 'lucide-react';
import { motion, useReducedMotion } from 'framer-motion';
import { SectionHeading } from './ui/Glass.jsx';

const FLOW = [
  { icon: FileText, title: 'Report' },
  { icon: Hash, title: 'SHA-256 hash' },
  { icon: Blocks, title: 'On-chain record' },
  { icon: ShieldCheck, title: 'Anyone can verify' },
];

export default function BlockchainVisualization() {
  const reduce = useReducedMotion();
  return (
    <section id="digital-trust" className="relative isolate overflow-x-clip mx-auto max-w-7xl px-4 py-24 sm:px-6 sm:py-32" aria-labelledby="chain-title">
      <div className="glass-light left-1/2 top-1/2 h-80 w-[44rem] -translate-x-1/2 bg-signal/15" aria-hidden />
      <SectionHeading id="chain-title" eyebrow="Digital trust & blockchain" title="Reports you can" accent="prove.">
        Each report's fingerprint is stored on a blockchain, so any later change is detectable.
      </SectionHeading>

      <ol className="glass-strong mx-auto flex max-w-4xl flex-col items-stretch rounded-2xl px-6 py-10 md:flex-row md:items-center md:px-10">
        {FLOW.map((f, i) => (
          <li key={f.title} className="flex flex-col items-center md:flex-1 md:flex-row">
            <motion.div
              initial={reduce ? false : { opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-60px' }}
              transition={{ delay: i * 0.15, duration: 0.5 }}
              className="flex w-full flex-col items-center text-center"
            >
              <span className="flex h-14 w-14 items-center justify-center glass-card rounded-full border-signal/40 text-signal">
                <f.icon size={22} strokeWidth={1.75} />
              </span>
              <span className="mt-3 text-sm font-medium text-white/85">{f.title}</span>
            </motion.div>
            {i < FLOW.length - 1 && <span className="my-3 h-8 w-px bg-white/15 md:mx-2 md:my-0 md:mb-7 md:h-px md:w-full md:max-w-16" aria-hidden />}
          </li>
        ))}
      </ol>

      <div className="mt-14 text-center">
        <Link to="/verify" className="btn-secondary px-6 py-3">
          Verify a report <ArrowRight size={16} />
        </Link>
      </div>
    </section>
  );
}
