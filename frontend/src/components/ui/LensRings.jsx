import { useRef } from 'react';
import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion';

/**
 * Concentric dashed "lens" rings driven by scroll: as the element passes
 * through the viewport the rings counter-rotate and zoom outward like a
 * lens focusing. Decorative only.
 */
const RINGS = [
  { r: 0.22, dash: '2 6', w: 1.5, o: 0.9, spin: 140 },
  { r: 0.34, dash: '30 10', w: 1, o: 0.55, spin: -90 },
  { r: 0.46, dash: '1 9', w: 2, o: 0.7, spin: 60 },
  { r: 0.6, dash: '80 24 6 24', w: 1, o: 0.4, spin: -45 },
  { r: 0.76, dash: '3 14', w: 1, o: 0.3, spin: 30 },
  { r: 0.94, dash: '140 60', w: 1, o: 0.18, spin: -20 },
];

function Ring({ ring, progress, reduce, i }) {
  const rotate = useTransform(progress, [0, 1], [0, reduce ? 0 : ring.spin]);
  const scale = useTransform(progress, [0, 0.5, 1], reduce ? [1, 1, 1] : [0.7 - i * 0.02, 1, 1.25 + i * 0.06]);
  const size = ring.r * 200;
  return (
    <motion.svg
      style={{ rotate, scale }}
      viewBox="0 0 200 200"
      className="absolute inset-0 h-full w-full will-change-transform"
    >
      <circle
        cx="100"
        cy="100"
        r={size / 2}
        fill="none"
        stroke={i === 2 ? '#ffffff' : '#00D1B2'}
        strokeOpacity={ring.o}
        strokeWidth={ring.w}
        strokeDasharray={ring.dash}
        vectorEffect="non-scaling-stroke"
      />
    </motion.svg>
  );
}

export default function LensRings({ className = '' }) {
  const ref = useRef(null);
  const reduce = useReducedMotion();
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start end', 'end start'] });
  const core = useTransform(scrollYProgress, [0, 0.5, 1], [0.4, 1, 0.4]);

  return (
    <div ref={ref} aria-hidden className={`pointer-events-none relative aspect-square ${className}`}>
      <motion.div
        style={{ opacity: core }}
        className="absolute inset-[30%] rounded-full bg-[radial-gradient(closest-side,rgba(0,209,178,0.35),rgba(0,209,178,0.08)_60%,transparent)]"
      />
      {RINGS.map((r, i) => (
        <Ring key={i} ring={r} progress={scrollYProgress} reduce={reduce} i={i} />
      ))}
      {/* Crosshair */}
      <div className="absolute left-1/2 top-[8%] bottom-[8%] w-px -translate-x-1/2 bg-gradient-to-b from-transparent via-signal/25 to-transparent" />
      <div className="absolute top-1/2 left-[8%] right-[8%] h-px -translate-y-1/2 bg-gradient-to-r from-transparent via-signal/25 to-transparent" />
      <div className="absolute left-1/2 top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-signal shadow-[0_0_14px_rgba(0,209,178,0.9)]" />
    </div>
  );
}
