import { motion, useReducedMotion, useTransform } from 'framer-motion';

/**
 * CircuitField — a circuit-board trace background with data packets running
 * along the traces, plus a scan beam that sweeps across as the section scrolls.
 * `progress` is a 0→1 MotionValue for the section's scroll. Decorative only.
 */

// Deterministic PRNG so the layout is stable between renders.
function rng(seed) {
  let s = seed;
  return () => {
    s = (s * 16807) % 2147483647;
    return (s - 1) / 2147483646;
  };
}

function buildTraces() {
  const r = rng(42);
  const traces = [];
  const STEP = 30;
  for (let i = 0; i < 26; i++) {
    const fromLeft = i % 2 === 0;
    let x = fromLeft ? -10 : 1210;
    let y = Math.round((40 + r() * 520) / STEP) * STEP;
    const dir = fromLeft ? 1 : -1;
    let d = `M${x} ${y}`;
    const segs = 2 + Math.floor(r() * 3);
    for (let k = 0; k < segs; k++) {
      x += dir * (60 + Math.round(r() * 5) * 40);
      d += ` H${x}`;
      if (k < segs - 1) {
        const dy = (r() < 0.5 ? -1 : 1) * STEP * (1 + Math.floor(r() * 2));
        x += dir * Math.abs(dy);
        y = Math.min(580, Math.max(20, y + dy));
        d += ` L${x} ${y}`;
      }
    }
    traces.push({ d, end: [x, y], pulse: r() < 0.6, delay: r() * 6, dur: 4 + r() * 4, bright: r() < 0.3 });
  }
  return traces;
}

const TRACES = buildTraces();

export default function CircuitField({ progress }) {
  const reduce = useReducedMotion();
  const beamX = useTransform(progress, [0, 1], ['-30vw', '110vw']);
  const glow = useTransform(progress, [0, 0.5, 1], [0.2, 1, 0.2]);

  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 -z-10 overflow-hidden">
      {/* Deep tint band with hairline edges */}
      <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(0,14,32,0.2),rgba(0,22,44,0.55)_50%,rgba(0,14,32,0.2))]" />
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-signal/40 to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-signal/25 to-transparent" />

      {/* Central glow that peaks mid-scroll */}
      <motion.div
        style={{ opacity: glow }}
        className="absolute left-1/2 top-1/2 h-[70%] w-[80%] -translate-x-1/2 -translate-y-1/2 bg-[radial-gradient(closest-side,rgba(0,209,178,0.14),transparent)]"
      />

      {/* Circuit traces */}
      <svg
        className="absolute inset-0 h-full w-full"
        viewBox="0 0 1200 600"
        preserveAspectRatio="xMidYMid slice"
        style={{
          maskImage: 'radial-gradient(ellipse 75% 70% at 50% 55%, rgba(0,0,0,0.35), #000 85%)',
          WebkitMaskImage: 'radial-gradient(ellipse 75% 70% at 50% 55%, rgba(0,0,0,0.35), #000 85%)',
        }}
      >
        {TRACES.map((t, i) => (
          <g key={i}>
            <path d={t.d} fill="none" stroke={t.bright ? 'rgba(0,209,178,0.22)' : 'rgba(255,255,255,0.07)'} strokeWidth="1.2" />
            <circle cx={t.end[0]} cy={t.end[1]} r="3.2" fill="none" stroke={t.bright ? 'rgba(0,209,178,0.55)' : 'rgba(255,255,255,0.18)'} strokeWidth="1.2" />
            {t.pulse && !reduce && (
              <path
                d={t.d}
                pathLength="100"
                fill="none"
                stroke="#00D1B2"
                strokeWidth="2"
                strokeLinecap="round"
                strokeDasharray="4 96"
                className="cl-fibre-pulse"
                style={{ animationDelay: `-${t.delay}s`, animationDuration: `${t.dur}s` }}
              />
            )}
          </g>
        ))}
        {/* Chip pads */}
        {[
          [160, 90],
          [1040, 120],
          [120, 500],
          [1080, 480],
        ].map(([x, y], i) => (
          <g key={`chip-${i}`} opacity="0.5">
            <rect x={x - 22} y={y - 22} width="44" height="44" rx="5" fill="rgba(0,31,63,0.6)" stroke="rgba(0,209,178,0.35)" />
            {[-12, 0, 12].map((o) => (
              <g key={o} stroke="rgba(0,209,178,0.35)">
                <line x1={x + o} y1={y - 22} x2={x + o} y2={y - 30} />
                <line x1={x + o} y1={y + 22} x2={x + o} y2={y + 30} />
                <line x1={x - 22} y1={y + o} x2={x - 30} y2={y + o} />
                <line x1={x + 22} y1={y + o} x2={x + 30} y2={y + o} />
              </g>
            ))}
            <circle cx={x} cy={y} r="4" fill="#00D1B2" className={reduce ? '' : 'animate-pulse'} />
          </g>
        ))}
      </svg>

      {/* Scan beam sweeping with scroll */}
      {!reduce && (
        <motion.div style={{ x: beamX }} className="absolute inset-y-0 left-0 w-[28rem] will-change-transform">
          <div className="absolute inset-0 bg-[linear-gradient(90deg,transparent,rgba(0,209,178,0.08)_45%,rgba(0,209,178,0.14)_50%,rgba(0,209,178,0.08)_55%,transparent)]" />
          <div className="absolute inset-y-0 left-1/2 w-px bg-gradient-to-b from-transparent via-signal/60 to-transparent" />
        </motion.div>
      )}
    </div>
  );
}
