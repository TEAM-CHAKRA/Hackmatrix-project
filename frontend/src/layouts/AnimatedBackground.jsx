import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { motion, useReducedMotion, useScroll, useSpring, useTransform } from 'framer-motion';

/**
 * Site-wide, scroll-reactive environment ("travelling through the data centre").
 *
 *  1. Midnight Grid base gradient + film grain + vignette (static).
 *  2. Perspective grid floor that streams toward the viewer as you scroll.
 *  3. Flat engineering grid with slow parallax.
 *  4. Fibre-optic cables along both edges that draw themselves with scroll,
 *     with light pulses travelling along them.
 *  5. "Data dust": three depth layers of particles with parallax.
 *  6. Cyan / blue light pools that drift and scale through the page.
 *  7. Inner pages: data-centre photo band with parallax that fades on scroll.
 *
 * Everything is driven by motion values / canvas (no React re-renders on scroll),
 * and respects prefers-reduced-motion.
 */

// Fibre paths in a 0–100 viewBox (stretched to the viewport).
const FIBRES = [
  { d: 'M3 -2 C3 18, 8 28, 6 46 S1.5 76, 4.5 102', w: 1.4, o: 0.55 },
  { d: 'M1 -2 C1.5 26, 4 40, 2 62 S3.5 88, 1 102', w: 1, o: 0.35 },
  { d: 'M6.5 -2 C7 12, 3 34, 5 52 S9 84, 7 102', w: 0.8, o: 0.25 },
  { d: 'M97 -2 C97 22, 92 32, 94 50 S98.5 78, 95.5 102', w: 1.4, o: 0.55 },
  { d: 'M99 -2 C98.5 20, 96 44, 98 64 S96.5 90, 99 102', w: 1, o: 0.35 },
  { d: 'M93.5 -2 C93 16, 97 36, 95 56 S91 86, 93 102', w: 0.8, o: 0.25 },
];

function DataDust({ reduce }) {
  const ref = useRef(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return undefined;
    const ctx = canvas.getContext('2d');
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    let w = 0;
    let h = 0;
    let raf = 0;
    let dust = [];

    // Three depth layers: far (slow, small, dim) → near (fast, larger, brighter).
    const LAYERS = [
      { speed: 0.12, r: [0.4, 0.8], a: [0.15, 0.35], density: 26000 },
      { speed: 0.3, r: [0.7, 1.2], a: [0.25, 0.5], density: 42000 },
      { speed: 0.6, r: [1.1, 1.9], a: [0.35, 0.7], density: 90000 },
    ];

    const seed = () => {
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      dust = [];
      LAYERS.forEach((L, li) => {
        const n = Math.round((w * h) / L.density);
        for (let i = 0; i < n; i++) {
          dust.push({
            layer: li,
            x: Math.random() * w,
            y: Math.random() * h,
            r: L.r[0] + Math.random() * (L.r[1] - L.r[0]),
            a: L.a[0] + Math.random() * (L.a[1] - L.a[0]),
            cyan: Math.random() < 0.7,
            drift: (Math.random() - 0.5) * 0.08,
            tw: Math.random() * Math.PI * 2,
          });
        }
      });
    };

    const draw = (t = 0) => {
      const sy = window.scrollY;
      ctx.clearRect(0, 0, w, h);
      for (const p of dust) {
        const L = LAYERS[p.layer];
        if (!reduce) p.x += p.drift;
        if (p.x < -4) p.x = w + 4;
        if (p.x > w + 4) p.x = -4;
        // Parallax: nearer layers move further per pixel scrolled.
        let y = (p.y - sy * L.speed) % h;
        if (y < 0) y += h;
        const twinkle = reduce ? 1 : 0.75 + 0.25 * Math.sin(t / 900 + p.tw);
        ctx.beginPath();
        ctx.arc(p.x, y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = p.cyan ? `rgba(0,209,178,${p.a * twinkle})` : `rgba(255,255,255,${p.a * 0.7 * twinkle})`;
        ctx.fill();
      }
    };

    // Idle twinkle at ~30fps; full rate only while the page is scrolling.
    let last = 0;
    let lastSy = -1;
    const loop = (t) => {
      const sy = window.scrollY;
      if (sy !== lastSy || t - last > 33) {
        draw(t);
        last = t;
        lastSy = sy;
      }
      raf = requestAnimationFrame(loop);
    };

    const onVis = () => {
      cancelAnimationFrame(raf);
      if (!document.hidden && !reduce) raf = requestAnimationFrame(loop);
    };
    const onScrollStatic = () => draw();

    seed();
    if (reduce) {
      draw();
      window.addEventListener('scroll', onScrollStatic, { passive: true });
    } else {
      raf = requestAnimationFrame(loop);
    }
    const onResize = () => {
      seed();
      draw();
    };
    window.addEventListener('resize', onResize);
    document.addEventListener('visibilitychange', onVis);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', onResize);
      window.removeEventListener('scroll', onScrollStatic);
      document.removeEventListener('visibilitychange', onVis);
    };
  }, [reduce]);

  return <canvas ref={ref} className="absolute inset-0" />;
}

export default function AnimatedBackground() {
  const { pathname } = useLocation();
  const isHome = pathname === '/';
  const reduce = useReducedMotion();

  const { scrollY, scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 80, damping: 24, mass: 0.4 });

  // Perspective floor streams toward the viewer.
  const floorY = useTransform(scrollY, (v) => (reduce ? 0 : (v * 0.9) % 64));
  // Flat grid parallax.
  const gridY = useTransform(scrollY, (v) => (reduce ? 0 : -((v * 0.15) % 80)));

  // Light pools travel through the page.
  const orbAx = useTransform(progress, [0, 0.5, 1], ['-10vw', '35vw', '5vw']);
  const orbAy = useTransform(progress, [0, 0.5, 1], ['-15vh', '25vh', '55vh']);
  const orbAs = useTransform(progress, [0, 0.5, 1], [1, 1.35, 0.9]);
  const orbBx = useTransform(progress, [0, 0.5, 1], ['55vw', '0vw', '45vw']);
  const orbBy = useTransform(progress, [0, 0.5, 1], ['55vh', '10vh', '-5vh']);
  const orbBs = useTransform(progress, [0, 1], [0.9, 1.4]);
  const tealWash = useTransform(progress, [0, 0.45, 0.6, 1], [0, 0.55, 0.55, 0.15]);

  // Inner-page horizon arc: parallax + fade.
  const bandY = useTransform(scrollY, (v) => (reduce ? 0 : -v * 0.35));
  const bandOpacity = useTransform(scrollY, [0, 600], [1, 0.15]);

  // Fibres draw with scroll (always visible for reduced motion).
  const fibreLength = useTransform(progress, [0, 1], [0.08, 1]);

  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden [contain:strict]">
      {/* 1. Depth gradient */}
      <div className="absolute inset-0 bg-[linear-gradient(180deg,#00244a_0%,#001a36_28%,#00122a_60%,#000b1b_100%)]" />

      {/* Scroll-linked teal wash mid-page */}
      <motion.div style={{ opacity: tealWash }} className="absolute inset-0 bg-[radial-gradient(70%_55%_at_50%_45%,rgba(0,90,110,0.35),transparent_75%)]" />

      {/* 7. Inner pages: a planet-horizon arc that sinks and fades on scroll */}
      {!isHome && (
        <motion.div style={{ y: bandY, opacity: bandOpacity }} className="absolute inset-x-0 top-0 h-[560px] overflow-hidden">
          <div className="absolute left-1/2 top-[-170vw] h-[200vw] w-[200vw] -translate-x-1/2 rounded-full border-b border-signal/50 bg-[radial-gradient(closest-side,transparent_96%,rgba(0,209,178,0.14)_99.6%,transparent)] shadow-[0_30px_80px_-20px_rgba(0,209,178,0.35)] sm:top-[-182vw]" />
          <div className="absolute inset-x-0 top-0 h-full bg-[radial-gradient(50%_60%_at_50%_0%,rgba(0,140,160,0.25),transparent_70%)]" />
        </motion.div>
      )}

      {/* 6. Light pools */}
      <motion.div
        style={{ x: orbAx, y: orbAy, scale: orbAs }}
        className="absolute left-0 top-0 h-[70vh] w-[70vw] rounded-full bg-[radial-gradient(closest-side,rgba(0,209,178,0.16),transparent)] will-change-transform"
      />
      <motion.div
        style={{ x: orbBx, y: orbBy, scale: orbBs }}
        className="absolute left-0 top-0 h-[65vh] w-[60vw] rounded-full bg-[radial-gradient(closest-side,rgba(30,82,160,0.28),transparent)] will-change-transform"
      />

      {/* 3. Flat engineering grid with parallax */}
      <div
        className="absolute inset-0 opacity-60"
        style={{
          maskImage: 'linear-gradient(180deg, rgba(0,0,0,0.85), rgba(0,0,0,0.3) 55%, transparent 75%)',
          WebkitMaskImage: 'linear-gradient(180deg, rgba(0,0,0,0.85), rgba(0,0,0,0.3) 55%, transparent 75%)',
        }}
      >
        <motion.div
          style={{ y: gridY }}
          className="absolute -bottom-20 left-0 right-0 top-0 will-change-transform [background-image:linear-gradient(rgba(255,255,255,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.035)_1px,transparent_1px)] [background-size:80px_80px]"
        />
      </div>

      {/* 2. Perspective floor */}
      <div className="absolute inset-x-0 bottom-0 h-[48vh] [perspective:420px] [perspective-origin:50%_0%]">
        <div
          className="absolute -inset-x-1/2 bottom-0 h-[220%] origin-bottom overflow-hidden [transform:rotateX(68deg)]"
          style={{
            maskImage: 'linear-gradient(0deg, rgba(0,0,0,0.9) 0%, rgba(0,0,0,0.4) 35%, transparent 60%)',
            WebkitMaskImage: 'linear-gradient(0deg, rgba(0,0,0,0.9) 0%, rgba(0,0,0,0.4) 35%, transparent 60%)',
          }}
        >
          <motion.div
            style={{ y: floorY }}
            className="absolute -top-16 bottom-0 left-0 right-0 will-change-transform [background-image:linear-gradient(rgba(0,209,178,0.22)_1px,transparent_1px),linear-gradient(90deg,rgba(0,209,178,0.16)_1px,transparent_1px)] [background-size:64px_64px]"
          />
        </div>
        {/* Horizon glow */}
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-signal/40 to-transparent" />
        <div className="absolute inset-x-[15%] top-0 h-24 -translate-y-1/2 bg-[radial-gradient(closest-side,rgba(0,209,178,0.18),transparent)]" />
      </div>

      {/* 5. Data dust */}
      <DataDust reduce={reduce} />

      {/* 4. Fibre-optic cables */}
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        <defs>
          <linearGradient id="fibre" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00D1B2" stopOpacity="0.9" />
            <stop offset="60%" stopColor="#00D1B2" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#5ee6d2" stopOpacity="0.2" />
          </linearGradient>
        </defs>
        {FIBRES.map((f, i) => (
          <g key={i} opacity={f.o}>
            {/* Dim full cable */}
            <path d={f.d} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={f.w} vectorEffect="non-scaling-stroke" />
            {/* Glow halo + lit portion grow with scroll */}
            <motion.path d={f.d} fill="none" stroke="#00D1B2" strokeOpacity="0.18" strokeWidth={f.w + 5} vectorEffect="non-scaling-stroke" strokeLinecap="round" style={{ pathLength: reduce ? 1 : fibreLength }} />
            <motion.path
              d={f.d}
              fill="none"
              stroke="url(#fibre)"
              strokeWidth={f.w + 0.4}
              vectorEffect="non-scaling-stroke"
              strokeLinecap="round"
              style={{ pathLength: reduce ? 1 : fibreLength }}
            />
            {/* Travelling light pulse */}
            {!reduce && (
              <path
                d={f.d}
                pathLength="100"
                fill="none"
                stroke="#ffffff"
                strokeWidth={f.w + 0.8}
                strokeLinecap="round"
                vectorEffect="non-scaling-stroke"
                strokeDasharray="1.5 98.5"
                className="cl-fibre-pulse"
                style={{ animationDelay: `${i * 1.3}s`, animationDuration: `${6 + (i % 3) * 1.5}s` }}
              />
            )}
          </g>
        ))}
      </svg>

      {/* 1b. Film grain */}
      <svg className="absolute inset-0 h-full w-full opacity-[0.07] mix-blend-overlay">
        <filter id="cl-grain">
          <feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="3" stitchTiles="stitch" />
          <feColorMatrix type="saturate" values="0" />
        </filter>
        <rect width="100%" height="100%" filter="url(#cl-grain)" />
      </svg>

      {/* Edge vignette */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_40%,transparent_55%,rgba(0,8,20,0.65)_100%)]" />
    </div>
  );
}
