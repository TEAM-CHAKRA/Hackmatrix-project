import { useEffect, useRef } from 'react';
import { useReducedMotion } from 'framer-motion';

/**
 * ThreatGlobe — a canvas-drawn 3D point globe with travelling signal arcs,
 * a sweeping scan ring and HUD rings. Purely decorative (aria-hidden).
 *
 * Scroll behaviour: as the hero scrolls away the globe spins faster, grows,
 * drifts with parallax and its points disperse outward into the background.
 * Arcs that land on amber/red points pulse like a detected threat.
 */
const CYAN = '0,209,178';
const WHITE = '255,255,255';
const THREAT = ['255,176,32', '255,84,84'];

function fibSphere(n) {
  const pts = [];
  const g = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < n; i++) {
    const y = 1 - (i / (n - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const th = g * i;
    pts.push({ x: Math.cos(th) * r, y, z: Math.sin(th) * r, j: 0.4 + Math.random() * 1.2, w: Math.random() < 0.18 });
  }
  return pts;
}

export default function ThreatGlobe({ className = '' }) {
  const ref = useRef(null);
  const reduce = useReducedMotion();

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext('2d');
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    let w = 0;
    let h = 0;
    let pts = [];
    let raf = 0;
    let visible = true;
    const arcs = [];
    const pings = [];
    let nextArc = 0;

    const resize = () => {
      const r = canvas.parentElement.getBoundingClientRect();
      w = r.width;
      h = r.height;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      pts = fibSphere(w >= 1024 ? 1700 : 900);
    };

    // Rotation (yaw a, fixed tilt) + perspective projection.
    const TILT = 0.38;
    const ct = Math.cos(TILT);
    const st = Math.sin(TILT);
    const project = (x, y, z, ca, sa) => {
      const x1 = x * ca + z * sa;
      const z1 = -x * sa + z * ca;
      const y2 = y * ct - z1 * st;
      const z2 = y * st + z1 * ct;
      const s = 3 / (3 - z2);
      return [x1 * s, y2 * s, z2, s];
    };

    const slerp = (a, b, t) => {
      const d = Math.min(1, Math.max(-1, a.x * b.x + a.y * b.y + a.z * b.z));
      const om = Math.acos(d);
      if (om < 1e-4) return { x: a.x, y: a.y, z: a.z, om };
      const so = Math.sin(om);
      const k1 = Math.sin((1 - t) * om) / so;
      const k2 = Math.sin(t * om) / so;
      return { x: a.x * k1 + b.x * k2, y: a.y * k1 + b.y * k2, z: a.z * k1 + b.z * k2, om };
    };

    const spawnArc = (now) => {
      const a = pts[(Math.random() * pts.length) | 0];
      let b = pts[(Math.random() * pts.length) | 0];
      let tries = 0;
      while (tries++ < 8) {
        const d = a.x * b.x + a.y * b.y + a.z * b.z;
        if (d < 0.6 && d > -0.4) break;
        b = pts[(Math.random() * pts.length) | 0];
      }
      const threat = Math.random() < 0.28 ? THREAT[Math.random() < 0.6 ? 0 : 1] : null;
      arcs.push({ a, b, t0: now, dur: 1500 + Math.random() * 900, threat });
    };

    const draw = (now) => {
      const sy = window.scrollY;
      const p = Math.min(1, Math.max(0, sy / (h * 0.9 || 1)));
      const lg = w >= 1024;

      const baseR = Math.min(w, h) * (lg ? 0.31 : 0.36);
      const R = baseR * (1 + p * 0.55);
      const cx = lg ? w * 0.71 : w * 0.5;
      const cy = (lg ? h * 0.47 : h * 0.3) + sy * 0.38;
      const fade = (1 - p * 0.9) * (lg ? 1 : 0.6);
      const disperse = p * p * 2.2;

      const ang = (reduce ? 0.6 : now * 0.00011) + sy * 0.0022;
      const ca = Math.cos(ang);
      const sa = Math.sin(ang);

      ctx.clearRect(0, 0, w, h);
      if (fade <= 0.01) return;

      // Atmosphere glow
      const glow = ctx.createRadialGradient(cx, cy, R * 0.2, cx, cy, R * 1.45);
      glow.addColorStop(0, `rgba(0,120,140,${0.22 * fade})`);
      glow.addColorStop(0.6, `rgba(0,80,120,${0.1 * fade})`);
      glow.addColorStop(1, 'rgba(0,40,80,0)');
      ctx.fillStyle = glow;
      ctx.fillRect(cx - R * 1.5, cy - R * 1.5, R * 3, R * 3);

      // Sphere body + limb (fades as the points disperse)
      const solid = fade * (1 - Math.min(1, disperse));
      const limbR = R * 1.02;
      const body = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.1, cx, cy, limbR);
      body.addColorStop(0, `rgba(0,90,110,${0.35 * solid})`);
      body.addColorStop(0.75, `rgba(0,30,60,${0.45 * solid})`);
      body.addColorStop(1, `rgba(0,209,178,${0.18 * solid})`);
      ctx.fillStyle = body;
      ctx.beginPath();
      ctx.arc(cx, cy, limbR, 0, Math.PI * 2);
      ctx.fill();
      ctx.lineWidth = 1;
      ctx.strokeStyle = `rgba(${CYAN},${0.4 * solid})`;
      ctx.stroke();

      // Meridians (front halves only)
      ctx.strokeStyle = `rgba(${CYAN},${0.13 * solid})`;
      for (let m = 0; m < 12; m++) {
        const lon = (m / 12) * Math.PI;
        const cl = Math.cos(lon);
        const sl = Math.sin(lon);
        let started = false;
        ctx.beginPath();
        for (let i = 0; i <= 64; i++) {
          const t = (i / 64) * Math.PI * 2;
          const [x, y, z] = project(Math.cos(t) * cl, Math.sin(t), Math.cos(t) * sl, ca, sa);
          if (z < 0) {
            started = false;
            continue;
          }
          if (!started) {
            ctx.moveTo(cx + x * R, cy + y * R);
            started = true;
          } else ctx.lineTo(cx + x * R, cy + y * R);
        }
        ctx.stroke();
      }

      // HUD: tick ring + two rotating arc segments
      ctx.lineWidth = 1;
      ctx.strokeStyle = `rgba(${CYAN},${0.12 * fade})`;
      const tickR = R * 1.3;
      ctx.beginPath();
      for (let i = 0; i < 72; i++) {
        const t = (i / 72) * Math.PI * 2 + ang * 0.15;
        const len = i % 6 === 0 ? 9 : 4;
        ctx.moveTo(cx + Math.cos(t) * tickR, cy + Math.sin(t) * tickR);
        ctx.lineTo(cx + Math.cos(t) * (tickR + len), cy + Math.sin(t) * (tickR + len));
      }
      ctx.stroke();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = `rgba(${CYAN},${0.5 * fade})`;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.18, -ang * 0.8, -ang * 0.8 + 1.1);
      ctx.stroke();
      ctx.strokeStyle = `rgba(${WHITE},${0.25 * fade})`;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.18, Math.PI - ang * 0.8, Math.PI - ang * 0.8 + 0.5);
      ctx.stroke();

      // Points (back first is unnecessary: tiny, alpha-weighted)
      for (const q of pts) {
        const k = 1 + disperse * q.j;
        const [x, y, z, s] = project(q.x * k, q.y * k, q.z * k, ca, sa);
        const front = z > 0;
        const a = (front ? 0.3 + 0.65 * z : 0.05 + 0.08 * (1 + z)) * fade;
        if (a < 0.02) continue;
        const size = (q.w ? 2 : 1.5) * s;
        ctx.fillStyle = `rgba(${q.w ? WHITE : CYAN},${a})`;
        ctx.fillRect(cx + x * R - size / 2, cy + y * R - size / 2, size, size);
      }

      // Equator + sweeping scan latitude
      const ring = (lat, alpha, width) => {
        const ry = Math.sin(lat);
        const rr = Math.cos(lat);
        ctx.lineWidth = width;
        let started = false;
        ctx.beginPath();
        for (let i = 0; i <= 96; i++) {
          const t = (i / 96) * Math.PI * 2;
          const [x, y, z] = project(Math.cos(t) * rr, ry, Math.sin(t) * rr, ca, sa);
          if (z < -0.02) {
            started = false;
            continue;
          }
          const X = cx + x * R;
          const Y = cy + y * R;
          if (!started) {
            ctx.moveTo(X, Y);
            started = true;
          } else ctx.lineTo(X, Y);
        }
        ctx.strokeStyle = `rgba(${CYAN},${alpha * fade})`;
        ctx.stroke();
      };
      for (const lat of [-1.05, -0.52, 0.52, 1.05]) ring(lat, 0.1 * (1 - Math.min(1, disperse)), 1);
      ring(0, 0.3, 1);
      if (!reduce) ring(Math.sin(now * 0.0006) * 1.2, 0.75, 1.6);

      if (reduce || p > 0.85) return;

      // Arcs
      if (now > nextArc && arcs.length < (lg ? 7 : 4)) {
        spawnArc(now);
        nextArc = now + 280 + Math.random() * 520;
      }
      ctx.lineWidth = 1.4;
      for (let i = arcs.length - 1; i >= 0; i--) {
        const A = arcs[i];
        const head = Math.min(1, (now - A.t0) / A.dur);
        const tail = Math.max(0, head - 0.4);
        const col = A.threat || CYAN;
        let prev = null;
        for (let sIdx = 0; sIdx <= 22; sIdx++) {
          const t = tail + ((head - tail) * sIdx) / 22;
          const m = slerp(A.a, A.b, t);
          const lift = 1 + 0.32 * Math.sin(Math.PI * t) * Math.min(1, m.om);
          const [x, y, z] = project(m.x * lift, m.y * lift, m.z * lift, ca, sa);
          const X = cx + x * R;
          const Y = cy + y * R;
          if (prev && z > -0.15 && prev[2] > -0.15) {
            ctx.strokeStyle = `rgba(${col},${(0.15 + 0.75 * (sIdx / 22)) * fade})`;
            ctx.beginPath();
            ctx.moveTo(prev[0], prev[1]);
            ctx.lineTo(X, Y);
            ctx.stroke();
          }
          prev = [X, Y, z];
        }
        if (prev && prev[2] > -0.15 && head < 1) {
          ctx.fillStyle = `rgba(${WHITE},${0.95 * fade})`;
          ctx.fillRect(prev[0] - 1.5, prev[1] - 1.5, 3, 3);
        }
        if (head >= 1) {
          pings.push({ p: A.b, t0: now, col });
          arcs.splice(i, 1);
        }
      }

      // Impact pings
      for (let i = pings.length - 1; i >= 0; i--) {
        const P = pings[i];
        const age = (now - P.t0) / 1300;
        if (age >= 1) {
          pings.splice(i, 1);
          continue;
        }
        const [x, y, z] = project(P.p.x, P.p.y, P.p.z, ca, sa);
        if (z < 0) continue;
        const X = cx + x * R;
        const Y = cy + y * R;
        ctx.strokeStyle = `rgba(${P.col},${(1 - age) * 0.8 * fade})`;
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(X, Y, 3 + age * 16, 0, Math.PI * 2);
        ctx.stroke();
        ctx.fillStyle = `rgba(${P.col},${(1 - age) * fade})`;
        ctx.fillRect(X - 2, Y - 2, 4, 4);
      }
    };

    const loop = (now) => {
      if (visible) draw(now);
      raf = requestAnimationFrame(loop);
    };

    resize();
    const ro = new ResizeObserver(() => {
      resize();
      if (reduce) draw(0);
    });
    ro.observe(canvas.parentElement);
    const io = new IntersectionObserver(([e]) => {
      visible = e.isIntersecting;
    });
    io.observe(canvas.parentElement);

    const onScrollStatic = () => draw(0);
    const onVis = () => {
      cancelAnimationFrame(raf);
      if (!document.hidden && !reduce) raf = requestAnimationFrame(loop);
    };
    if (reduce) {
      draw(0);
      window.addEventListener('scroll', onScrollStatic, { passive: true });
    } else {
      raf = requestAnimationFrame(loop);
      document.addEventListener('visibilitychange', onVis);
    }
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      window.removeEventListener('scroll', onScrollStatic);
      document.removeEventListener('visibilitychange', onVis);
    };
  }, [reduce]);

  return <canvas ref={ref} aria-hidden className={`pointer-events-none absolute inset-0 ${className}`} />;
}
