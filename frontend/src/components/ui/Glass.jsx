import { motion, useReducedMotion } from 'framer-motion';
import { FlaskConical } from 'lucide-react';
import { cx } from '../../utils/format.js';

/** Scroll-triggered reveal. Respects reduced motion. */
export function Reveal({ children, delay = 0, y = 16, className, as = 'div' }) {
  const reduce = useReducedMotion();
  const Comp = motion[as] || motion.div;
  return (
    <Comp
      className={className}
      initial={reduce ? false : { opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-40px' }}
      transition={{ duration: 0.5, delay, ease: [0.2, 0.8, 0.2, 1] }}
    >
      {children}
    </Comp>
  );
}

export function GlassPanel({ children, className, strong = false, hover = false, as: Tag = 'div', ...rest }) {
  return (
    <Tag className={cx(strong ? 'glass-strong' : 'glass', 'rounded-xl', hover && 'glass-hover', className)} {...rest}>
      {children}
    </Tag>
  );
}

export function GlassButton({ children, variant = 'primary', className, ...rest }) {
  return (
    <button className={cx(variant === 'primary' ? 'btn-primary' : variant === 'ghost' ? 'btn-ghost' : 'btn-secondary', className)} {...rest}>
      {children}
    </button>
  );
}

export function SectionHeading({ eyebrow, title, accent, children, align = 'center', id }) {
  const center = align === 'center';
  return (
    <Reveal className={cx('mb-14 max-w-3xl', center ? 'mx-auto text-center' : '')}>
      {eyebrow && (
        <div className={cx('mb-6 flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.22em] text-white/55', center && 'justify-center')}>
          <span className="h-px w-8 bg-signal" />
          {eyebrow}
          {center && <span className="h-px w-8 bg-signal" />}
        </div>
      )}
      <h2 id={id} className="font-display text-4xl font-semibold leading-[1.06] tracking-[-0.03em] text-white sm:text-5xl">
        {title} {accent && <span className="text-white/50">{accent}</span>}
      </h2>
      {children && <p className={cx('mt-6 text-[16px] leading-relaxed text-white/65 sm:text-[17px]', center && 'mx-auto max-w-2xl')}>{children}</p>}
    </Reveal>
  );
}

/** Marks static, illustrative visuals so they are never mistaken for live results. */
export function ExampleLabel({ children = 'Illustrative example — not a live scan', className }) {
  return (
    <span className={cx('inline-flex items-center gap-1.5 rounded-md border border-white/10 glass-inset px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-white/60', className)}>
      <FlaskConical size={11} className="text-signal" />
      {children}
    </span>
  );
}

/** Shared inner-page header: small label, title, one short line. */
export function PageHeader({ eyebrow, title, accent, children, align = 'left', action }) {
  const center = align === 'center';
  return (
    <header className={cx('flex flex-col gap-6', center ? 'items-center text-center' : 'lg:flex-row lg:items-end lg:justify-between')}>
      <div className={center ? 'max-w-2xl' : 'max-w-2xl'}>
        {eyebrow && (
          <div className={cx('mb-5 flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.22em] text-white/55', center && 'justify-center')}>
            <span className="h-px w-8 bg-signal" />
            {eyebrow}
            {center && <span className="h-px w-8 bg-signal" />}
          </div>
        )}
        <h1 className="font-display text-4xl font-semibold leading-[1.05] tracking-[-0.03em] text-white sm:text-5xl">
          {title} {accent && <span className="text-signal">{accent}</span>}
        </h1>
        {children && <p className="mt-4 text-[16px] leading-relaxed text-white/60 sm:text-[17px]">{children}</p>}
      </div>
      {action}
    </header>
  );
}
