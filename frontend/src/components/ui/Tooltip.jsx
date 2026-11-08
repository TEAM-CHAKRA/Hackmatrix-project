import { useId } from 'react';
import { Info } from 'lucide-react';

/** Accessible tooltip for technical terms. Works on hover and keyboard focus. */
export default function Tooltip({ text, children, className = '' }) {
  const id = useId();
  return (
    <span className={`group relative inline-flex items-center gap-1 ${className}`}>
      {children}
      <button
        type="button"
        aria-describedby={id}
        className="text-white/40 transition hover:text-white/70 focus:text-white/70"
        aria-label="More information"
      >
        <Info size={12} />
      </button>
      <span
        id={id}
        role="tooltip"
        className="pointer-events-none absolute bottom-full left-1/2 z-40 mb-2 w-60 -translate-x-1/2 rounded-lg border border-white/15 bg-[#001a36]/80 backdrop-blur-xl px-3 py-2 text-xs font-normal normal-case leading-relaxed tracking-normal text-white/90 opacity-0 shadow-lg transition-opacity duration-150 group-hover:opacity-100 group-focus-within:opacity-100"
      >
        {text}
      </span>
    </span>
  );
}
