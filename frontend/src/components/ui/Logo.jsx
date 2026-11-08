/** CYBERLENS mark: a precision lens/target reticle with restrained technical styling. */
export default function Logo({ size = 28, animated = false }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" aria-hidden="true" className="shrink-0">
      <defs>
        <radialGradient id="cl-core" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#ffffff" />
          <stop offset="50%" stopColor="#00D1B2" />
          <stop offset="100%" stopColor="#00D1B2" stopOpacity="0" />
        </radialGradient>
      </defs>
      {/* Outer technical ring */}
      <circle cx="20" cy="20" r="17" fill="none" stroke="rgba(255, 255, 255, 0.18)" strokeWidth="1" />
      {/* Inner reticle ring */}
      <circle cx="20" cy="20" r="11" fill="none" stroke="#00D1B2" strokeWidth="1.5" strokeDasharray="3 3" opacity="0.8" />
      {/* Precision reticle crosshairs */}
      <path d="M20 2v5M20 33v5M2 20h5M33 20h5" stroke="#ffffff" strokeWidth="1.5" strokeLinecap="round" opacity="0.85" />
      {/* Core lens node */}
      <circle cx="20" cy="20" r="3.5" fill="url(#cl-core)" />
    </svg>
  );
}
