// Semantic tones mapped to the CYBERLENS palette.
// Brand: Cyan Pulse (positive/active), Pure Signal (technical/neutral info), Carbon/Midnight (muted).
// Amber, orange and red are used ONLY for risk states, as the brand guide permits.
export const TONE = {
  green: {
    // "Low risk" / positive -> Cyan Pulse
    text: 'text-signal',
    bg: 'bg-signal/10',
    border: 'border-signal/30',
    dot: 'bg-signal',
    solid: 'bg-signal text-midnight',
    glow: '',
  },
  cyan: {
    text: 'text-signal',
    bg: 'bg-signal/10',
    border: 'border-signal/30',
    dot: 'bg-signal',
    solid: 'bg-signal text-midnight',
    glow: '',
  },
  blue: {
    // Technical / informational -> Pure Signal
    text: 'text-white/90',
    bg: 'bg-white/[0.06]',
    border: 'border-white/15',
    dot: 'bg-white/80',
    solid: 'bg-white text-midnight',
    glow: '',
  },
  amber: {
    text: 'text-amber-300',
    bg: 'bg-amber-400/10',
    border: 'border-amber-400/30',
    dot: 'bg-amber-400',
    solid: 'bg-amber-400 text-midnight',
    glow: '',
  },
  orange: {
    text: 'text-orange-300',
    bg: 'bg-orange-500/10',
    border: 'border-orange-400/35',
    dot: 'bg-orange-400',
    solid: 'bg-orange-500 text-midnight',
    glow: '',
  },
  red: {
    text: 'text-red-300',
    bg: 'bg-red-500/15',
    border: 'border-red-400/40',
    dot: 'bg-red-500',
    solid: 'bg-red-500 text-white',
    glow: '',
  },
  gray: {
    text: 'text-white/60',
    bg: 'bg-carbon/40',
    border: 'border-white/12',
    dot: 'bg-white/40',
    solid: 'bg-carbon text-white',
    glow: '',
  },
};

export const tone = (t) => TONE[t] || TONE.gray;
