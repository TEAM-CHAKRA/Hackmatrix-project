/** @type {import('tailwindcss').Config} */
// CYBERLENS brand palette:
//   Cyan Pulse #00D1B2 · Midnight Grid #001F3F · Pure Signal #FFFFFF · Carbon Core #2E2E2E
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        midnight: '#001F3F',
        carbon: '#2E2E2E',
        pulse: '#00D1B2',
        ink: {
          950: '#010810',
          900: '#030f1e',
          850: '#06162a',
          800: '#001F3F',
          700: '#0a2d52',
          600: '#143e6a',
          500: '#1e5287',
        },
        signal: {
          DEFAULT: '#00D1B2',
          dim: '#00a88f',
          soft: '#4ae3cb',
          hover: '#19e3c5',
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
        display: ['"Space Grotesk"', '"IBM Plex Sans"', 'sans-serif'],
      },
      boxShadow: {
        sm: '0 1px 2px 0 rgba(0, 0, 0, 0.4)',
        card: '0 2px 10px -2px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 255, 255, 0.07)',
        'card-hover': '0 8px 24px -4px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(0, 209, 178, 0.35)',
        elevated: '0 16px 36px -8px rgba(0, 0, 0, 0.75), 0 0 0 1px rgba(255, 255, 255, 0.08)',
        subtle: '0 1px 1px 0 rgba(0, 0, 0, 0.35), 0 0 0 1px rgba(255, 255, 255, 0.05)',
      },
      keyframes: {
        sweep: { to: { transform: 'rotate(360deg)' } },
      },
      animation: {
        sweep: 'sweep 8s linear infinite',
      },
    },
  },
  plugins: [],
};
