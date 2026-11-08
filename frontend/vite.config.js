import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    plugins: [react()],
    server: {
      port: 5173,
      // Fail loudly if 5173 is taken instead of silently moving to 5174, 5175…
      // (an old tab on a stale port then can't reach the backend).
      strictPort: true,
      // In development, /api is proxied to the Express backend so no CORS setup is needed locally.
      proxy: {
        '/api': {
          target: env.VITE_BACKEND_PROXY_TARGET || 'http://localhost:4000',
          changeOrigin: true,
        },
      },
    },
  };
});
