import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          // A group also takes the dependencies of its modules that no higher-priority group
          // claimed, so react has to outrank every library built on it.
          groups: [
            { name: 'vendor-react', test: /[\\/]node_modules[\\/](react|react-dom|react-router|react-router-dom|scheduler)[\\/]/, priority: 4 },
            { name: 'vendor-ui', test: /[\\/]node_modules[\\/]@radix-ui[\\/]/, priority: 3 },
            { name: 'vendor-query', test: /[\\/]node_modules[\\/]@tanstack[\\/]/, priority: 2 },
          ],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api/v1': {
        target: 'https://api.dependencycontrol.local',
        changeOrigin: true,
        secure: true
      }
    }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['lcov', 'text'],
      reportsDirectory: 'coverage',
    },
  },
})
