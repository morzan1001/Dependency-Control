import { defineConfig } from 'vite'
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
    rollupOptions: {
      output: {
        // Automatic chunking based on module paths for better caching
        manualChunks(id) {
          if (id.includes('node_modules')) {
            // Core React dependencies
            if (id.includes('react') || id.includes('react-dom') || id.includes('react-router')) {
              return 'vendor-react'
            }
            // UI framework (Radix)
            if (id.includes('@radix-ui')) {
              return 'vendor-ui'
            }
            // Data fetching & state
            if (id.includes('@tanstack')) {
              return 'vendor-query'
            }
            // Charts
            if (id.includes('recharts') || id.includes('d3-')) {
              return 'vendor-charts'
            }
          }
        },
      },
    },
    // Increase chunk size warning limit slightly
    chunkSizeWarningLimit: 600,
  },
  server: {
    proxy: {
      '/api/v1': {
        target: 'https://api.dependencycontrol.local',
        changeOrigin: true,
        secure: true
      }
    }
  }
})
