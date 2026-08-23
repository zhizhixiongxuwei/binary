import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

const sourceRoot = fileURLToPath(new URL('./src', import.meta.url))

export default defineConfig({
    plugins: [vue()],
    resolve: {
      alias: [{ find: '@', replacement: sourceRoot }],
    },
    server: {
      port: 5173,
      proxy: {
        '/api': {
          target: process.env.VITE_API_PROXY_TARGET ?? 'http://localhost:8080',
          changeOrigin: true,
        },
      },
    },
})
