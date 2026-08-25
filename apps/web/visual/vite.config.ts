import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'node:path'
import { defineConfig } from 'vite'

export default defineConfig({
  root: resolve(import.meta.dirname),
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: [{ find: /.*\/api\/client$/, replacement: resolve(import.meta.dirname, 'api-fixture.ts') }],
  },
  server: { host: '127.0.0.1', port: 4174, strictPort: true },
})
