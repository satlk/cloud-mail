import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
export default defineConfig({
  resolve: { alias: { '@': fileURLToPath(new URL('../mail-vue/src', import.meta.url)) } },
  plugins: [{
    name: 'cloudflare-email-test-stub',
    resolveId(id) { if (id === 'cloudflare:email') return '\0cloudflare-email-test-stub'; },
    load(id) { if (id === '\0cloudflare-email-test-stub') return 'export class EmailMessage {}'; },
  }],
  test: { include: ['test/security.spec.js', 'test/frontend-auth.spec.js'], environment: 'node' },
});
