import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: {
      provider: 'istanbul',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'src/test/setup.ts',
        'src/test/mocks.ts',
        'node_modules/**',
        'src/**/*.test.{ts,tsx}',
        'src/**/*.d.ts',
        'src/**/*.spec.{ts,tsx}',
        'src/**/*.mock.{ts,tsx}',
        'src/__tests__/**',
        'src/__mocks__/**',
        'lib/**',
        'dist/**',
      ],
    },
  },
});