import { defineConfig } from 'vitest/config';
import * as dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['__tests__/**/*.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'cobertura', 'json'],
      include: ['src/**/*.ts'],
      exclude: ['src/@types/**', 'src/**/*.d.ts'],
    },
    // Match jest's behavior
    testTimeout: 10000,
    hookTimeout: 10000,
  },
});
