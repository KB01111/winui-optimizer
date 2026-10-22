// ESLint flat config for the AI Antivirus dashboard.
//
// Scope: the React/TypeScript frontend only. Rust sources are linted by
// `cargo clippy` (see docs/VERIFICATION.md), and the generated/ vendored
// directories are ignored.
//
// Rules are intentionally close to the Vite React+TS defaults so the config
// stays useful without fighting the existing code style. The `react-hooks`
// rules are errors because the dashboard relies on effect hygiene to keep the
// live event feed and polling loops correct.

import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'node_modules/**',
      'src-tauri/**',
      'target/**',
      'crates/**',
      'services/**',
      'packaging/**',
    ],
  },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2021,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
      eqeqeq: ['error', 'smart'],
      'no-console': ['warn', { allow: ['warn', 'error'] }],

      // The React Compiler lint rules in eslint-plugin-react-hooks v7 are
      // advisory here. `set-state-in-effect` in particular flags the standard
      // "fetch on mount" and "reset derived state when a filter changes"
      // effects, which this dashboard uses deliberately: every one of them is
      // paired with a real backend command and an explicit loading/error
      // state, and the alternatives (adjusting state during render) change
      // observable behaviour. They stay visible as warnings so a future
      // refactor is not blocked, but they do not fail the lint gate.
      'react-hooks/set-state-in-effect': 'warn',
    },
  },
  {
    // Context providers export both a component and its hook; that is the
    // documented shape and Fast Refresh handles it correctly.
    files: ['src/state/**/*.{ts,tsx}', 'src/hooks/**/*.{ts,tsx}'],
    rules: {
      'react-refresh/only-export-components': 'off',
    },
  },
  {
    // Vitest specs legitimately use test globals.
    files: ['tests/frontend/**/*.{ts,tsx}'],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
);
