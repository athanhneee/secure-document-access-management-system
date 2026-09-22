export default {
  '*.{ts,tsx,js,mjs,cjs}': ['oxlint --deny-warnings', 'prettier --check'],
  '*.{json,yaml,yml,md,css}': 'prettier --check --ignore-unknown',
};
