/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.js', '**/*.test.js'],
  collectCoverageFrom: ['electron/**/*.js', 'engine/**/*.js', 'whitelist/**/*.js'],
};
