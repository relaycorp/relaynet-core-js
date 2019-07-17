const mainJestConfig = require('./jest.config');

module.exports = Object.assign({}, mainJestConfig, {
  collectCoverageFrom: ['**/*.js', '**/*.ts'],
  // moduleFileExtensions: ['js'],
  preset: null,
  roots: ['build/main']
});
