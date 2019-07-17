const mainJestConfig = require('./jest.config');

module.exports = Object.assign({}, mainJestConfig, {
  collectCoverageFrom: ['**/*.js'],
  moduleFileExtensions: ['js'],
  preset: null,
  roots: ['build/main']
});
