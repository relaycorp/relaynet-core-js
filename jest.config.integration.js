const mainJestConfig = require('./jest.config');

module.exports = {
  preset: mainJestConfig.preset,
  roots: ['integration_tests'],
  testEnvironment: mainJestConfig.testEnvironment,
  setupFilesAfterEnv: mainJestConfig.setupFilesAfterEnv
};
