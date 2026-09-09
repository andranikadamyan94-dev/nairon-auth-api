/**
 * Unit tests only, matching the convention nairon-ai-api already uses.
 *
 * Nothing here reaches the database or another service: Prisma and the network
 * are stubbed, so the suite runs anywhere and tells the truth about the code
 * rather than about the machine it happens to be on.
 */
module.exports = {
  rootDir: 'src',
  testEnvironment: 'node',
  testRegex: '.*\\.spec\\.ts$',
  transform: { '^.+\\.ts$': 'ts-jest' },
  moduleFileExtensions: ['ts', 'js', 'json'],
  collectCoverageFrom: ['**/*.(t|j)s'],
  coverageDirectory: '../coverage',
};
