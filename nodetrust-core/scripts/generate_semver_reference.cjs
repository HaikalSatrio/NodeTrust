// Optional development oracle. No npm dependency is needed at Python runtime.
// node scripts/generate_semver_reference.cjs /path/to/node_modules/semver
const fs = require('node:fs');
const path = require('node:path');
const modulePath = process.argv[2] || 'semver';
const semver = require(modulePath);
const version = require(path.join(path.dirname(require.resolve(modulePath)), 'package.json')).version;
const versions = [
  '0.0.0', '0.0.1', '0.0.3', '0.0.4', '0.1.0', '0.2.3', '0.2.9', '0.3.0',
  '1.0.0', '1.1.0', '1.2.0', '1.2.3-alpha', '1.2.3-alpha.2', '1.2.3-beta',
  '1.2.3', '1.2.3+build.1', '1.2.4', '1.3.0-beta', '1.3.0', '1.9.9',
  '2.0.0-0', '2.0.0', '2.3.4', '2.9.0', '3.0.0', 'v1.2.3', 'garbage',
];
const ranges = [
  '', '*', 'x', '1', '1.2', '1.x', '1.2.*', '^1.2.3', '^0.2.3', '^0.0.3',
  '^0.0', '^0', '^0.x', '^1.x', '~1.2.3', '~1.2', '~1', '~>1.2.3',
  '1.2.3', '=1.2.3', 'v1.2.3', '1.2.3+build.1', '>= 1.2.3 < 2',
  '>1.2', '<=1.2', '<1.2', '>1', '<=1', '>=*', '>*', '<*',
  '1.2.3 - 2.3.4', '1.2 - 2.3', '* - 2', '1 - *',
  '1.x || >=2.3.4', '^1.2.3-alpha', '>=1.2.3-alpha <1.3.0',
  '^1.2.3-01', 'latest || 1.2.3', '1.x.3', '*.2', 'workspace:*',
];
const fixture = {
  source: 'https://github.com/npm/node-semver',
  oracle: `node-semver ${version}; loose=false; includePrerelease=false`,
  versions,
  cases: ranges.map(spec => ({ spec, matches: versions.filter(v => semver.satisfies(v, spec)) })),
};
const target = path.join(__dirname, '../fixtures/nt005/semver-reference.json');
fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, JSON.stringify(fixture, null, 2) + '\n');
console.log(`${fixture.cases.length * versions.length} comparisons from ${fixture.oracle}`);
