import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const repositoryRoot = new URL('../../', import.meta.url);
const [cargoManifest, ciWorkflow, campaignWorkflow] = await Promise.all([
	readFile(new URL('fuzz/Cargo.toml', repositoryRoot), 'utf8'),
	readFile(new URL('.github/workflows/ci.yml', repositoryRoot), 'utf8'),
	readFile(new URL('.github/workflows/fuzz.yml', repositoryRoot), 'utf8')
]);
const targets = [...cargoManifest.matchAll(/\[\[bin\]\]\s+name = "([^"]+)"/g)].map(
	([, target]) => target
);
const ciTargets = /for target in ([^;]+); do/.exec(ciWorkflow)?.[1]?.split(/\s+/);
const campaignTargets = /matrix:\s*\n\s*target:\s*\[([^\]]+)\]/
	.exec(campaignWorkflow)?.[1]
	?.split(',')
	.map((target) => target.trim());

assert.ok(targets.length > 0, 'the verifier must declare at least one fuzz target');
assert.equal(new Set(targets).size, targets.length, 'Cargo fuzz target names must be unique');
assert.ok(ciTargets, 'the CI workflow must declare its fuzz target loop');
assert.ok(campaignTargets, 'the campaign workflow must declare its fuzz target matrix');
assert.deepEqual(
	[...ciTargets].sort(),
	[...targets].sort(),
	'the CI fuzz target list must exactly match Cargo.toml'
);
assert.deepEqual(
	[...campaignTargets].sort(),
	[...targets].sort(),
	'the campaign fuzz target list must exactly match Cargo.toml'
);
assert.match(
	campaignWorkflow,
	/path: fuzz\/corpus\/\$\{\{ matrix\.target }}/,
	'the fuzz campaign must restore and advance each generated corpus'
);
