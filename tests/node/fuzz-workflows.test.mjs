import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const repositoryRoot = new URL('../../', import.meta.url);
const [cargoManifest, pullRequestWorkflow, scheduledWorkflow] = await Promise.all([
	readFile(new URL('fuzz/Cargo.toml', repositoryRoot), 'utf8'),
	readFile(new URL('.github/workflows/ci.yml', repositoryRoot), 'utf8'),
	readFile(new URL('.github/workflows/fuzz.yml', repositoryRoot), 'utf8')
]);
const targets = [...cargoManifest.matchAll(/\[\[bin\]\]\s+name = "([^"]+)"/g)].map(
	([, target]) => target
);
const pullRequestTargets = /for target in ([^;]+); do/.exec(pullRequestWorkflow)?.[1]?.split(/\s+/);
const scheduledTargets = /matrix:\s*\n\s*target:\s*\[([^\]]+)\]/
	.exec(scheduledWorkflow)?.[1]
	?.split(',')
	.map((target) => target.trim());

assert.ok(targets.length > 0, 'the verifier must declare at least one fuzz target');
assert.equal(new Set(targets).size, targets.length, 'Cargo fuzz target names must be unique');
assert.ok(pullRequestTargets, 'the pull-request workflow must declare its fuzz target loop');
assert.ok(scheduledTargets, 'the scheduled workflow must declare its fuzz target matrix');
assert.deepEqual(
	[...pullRequestTargets].sort(),
	[...targets].sort(),
	'the pull-request fuzz target list must exactly match Cargo.toml'
);
assert.deepEqual(
	[...scheduledTargets].sort(),
	[...targets].sort(),
	'the scheduled fuzz target list must exactly match Cargo.toml'
);
assert.match(
	scheduledWorkflow,
	/path: fuzz\/corpus\/\$\{\{ matrix\.target }}/,
	'the scheduled campaign must restore and advance each generated corpus'
);
