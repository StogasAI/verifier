import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Verifier, verify_bundle_at } from '@stogas/verifier';

const verifier = new Verifier(60_000);
assert.throws(
	() => verifier.verify_bundle_at(new TextEncoder().encode('{"body":'), 1),
	/invalid bundle JSON/
);
verifier.free();

const bundle = readFileSync(
	new URL('../../crates/verifier/tests/fixtures/staging-bundle-sequence-1927.json', import.meta.url)
);
const fullVerifier = new Verifier();
const output = fullVerifier.verify_bundle_at(bundle, 1_784_414_117_082);
assert.equal(output.bundle.sequence, 1927);
assert.equal(output.bundle.nodes.length, 1);
assert.equal(output.bundle.releases.length, 1);
assert.equal(output.bundle.original.body.nodes[0].health.secret_versions instanceof Map, false);
assert.equal(
	Object.getPrototypeOf(output.bundle.original.body.nodes[0].health.secret_versions),
	Object.prototype
);
fullVerifier.free();

const stateless = verify_bundle_at(bundle, 1_784_414_117_082);
assert.equal(stateless.bundle.releases[0].release_tag, 'v0.0.1');
