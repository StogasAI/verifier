import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as publicAPI from '@stogas/verifier';
import { EvidenceVerifier, StogasTransport } from '@stogas/verifier';

for (const retired of [
	'Verifier',
	'verify_bundle',
	'verify_staging_catalog_approval',
	'verify_staging_release_approval'
])
	assert.equal(retired in publicAPI, false);

const { root } = JSON.parse(readFileSync(new URL('../fixtures/logged-key-manifest.json', import.meta.url), 'utf8'));
const verifier = new EvidenceVerifier('prod', root.key_id, root.public_key);
try {
	assert.throws(() => verifier.refresh(new TextEncoder().encode('{"body":')));
} finally {
	verifier.free();
}
assert.throws(() => new StogasTransport({ maxConnections: 0 }), /positive safe integer/);
