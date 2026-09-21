import assert from 'node:assert/strict';
import * as publicAPI from '@stogas/verifier';
import { EvidenceVerifier, StogasTransport } from '@stogas/verifier';

for (const retired of [
	'Verifier',
	'verify_bundle',
	'verify_staging_catalog_approval',
	'verify_staging_release_approval'
])
	assert.equal(retired in publicAPI, false);

const verifier = new EvidenceVerifier(
	'prod',
	'stogas-fixture-root-20260920',
	'MCowBQYDK2VwAyEA3L5P2vQ8YUaIm4Kw5pD8iMEoZgUuo+oEKx95iLylrgg='
);
try {
	assert.throws(() => verifier.refresh(new TextEncoder().encode('{"body":')));
} finally {
	verifier.free();
}
assert.throws(() => new StogasTransport({ maxConnections: 0 }), /positive safe integer/);
