import assert from 'node:assert/strict';
import * as publicAPI from '@stogas/verifier';
import { StogasTransport, Verifier, verify_bundle } from '@stogas/verifier';

assert.equal('verify_staging_release_approval' in publicAPI, false);

const verifier = new Verifier();
assert.throws(
	() => verifier.verify_bundle(new TextEncoder().encode('{"body":')),
	/invalid bundle JSON/
);
verifier.free();

assert.throws(() => verify_bundle(new TextEncoder().encode('{"body":')), /invalid bundle JSON/);
assert.throws(
	() => new StogasTransport({ bundleRefreshIntervalSeconds: 0 }),
	/positive safe integer/
);
