import assert from 'node:assert/strict';
import { Verifier, verify_bundle } from '@stogas/verifier';

const verifier = new Verifier();
assert.throws(
	() => verifier.verify_bundle(new TextEncoder().encode('{"body":')),
	/invalid bundle JSON/
);
verifier.free();

assert.throws(() => verify_bundle(new TextEncoder().encode('{"body":')), /invalid bundle JSON/);
