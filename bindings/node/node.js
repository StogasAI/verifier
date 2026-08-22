import { readFileSync } from 'node:fs';
import {
	Verifier as CoreVerifier,
	initSync,
	verify_bundle,
	verify_bundle_with_policy
} from '../../pkg/browser/stogas_verifier.js';
import { createVerifierBindings } from '../shared/verifier.js';

const wasm = readFileSync(new URL('../../pkg/browser/stogas_verifier_bg.wasm', import.meta.url));
initSync({ module: wasm });

export { verify_bundle, verify_bundle_with_policy };
export { StogasTransport } from '../browser/browser.js';

export const { ResponseProofStream, Verifier } = createVerifierBindings(CoreVerifier);
