import wasmModule from '../../pkg/browser/stogas_verifier_bg.wasm';
import {
	Verifier as CoreVerifier,
	initSync,
	verify_bundle,
	verify_bundle_with_policy
} from '../../pkg/browser/stogas_verifier.js';
import { createVerifierBindings } from '../shared/verifier.js';

initSync({ module: wasmModule });

export { verify_bundle, verify_bundle_with_policy };
export { StogasTransport } from '../browser/browser.js';

export const { ResponseProofStream, Verifier } = createVerifierBindings(CoreVerifier);
