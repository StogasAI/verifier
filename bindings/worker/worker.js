import wasmModule from '../../pkg/browser/stogas_verifier_bg.wasm';
import { initSync } from '../../pkg/browser/stogas_verifier.js';

initSync({ module: wasmModule });

export { StogasTransport } from '../browser/browser.js';

export { EvidenceVerifier, EvidenceSnapshot } from '../../pkg/browser/stogas_verifier.js';

export {
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt
} from '../../pkg/browser/stogas_verifier.js';
