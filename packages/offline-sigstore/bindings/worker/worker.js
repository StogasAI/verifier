import wasmModule from '../../pkg/browser/stogas_offline_sigstore_bg.wasm';
import {
	initSync,
	verify_github_attestation,
	verify_github_attestation_at
} from '../../pkg/browser/stogas_offline_sigstore.js';

initSync({ module: wasmModule });

export { verify_github_attestation, verify_github_attestation_at };
