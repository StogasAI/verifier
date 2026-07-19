import { readFileSync } from 'node:fs';
import {
	initSync,
	verify_github_attestation,
	verify_github_attestation_at
} from '../../pkg/browser/stogas_offline_sigstore.js';

const wasm = readFileSync(
	new URL('../../pkg/browser/stogas_offline_sigstore_bg.wasm', import.meta.url)
);
initSync({ module: wasm });

export { verify_github_attestation, verify_github_attestation_at };
