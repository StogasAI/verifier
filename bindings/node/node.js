import { readFileSync } from 'node:fs';
import {
	Verifier,
	initSync,
	verify_bundle,
	verify_bundle_at
} from '../../pkg/browser/stogas_verifier.js';

const wasm = readFileSync(new URL('../../pkg/browser/stogas_verifier_bg.wasm', import.meta.url));
initSync({ module: wasm });

export { Verifier, verify_bundle, verify_bundle_at };
