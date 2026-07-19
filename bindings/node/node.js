import { readFileSync } from 'node:fs';
import {
	Verifier as CoreVerifier,
	initSync,
	verify_bundle
} from '../../pkg/browser/stogas_verifier.js';

const wasm = readFileSync(new URL('../../pkg/browser/stogas_verifier_bg.wasm', import.meta.url));
initSync({ module: wasm });

export { verify_bundle };

export class Verifier {
	#core;

	constructor(maxNodeAgeMs) {
		this.#core = new CoreVerifier(maxNodeAgeMs);
	}

	verify_bundle(bundle) {
		return this.#core.verify_bundle(bundle);
	}

	free() {
		this.#core.free();
	}
}
