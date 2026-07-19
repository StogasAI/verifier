import init, {
	Verifier as CoreVerifier,
	verify_bundle
} from '../../pkg/browser/stogas_verifier.js';

export default init;
export { verify_bundle };

export class Verifier {
	#core;

	constructor(maxNodeAgeMs, staging = false) {
		this.#core = new CoreVerifier(maxNodeAgeMs, staging);
	}

	verify_bundle(bundle) {
		return this.#core.verify_bundle(bundle);
	}

	free() {
		this.#core.free();
	}
}
