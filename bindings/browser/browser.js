import init, {
	Verifier as CoreVerifier,
	verify_bundle
} from '../../pkg/browser/stogas_verifier.js';

export default init;
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
