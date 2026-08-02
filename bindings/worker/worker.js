import wasmModule from '../../pkg/browser/stogas_verifier_bg.wasm';
import {
	Verifier as CoreVerifier,
	initSync,
	verify_bundle
} from '../../pkg/browser/stogas_verifier.js';

initSync({ module: wasmModule });

export { verify_bundle };
export { StogasTransport } from '../browser/browser.js';

export class Verifier {
	#core;

	constructor() {
		this.#core = new CoreVerifier();
	}

	verify_bundle(bundle) {
		return this.#core.verify_bundle(bundle);
	}

	verify_response_proof(proof, requestBody, responseBody, e2eeTranscriptSHA256) {
		return this.#core.verify_response_proof(proof, requestBody, responseBody, e2eeTranscriptSHA256);
	}

	verify_historical_response_proof(
		proof,
		requestBody,
		responseBody,
		ledger,
		catalog,
		e2eeTranscriptSHA256
	) {
		return this.#core.verify_historical_response_proof(
			proof,
			requestBody,
			responseBody,
			ledger,
			catalog,
			e2eeTranscriptSHA256
		);
	}

	verify_node_ledger_record(ledger) {
		return this.#core.verify_node_ledger_record(ledger);
	}

	free() {
		this.#core.free();
	}
}
