export function createVerifierBindings(CoreVerifier) {
	class ResponseProofStream {
		#core;
		#verifier;

		constructor(core, verifier) {
			this.#core = core;
			this.#verifier = verifier;
		}

		write(chunk) {
			this.#assertOpen();
			this.#core.write(chunk);
		}

		finish(proof, e2eeTranscriptSHA256) {
			this.#assertOpen();
			try {
				return this.#core.finish(this.#verifier, proof, e2eeTranscriptSHA256);
			} finally {
				this.free();
			}
		}

		finishHistorical(proof, ledger, catalog, e2eeTranscriptSHA256) {
			this.#assertOpen();
			try {
				return this.#core.finish_historical(
					this.#verifier,
					proof,
					ledger,
					catalog,
					e2eeTranscriptSHA256
				);
			} finally {
				this.free();
			}
		}

		free() {
			this.#core?.free();
			this.#core = undefined;
			this.#verifier = undefined;
		}

		#assertOpen() {
			if (!this.#core || !this.#verifier) throw new Error('ResponseProofStream is closed');
		}
	}

	class Verifier {
		#core;

		constructor() {
			this.#core = new CoreVerifier();
		}

		verify_bundle(bundle) {
			return this.#core.verify_bundle(bundle);
		}

		verify_bundle_with_policy(bundle, policy) {
			return this.#core.verify_bundle_with_policy(bundle, policy);
		}

		verify_response_proof(proof, requestBody, responseBody, e2eeTranscriptSHA256) {
			return this.#core.verify_response_proof(
				proof,
				requestBody,
				responseBody,
				e2eeTranscriptSHA256
			);
		}

		start_response_proof(requestBody) {
			return new ResponseProofStream(this.#core.start_response_proof(requestBody), this.#core);
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

		verify_release_approval(release) {
			return this.#core.verify_release_approval(release);
		}

		verify_catalog_approval(catalog) {
			return this.#core.verify_catalog_approval(catalog);
		}

		free() {
			this.#core.free();
		}
	}

	return { ResponseProofStream, Verifier };
}
