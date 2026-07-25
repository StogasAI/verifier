import type { Verifier as CoreVerifier } from '../../pkg/browser/stogas_verifier.js';

export { verify_bundle } from '../../pkg/browser/stogas_verifier.js';
export { StogasTransport } from '../browser/browser.js';

export declare class Verifier {
	constructor();
	verify_bundle(bundle: Uint8Array): ReturnType<CoreVerifier['verify_bundle']>;
	verify_response_proof(
		proof: Uint8Array,
		requestBody: Uint8Array,
		responseBody: Uint8Array,
		e2eeTranscriptSHA256?: string
	): ReturnType<CoreVerifier['verify_response_proof']>;
	verify_historical_response_proof(
		proof: Uint8Array,
		requestBody: Uint8Array,
		responseBody: Uint8Array,
		ledger: Uint8Array,
		e2eeTranscriptSHA256?: string
	): ReturnType<CoreVerifier['verify_historical_response_proof']>;
	verify_node_ledger_record(
		ledger: Uint8Array
	): ReturnType<CoreVerifier['verify_node_ledger_record']>;
	free(): void;
}
