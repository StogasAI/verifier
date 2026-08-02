import type {
	ResponseProofStream as CoreResponseProofStream,
	Verifier as CoreVerifier
} from '../../pkg/browser/stogas_verifier.js';

export { default, verify_bundle } from '../../pkg/browser/stogas_verifier.js';

export declare class Verifier {
	constructor();
	verify_bundle(bundle: Uint8Array): ReturnType<CoreVerifier['verify_bundle']>;
	verify_response_proof(
		proof: Uint8Array,
		requestBody: Uint8Array,
		responseBody: Uint8Array,
		e2eeTranscriptSHA256?: string
	): ReturnType<CoreVerifier['verify_response_proof']>;
	start_response_proof(requestBody: Uint8Array): ResponseProofStream;
	verify_historical_response_proof(
		proof: Uint8Array,
		requestBody: Uint8Array,
		responseBody: Uint8Array,
		ledger: Uint8Array,
		catalog: Uint8Array,
		e2eeTranscriptSHA256?: string
	): ReturnType<CoreVerifier['verify_historical_response_proof']>;
	verify_node_ledger_record(
		ledger: Uint8Array
	): ReturnType<CoreVerifier['verify_node_ledger_record']>;
	verify_release_approval(
		release: Uint8Array
	): ReturnType<CoreVerifier['verify_release_approval']>;
	verify_catalog_approval(
		catalog: Uint8Array
	): ReturnType<CoreVerifier['verify_catalog_approval']>;
	free(): void;
}

export declare class ResponseProofStream {
	write(chunk: Uint8Array): void;
	finish(
		proof: Uint8Array,
		e2eeTranscriptSHA256?: string
	): ReturnType<CoreResponseProofStream['finish']>;
	finishHistorical(
		proof: Uint8Array,
		ledger: Uint8Array,
		catalog: Uint8Array,
		e2eeTranscriptSHA256?: string
	): ReturnType<CoreResponseProofStream['finish_historical']>;
	free(): void;
}

export interface StogasTransportOptions {
	baseURL?: string;
	bundleURL?: string;
	bundleRefreshIntervalSeconds?: number;
	environment?: 'production' | 'staging';
	fetch?: typeof globalThis.fetch;
}

export interface StogasBundleSnapshot {
	bundle: ReturnType<CoreVerifier['verify_bundle']>['bundle'] | null;
	bundleURL: string | null;
	envelopeSha256: string | null;
	error: string | null;
	fetchedAtUnixMs: number | null;
	status: 'idle' | 'refreshing' | 'ready' | 'error';
	verificationDurationMs: number | null;
	verifiedAtUnixMs: number | null;
}

export interface StogasOpenAIOptions {
	apiKey: string;
	baseURL: string;
	dangerouslyAllowBrowser: true;
	fetch: typeof globalThis.fetch;
	maxRetries: 0;
}

export declare class StogasTransport {
	static create(options?: StogasTransportOptions): Promise<StogasTransport>;
	readonly baseURL: string;
	readonly bundleSnapshot: StogasBundleSnapshot;
	readonly bundleURLs: string[];
	readonly fetch: typeof globalThis.fetch;
	openAIOptions(apiKey: string): StogasOpenAIOptions;
	verifyResponseProof(
		proof: Uint8Array,
		requestBody: Uint8Array,
		responseBody: Uint8Array,
		e2eeTranscriptSHA256?: string
	): ReturnType<CoreVerifier['verify_response_proof']>;
	createResponseProofStream(requestBody: Uint8Array): ResponseProofStream;
	verifyNodeLedgerRecord(ledger: Uint8Array): ReturnType<CoreVerifier['verify_node_ledger_record']>;
	verifyReleaseApproval(release: Uint8Array): ReturnType<CoreVerifier['verify_release_approval']>;
	verifyCatalogApproval(catalog: Uint8Array): ReturnType<CoreVerifier['verify_catalog_approval']>;
	refreshBundle(): Promise<boolean>;
	subscribe(listener: (snapshot: StogasBundleSnapshot) => void): () => void;
	close(): void;
}
