export { default } from '../../pkg/browser/stogas_verifier.js';

export interface StogasTransportOptions {
	baseURL?: string;
	environment?: 'prod' | 'staging';
	/** One initial session, growing on capacity pressure to this maximum. Default: four. */
	maxConnections?: number;
	fetch?: typeof globalThis.fetch;
	/** Delivered only after the requested terminal content receipt verifies. */
	onMetadata?: (metadata: unknown) => void;
}

export interface StogasBundleSnapshot {
	bundle: unknown | null;
	bundleURL: string | null;
	error: string | null;
	fetchedAtUnixMs: number | null;
	status: 'idle' | 'refreshing' | 'ready' | 'error';
	verificationDurationMs: number | null;
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
	refreshBundle(): Promise<unknown>;
	subscribe(listener: (snapshot: StogasBundleSnapshot) => void): () => void;
	close(): Promise<void>;
}

export { EvidenceVerifier, EvidenceSnapshot, inspect_snp_report } from '../../pkg/browser/stogas_verifier.js';

export {
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt
} from '../../pkg/browser/stogas_verifier.js';
