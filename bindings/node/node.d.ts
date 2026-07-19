import type { Verifier as CoreVerifier } from '../../pkg/browser/stogas_verifier.js';

export { verify_bundle } from '../../pkg/browser/stogas_verifier.js';

export declare class Verifier {
	constructor(maxNodeAgeMs?: number | null);
	verify_bundle(bundle: Uint8Array): ReturnType<CoreVerifier['verify_bundle']>;
	free(): void;
}
