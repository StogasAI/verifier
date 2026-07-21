import type { Verifier as CoreVerifier } from '../../pkg/browser/stogas_verifier.js';

export { default, verify_bundle } from '../../pkg/browser/stogas_verifier.js';

export declare class Verifier {
	constructor(staging?: boolean);
	verify_bundle(bundle: Uint8Array): ReturnType<CoreVerifier['verify_bundle']>;
	free(): void;
}
