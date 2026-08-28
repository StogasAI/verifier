import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '../..');
const GLUE = resolve(ROOT, 'target/browser/stogas_verifier.js');
const WASM = resolve(ROOT, 'target/browser/stogas_verifier_bg.wasm');
const OFFLINE_SIGSTORE_GLUE = resolve(ROOT, 'target/offline-browser/stogas_offline_sigstore.js');
const OFFLINE_SIGSTORE_WASM = resolve(
	ROOT,
	'target/offline-browser/stogas_offline_sigstore_bg.wasm'
);
const FIXTURE = resolve(ROOT, 'tests/fixtures/gateway-v0.0.1-attestation.jsonl');
const STAGING_BUNDLE_FIXTURE = resolve(
	ROOT,
	'crates/verifier/tests/fixtures/staging-bundle-sequence-1927.json'
);
const NOW_UNIX_MS = 1_784_246_400_000;
const STAGING_BUNDLE_NOW_UNIX_MS = 1_784_414_117_082;
const SUBJECTS = [
	{
		name: 'gateway.igvm',
		sha256: '1b75d0ea7f94bc5f5a21080dd30e21370e14278a5b90eb19858c90dcc83a1bc6'
	},
	{
		name: 'gateway-launch-policy.json',
		sha256: '8cc8926592b179283c8cab267a27dfb3df4d1086dff2504e51df5fa12b8ff008'
	}
];
const POLICY = {
	predicate_type: 'https://slsa.dev/provenance/v1',
	repository: 'https://github.com/StogasAI/gateway',
	require_github_hosted: true,
	source_commit: '27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f',
	source_ref: 'refs/tags/v0.0.1',
	workflow_identity:
		'https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1'
};

async function initialize(page: import('@playwright/test').Page) {
	const requests: string[] = [];
	await page.route('**/*', async (route) => {
		requests.push(route.request().url());
		await route.abort('blockedbyclient');
	});
	const glue = await readFile(GLUE, 'utf8');
	await page.evaluate((source) => {
		globalThis.eval(`${source}\nglobalThis.stogasVerifierBindings = wasm_bindgen;`);
	}, glue);
	const bindingType = await page.evaluate(
		() =>
			typeof (globalThis as typeof globalThis & { stogasVerifierBindings?: unknown })
				.stogasVerifierBindings
	);
	if (bindingType !== 'function') throw new Error(`unexpected WASM binding type: ${bindingType}`);
	const wasm = (await readFile(WASM)).toString('base64');
	await page.evaluate(async (encoded) => {
		const binary = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
		const bindings = (
			globalThis as typeof globalThis & {
				stogasVerifierBindings: (input: Uint8Array) => Promise<void>;
			}
		).stogasVerifierBindings;
		await bindings(binary);
	}, wasm);
	return requests;
}

async function initializeOfflineSigstore(page: import('@playwright/test').Page) {
	const requests: string[] = [];
	await page.route('**/*', async (route) => {
		requests.push(route.request().url());
		await route.abort('blockedbyclient');
	});
	const glue = await readFile(OFFLINE_SIGSTORE_GLUE, 'utf8');
	await page.evaluate((source) => {
		globalThis.eval(`${source}\nglobalThis.stogasOfflineSigstoreBindings = wasm_bindgen;`);
	}, glue);
	const wasm = (await readFile(OFFLINE_SIGSTORE_WASM)).toString('base64');
	await page.evaluate(async (encoded) => {
		const binary = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
		const bindings = (
			globalThis as typeof globalThis & {
				stogasOfflineSigstoreBindings: (input: Uint8Array) => Promise<void>;
			}
		).stogasOfflineSigstoreBindings;
		await bindings(binary);
	}, wasm);
	return requests;
}

test('standalone lightweight package verifies GitHub evidence with networking disabled', async ({
	page
}) => {
	const requests = await initializeOfflineSigstore(page);
	const fixture = await readFile(FIXTURE, 'utf8');
	const result = await page.evaluate(
		({ fixture, subjects, policy, now }) => {
			const api = (
				globalThis as typeof globalThis & {
					stogasOfflineSigstoreBindings: {
						verify_github_attestation_at(
							bundle: Uint8Array,
							subjects: string,
							policy: string,
							now: number
						): { subjects: unknown[] };
					};
				}
			).stogasOfflineSigstoreBindings;
			return api.verify_github_attestation_at(
				new TextEncoder().encode(fixture),
				JSON.stringify(subjects),
				JSON.stringify(policy),
				now
			);
		},
		{ fixture, subjects: SUBJECTS, policy: POLICY, now: NOW_UNIX_MS }
	);
	expect(result.subjects).toHaveLength(2);
	expect(requests).toEqual([]);
});

test('verifies the real GitHub release fixture with networking disabled', async ({ page }) => {
	const requests = await initialize(page);
	const fixture = await readFile(FIXTURE, 'utf8');
	const result = await page.evaluate(
		({ fixture, subjects, policy, now }) => {
			const api = (
				globalThis as typeof globalThis & {
					stogasVerifierBindings: {
						verify_sigstore_github_attestation(
							bundle: Uint8Array,
							subjects: string,
							policy: string,
							now: number
						): { subjects: unknown[] };
					};
				}
			).stogasVerifierBindings;
			return api.verify_sigstore_github_attestation(
				new TextEncoder().encode(fixture),
				JSON.stringify(subjects),
				JSON.stringify(policy),
				now
			);
		},
		{ fixture, subjects: SUBJECTS, policy: POLICY, now: NOW_UNIX_MS }
	);
	expect(result.subjects).toHaveLength(2);
	expect(requests).toEqual([]);
});

test('rejects an invalid Rekor inclusion proof without networking', async ({ page }) => {
	const requests = await initialize(page);
	const fixture = JSON.parse(await readFile(FIXTURE, 'utf8'));
	const hash = fixture.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0] as string;
	fixture.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0] = `${hash.startsWith('A') ? 'B' : 'A'}${hash.slice(1)}`;
	const error = await page.evaluate(
		({ fixture, subjects, policy, now }) => {
			try {
				const api = (
					globalThis as typeof globalThis & {
						stogasVerifierBindings: {
							verify_sigstore_github_attestation(
								bundle: Uint8Array,
								subjects: string,
								policy: string,
								now: number
							): unknown;
						};
					}
				).stogasVerifierBindings;
				api.verify_sigstore_github_attestation(
					new TextEncoder().encode(JSON.stringify(fixture)),
					JSON.stringify(subjects),
					JSON.stringify(policy),
					now
				);
				return null;
			} catch (failure) {
				return String(failure);
			}
		},
		{ fixture, subjects: SUBJECTS, policy: POLICY, now: NOW_UNIX_MS }
	);
	expect(error).toContain('Sigstore cryptographic verification failed');
	expect(requests).toEqual([]);
});

test('rejects the legacy full staging bundle with networking disabled', async ({ page }) => {
	const requests = await initialize(page);
	const fixture = await readFile(STAGING_BUNDLE_FIXTURE, 'utf8');
	const error = await page.evaluate(
		({ fixture, now }) => {
			const platformNow = Date.now;
			Date.now = () => now;
			const api = (
				globalThis as typeof globalThis & {
					stogasVerifierBindings: {
						Verifier: new () => {
							free(): void;
							verify_bundle(bundle: Uint8Array): {
								bundle: { nodes: unknown[]; releases: unknown[]; sequence: number };
							};
						};
					};
				}
			).stogasVerifierBindings;
			const verifier = new api.Verifier();
			try {
				verifier.verify_bundle(new TextEncoder().encode(fixture));
				return null;
			} catch (failure) {
				return String(failure);
			} finally {
				verifier.free();
				Date.now = platformNow;
			}
		},
		{ fixture, now: STAGING_BUNDLE_NOW_UNIX_MS }
	);
	expect(error).toContain('unsupported or invalid bundle');
	expect(requests).toEqual([]);
});

test('does not activate or seal from a legacy bundle', async ({ page }) => {
	const requests = await initialize(page);
	const fixture = await readFile(STAGING_BUNDLE_FIXTURE, 'utf8');
	const result = await page.evaluate(
		({ fixture, now }) => {
			const platformNow = Date.now;
			Date.now = () => now;
			const api = (
				globalThis as typeof globalThis & {
					stogasVerifierBindings: {
						Verifier: new () => {
							free(): void;
							seal_e2ee_request(
								path: string,
								apiKey: string,
								body: Uint8Array,
								accept?: string
							): {
								body: Uint8Array;
								free(): void;
								request_id: string;
								transcript_sha256: string;
							};
							verify_bundle(bundle: Uint8Array): unknown;
						};
					};
				}
			).stogasVerifierBindings;
			const verifier = new api.Verifier();
			try {
				let verifyError: string | null = null;
				try {
					verifier.verify_bundle(new TextEncoder().encode(fixture));
				} catch (failure) {
					verifyError = String(failure);
				}
				let sealError: string | null = null;
				try {
					verifier.seal_e2ee_request(
						'/v1/responses',
						'sk-never-outer',
						new TextEncoder().encode('{"model":"gpt-5","input":"never-outer"}'),
						'application/json'
					);
				} catch (failure) {
					sealError = String(failure);
				}
				return { sealError, verifyError };
			} finally {
				verifier.free();
				Date.now = platformNow;
			}
		},
		{ fixture, now: STAGING_BUNDLE_NOW_UNIX_MS }
	);
	expect(result.verifyError).toContain('unsupported or invalid bundle');
	expect(result.sealError).toContain('bundle must be verified');
	expect(requests).toEqual([]);
});

test('rejects deterministic legacy mutations across the WASM bundle boundary', async ({ page }) => {
	const requests = await initialize(page);
	const fixture = await readFile(STAGING_BUNDLE_FIXTURE, 'utf8');
	const result = await page.evaluate(
		({ fixture, now }) => {
			const platformNow = Date.now;
			Date.now = () => now;
			const api = (
				globalThis as typeof globalThis & {
					stogasVerifierBindings: {
						Verifier: new () => {
							free(): void;
							verify_bundle(bundle: Uint8Array): unknown;
						};
					};
				}
			).stogasVerifierBindings;
			const original = new TextEncoder().encode(fixture);
			const verifier = new api.Verifier();
			let rejected = 0;
			try {
				for (let index = 0; index < 64; index += 1) {
					const mutation = original.slice();
					const position = (index * 421 + 17) % mutation.length;
					mutation[position] ^= 1;
					try {
						verifier.verify_bundle(mutation);
					} catch {
						rejected += 1;
					}
				}
				return { rejected };
			} finally {
				verifier.free();
				Date.now = platformNow;
			}
		},
		{ fixture, now: STAGING_BUNDLE_NOW_UNIX_MS }
	);
	expect(result).toEqual({ rejected: 64 });
	expect(requests).toEqual([]);
});
