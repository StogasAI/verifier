import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
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
const NOW_UNIX_MS = 1_784_246_400_000;
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

test('ML-DSA publisher bindings verify independent Go signatures and erase key inputs', async ({
	page
}) => {
	const requests = await initialize(page);
	const fixture = JSON.parse(
		await readFile(resolve(ROOT, 'tests/fixtures/mldsa65-v1.json'), 'utf8')
	);
	fixture.sha512 = createHash('sha512').update(Buffer.from(fixture.message, 'hex')).digest('hex');
	const result = await page.evaluate((fixture) => {
		const api = (
			globalThis as unknown as {
				stogasVerifierBindings: typeof import('../../pkg/browser/stogas_verifier.js');
			}
		).stogasVerifierBindings;
		const bytes = (value: string) =>
			Uint8Array.from(value.match(/../g)!, (part) => Number.parseInt(part, 16));
		const hex = (value: Uint8Array) =>
			[...value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
		const message = bytes(fixture.message);
		const context = new TextEncoder().encode(fixture.context);
		const publicKey = bytes(fixture.spki);
		api.verify_mldsa65(publicKey, message, context, bytes(fixture.context_signature));
		const privateKey = bytes(fixture.pkcs8);
		const derived = api.mldsa65_public_key(privateKey);
		const derivedErased = privateKey.every((byte) => byte === 0);
		privateKey.set(bytes(fixture.pkcs8));
		const signature = api.sign_mldsa65(privateKey, message, context);
		api.verify_mldsa65(publicKey, message, context, signature);
		const signedErased = privateKey.every((byte) => byte === 0);
		let rejected = 0;
		try {
			api.verify_mldsa65(publicKey, message, new Uint8Array(), signature);
		} catch {
			rejected++;
		}
		const malformed = new Uint8Array([1, 2, 3]);
		try {
			api.sign_mldsa65(malformed, message, context);
		} catch {
			rejected++;
		}
		const failedErased = malformed.every((byte) => byte === 0);
		privateKey.set(bytes(fixture.pkcs8));
		const rekorPublicKey = api.rekor_public_key(privateKey);
		const rekorDerivedErased = privateKey.every((byte) => byte === 0);
		privateKey.set(bytes(fixture.pkcs8));
		const submission = JSON.parse(api.prepare_rekor_submission(privateKey, message));
		const rekorSignedErased = privateKey.every((byte) => byte === 0);
		return {
			publicKey: hex(derived),
			rekorPublicKey: hex(rekorPublicKey),
			rekorSignature: submission.spec.signature.content,
			rekorDerivedErased,
			rekorSignedErased,
			derivedErased,
			signedErased,
			failedErased,
			rejected,
			kind: submission.kind,
			digestMatches: submission.spec.data.hash.value === fixture.sha512
		};
	}, fixture);
	expect(result).toEqual({
		publicKey: fixture.spki,
		rekorPublicKey: fixture.rekor_spki,
		rekorSignature: Buffer.from(fixture.rekor_signature, 'hex').toString('base64'),
		rekorDerivedErased: true,
		rekorSignedErased: true,
		derivedErased: true,
		signedErased: true,
		failedErased: true,
		rejected: 2,
		kind: 'hashedrekord',
		digestMatches: true
	});
	expect(requests).toEqual([]);
});

test('browser boot history remains offline and separate from current evidence', async ({
	page
}) => {
	const requests = await initialize(page);
	const fixture = JSON.parse(
		await readFile(resolve(ROOT, 'tests/fixtures/hardware-session-v1.json'), 'utf8')
	);
	const evidence = Buffer.from(fixture.e2ee.response, 'base64url').subarray(1198);
	const start = 1186 + evidence.readUInt16BE(1184);
	const boot = evidence.subarray(start + 4, start + 4 + evidence.readUInt32BE(start));
	const proofStart = start + 4 + boot.length;
	const archive = {
		boot: JSON.parse(boot.toString()),
		inclusion: JSON.parse(evidence.subarray(proofStart + 4).toString()),
		evidence_sha256: fixture.bundle.body_sha256
	};
	const result = await page.evaluate(
		({ fixture, archive }) => {
			const api = (
				globalThis as unknown as {
					stogasVerifierBindings: typeof import('../../pkg/browser/stogas_verifier.js');
				}
			).stogasVerifierBindings;
			const core = new api.EvidenceVerifier(
				'staging',
				fixture.root.key_id,
				fixture.root.public_key
			);
			const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
			const previousNow = Date.now;
			Date.now = () => fixture.verified_at_ms + 366 * 24 * 60 * 60 * 1000;
			try {
				const verified = core.verify_boot_archive(encode(archive), encode(fixture.bundle));
				archive.evidence_sha256 = '0'.repeat(64);
				let rejected = false;
				try {
					core.verify_boot_archive(encode(archive), encode(fixture.bundle));
				} catch {
					rejected = true;
				}
				return { digest: verified.boot_sha256, rejected };
			} finally {
				core.free();
				Date.now = previousNow;
			}
		},
		{ fixture, archive }
	);
	expect(result).toEqual({
		digest: createHash('sha256').update(boot).digest('hex'),
		rejected: true
	});
	expect(requests).toEqual([]);
});

test('encrypted setup cannot release a browser session without its own verified exchange', async ({
	page
}) => {
	const requests = await initialize(page);
	const fixture = JSON.parse(
		await readFile(resolve(ROOT, 'tests/fixtures/hardware-session-v1.json'), 'utf8')
	);
	const result = await page.evaluate((fixture) => {
		const api = (
			globalThis as unknown as {
				stogasVerifierBindings: typeof import('../../pkg/browser/stogas_verifier.js');
			}
		).stogasVerifierBindings;
		const platformNow = Date.now;
		Date.now = () => fixture.verified_at_ms;
		const verifier = new api.EvidenceVerifier(
			'staging',
			fixture.root.key_id,
			fixture.root.public_key
		);
		let snapshot: InstanceType<typeof api.EvidenceSnapshot> | undefined;
		let pending: InstanceType<typeof api.EncryptedSetup> | undefined;
		let second: InstanceType<typeof api.EncryptedSetup> | undefined;
		try {
			snapshot = verifier.refresh(new TextEncoder().encode(JSON.stringify(fixture.bundle)));
			pending = new api.EncryptedSetup('staging');
			second = new api.EncryptedSetup('staging');
			const hello = pending.hello;
			const response = Uint8Array.from(
				atob(fixture.e2ee.response.replaceAll('-', '+').replaceAll('_', '/')),
				(value) => value.charCodeAt(0)
			);
			let rejected = 0;
			// The archived response has genuine hardware evidence, but belongs to another
			// client's hello. Neither that evidence nor malformed framing can create keys.
			for (const candidate of [
				response,
				response.slice(0, -1),
				new Uint8Array(),
				new Uint8Array(64 * 1024)
			]) {
				try {
					pending.complete(candidate, snapshot);
				} catch {
					rejected++;
				}
			}
			const secondHello = second.hello;
			const retainedHello = pending.hello;
			return {
				helloLength: hello.length,
				fresh: !hello.every((value: number, index: number) => value === secondHello[index]),
				retainedHello: hello.every(
					(value: number, index: number) => value === retainedHello[index]
				),
				noPrematureSeal: !('seal' in pending),
				rejected
			};
		} finally {
			pending?.free();
			second?.free();
			snapshot?.free();
			verifier.free();
			Date.now = platformNow;
		}
	}, fixture);
	expect(result).toEqual({
		helloLength: 1255,
		fresh: true,
		retainedHello: true,
		noPrematureSeal: true,
		rejected: 4
	});
	expect(requests).toEqual([]);
});

test('compiled staging authority verifies logged key decisions without network access', async ({
	page
}) => {
	const requests = await initialize(page);
	const signed = JSON.parse(
		await readFile(resolve(ROOT, 'tests/fixtures/staging-key-manifest.json'), 'utf8')
	);
	const result = await page.evaluate((signed) => {
		const api = (
			globalThis as unknown as {
				stogasVerifierBindings: typeof import('../../pkg/browser/stogas_verifier.js');
			}
		).stogasVerifierBindings;
		const core = api.EvidenceVerifier.for_stogas('staging');
		try {
			const keys = core.verify_key_manifest(new TextEncoder().encode(JSON.stringify(signed)));
			signed.manifest.generation++;
			let rejected = false;
			try {
				core.verify_key_manifest(new TextEncoder().encode(JSON.stringify(signed)));
			} catch {
				rejected = true;
			}
			return { key: keys.active_key.key_id, rejected };
		} finally {
			core.free();
		}
	}, signed);
	expect(result).toEqual({ key: signed.manifest.active_key.key_id, rejected: true });
	expect(requests).toEqual([]);
});

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
