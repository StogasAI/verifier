import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import init, { StogasTransport } from '../../bindings/browser/browser.js';

const wasm = await readFile(new URL('../../pkg/browser/stogas_verifier_bg.wasm', import.meta.url));
await init({ module_or_path: wasm });

assert.throws(() => new StogasTransport({ bundleRefreshIntervalSeconds: 0 }), /between 1 and 840/);
assert.throws(
	() => new StogasTransport({ bundleRefreshIntervalSeconds: 841 }),
	/between 1 and 840/
);
assert.throws(
	() =>
		new StogasTransport({
			baseURL: 'https://api.example/v1',
			bundleURL: 'https://evidence.example/bundles/latest.json',
			environment: 'staging'
		}),
	/restricted to the Stogas staging API/
);
const defaultTransport = new StogasTransport();
assert.deepEqual(defaultTransport.bundleURLs, [
	'https://evidence.stogas.ai/bundles/latest.json',
	'https://evidence2.stogas.ai/bundles/latest.json'
]);
assert.deepEqual(defaultTransport.bundleSnapshot, {
	bundle: null,
	bundleURL: null,
	envelopeSha256: null,
	error: null,
	fetchedAtUnixMs: null,
	status: 'idle',
	verificationDurationMs: null,
	verifiedAtUnixMs: null
});
defaultTransport.close();

const originalFetch = globalThis.fetch;
let defaultFetchReceiverMatches = false;
globalThis.fetch = function () {
	defaultFetchReceiverMatches = this === globalThis;
	return Promise.resolve(new Response(null, { status: 503 }));
};
const defaultFetchTransport = new StogasTransport();
try {
	await assert.rejects(defaultFetchTransport.refreshBundle(), /every evidence origin failed/);
	assert.equal(defaultFetchReceiverMatches, true);
} finally {
	defaultFetchTransport.close();
	globalThis.fetch = originalFetch;
}

const abortTransport = new StogasTransport({
	bundleURL: 'https://evidence.example/bundles/latest.json',
	fetch: async (_input, options = {}) =>
		new Promise((_resolve, reject) => {
			options.signal.addEventListener(
				'abort',
				() => reject(new DOMException('aborted', 'AbortError')),
				{ once: true }
			);
		})
});
const abortedRefresh = abortTransport.refreshBundle();
abortTransport.close();
await assert.rejects(abortedRefresh, /abort/i);

const attemptedOrigins = [];
const fallbackTransport = new StogasTransport({
	fetch: async (input) => {
		attemptedOrigins.push(new URL(input).host);
		return new Response(null, { status: 503 });
	}
});
try {
	await assert.rejects(fallbackTransport.refreshBundle(), /every evidence origin failed/);
	assert.equal(attemptedOrigins.length, 2);
	assert.deepEqual(
		new Set(attemptedOrigins),
		new Set(['evidence.stogas.ai', 'evidence2.stogas.ai'])
	);
} finally {
	fallbackTransport.close();
}

const fetch = async () => new Response(null, { status: 503 });
const transport = new StogasTransport({
	baseURL: 'https://api.example/v1',
	bundleRefreshIntervalSeconds: 300,
	bundleURL: 'https://evidence.example/bundles/latest.json',
	fetch
});
try {
	assert.deepEqual(transport.openAIOptions('sk-browser'), {
		apiKey: 'sk-browser',
		baseURL: 'https://api.example/v1',
		dangerouslyAllowBrowser: true,
		fetch: transport.fetch,
		maxRetries: 0
	});
	assert.throws(
		() => transport.verifyResponseProof(new Uint8Array(), new Uint8Array(), new Uint8Array()),
		/a bundle must be verified before a response proof/
	);
	assert.throws(() => transport.verifyNodeLedgerRecord(new Uint8Array()), /invalid bundle JSON/);
} finally {
	transport.close();
}

const browserSource = await readFile(
	new URL('../../bindings/browser/browser.js', import.meta.url),
	'utf8'
);
assert.doesNotMatch(
	browserSource,
	/'cache-control'\s*:\s*'no-store'/,
	'encrypted browser requests must not add a non-safelisted Cache-Control header'
);
const encryptedRequestOptions = browserSource.slice(
	browserSource.indexOf('body: session.body'),
	browserSource.indexOf('return decryptResponse')
);
assert.doesNotMatch(
	encryptedRequestOptions,
	/cache:\s*'no-store'/,
	'encrypted POSTs must not ask the browser to synthesize Cache-Control'
);
assert.doesNotMatch(
	browserSource,
	/cache:\s*'no-store'/,
	'bundle reads must preserve normal browser and shared-cache revalidation'
);
assert.doesNotMatch(
	browserSource,
	/#inFlightRequests/,
	'long-lived responses must not postpone bundle refresh'
);
assert.match(
	browserSource,
	/evidence2\.stogas\.ai\/bundles\/latest\.json/,
	'the production transport must include the independent evidence origin'
);
