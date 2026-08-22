import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import init, { StogasTransport } from '../../bindings/browser/browser.js';

const wasm = await readFile(new URL('../../pkg/browser/stogas_verifier_bg.wasm', import.meta.url));
await init({ module_or_path: wasm });

assert.throws(
	() => new StogasTransport({ bundleRefreshIntervalSeconds: 0 }),
	/positive safe integer/
);
assert.throws(
	() => new StogasTransport({ bundleRefreshIntervalSeconds: Number.MAX_SAFE_INTEGER + 1 }),
	/positive safe integer/
);
new StogasTransport({ bundleRefreshIntervalSeconds: 86_400 }).close();
for (const options of [
	{ baseURL: 'https://api.example/v1?' },
	{ baseURL: 'https://api.example/v1#' },
	{ bundleURL: 'https://evidence.example/bundles/latest.json?' },
	{ bundleURL: 'https://evidence.example/bundles/latest.json#' }
]) {
	assert.throws(() => new StogasTransport(options), /without credentials|HTTPS origin/);
}
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

let passThroughOptions;
const passThroughTransport = new StogasTransport({
	baseURL: 'https://api.example/v1',
	bundleURL: 'https://evidence.example/bundles/latest.json',
	fetch: async (_input, options) => {
		passThroughOptions = options;
		return new Response(null, { status: 204 });
	}
});
try {
	await passThroughTransport.fetch('https://api.example/v1/models', {
		headers: { authorization: 'Bearer secret' }
	});
	assert.equal(passThroughOptions.redirect, 'error');
} finally {
	passThroughTransport.close();
}

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
const bundleRequestOptions = [];
const fallbackTransport = new StogasTransport({
	fetch: async (input, options = {}) => {
		attemptedOrigins.push(new URL(input).host);
		bundleRequestOptions.push(options);
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
	assert.equal(
		bundleRequestOptions.every((options) => options.cache === undefined),
		true
	);
	assert.equal(
		bundleRequestOptions.every((options) => !new Headers(options.headers).has('cache-control')),
		true
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
	assert.throws(
		() => transport.createResponseProofStream(new Uint8Array()),
		/a bundle must be verified before a response proof/
	);
	assert.throws(() => transport.verifyNodeLedgerRecord(new Uint8Array()), /invalid bundle JSON/);
	assert.throws(() => transport.verifyReleaseApproval(new Uint8Array()), /invalid bundle JSON/);
	assert.throws(() => transport.verifyCatalogApproval(new Uint8Array()), /invalid bundle JSON/);
} finally {
	transport.close();
}

let subscriberFetches = 0;
let subscriberCalls = 0;
const subscriberTransport = new StogasTransport({
	bundleURL: 'https://evidence.example/bundles/latest.json',
	fetch: async () => {
		subscriberFetches += 1;
		return new Response(null, { status: 503 });
	}
});
subscriberTransport.subscribe(() => {
	subscriberCalls += 1;
	if (subscriberCalls > 1) throw new Error('consumer listener failed');
});
try {
	await assert.rejects(subscriberTransport.refreshBundle(), /every evidence origin failed/);
	assert.equal(subscriberFetches, 1, 'a listener exception must not stop evidence retrieval');
	assert.equal(subscriberCalls, 2, 'a failing listener must be removed after its first failure');
} finally {
	subscriberTransport.close();
}

const browserSource = await readFile(
	new URL('../../bindings/browser/browser.js', import.meta.url),
	'utf8'
);
assert.doesNotMatch(
	browserSource,
	/bundle\.sequence\s*[<=>]/,
	'an unsigned bundle sequence must not control refresh activation'
);
assert.match(
	browserSource,
	/if \(raw === null\) return false;/,
	'response fields must remain opt-in when the header is absent'
);
assert.match(
	browserSource,
	/the verified fleet is unavailable/,
	'a verified empty trust set must fail inference without invalidating the transport'
);
assert.match(
	browserSource,
	/status: candidate\.output\.bundle\.nodes\.length === 0 \? 'unavailable' : 'ready'/,
	'a verified empty trust set must be exposed as unavailable'
);
assert.match(
	browserSource,
	/unavailableCandidates === urls\.length/,
	'an active non-empty trust set must require empty candidates from both official origins'
);
assert.match(
	browserSource,
	/this\.#verifyBundle\(this\.#candidateCore, candidate\.bytes\)/,
	'candidate verification must not mutate the active request verifier'
);
assert.match(
	browserSource,
	/core\.verify_bundle_with_policy\(bundle, this\.#hardwarePolicy\)/,
	'a caller-owned hardware policy must use the isolated verification path'
);
assert.match(
	browserSource,
	/core\.verify_bundle\(bundle\)/,
	'the signed bundle policy must remain the default'
);
assert.match(browserSource, /DEFAULT_REFRESH_SECONDS = 300/);
assert.match(browserSource, /REFRESH_INTERVAL_JITTER_MIN_PERCENT = 90/);
assert.match(browserSource, /REFRESH_INTERVAL_JITTER_MAX_PERCENT = 110/);
assert.match(browserSource, /jitteredRefreshIntervalMs\(this\.#refreshIntervalMs\)/);
