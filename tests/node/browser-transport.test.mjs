import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createTransportClass } from '../../bindings/shared/transport.js';

// Lifecycle doubles; cryptographic checks use the real Wasm core in browser tests.
function binding() {
	let freed = 0;
	const Transport = createTransportClass({
		transport_configuration(environment) {
			assert.equal(environment, 'prod');
			return {
				environment,
				e2ee_origin: 'https://e2ee.example',
				evidence_origins: ['https://r2.example/bundle', 'https://aws.example/bundle']
			};
		},
		EvidenceVerifier: class {
			static for_stogas() {
				return new this();
			}
			refresh(bytes) {
				assert.equal(new TextDecoder().decode(bytes), '{}');
				return {
					summary: () => ({ approvals: { revision: 1 } }),
					require_current_keys() {},
					free() {}
				};
			}
			free() {
				freed++;
			}
		},
		EncryptedSetup: class {}
	});
	return {
		Transport,
		get freed() {
			return freed;
		}
	};
}

test('options are explicit and confidential fetch never falls through to ordinary requests', async () => {
	const { Transport } = binding();
	for (const options of [
		{ maxConnections: 0 },
		{ maxConnections: 1.5 },
		{ maxConnections: Infinity },
		{ bundleRefreshIntervalSeconds: 300 },
		{ security: 'both' }
	])
		assert.throws(() => new Transport(options), /Unsupported|positive safe integer/);
	for (const baseURL of [
		'http://e2ee.example/v1',
		'https://user@e2ee.example/v1',
		'https://e2ee.example/v1?',
		'https://e2ee.example/v1#',
		'https://e2ee.example/other'
	])
		assert.throws(() => new Transport({ baseURL }), /HTTPS/);
	let calls = 0;
	const transport = new Transport({
		fetch: async () => {
			calls++;
			throw new Error('must not send');
		}
	});
	for (const url of [
		'https://unrelated.example/v1/chat/completions',
		'https://e2ee.example/v1/models',
		'https://e2ee.example/v1/files',
		'https://e2ee.example/v1/chat/completions?key=secret'
	])
		await assert.rejects(
			transport.fetch(url, {
				method: 'POST',
				headers: { authorization: 'Bearer secret' },
				body: '{}'
			}),
			(error) => error.submission === 'not_sent'
		);
	await assert.rejects(
		transport.fetch('https://e2ee.example/v1/chat/completions'),
		(error) => error.submission === 'not_sent'
	);
	assert.equal(calls, 0);
	const options = transport.openAIOptions('secret');
	assert.equal(options.baseURL, 'https://e2ee.example/v1');
	assert.equal(options.maxRetries, 0);
	assert.equal(options.fetch, transport.fetch);
	await transport.close();
	await assert.rejects(
		transport.fetch('https://e2ee.example/v1/chat/completions', { method: 'POST' }),
		(error) => error.submission === 'not_sent'
	);
});

test('explicit refresh shares acquisition, exposes copied evidence, and isolates failed observers', async () => {
	const fixture = binding();
	const attempts = [];
	const transport = new fixture.Transport({
		fetch: async (url, options) => {
			attempts.push(url);
			assert.equal(options.credentials, 'omit');
			assert.equal(options.redirect, 'error');
			assert.equal(new Headers(options.headers).has('authorization'), false);
			return url.includes('r2') ? new Response(null, { status: 503 }) : new Response('{}');
		}
	});
	let observed = 0;
	transport.subscribe(() => {
		observed++;
		if (observed > 1) throw new Error('observer');
	});
	const [first, second] = await Promise.all([transport.refreshBundle(), transport.refreshBundle()]);
	assert.deepEqual(first, second);
	assert.deepEqual(attempts, ['https://r2.example/bundle', 'https://aws.example/bundle']);
	assert.equal(observed, 2);
	const snapshot = transport.bundleSnapshot;
	assert.equal(snapshot.status, 'ready');
	snapshot.bundle.approvals.revision = 999;
	assert.equal(transport.bundleSnapshot.bundle.approvals.revision, 1);
	assert.deepEqual(transport.bundleURLs, attempts);
	await transport.close();
	await transport.close();
	assert.equal(fixture.freed, 1);
});

test('disposal aborts acquisition and failed creation frees the compiled verifier', async () => {
	const fixture = binding();
	let started;
	const waiting = new Promise((resolve) => {
		started = resolve;
	});
	let aborted = false;
	const transport = new fixture.Transport({
		fetch: (_url, options) =>
			new Promise((_resolve, reject) => {
				options.signal.addEventListener(
					'abort',
					() => {
						aborted = true;
						reject(options.signal.reason);
					},
					{ once: true }
				);
				started();
			})
	});
	const refresh = transport.refreshBundle();
	await waiting;
	await transport.close();
	await assert.rejects(refresh, /closed/i);
	assert.equal(aborted, true);
	assert.equal(fixture.freed, 1);
	await assert.rejects(
		fixture.Transport.create({ fetch: async () => new Response(null, { status: 503 }) }),
		/503/
	);
	assert.equal(fixture.freed, 2);
});
