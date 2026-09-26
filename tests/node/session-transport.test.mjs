import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SessionTransport } from '../../bindings/shared/session-transport.js';
import { SESSION_CONTENT_TYPE } from '../../bindings/shared/channel-http.js';
import { Exchange, record, response } from './channel-fixture.mjs';

function fixture({
	fetchResponse,
	maxSessions = 1,
	verify = () => {},
	request = () => {},
	fetchSetup
} = {}) {
	const cores = [];
	let setups = 0;
	let setupFreed = 0;
	let requests = 0;
	let closeRequests = 0;
	let snapshots = 1;
	let acquisitions = 0;
	const evidence = {
		check(check) {
			return check(snapshots);
		},
		async acquire(_signal, check = () => {}) {
			acquisitions++;
			snapshots++;
			return check(snapshots);
		}
	};
	class Setup {
		hello = new Uint8Array([99]);
		complete(bytes, snapshot) {
			verify(bytes, snapshot);
			const owner = {
				closed: false,
				freed: false,
				node_id: `node-${cores.length}`,
				idle_seconds: 10,
				request(snapshot) {
					assert.equal(this.closed, false);
					request(snapshot, this);
					return new Exchange();
				},
				close() {
					this.closed = true;
				},
				free() {
					assert.equal(this.freed, false);
					this.freed = true;
				}
			};
			cores.push(owner);
			return owner;
		}
		free() {
			setupFreed++;
		}
	}
	const transport = new SessionTransport({
		Setup,
		evidence,
		environment: 'staging',
		endpoint: 'https://e2ee.example/v1/session',
		maxSessions,
		fetch: async (url, options) => {
			assert.equal(url, 'https://e2ee.example/v1/session');
			assert.equal(options.headers.authorization, undefined);
			if (options.body instanceof Uint8Array) {
				setups++;
				assert.deepEqual([...options.body], [99]);
				assert.equal(options.headers['Stogas-Node-ID'], undefined);
				return fetchSetup
					? fetchSetup(options)
					: new Response(new Uint8Array([12]), {
							headers: { 'content-type': SESSION_CONTENT_TYPE }
						});
			}
			const bytes = new Uint8Array(await options.body.arrayBuffer());
			// The boundary double emits no DATA record for the authenticated close.
			if (bytes.length === 5) {
				closeRequests++;
				return response([record(1, '{"status":204,"headers":{}}'), record(3)]);
			}
			requests++;
			return fetchResponse
				? fetchResponse(options, requests)
				: response([
						record(1, '{"status":200,"headers":{"content-type":"application/json"}}'),
						record(2, '{"ok":true}'),
						record(3)
					]);
		}
	});
	return {
		transport,
		cores,
		get setups() {
			return setups;
		},
		get setupFreed() {
			return setupFreed;
		},
		get requests() {
			return requests;
		},
		get closeRequests() {
			return closeRequests;
		},
		get acquisitions() {
			return acquisitions;
		},
		send(signal) {
			return transport.send(
				new Request('https://e2ee.example/v1/chat/completions', {
					method: 'POST',
					headers: { authorization: 'Bearer private-key' },
					body: '{}',
					signal
				})
			);
		}
	};
}

test('concurrent requests share one verified setup and explicit close sends one authenticated disposal', async () => {
	const state = fixture();
	const results = await Promise.all(
		Array.from({ length: 20 }, async () => (await state.send()).json())
	);
	assert.deepEqual(results, Array(20).fill({ ok: true }));
	assert.equal(state.setups, 1);
	assert.equal(state.setupFreed, 1);
	assert.equal(state.requests, 20);
	assert.equal(state.cores[0].freed, false);
	await state.transport.close();
	await state.transport.close();
	assert.equal(state.closeRequests, 1);
	assert.equal(state.cores[0].freed, true);
	await assert.rejects(state.send(), { submission: 'not_sent' });
});

test('canceling the first waiter preserves shared setup for another request', async () => {
	let markReady, finishSetup;
	const ready = new Promise((resolve) => {
		markReady = resolve;
	});
	const setup = new Promise((resolve) => {
		finishSetup = resolve;
	});
	let setupSignal;
	const state = fixture({
		fetchSetup: ({ signal }) => {
			setupSignal = signal;
			markReady();
			return setup;
		}
	});
	const controller = new AbortController();
	const first = state.send(controller.signal);
	const rejected = assert.rejects(first, { submission: 'not_sent' });
	await ready;
	const second = state.send();
	controller.abort();
	await rejected;
	assert.equal(setupSignal.aborted, false);
	finishSetup(
		new Response(new Uint8Array([12]), { headers: { 'content-type': SESSION_CONTENT_TYPE } })
	);
	assert.deepEqual(await (await second).json(), { ok: true });
	assert.equal(state.setups, 1);
	assert.equal(state.requests, 1);
	assert.equal(state.setupFreed, 1);
	await state.transport.close();
});

test('idle hints renew unsent work; an active stream keeps its session alive', async () => {
	const originalNow = Date.now;
	let now = 100_000;
	Date.now = () => now;
	try {
		const state = fixture();
		const active = await state.send();
		now += 20_000;
		await (await state.send()).text();
		assert.equal(state.setups, 1);
		await active.text();
		now += 10_001;
		await (await state.send()).text();
		assert.equal(state.setups, 2);
		assert.equal(state.cores[0].freed, true);
		await state.transport.close();
	} finally {
		Date.now = originalNow;
	}
});

test('evidence recovery verifies the same setup before any application credentials leave', async () => {
	let verified = 0;
	const state = fixture({
		verify(bytes, snapshot) {
			verified++;
			assert.deepEqual([...bytes], [12]);
			if (snapshot === 1)
				throw Object.assign(new Error('missing release'), { name: 'EvidenceVerificationError' });
		}
	});
	await (await state.send()).text();
	assert.equal(state.setups, 1);
	assert.equal(state.requests, 1);
	assert.equal(state.acquisitions, 1);
	assert.equal(verified, 2);
	await state.transport.close();
});

test('invalid setup possession fails closed without refreshing or sending inference', async () => {
	const state = fixture({
		verify() {
			throw new Error('invalid confirmation');
		}
	});
	await assert.rejects(state.send(), { submission: 'not_sent' });
	assert.equal(state.requests, 0);
	assert.equal(state.acquisitions, 0);
	assert.equal(state.setupFreed, 1);
	await state.transport.close();
});

test('a lost request is never retried; subsequent new work establishes another owner', async () => {
	const state = fixture({
		fetchResponse: async (_options, count) =>
			count === 1
				? new Response(null, { status: 503 })
				: response([record(1, '{"status":200,"headers":{}}'), record(3)])
	});
	await assert.rejects(state.send(), { submission: 'execution_unknown' });
	assert.equal(state.requests, 1);
	await (await state.send()).text();
	assert.equal(state.requests, 2);
	assert.equal(state.setups, 2);
	assert.equal(state.cores[0].freed, true);
	await state.transport.close();
});

test('midstream failure retires only future use while admitted responses keep their keys', async () => {
	const state = fixture({
		fetchResponse: async (_options, count) =>
			count === 2
				? response([record(1, '{"status":200,"headers":{}}'), record(2, 'partial')])
				: response([record(1, '{"status":200,"headers":{}}'), record(3)])
	});
	const first = await state.send();
	const broken = await state.send();
	await assert.rejects(broken.text(), { submission: 'execution_unknown' });
	assert.equal(state.cores[0].closed, true);
	assert.equal(state.cores[0].freed, false);
	await (await state.send()).text();
	assert.equal(state.setups, 2);
	await first.text();
	assert.equal(state.cores[0].freed, true);
	await state.transport.close();
});

test('session growth follows actual replay-window pressure and honors the caller maximum', async () => {
	const pending = new Set();
	const state = fixture({
		maxSessions: 2,
		request(_snapshot, owner) {
			if (pending.has(owner.node_id))
				throw Object.assign(new Error('pending'), {
					name: 'EncryptedChannelError',
					code: 'pending'
				});
		}
	});
	await (await state.send()).text();
	pending.add('node-0');
	await (await state.send()).text();
	assert.equal(state.setups, 2);
	pending.add('node-1');
	await assert.rejects(state.send(), { submission: 'not_sent' });
	assert.equal(state.requests, 2);
	assert.equal(state.setups, 2);
	pending.clear();
	await state.transport.close();
});

test('close aborts a pending setup and never releases application bytes', async () => {
	let aborted = 0;
	let started;
	const ready = new Promise((resolve) => {
		started = resolve;
	});
	const state = fixture({
		fetchSetup: ({ signal }) =>
			new Promise((_resolve, reject) => {
				signal.addEventListener(
					'abort',
					() => {
						aborted++;
						reject(signal.reason);
					},
					{ once: true }
				);
				started();
			})
	});
	const waiting = state.send();
	await ready;
	await state.transport.close();
	await assert.rejects(waiting, { submission: 'not_sent' });
	assert.equal(aborted, 1);
	assert.equal(state.requests, 0);
	assert.equal(state.setupFreed, 1);
});
