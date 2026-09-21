import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SESSION_CONTENT_TYPE, sendSessionRequest } from '../../bindings/shared/channel-http.js';

import { readBoundedBody } from '../../bindings/shared/http.js';

import { Exchange, record, response } from './channel-fixture.mjs';

const header = { status: 200, headers: { 'Content-Type': 'text/event-stream' } };

function fixture(options = {}) {
	const exchange = new Exchange();
	let releases = 0;
	let calls = 0;
	const request = new Request('https://e2ee.example/v1/chat/completions', {
		method: 'POST',
		headers: { authorization: 'Bearer private-key', 'content-type': 'application/json' },
		body: '{"messages":[]}'
	});
	return {
		exchange,
		get releases() {
			return releases;
		},
		get calls() {
			return calls;
		},
		send(extra = {}) {
			return sendSessionRequest({
				exchange,
				nodeID: 'test-owner',
				endpoint: 'https://e2ee.example/v1/session',
				request,
				fetch: async (...args) => {
					calls++;
					return options.fetch(...args);
				},
				release: () => {
					releases++;
				},
				...extra
			});
		}
	};
}

test('binary HTTP keeps credentials inside the first record and streams across arbitrary Fetch boundaries', async () => {
	for (const split of [1, 3, 65_536, 0]) {
		let sent;
		const state = fixture({
			fetch: async (url, init) => {
				sent = { url, init };
				return response(
					[
						record(1, JSON.stringify(header)),
						record(4),
						record(2, 'data: hello\n\ndata: [DONE]\n\n'),
						record(3)
					],
					{ split }
				);
			}
		});
		const result = await state.send();
		assert.equal(await result.text(), 'data: hello\n\ndata: [DONE]\n\n');
		assert.equal(result.headers.get('content-type'), 'text/event-stream');
		assert.equal(sent.url, 'https://e2ee.example/v1/session');
		assert.deepEqual(sent.init.headers, {
			'content-type': SESSION_CONTENT_TYPE,
			accept: SESSION_CONTENT_TYPE,
			'Stogas-Node-ID': 'test-owner'
		});
		assert.equal(sent.init.credentials, 'omit');
		assert.equal(sent.init.redirect, 'error');
		assert.ok(sent.init.body instanceof Blob);
		assert.deepEqual([...new Uint8Array(await sent.init.body.arrayBuffer())], [7, 8, 9, 1, 2, 3]);
		assert.equal(
			JSON.parse(new TextDecoder().decode(state.exchange.sealed[0].bytes)).headers.authorization,
			'Bearer private-key'
		);
		assert.equal(state.exchange.freed, 1);
		assert.equal(state.releases, 1);
	}
});

test('malformed, missing and trailing completion fail without replaying the request', async () => {
	for (const records of [
		[],
		[record(1, JSON.stringify(header)), record(2, 'partial')],
		[record(1, JSON.stringify(header)), record(3), record(2, 'late')],
		[record(1, JSON.stringify(header)), record(1, JSON.stringify(header)), record(3)],
		[record(1, '{"status":200,"headers":{"Set-Cookie":"private"}}'), record(3)],
		[record(1, '{"status":200,"headers":{"content-type":"a","Content-Type":"b"}}'), record(3)],
		[record(1, '{"status":101,"headers":{}}'), record(3)]
	]) {
		const state = fixture({ fetch: async () => response(records) });
		await assert.rejects(
			async () => {
				const result = await state.send();
				await result.text();
			},
			{ submission: 'execution_unknown' }
		);
		assert.equal(state.calls, 1);
		assert.equal(state.exchange.freed, 1);
		assert.equal(state.releases, 1);
	}
});

test('outer errors and lost connections never claim nonexecution', async () => {
	for (const fetch of [
		async () => new Response('retry', { status: 503 }),
		async () => {
			throw new TypeError('network lost');
		}
	]) {
		const state = fixture({ fetch });
		await assert.rejects(state.send(), { submission: 'execution_unknown' });
		assert.equal(state.calls, 1);
		assert.equal(state.releases, 1);
	}
});

test('an aborted unsent request never reaches Fetch', async () => {
	const state = fixture({
		fetch: async () => {
			throw new Error('unexpected fetch');
		}
	});
	const abort = new AbortController();
	abort.abort();
	await assert.rejects(state.send({ signal: abort.signal }), { submission: 'not_sent' });
	assert.equal(state.calls, 0);
	assert.equal(state.releases, 1);
});

test('upload cancellation releases a stalled body before submission', async () => {
	const abort = new AbortController();
	let cancelled = 0;
	const request = new Request('https://e2ee.example/v1/responses', {
		method: 'POST',
		duplex: 'half',
		body: new ReadableStream({
			cancel() {
				cancelled++;
			}
		})
	});
	const state = fixture({
		fetch: async () => {
			throw new Error('unexpected fetch');
		}
	});
	const sending = state.send({ request, signal: abort.signal });
	await new Promise((resolve) => setImmediate(resolve));
	abort.abort();
	await assert.rejects(sending, { submission: 'not_sent' });
	assert.equal(cancelled, 1);
	assert.equal(state.exchange.freed, 1);
	assert.equal(state.calls, 0);
});

test('response cancellation releases its cipher without waiting for server EOF', async () => {
	let cancelled = 0;
	const state = fixture({
		fetch: async () =>
			new Response(
				new ReadableStream({
					start(controller) {
						controller.enqueue(record(1, JSON.stringify(header)));
					},
					cancel() {
						cancelled++;
					}
				}),
				{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
			)
	});
	const result = await state.send();
	assert.equal(state.releases, 0);
	await result.body.cancel();
	assert.equal(cancelled, 1);
	assert.equal(state.exchange.freed, 1);
	assert.equal(state.releases, 1);
});

test('response-body abort interrupts a stalled read and retains execution ambiguity', async () => {
	const abort = new AbortController();
	let cancelled = 0;
	const state = fixture({
		fetch: async () =>
			new Response(
				new ReadableStream({
					start(controller) {
						controller.enqueue(record(1, JSON.stringify(header)));
					},
					cancel() {
						cancelled++;
					}
				}),
				{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
			)
	});
	const result = await state.send({ signal: abort.signal });
	const body = result.text();
	await new Promise((resolve) => setImmediate(resolve));
	abort.abort();
	await assert.rejects(body, { submission: 'execution_unknown' });
	assert.equal(cancelled, 1);
	assert.equal(state.releases, 1);
});

test('large source chunks split into bounded records without base64', async () => {
	const state = fixture({
		fetch: async () =>
			response([record(1, JSON.stringify({ status: 204, headers: {} })), record(3)])
	});
	const request = new Request('https://e2ee.example/v1/chat/completions', {
		method: 'POST',
		body: new Uint8Array(200_000)
	});
	const result = await state.send({ request });
	assert.equal(result.status, 204);
	assert.equal(result.body, null);
	assert.deepEqual(
		state.exchange.sealed.filter((entry) => entry.kind === 2).map((entry) => entry.bytes.length),
		[65_515, 65_515, 65_515, 3_455]
	);
	assert.equal(state.releases, 1);
});

test('bodyless statuses still require authenticated completion and reject body data', async () => {
	for (const tail of [[], [record(2, 'unexpected'), record(3)]]) {
		const state = fixture({
			fetch: async () =>
				response([record(1, JSON.stringify({ status: 204, headers: {} })), ...tail])
		});
		await assert.rejects(state.send(), { submission: 'execution_unknown' });
		assert.equal(state.releases, 1);
	}
});

test('bounded downloads enforce decoded bytes and abort physical readers', async () => {
	for (const headers of [{}, { 'content-length': '2' }, { 'content-length': '100' }]) {
		await assert.rejects(
			readBoundedBody(new Response(new Uint8Array(10), { headers }), 5),
			/byte limit/
		);
	}
	const abort = new AbortController();
	let cancelled = 0;
	const reading = readBoundedBody(
		new Response(
			new ReadableStream({
				cancel() {
					cancelled++;
				}
			})
		),
		10,
		abort.signal
	);
	abort.abort();
	await assert.rejects(reading, { name: 'AbortError' });
	assert.equal(cancelled, 1);
});

test('abort cleans up even when the caller never reads the response body', async () => {
	const abort = new AbortController();
	let cancelled = 0;
	const state = fixture({
		fetch: async () =>
			new Response(
				new ReadableStream({
					start(controller) {
						controller.enqueue(record(1, JSON.stringify(header)));
					},
					cancel() {
						cancelled++;
					}
				}),
				{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
			)
	});
	const result = await state.send({ signal: abort.signal });
	abort.abort();
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(cancelled, 1);
	assert.equal(state.releases, 1);
	await assert.rejects(result.text(), { submission: 'execution_unknown' });
	assert.equal(state.exchange.freed, 1);
});
