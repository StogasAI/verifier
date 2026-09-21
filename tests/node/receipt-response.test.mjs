import assert from 'node:assert/strict';
import { test } from 'node:test';
import { verifyReceiptResponse } from '../../bindings/shared/receipt-response.js';

// Only HTTP ownership is mocked here. The Rust suite checks actual signatures,
// framing, retained hardware evidence and every fragmentation boundary.
function context() {
	let freed = 0;
	return {
		get freed() {
			return freed;
		},
		free() {
			freed++;
		},
		finish_buffered(bytes) {
			assert.equal(new TextDecoder().decode(bytes), 'body');
			return { metadata: { receipt: true } };
		},
		push_sse(bytes) {
			return [bytes];
		},
		finish_sse() {
			return { metadata: { receipt: true } };
		}
	};
}

test('unary verification owns its context once and failed HTTP responses do not require receipts', async () => {
	for (const status of [200, 400]) {
		const receipt = context();
		let metadata;
		const response = await verifyReceiptResponse(
			new Response('body', { status }),
			receipt,
			undefined,
			(value) => {
				metadata = value;
			}
		);
		assert.equal(await response.text(), 'body');
		assert.equal(receipt.freed, 1);
		assert.equal(metadata?.receipt, status === 200 ? true : undefined);
	}
});

test('stream completion waits for original receipt verification and reports post-execution failure without replay', async () => {
	for (const valid of [true, false]) {
		const receipt = context();
		let verified = 0;
		receipt.finish_sse = () => {
			verified++;
			if (!valid) throw new Error('altered content');
			return { metadata: { receipt: true } };
		};
		const response = await verifyReceiptResponse(
			new Response('data: complete', { headers: { 'content-type': 'text/event-stream' } }),
			receipt
		);
		assert.equal(verified, 0);
		if (valid) assert.equal(await response.text(), 'data: complete\n\n');
		else await assert.rejects(response.text(), (error) => error.submission === 'execution_unknown');
		assert.equal(verified, 1);
		assert.equal(receipt.freed, 1);
	}
});

test('cancel and unread abort release the retained receipt context and underlying stream', async () => {
	for (const abort of [true, false]) {
		let canceled = 0;
		const controller = new AbortController();
		const receipt = context();
		const source = new ReadableStream(
			{
				cancel() {
					canceled++;
				}
			},
			{ highWaterMark: 0 }
		);
		const response = await verifyReceiptResponse(
			new Response(source, { headers: { 'content-type': 'text/event-stream' } }),
			receipt,
			controller.signal
		);
		if (abort) {
			controller.abort();
			await new Promise((resolve) => setImmediate(resolve));
		} else await response.body.cancel();
		assert.equal(receipt.freed, 1);
		assert.equal(canceled, 1);
	}
});
