import { abortableReader, readBoundedBody, TransportError } from './http.js';

const MAX_BUFFERED_RESPONSE = 64 * 1024 * 1024 + 8 * 1024 + 16;
const TERMINAL_DELIMITER = new Uint8Array([10, 10]);

// This only verifies the already-executed response. It never sends a request or
// consults a newer catalog in place of the original request's boot appraisal.
export async function verifyReceiptResponse(response, receipt, signal, onMetadata = () => {}) {
	let freed = false;
	const dispose = () => {
		if (freed) return;
		freed = true;
		receipt.free();
	};
	const fail = (cause) =>
		new TransportError('Response receipt verification failed', 'execution_unknown', cause);
	if (!response.ok) {
		dispose();
		return response;
	}
	if (!response.headers.get('content-type')?.toLowerCase().startsWith('text/event-stream')) {
		try {
			const bytes = await readBoundedBody(response, MAX_BUFFERED_RESPONSE, signal);
			const verified = receipt.finish_buffered(bytes);
			onMetadata(verified.metadata);
			return new Response(bytes, { status: response.status, headers: response.headers });
		} catch (error) {
			throw fail(error);
		} finally {
			dispose();
		}
	}
	if (!response.body) {
		dispose();
		throw fail(new Error('stream body is unavailable'));
	}
	const reader = abortableReader(response.body, signal);
	let closed = false;
	const cleanup = () => {
		if (closed) return;
		closed = true;
		signal?.removeEventListener('abort', abort);
		reader.release();
		dispose();
	};
	const abort = () => {
		void reader.cancel(signal.reason).then(cleanup);
	};
	signal?.addEventListener('abort', abort, { once: true });
	if (signal?.aborted) abort();
	return new Response(
		new ReadableStream(
			{
				async pull(controller) {
					try {
						signal?.throwIfAborted();
						for (;;) {
							const next = await reader.read();
							if (next.done) {
								const verified = receipt.finish_sse();
								onMetadata(verified.metadata);
								controller.enqueue(TERMINAL_DELIMITER);
								controller.close();
								cleanup();
								return;
							}
							let emitted = false;
							for (const bytes of receipt.push_sse(next.value)) {
								if (bytes.byteLength) {
									controller.enqueue(bytes);
									emitted = true;
								}
							}
							if (emitted) return;
						}
					} catch (error) {
						await reader.cancel(error);
						cleanup();
						controller.error(fail(error));
					}
				},
				async cancel(reason) {
					await reader.cancel(reason);
					cleanup();
				}
			},
			{ highWaterMark: 0 }
		),
		{ status: response.status, headers: response.headers }
	);
}
