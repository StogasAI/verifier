import { abortableReader, TransportError } from './http.js';
import { verifyReceiptResponse } from './receipt-response.js';

// HTTP owns delivery; the Rust core owns verification, record keys and counters.
export const SESSION_CONTENT_TYPE = 'application/vnd.stogas.session';
export const MAX_SETUP_RESPONSE_BYTES = 62_638;
const MAX_RECORD_PAYLOAD = 65_515;
const MAX_METADATA_BYTES = 16 * 1024;
const MAX_REQUEST_BYTES = 128 * 1024 * 1024;
const EMPTY = new Uint8Array();
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

async function encodeRequest(exchange, request, signal) {
	const url = new URL(request.url);
	if (url.search || url.hash)
		throw new Error('encrypted requests cannot contain a query or fragment');
	const headers = Object.fromEntries(request.headers);
	// Fetch may add a body length. HTTP framing belongs to the outer exchange.
	delete headers['content-length'];
	const metadata = encoder.encode(
		JSON.stringify({
			method: request.method,
			path: url.pathname,
			headers
		})
	);
	if (metadata.byteLength > MAX_METADATA_BYTES)
		throw new Error('request headers exceed their byte limit');
	const parts = [exchange.prefix, exchange.seal(1, metadata)];
	let size = 0;
	if (request.body) {
		const reader = abortableReader(request.body, signal);
		try {
			if (Number(request.headers.get('content-length')) > MAX_REQUEST_BYTES) {
				throw new Error('request exceeds its byte limit');
			}
			for (;;) {
				const { value, done } = await reader.read();
				if (done) break;
				if (!(value instanceof Uint8Array) || value.byteLength > MAX_REQUEST_BYTES - size) {
					throw new Error('request exceeds its byte limit');
				}
				size += value.byteLength;
				for (let offset = 0; offset < value.byteLength; offset += MAX_RECORD_PAYLOAD) {
					parts.push(exchange.seal(2, value.subarray(offset, offset + MAX_RECORD_PAYLOAD)));
				}
			}
		} catch (error) {
			await reader.cancel(error);
			throw error;
		} finally {
			reader.release();
		}
	}
	parts.push(exchange.seal(3, EMPTY));
	// A Blob works in browsers without streaming-upload support. Its contents are
	// only ciphertext; do not concatenate or base64-encode the complete request.
	return new Blob(parts, { type: SESSION_CONTENT_TYPE });
}

function responseMetadata(bytes) {
	if (bytes.byteLength > MAX_METADATA_BYTES)
		throw new Error('response headers exceed their byte limit');
	const value = JSON.parse(decoder.decode(bytes));
	if (
		!value ||
		typeof value !== 'object' ||
		Array.isArray(value) ||
		Object.keys(value).some((key) => key !== 'status' && key !== 'headers') ||
		!Number.isInteger(value.status) ||
		value.status < 200 ||
		value.status > 599 ||
		!value.headers ||
		typeof value.headers !== 'object' ||
		Array.isArray(value.headers)
	) {
		throw new Error('invalid encrypted response metadata');
	}
	const headers = new Headers();
	for (const [name, content] of Object.entries(value.headers)) {
		if (
			!['content-type', 'cache-control', 'retry-after'].includes(name.toLowerCase()) ||
			typeof content !== 'string' ||
			headers.has(name)
		) {
			throw new Error('invalid encrypted response header');
		}
		headers.set(name, content);
	}
	return { status: value.status, headers };
}

// No delivery failure in this function retries an inference. The returned
// Response owns the exchange until authenticated EOF, cancellation or failure.
export async function sendSessionRequest({
	exchange,
	nodeID,
	endpoint,
	request,
	fetch,
	signal = request.signal,
	release = () => {},
	failed = () => {},
	onMetadata = () => {}
}) {
	let submitted = false;
	let reader;
	let released = false;
	let abortResponse;
	let receipt;
	const cleanup = () => {
		if (released) return;
		released = true;
		if (abortResponse) signal?.removeEventListener('abort', abortResponse);
		reader?.release();
		exchange.free();
		release();
	};
	const failure = (error) => {
		if (submitted) failed(error);
		return new TransportError(
			'Encrypted request failed',
			submitted ? 'execution_unknown' : 'not_sent',
			error
		);
	};
	try {
		signal?.throwIfAborted();
		const body = await encodeRequest(exchange, request, signal);
		if (request.headers.get('Stogas-Metadata') === 'v1') receipt = exchange.response_receipt();
		signal?.throwIfAborted();
		submitted = true;
		const outer = await fetch(endpoint, {
			method: 'POST',
			body,
			credentials: 'omit',
			redirect: 'error',
			headers: {
				'content-type': SESSION_CONTENT_TYPE,
				accept: SESSION_CONTENT_TYPE,
				'Stogas-Node-ID': nodeID
			},
			signal
		});
		if (
			outer.status !== 200 ||
			outer.headers.get('content-type') !== SESSION_CONTENT_TYPE ||
			!outer.body
		) {
			await outer.body?.cancel().catch(() => {});
			throw new Error('origin did not return an encrypted response');
		}
		reader = abortableReader(outer.body, signal);
		abortResponse = () => {
			void reader.cancel(signal.reason).then(cleanup);
		};
		signal?.addEventListener('abort', abortResponse, { once: true });
		if (signal?.aborted) abortResponse();
		let metadata;
		let pending = [];
		let input = EMPTY;
		let inputOffset = 0;
		let finished = false;
		const emit = (kind, content) => {
			if (kind === 1) {
				if (metadata) throw new Error('duplicate encrypted response metadata');
				metadata = responseMetadata(content);
			} else if (kind === 2) {
				if (!metadata || [204, 205, 304].includes(metadata.status))
					throw new Error('unexpected encrypted response body');
				pending.push(content);
			}
		};
		const advance = async () => {
			if (inputOffset === input.byteLength) {
				const next = await reader.read();
				if (next.done) {
					exchange.finish(); // Finished alone is insufficient: also consume outer EOF.
					finished = true;
					cleanup();
					return;
				}
				if (!(next.value instanceof Uint8Array)) throw new Error('invalid response bytes');
				input = next.value;
				inputOffset = 0;
			}
			// Limit copied plaintext per pull even when Fetch delivers a large chunk.
			const end = Math.min(inputOffset + 65_536, input.byteLength);
			exchange.push(input.subarray(inputOffset, end), emit);
			inputOffset = end;
		};
		while (!metadata && !finished) await advance();
		if (!metadata) throw new Error('encrypted response ended before metadata');
		if ([204, 205, 304].includes(metadata.status)) {
			while (!finished) await advance();
			if (receipt) throw new Error('receipt response has no content');
			return new Response(null, metadata);
		}
		const response = new Response(
			new ReadableStream(
				{
					async pull(controller) {
						try {
							signal?.throwIfAborted();
							while (pending.length === 0 && !finished) await advance();
							if (pending.length) {
								// One bounded decoder pass can produce several small records.
								for (const bytes of pending) controller.enqueue(bytes);
								pending = [];
							} else {
								controller.close();
							}
						} catch (error) {
							await reader.cancel(error);
							cleanup();
							controller.error(failure(error));
						}
					},
					async cancel(reason) {
						await reader.cancel(reason);
						cleanup();
					}
				},
				{ highWaterMark: 0 }
			),
			metadata
		);
		if (!receipt) return response;
		const ownedReceipt = receipt;
		receipt = undefined;
		return await verifyReceiptResponse(response, ownedReceipt, signal, onMetadata);
	} catch (error) {
		receipt?.free();
		await reader?.cancel(error);
		cleanup();
		throw failure(error);
	}
}
