export class TransportError extends Error {
	constructor(message, submission, cause) {
		super(message, { cause });
		this.name = 'StogasTransportError';
		this.submission = submission;
	}
}

// The signal covers the response body as well as response headers. Cancel the
// physical reader before releasing its owner, including with custom Fetch implementations.
export function abortableReader(body, signal) {
	const reader = body.getReader();
	const abort = () => {
		void reader.cancel(signal.reason).catch(() => {});
	};
	signal?.addEventListener('abort', abort, { once: true });
	if (signal?.aborted) abort();
	return {
		async read() {
			signal?.throwIfAborted();
			const next = await reader.read();
			signal?.throwIfAborted();
			return next;
		},
		async cancel(reason) {
			await reader.cancel(reason).catch(() => {});
		},
		release() {
			signal?.removeEventListener('abort', abort);
			reader.releaseLock();
		}
	};
}

export async function readBoundedBody(response, limit, signal) {
	if (!response.body) throw new Error('response body is unavailable');
	const reader = abortableReader(response.body, signal);
	const chunks = [];
	let size = 0;
	try {
		if (Number(response.headers.get('content-length')) > limit) {
			throw new Error('response exceeds its byte limit');
		}
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			if (!(value instanceof Uint8Array) || value.byteLength > limit - size) {
				throw new Error('response exceeds its byte limit');
			}
			size += value.byteLength;
			chunks.push(value);
		}
		const bytes = new Uint8Array(size);
		let offset = 0;
		for (const chunk of chunks) {
			bytes.set(chunk, offset);
			offset += chunk.byteLength;
		}
		return bytes;
	} catch (error) {
		await reader.cancel(error);
		throw error;
	} finally {
		reader.release();
	}
}
