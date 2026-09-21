import assert from 'node:assert/strict';
import { SESSION_CONTENT_TYPE } from '../../bindings/shared/channel-http.js';

// Deliberately noncryptographic HTTP-boundary double. Rust/Go vectors test the
// real codec; here events exercise reader ownership and Fetch failure semantics.
export class Exchange {
	prefix = new Uint8Array([7, 8, 9]);
	sealed = [];
	freed = 0;
	final = false;
	buffer = '';
	seal(kind, bytes) {
		this.sealed.push({ kind, bytes: bytes.slice() });
		return new Uint8Array([kind]);
	}
	push(bytes, emit) {
		assert.equal(this.freed, 0);
		this.buffer += new TextDecoder().decode(bytes);
		for (;;) {
			const end = this.buffer.indexOf('\n');
			if (end < 0) return;
			if (this.final) throw new Error('trailing record');
			const [kind, value] = JSON.parse(this.buffer.slice(0, end));
			this.buffer = this.buffer.slice(end + 1);
			if (kind === 3) this.final = true;
			emit(kind, new TextEncoder().encode(value));
		}
	}
	finish() {
		if (!this.final || this.buffer.length) throw new Error('truncated response');
	}
	free() {
		this.freed++;
	}
}
export function record(kind, value = '') {
	return new TextEncoder().encode(JSON.stringify([kind, value]) + '\n');
}
export function response(records, { split = 0, cancelled = () => {} } = {}) {
	const all = new Blob(records);
	return new Response(
		split
			? new ReadableStream({
					async start(controller) {
						const bytes = new Uint8Array(await all.arrayBuffer());
						for (let offset = 0; offset < bytes.length; offset += split)
							controller.enqueue(bytes.slice(offset, offset + split));
						controller.close();
					},
					cancel: cancelled
				})
			: all,
		{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
	);
}
