import { readBoundedBody } from './http.js';

const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
const ORIGIN_TIMEOUT_MS = 5_000;
export const SETUP_TIMEOUT_MS = 15_000;

export function deadlineSignal(signal, milliseconds) {
	const controller = new AbortController();
	const abort = () => controller.abort(signal.reason);
	signal?.addEventListener('abort', abort, { once: true });
	const timeout = setTimeout(
		() => controller.abort(new DOMException('Setup deadline expired', 'TimeoutError')),
		Math.max(0, milliseconds)
	);
	timeout.unref?.();
	if (signal?.aborted) abort();
	return {
		signal: controller.signal,
		dispose() {
			clearTimeout(timeout);
			signal?.removeEventListener('abort', abort);
		}
	};
}

export function waitWithSignal(promise, signal) {
	if (!signal) return promise;
	return new Promise((resolve, reject) => {
		const abort = () => reject(signal.reason);
		signal.addEventListener('abort', abort, { once: true });
		if (signal.aborted) abort();
		promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
	});
}

// One network acquisition, two origin-specific representations and one current
// Rust snapshot. No polling, third-party fetches or per-missing-object registry.
export class EvidenceClient {
	#verifier;
	#fetch;
	#origins;
	#representations;
	#current;
	#pending;
	#onSnapshot;
	#retryAt = 0;
	#closed = new AbortController();

	constructor(verifier, origins, fetch, onSnapshot = () => {}) {
		this.#verifier = verifier;
		this.#fetch = fetch;
		this.#origins = origins;
		this.#representations = origins.map(() => undefined);
		this.#onSnapshot = onSnapshot;
	}

	check(check) {
		if (!this.#current) throw new Error('evidence has not been initialized');
		this.#current.require_current_keys();
		return check(this.#current);
	}

	// Check is synchronous and must not consume a setup secret on failure. A
	// successful check may return its newly verified session directly.
	async acquire(signal, check) {
		const deadline = deadlineSignal(signal, SETUP_TIMEOUT_MS);
		const combined = AbortSignal.any([deadline.signal, this.#closed.signal]);
		try {
			combined.throwIfAborted();
			if (check && this.#current) {
				try {
					this.#current.require_current_keys();
					return check(this.#current);
				} catch {
					/* Try current evidence once. */
				}
			}
			const previous = this.#current;
			while (this.#pending) {
				await waitWithSignal(
					this.#pending.catch(() => {}),
					combined
				);
				combined.throwIfAborted();
				if (this.#current) {
					if (check) {
						try {
							this.#current.require_current_keys();
							return check(this.#current);
						} catch {
							/* The other caller may have needed different evidence. */
						}
					} else if (this.#current !== previous) {
						return this.#current.summary();
					}
				}
			}
			if (Date.now() < this.#retryAt) throw new Error('evidence recovery is cooling down');
			const pending = this.#load(combined, check);
			this.#pending = pending;
			try {
				return await pending;
			} finally {
				if (this.#pending === pending) this.#pending = undefined;
			}
		} finally {
			deadline.dispose();
		}
	}

	async #load(signal, check) {
		let failure;
		for (let index = 0; index < this.#origins.length; index++) {
			signal.throwIfAborted();
			const attempt = deadlineSignal(signal, ORIGIN_TIMEOUT_MS);
			try {
				const cached = this.#representations[index];
				const response = await this.#fetch(this.#origins[index], {
					method: 'GET',
					credentials: 'omit',
					redirect: 'manual',
					signal: attempt.signal,
					headers: {
						accept: 'application/json',
						...(cached?.etag ? { 'if-none-match': cached.etag } : {})
					}
				});
				let bytes;
				let etag;
				if (response.status === 304 && cached) {
					await response.body?.cancel().catch(() => {});
					({ bytes, etag } = cached);
				} else if (response.status === 200) {
					bytes = await readBoundedBody(response, MAX_BUNDLE_BYTES, attempt.signal);
					etag = response.headers.get('etag');
				} else {
					await response.body?.cancel().catch(() => {});
					throw new Error(`evidence origin returned HTTP ${response.status}`);
				}
				attempt.signal.throwIfAborted();
				// Rust retains authentic revocations even if another candidate object
				// fails validation. A 304 must still recheck time and those decisions.
				const started = performance.now();
				const snapshot = this.#verifier.refresh(bytes);
				this.#representations[index] = { bytes, etag };
				const old = this.#current;
				this.#current = snapshot;
				old?.free(); // Requests own independent Arc-backed snapshot handles.
				try {
					this.#onSnapshot({
						bundle: snapshot.summary(),
						bundleURL: this.#origins[index],
						fetchedAtUnixMs: Date.now(),
						verificationDurationMs: performance.now() - started
					});
				} catch {
					/* An observer cannot change authenticated state or delivery. */
				}
				snapshot.require_current_keys();
				const result = check ? check(snapshot) : snapshot.summary();
				this.#retryAt = 0;
				return result;
			} catch (error) {
				failure = error;
			} finally {
				attempt.dispose();
			}
		}
		signal.throwIfAborted();
		this.#retryAt = Date.now() + 4_500 + Math.floor(Math.random() * 1_001);
		throw failure;
	}

	close() {
		if (this.#closed.signal.aborted) return;
		this.#closed.abort(new DOMException('Transport closed', 'AbortError'));
		this.#representations = [];
		this.#current?.free();
		this.#current = undefined;
		this.#verifier.free();
	}
}
