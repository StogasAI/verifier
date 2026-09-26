import { EvidenceClient } from './evidence-client.js';
import { SessionTransport } from './session-transport.js';
import { TransportError } from './http.js';

const PATHS = new Set(['/v1/chat/completions', '/v1/responses']);
const OPTIONS = new Set(['environment', 'baseURL', 'maxConnections', 'fetch', 'onMetadata']);

function baseURL(value) {
	let url;
	try {
		url = new URL(value);
	} catch {
		throw new TypeError('baseURL must be an HTTPS /v1 URL');
	}
	if (
		url.protocol !== 'https:' ||
		url.username ||
		url.password ||
		/[?#]/.test(url.href) ||
		!/^\/v1\/?$/.test(url.pathname)
	)
		throw new TypeError('baseURL must be an HTTPS /v1 URL without credentials, query or fragment');
	return `${url.origin}/v1`;
}

// The same Fetch adapter runs in browsers, Node and Workers. All cryptographic
// state and trust choices come from the compiled Wasm core.
export function createTransportClass({
	EvidenceVerifier,
	EncryptedSetup,
	transport_configuration
}) {
	return class StogasTransport {
		#baseURL;
		#origins;
		#evidence;
		#sessions;
		#listeners = new Set();
		#closed = false;
		#closing;
		#refresh;
		#snapshot = Object.freeze({
			bundle: null,
			bundleURL: null,
			error: null,
			fetchedAtUnixMs: null,
			verificationDurationMs: null,
			status: 'idle'
		});

		constructor(options = {}) {
			if (
				!options ||
				typeof options !== 'object' ||
				Array.isArray(options) ||
				Object.keys(options).some((key) => !OPTIONS.has(key))
			)
				throw new TypeError('Unsupported transport option');
			const maximum = options.maxConnections ?? 4;
			if (!Number.isSafeInteger(maximum) || maximum < 1)
				throw new RangeError('maxConnections must be a positive safe integer');
			const fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
			if (
				typeof fetch !== 'function' ||
				(options.onMetadata !== undefined && typeof options.onMetadata !== 'function')
			)
				throw new TypeError('fetch and onMetadata must be functions');
			const config = transport_configuration(options.environment ?? 'prod');
			this.#baseURL = baseURL(options.baseURL ?? `${config.e2ee_origin}/v1`);
			this.#origins = config.evidence_origins;
			const core = EvidenceVerifier.for_stogas(config.environment);
			this.#evidence = new EvidenceClient(core, this.#origins, fetch, (snapshot) => {
				this.#publish({ ...snapshot, status: 'ready', error: null });
			});
			this.#sessions = new SessionTransport({
				Setup: EncryptedSetup,
				evidence: this.#evidence,
				environment: config.environment,
				endpoint: `${this.#baseURL}/session`,
				fetch,
				maxSessions: maximum,
				onMetadata: options.onMetadata
			});
			this.fetch = this.fetch.bind(this);
		}

		static async create(options = {}) {
			const transport = new this(options);
			try {
				await transport.refreshBundle();
				return transport;
			} catch (error) {
				await transport.close();
				throw error;
			}
		}

		get baseURL() {
			return this.#baseURL;
		}
		get bundleURLs() {
			return [...this.#origins];
		}
		get bundleSnapshot() {
			return structuredClone(this.#snapshot);
		}

		openAIOptions(apiKey) {
			this.#assertOpen();
			if (typeof apiKey !== 'string' || !apiKey) throw new TypeError('apiKey is required');
			return {
				apiKey,
				baseURL: this.#baseURL,
				dangerouslyAllowBrowser: true,
				fetch: this.fetch,
				maxRetries: 0
			};
		}

		subscribe(listener) {
			this.#assertOpen();
			if (typeof listener !== 'function') throw new TypeError('listener must be a function');
			this.#listeners.add(listener);
			try {
				listener(this.bundleSnapshot);
			} catch {
				this.#listeners.delete(listener);
			}
			return () => this.#listeners.delete(listener);
		}

		async refreshBundle() {
			this.#assertOpen();
			if (this.#refresh) return this.#refresh;
			this.#publish({ ...this.#snapshot, status: 'refreshing', error: null });
			const refresh = this.#evidence
				.acquire()
				.catch((error) => {
					if (!this.#closed)
						this.#publish({
							...this.#snapshot,
							status: 'error',
							error: String(error.message ?? error)
						});
					throw error;
				})
				.finally(() => {
					if (this.#refresh === refresh) this.#refresh = undefined;
				});
			this.#refresh = refresh;
			return refresh;
		}

		async fetch(input, init) {
			this.#assertOpen();
			const request = new Request(input, init);
			const url = new URL(request.url);
			if (
				url.origin !== new URL(this.#baseURL).origin ||
				!PATHS.has(url.pathname) ||
				request.method !== 'POST' ||
				url.search ||
				url.hash ||
				url.username ||
				url.password
			) {
				await request.body?.cancel().catch(() => {});
				throw new TransportError(
					'Unsupported confidential request origin, method or path',
					'not_sent'
				);
			}
			return this.#sessions.send(request);
		}

		close() {
			if (this.#closing) return this.#closing;
			this.#closed = true;
			this.#listeners.clear();
			// Close exchanges are constructed while current evidence is still owned.
			this.#closing = this.#sessions.close().finally(() => this.#evidence.close());
			return this.#closing;
		}

		#assertOpen() {
			if (this.#closed) throw new TransportError('Transport closed', 'not_sent');
		}
		#publish(snapshot) {
			if (this.#closed) return;
			this.#snapshot = Object.freeze(snapshot);
			for (const listener of this.#listeners) {
				try {
					listener(this.bundleSnapshot);
				} catch {
					this.#listeners.delete(listener);
				}
			}
		}
	};
}
