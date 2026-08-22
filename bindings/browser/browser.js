import init, {
	Verifier as CoreVerifier,
	verify_bundle,
	verify_bundle_with_policy
} from '../../pkg/browser/stogas_verifier.js';
import { createVerifierBindings } from '../shared/verifier.js';

export default init;
export { verify_bundle, verify_bundle_with_policy };

const PRODUCTION_API_BASE_URL = 'https://api.stogas.ai/v1';
const PRODUCTION_BUNDLE_URL = 'https://evidence.stogas.ai/bundles/latest.json';
const PRODUCTION_BUNDLE_FALLBACK_URL = 'https://evidence2.stogas.ai/bundles/latest.json';
const STAGING_API_BASE_URL = 'https://api-staging.stogas.ai/v1';
const STAGING_BUNDLE_URL = 'https://evidence-staging.stogas.ai/bundles/latest.json';
const STAGING_BUNDLE_FALLBACK_URL = 'https://evidence2-staging.stogas.ai/bundles/latest.json';
const DEFAULT_REFRESH_SECONDS = 300;
const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
const MAX_E2EE_REQUEST_BYTES = 94 * 1024 * 1024;
const BUNDLE_ORIGIN_TIMEOUT_MS = 5_000;
const EXPIRY_REFRESH_LEAD_MIN_MS = 40_000;
const EXPIRY_REFRESH_LEAD_MAX_MS = 70_000;
const REFRESH_RETRY_MIN_MS = 4_000;
const REFRESH_RETRY_MAX_MS = 8_000;
const REFRESH_INTERVAL_JITTER_MIN_PERCENT = 90;
const REFRESH_INTERVAL_JITTER_MAX_PERCENT = 110;
const E2EE_CONTENT_TYPE = 'application/vnd.stogas.e2ee';
const E2EE_TRANSCRIPT_HEADER = 'x-stogas-e2ee-transcript-sha256';
const E2EE_PATHS = new Set(['/v1/chat/completions', '/v1/responses']);

export const { ResponseProofStream, Verifier } = createVerifierBindings(CoreVerifier);

export class StogasTransport {
	#active;
	#baseURL;
	#bundleURLs;
	#bundleAbort;
	#candidateCore;
	#closed = false;
	#core;
	#fetchImpl;
	#listeners = new Set();
	#hardwarePolicy;
	#refreshIntervalMs;
	#refreshPromise;
	#snapshot = Object.freeze({
		bundle: null,
		bundleURL: null,
		envelopeSha256: null,
		error: null,
		fetchedAtUnixMs: null,
		status: 'idle',
		verificationDurationMs: null,
		verifiedAtUnixMs: null
	});
	#timer;

	static async create(options = {}) {
		const transport = new StogasTransport(options);
		try {
			await transport.refreshBundle();
			return transport;
		} catch (error) {
			transport.close();
			throw error;
		}
	}

	constructor(options = {}) {
		const environment = options.environment ?? 'production';
		if (!['production', 'staging'].includes(environment)) {
			throw new TypeError('environment must be production or staging');
		}
		const refreshIntervalSeconds = options.bundleRefreshIntervalSeconds ?? DEFAULT_REFRESH_SECONDS;
		if (
			!Number.isInteger(refreshIntervalSeconds) ||
			refreshIntervalSeconds < 1 ||
			!Number.isSafeInteger(refreshIntervalSeconds)
		) {
			throw new RangeError('bundleRefreshIntervalSeconds must be a positive safe integer');
		}
		this.#baseURL = normalizeBaseURL(
			options.baseURL ??
				(environment === 'staging' ? STAGING_API_BASE_URL : PRODUCTION_API_BASE_URL)
		);
		const defaultBundleURLs =
			environment === 'staging'
				? [STAGING_BUNDLE_URL, STAGING_BUNDLE_FALLBACK_URL]
				: [PRODUCTION_BUNDLE_URL, PRODUCTION_BUNDLE_FALLBACK_URL];
		const configuredBundleURL =
			options.bundleURL === undefined ? undefined : normalizeBundleURL(options.bundleURL);
		this.#bundleURLs =
			configuredBundleURL === undefined || configuredBundleURL === defaultBundleURLs[0]
				? defaultBundleURLs
				: [configuredBundleURL];
		if (
			environment === 'staging' &&
			(this.#baseURL !== STAGING_API_BASE_URL || !sameStrings(this.#bundleURLs, defaultBundleURLs))
		) {
			throw new TypeError(
				'staging verification is restricted to the Stogas staging API and evidence origins'
			);
		}
		this.#fetchImpl = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
		if (typeof this.#fetchImpl !== 'function') {
			throw new TypeError('a Fetch API implementation is required');
		}
		this.#refreshIntervalMs = refreshIntervalSeconds * 1_000;
		if (options.hardwarePolicy !== undefined && !(options.hardwarePolicy instanceof Uint8Array)) {
			throw new TypeError('hardwarePolicy must be a Uint8Array');
		}
		this.#hardwarePolicy = options.hardwarePolicy?.slice();
		const staging = environment === 'staging' ? true : undefined;
		this.#core = new CoreVerifier(staging);
		this.#candidateCore = new CoreVerifier(staging);
		this.fetch = this.fetch.bind(this);
	}

	get baseURL() {
		return this.#baseURL;
	}

	get bundleSnapshot() {
		return this.#snapshot;
	}

	get bundleURLs() {
		return [...this.#bundleURLs];
	}

	subscribe(listener) {
		if (typeof listener !== 'function') throw new TypeError('listener must be a function');
		this.#assertOpen();
		this.#listeners.add(listener);
		try {
			listener(this.#snapshot);
		} catch (error) {
			this.#listeners.delete(listener);
			throw error;
		}
		return () => this.#listeners.delete(listener);
	}

	openAIOptions(apiKey) {
		if (typeof apiKey !== 'string' || apiKey.length === 0) {
			throw new TypeError('apiKey is required');
		}
		return {
			apiKey,
			baseURL: this.#baseURL,
			dangerouslyAllowBrowser: true,
			fetch: this.fetch,
			maxRetries: 0
		};
	}

	verifyResponseProof(proof, requestBody, responseBody, e2eeTranscriptSHA256) {
		this.#assertOpen();
		return this.#core.verify_response_proof(proof, requestBody, responseBody, e2eeTranscriptSHA256);
	}

	createResponseProofStream(requestBody) {
		this.#assertOpen();
		return new ResponseProofStream(this.#core.start_response_proof(requestBody), this.#core);
	}

	verifyNodeLedgerRecord(ledger) {
		this.#assertOpen();
		return this.#core.verify_node_ledger_record(ledger);
	}

	verifyReleaseApproval(release) {
		this.#assertOpen();
		return this.#core.verify_release_approval(release);
	}

	verifyCatalogApproval(catalog) {
		this.#assertOpen();
		return this.#core.verify_catalog_approval(catalog);
	}

	async refreshBundle() {
		this.#assertOpen();
		if (this.#refreshPromise) return this.#refreshPromise;
		this.#refreshPromise = this.#refreshBundle().finally(() => {
			this.#refreshPromise = undefined;
		});
		return this.#refreshPromise;
	}

	async fetch(input, init) {
		this.#assertOpen();
		const request = new Request(input, init);
		const url = new URL(request.url);
		if (
			request.method !== 'POST' ||
			url.origin !== new URL(this.#baseURL).origin ||
			!E2EE_PATHS.has(url.pathname)
		) {
			return this.#fetchImpl(input, { ...init, redirect: 'error' });
		}
		if (url.search !== '') {
			throw new TypeError('encrypted inference does not accept URL query parameters');
		}
		await this.#ensureCurrentBundle();

		const apiKey = bearerAPIKey(request.headers.get('authorization'));
		const upstream = upstreamCredential(request.headers);
		const body = await readBoundedBody(request, MAX_E2EE_REQUEST_BYTES, 'request');
		const session = this.#core.seal_e2ee_request(
			url.pathname,
			apiKey,
			body,
			request.headers.get('accept') ?? undefined,
			extraFieldsEnabled(request.headers),
			upstream?.provider,
			upstream?.apiKey
		);
		let response;
		try {
			response = await this.#fetchImpl(request.url, {
				body: session.body,
				credentials: 'omit',
				headers: {
					accept: E2EE_CONTENT_TYPE,
					'content-type': 'application/json'
				},
				method: 'POST',
				redirect: 'error',
				signal: request.signal
			});
		} catch (error) {
			session.free();
			throw error;
		}
		return decryptResponse(response, session);
	}

	close() {
		if (this.#closed) return;
		this.#closed = true;
		clearTimeout(this.#timer);
		this.#bundleAbort?.abort();
		this.#core.free();
		this.#candidateCore.free();
		this.#active = undefined;
		this.#listeners.clear();
	}

	async #ensureCurrentBundle() {
		if (!this.#active || Date.now() >= this.#active.expiresAtUnixMs) {
			await this.refreshBundle();
		}
		if (!this.#active || Date.now() >= this.#active.expiresAtUnixMs) {
			throw new Error('the active verified bundle has expired');
		}
		if (this.#active.bundle.nodes.length === 0) {
			throw new Error('the verified fleet is unavailable');
		}
	}

	async #refreshBundle() {
		clearTimeout(this.#timer);
		this.#publish({ ...this.#snapshot, error: null, status: 'refreshing' });
		try {
			const urls =
				this.#bundleURLs.length === 2 && Math.random() < 0.5
					? [this.#bundleURLs[1], this.#bundleURLs[0]]
					: this.#bundleURLs;
			const failures = [];
			let candidateCoreSha256 = null;
			let currentUnavailableObserved = false;
			let pendingUnavailable = null;
			let unavailableCandidates = 0;
			for (const url of urls) {
				try {
					const candidate = await this.#fetchBundleCandidate(url);
					const unchangedBytes = this.#active?.sha256 === candidate.sha256;
					const fetchedAtUnixMs = Date.now();
					if (this.#active && unchangedBytes) {
						this.#active.bundleURL = url;
						this.#active.fetchedAtUnixMs = fetchedAtUnixMs;
						this.#publish({
							...this.#snapshot,
							bundleURL: url,
							error: null,
							fetchedAtUnixMs,
							status: this.#active.bundle.nodes.length === 0 ? 'unavailable' : 'ready'
						});
						this.#scheduleRefresh();
						if (this.#active.bundle.nodes.length === 0) {
							currentUnavailableObserved = true;
							continue;
						}
						if (pendingUnavailable) continue;
						return false;
					}
					const verificationStartedAt = monotonicNow();
					const output = this.#verifyBundle(this.#candidateCore, candidate.bytes);
					candidateCoreSha256 = candidate.sha256;
					const verificationDurationMs = monotonicNow() - verificationStartedAt;
					const verifiedAtUnixMs = Date.now();
					if (
						this.#active &&
						output.bundle.created_at_unix_ms <= this.#active.bundle.created_at_unix_ms
					) {
						throw new Error('origin returned a non-advancing verified snapshot');
					}
					const verifiedCandidate = {
						bytes: candidate.bytes,
						fetchedAtUnixMs,
						output,
						sha256: candidate.sha256,
						url,
						verificationDurationMs,
						verifiedAtUnixMs
					};
					if (output.bundle.nodes.length === 0 && urls.length === 2) {
						unavailableCandidates += 1;
						if (
							!pendingUnavailable ||
							output.bundle.created_at_unix_ms > pendingUnavailable.output.bundle.created_at_unix_ms
						) {
							pendingUnavailable = verifiedCandidate;
						}
						continue;
					}
					this.#activateCandidate(verifiedCandidate);
					return true;
				} catch (error) {
					failures.push(new Error(`${new URL(url).host}: ${errorMessage(error)}`));
					if (this.#closed) throw error;
				}
			}
			if (pendingUnavailable) {
				const canActivate =
					!this.#active ||
					this.#active.bundle.nodes.length === 0 ||
					unavailableCandidates === urls.length;
				if (canActivate) {
					if (candidateCoreSha256 !== pendingUnavailable.sha256) {
						pendingUnavailable.output = this.#verifyBundle(
							this.#candidateCore,
							pendingUnavailable.bytes
						);
					}
					this.#activateCandidate(pendingUnavailable);
					return true;
				}
				this.#publish({
					...this.#snapshot,
					error: null,
					status: this.#active.bundle.nodes.length === 0 ? 'unavailable' : 'ready'
				});
				this.#scheduleRetry();
				return false;
			}
			if (currentUnavailableObserved) return false;
			throw new AggregateError(
				failures,
				`every evidence origin failed: ${failures.map(errorMessage).join('; ')}`
			);
		} catch (error) {
			this.#publish({
				...this.#snapshot,
				error: error instanceof Error ? error.message : String(error),
				status: 'error'
			});
			this.#scheduleRetry();
			throw error;
		}
	}

	#verifyBundle(core, bundle) {
		return this.#hardwarePolicy
			? core.verify_bundle_with_policy(bundle, this.#hardwarePolicy)
			: core.verify_bundle(bundle);
	}

	#activateCandidate(candidate) {
		const activeCore = this.#core;
		this.#core = this.#candidateCore;
		this.#candidateCore = activeCore;
		this.#active = {
			bundle: candidate.output.bundle,
			bundleURL: candidate.url,
			expiresAtUnixMs: candidate.output.bundle.expires_at_unix_ms,
			fetchedAtUnixMs: candidate.fetchedAtUnixMs,
			sha256: candidate.sha256,
			verificationDurationMs: candidate.verificationDurationMs,
			verifiedAtUnixMs: candidate.verifiedAtUnixMs
		};
		this.#publish({
			bundle: candidate.output.bundle,
			bundleURL: candidate.url,
			envelopeSha256: candidate.sha256,
			error: null,
			fetchedAtUnixMs: candidate.fetchedAtUnixMs,
			status: candidate.output.bundle.nodes.length === 0 ? 'unavailable' : 'ready',
			verificationDurationMs: candidate.verificationDurationMs,
			verifiedAtUnixMs: candidate.verifiedAtUnixMs
		});
		this.#scheduleRefresh();
	}

	async #fetchBundleCandidate(url) {
		const abort = new AbortController();
		this.#bundleAbort = abort;
		const timeout = setTimeout(() => abort.abort(), BUNDLE_ORIGIN_TIMEOUT_MS);
		timeout.unref?.();
		try {
			const response = await this.#fetchImpl(url, {
				credentials: 'omit',
				headers: { accept: 'application/json' },
				method: 'GET',
				redirect: 'error',
				signal: abort.signal
			});
			if (!response.ok) {
				await response.body?.cancel().catch(() => {});
				throw new Error(`returned HTTP ${response.status}`);
			}
			const bytes = await readBoundedBody(response, MAX_BUNDLE_BYTES, 'bundle', true);
			return { bytes, sha256: await sha256Hex(bytes) };
		} finally {
			clearTimeout(timeout);
			if (this.#bundleAbort === abort) this.#bundleAbort = undefined;
		}
	}

	#scheduleRefresh() {
		if (this.#closed) return;
		if (this.#active?.bundle.nodes.length === 0) {
			const spread = REFRESH_RETRY_MAX_MS - REFRESH_RETRY_MIN_MS;
			this.#setTimer(REFRESH_RETRY_MIN_MS + Math.floor(Math.random() * (spread + 1)));
			return;
		}
		const now = Date.now();
		const expiryLeadSpread = EXPIRY_REFRESH_LEAD_MAX_MS - EXPIRY_REFRESH_LEAD_MIN_MS;
		const expiryLeadMs =
			EXPIRY_REFRESH_LEAD_MIN_MS + Math.floor(Math.random() * (expiryLeadSpread + 1));
		const scheduledAt = Math.min(
			now + jitteredRefreshIntervalMs(this.#refreshIntervalMs),
			(this.#active?.expiresAtUnixMs ?? now) - expiryLeadMs
		);
		if (scheduledAt <= now) {
			this.#scheduleRetry();
			return;
		}
		this.#setTimer(scheduledAt - now);
	}

	#scheduleRetry() {
		if (this.#closed) return;
		const spread = REFRESH_RETRY_MAX_MS - REFRESH_RETRY_MIN_MS;
		this.#setTimer(REFRESH_RETRY_MIN_MS + Math.floor(Math.random() * (spread + 1)));
	}

	#setTimer(delay) {
		clearTimeout(this.#timer);
		this.#timer = setTimeout(() => {
			void this.refreshBundle().catch(() => {});
		}, delay);
		this.#timer.unref?.();
	}

	#assertOpen() {
		if (this.#closed) throw new Error('StogasTransport is closed');
	}

	#publish(snapshot) {
		this.#snapshot = Object.freeze(snapshot);
		for (const listener of this.#listeners) {
			try {
				listener(this.#snapshot);
			} catch {
				this.#listeners.delete(listener);
			}
		}
	}
}

function jitteredRefreshIntervalMs(intervalMs) {
	const spread = REFRESH_INTERVAL_JITTER_MAX_PERCENT - REFRESH_INTERVAL_JITTER_MIN_PERCENT;
	const percent = REFRESH_INTERVAL_JITTER_MIN_PERCENT + Math.floor(Math.random() * (spread + 1));
	return Math.max(1, Math.round((intervalMs * percent) / 100));
}

function normalizeBaseURL(value) {
	const url = new URL(value);
	if (
		url.protocol !== 'https:' ||
		url.username !== '' ||
		url.password !== '' ||
		url.href.includes('?') ||
		url.href.includes('#') ||
		url.search !== '' ||
		url.hash !== '' ||
		!['', '/', '/v1', '/v1/'].includes(url.pathname)
	) {
		throw new TypeError('baseURL must be an HTTPS origin with an optional /v1 path');
	}
	url.pathname = '/v1';
	return url.toString().replace(/\/$/, '');
}

function normalizeBundleURL(value) {
	const url = new URL(value);
	if (
		url.protocol !== 'https:' ||
		url.username !== '' ||
		url.password !== '' ||
		url.href.includes('?') ||
		url.href.includes('#') ||
		url.search !== '' ||
		url.hash !== ''
	) {
		throw new TypeError('bundleURL must be an HTTPS URL without credentials, query, or fragment');
	}
	return url.toString();
}

function sameStrings(left, right) {
	return left.length === right.length && left.every((value, index) => value === right[index]);
}

function errorMessage(error) {
	return error instanceof Error ? error.message : String(error);
}

function monotonicNow() {
	return globalThis.performance?.now() ?? Date.now();
}

function bearerAPIKey(value) {
	if (typeof value !== 'string') {
		throw new TypeError('a Bearer authorization value is required');
	}
	const match = /^Bearer ([^\s]+)$/i.exec(value);
	if (!match) throw new TypeError('a Bearer authorization value is required');
	return match[1];
}

function extraFieldsEnabled(headers) {
	const raw = headers.get('x-stogas-extra-fields');
	if (raw === null) return false;
	const value = raw.trim().toLowerCase();
	if (value === 'true') return true;
	if (value === 'false') return false;
	throw new TypeError('X-Stogas-Extra-Fields must be true or false');
}

function upstreamCredential(headers) {
	const apiKey = headers.get('x-stogas-upstream-api-key');
	const provider = headers.get('x-stogas-upstream-provider');
	if (apiKey === null) {
		if (provider !== null) {
			throw new TypeError('an upstream API key is required with credential metadata');
		}
		return undefined;
	}
	if (apiKey.length === 0) throw new TypeError('the upstream API key must not be empty');
	if (provider === null || provider.trim() === '') {
		throw new TypeError('X-Stogas-Upstream-Provider is required with a pass-through credential');
	}
	if (provider === 'azure') {
		throw new TypeError('Azure pass-through credentials are not supported');
	}
	return {
		apiKey,
		provider
	};
}

async function sha256Hex(bytes) {
	const subtle = globalThis.crypto?.subtle;
	if (!subtle) throw new Error('Web Crypto SHA-256 is unavailable');
	const digest = new Uint8Array(await subtle.digest('SHA-256', bytes));
	return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function readBoundedBody(message, limit, label, required = false) {
	const declaredLength = Number(message.headers.get('content-length'));
	if (Number.isFinite(declaredLength) && declaredLength > limit) {
		await message.body?.cancel().catch(() => {});
		throw new Error(`${label} exceeds ${limit} bytes`);
	}
	if (!message.body) {
		if (required) throw new Error(`${label} response body is unavailable`);
		return new Uint8Array();
	}
	const reader = message.body.getReader();
	const chunks = [];
	let total = 0;
	try {
		for (;;) {
			const next = await reader.read();
			if (next.done) break;
			total += next.value.byteLength;
			if (total > limit) {
				await reader.cancel().catch(() => {});
				throw new Error(`${label} exceeds ${limit} bytes`);
			}
			chunks.push(next.value);
		}
	} finally {
		reader.releaseLock();
	}
	const bytes = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return bytes;
}

async function decryptResponse(response, session) {
	const transcriptSHA256 = session.transcript_sha256;
	if (
		response.status !== 200 ||
		response.headers.get('content-type') !== E2EE_CONTENT_TYPE ||
		response.headers.get('x-stogas-e2ee') !== '1' ||
		!response.body
	) {
		await response.body?.cancel().catch(() => {});
		session.free();
		throw new Error('upstream did not return an encrypted response');
	}
	const reader = response.body.getReader();
	const pending = [];
	let metadata;
	let finalSeen = false;
	let sessionFreed = false;
	const freeSession = () => {
		if (!sessionFreed) {
			sessionFreed = true;
			session.free();
		}
	};
	try {
		while (!metadata) {
			const next = await reader.read();
			if (next.done) {
				session.finish();
				throw new Error('encrypted response ended before metadata');
			}
			for (const event of session.push_response(next.value)) {
				if (event.type === 'metadata') metadata = event.metadata;
				else if (event.type === 'data') pending.push(event.data);
				else if (event.type === 'final') finalSeen = true;
			}
		}
	} catch (error) {
		await reader.cancel(error).catch(() => {});
		freeSession();
		throw error;
	}

	const body = new ReadableStream({
		async pull(controller) {
			try {
				while (pending.length === 0) {
					if (finalSeen) {
						session.finish();
						freeSession();
						controller.close();
						void reader.cancel().catch(() => {});
						return;
					}
					const next = await reader.read();
					if (next.done) {
						session.finish();
						freeSession();
						controller.close();
						return;
					}
					for (const event of session.push_response(next.value)) {
						if (event.type === 'metadata') {
							throw new Error('encrypted response contained duplicate metadata');
						}
						if (event.type === 'data') pending.push(event.data);
						else if (event.type === 'final') finalSeen = true;
					}
				}
				controller.enqueue(pending.shift());
			} catch (error) {
				await reader.cancel(error).catch(() => {});
				freeSession();
				controller.error(error);
			}
		},
		async cancel(reason) {
			freeSession();
			await reader.cancel(reason).catch(() => {});
		}
	});
	const headers = new Headers(metadata.headers);
	headers.set('content-type', metadata.content_type);
	headers.set(E2EE_TRANSCRIPT_HEADER, transcriptSHA256);
	headers.delete('content-length');
	return new Response(body, {
		headers,
		status: metadata.status
	});
}
