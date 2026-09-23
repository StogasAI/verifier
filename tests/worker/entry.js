import { EvidenceVerifier } from '../../bindings/worker/worker.js';
import { EvidenceClient } from '../../bindings/shared/evidence-client.js';
import { SessionTransport } from '../../bindings/shared/session-transport.js';
import { sendSessionRequest } from '../../bindings/shared/channel-http.js';
import root from './root.js';

const fetchOrigin = (input, init) => globalThis.fetch(input, init);

// Network-boundary doubles only. The packaged Wasm core is loaded above and its
// cryptographic fixtures are exercised separately by the browser/Rust suites.
export default {
	async fetch(request) {
		const path = new URL(request.url).pathname;
		if (path === '/core') {
			const verifier = new EvidenceVerifier('prod', root.key_id, root.public_key);
			try {
				verifier.refresh(new Uint8Array());
				throw new Error('accepted empty evidence');
			} catch (error) {
				return Response.json({ code: error.code });
			} finally {
				verifier.free();
			}
		}
		if (path === '/evidence') {
			const client = new EvidenceClient(
				{
					refresh(bytes) {
						const value = JSON.parse(new TextDecoder().decode(bytes));
						return { summary: () => value, require_current_keys() {}, free() {} };
					},
					free() {}
				},
				['https://r2.example/latest.json', 'https://aws.example/latest.json'],
				fetchOrigin
			);
			try {
				return Response.json([await client.acquire(), await client.acquire()]);
			} finally {
				client.close();
			}
		}
		const input = new Request('https://gateway.example/v1/chat/completions', {
			method: 'POST',
			body: '{}',
			headers: { authorization: 'Bearer private-example-key' }
		});
		if (path === '/setup') {
			let freed = 0;
			const sessions = new SessionTransport({
				Setup: class {
					hello = new Uint8Array([1]);
					free() {
						freed++;
					}
				},
				evidence: { check: (fn) => fn({}) },
				environment: 'prod',
				endpoint: 'https://gateway.example/session',
				fetch: fetchOrigin
			});
			try {
				await sessions.send(input);
				throw new Error('accepted redirect');
			} catch (error) {
				return Response.json({ submission: error.submission, freed });
			} finally {
				await sessions.close();
			}
		}
		let freed = 0,
			released = 0;
		try {
			await sendSessionRequest({
				exchange: {
					prefix: new Uint8Array([1]),
					seal: () => new Uint8Array([2]),
					response_completion: () => ({ free() {} }),
					free() {
						freed++;
					}
				},
				nodeID: 'example-node',
				endpoint: 'https://gateway.example/session',
				request: input,
				fetch: fetchOrigin,
				release() {
					released++;
				}
			});
			throw new Error('accepted redirect');
		} catch (error) {
			return Response.json({ submission: error.submission, freed, released });
		}
	}
};
