import { EvidenceVerifier } from '../../bindings/worker/worker.js';
import { EvidenceClient } from '../../bindings/shared/evidence-client.js';
import { SessionTransport } from '../../bindings/shared/session-transport.js';
import { sendSessionRequest } from '../../bindings/shared/channel-http.js';
import {
	sign_mldsa65,
	verify_mldsa65,
	rekor_public_key,
	prepare_rekor_submission
} from '../../pkg/browser/stogas_verifier.js';
import root from './root.js';
import signing from './signing.js';

const fetchOrigin = (input, init) => globalThis.fetch(input, init);

// Transport checks use network-boundary doubles. Signing uses the packaged Wasm
// and the shared Go vector, including the runtime's randomness and key erasure.
export default {
	async fetch(request) {
		const path = new URL(request.url).pathname;
		if (path === '/sign') {
			const bytes = (hex) => Uint8Array.from(hex.match(/../g), (part) => Number.parseInt(part, 16));
			const message = bytes(signing.message);
			const context = new TextEncoder().encode(signing.context);
			const publicKey = bytes(signing.spki);
			verify_mldsa65(publicKey, message, context, bytes(signing.context_signature));
			const privateKey = bytes(signing.pkcs8);
			const signature = sign_mldsa65(privateKey, message, context);
			verify_mldsa65(publicKey, message, context, signature);
			const submissionKey = bytes(signing.pkcs8);
			const submission = JSON.parse(prepare_rekor_submission(submissionKey, message));
			const publicInput = bytes(signing.pkcs8);
			const rekorPublicKey = rekor_public_key(publicInput);
			const retryKey = bytes(signing.pkcs8);
			const retry = JSON.parse(prepare_rekor_submission(retryKey, message));
			const badKey = bytes(signing.pkcs8);
			badKey[0] ^= 1;
			let rejected = false;
			try {
				prepare_rekor_submission(badKey, message);
			} catch {
				rejected = true;
			}
			return Response.json({
				erased: [privateKey, submissionKey, publicInput, retryKey, badKey].every((key) =>
					key.every((byte) => byte === 0)
				),
				rejected,
				stable: JSON.stringify(submission) === JSON.stringify(retry),
				rekorPublicKey: Array.from(rekorPublicKey, (byte) =>
					byte.toString(16).padStart(2, '0')
				).join(''),
				rekorSignature: submission.spec.signature.content,
				signatureBytes: signature.length,
				hash: submission.spec.data.hash
			});
		}
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
