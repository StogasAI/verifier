import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EvidenceClient } from '../../bindings/shared/evidence-client.js';

const origins = [
	'https://evidence.example/bundles/latest.json',
	'https://replica.example/bundles/latest.json'
];
// Only delivery/ownership is doubled here. Signed decision and CRL behavior is
// exercised by Rust and packaged Wasm tests against genuine evidence.
function verifier() {
	let retired = false;
	return {
		freed: false,
		refresh(bytes) {
			assert.equal(this.freed, false);
			const { revision, invalid, retire } = JSON.parse(new TextDecoder().decode(bytes));
			if (retire) retired = true;
			if (invalid) throw new Error('invalid evidence');
			return {
				revision,
				freed: false,
				require_current_keys() {
					assert.equal(this.freed, false);
					if (retired) throw new Error('retired key');
				},
				summary() {
					return { revision };
				},
				free() {
					assert.equal(this.freed, false);
					this.freed = true;
				}
			};
		},
		free() {
			assert.equal(this.freed, false);
			this.freed = true;
		}
	};
}
function response(revision, etag, extra = {}) {
	return Response.json({ revision, ...extra }, { headers: etag ? { etag } : {} });
}
const requireRevision = (revision) => (snapshot) => {
	if (snapshot.revision < revision) throw new Error('unknown release');
	return snapshot.revision;
};

test('R2-first recovery checks progress before accepting 200/304 and keeps origin ETags separate', async () => {
	const calls = [];
	let stage = 0;
	const client = new EvidenceClient(verifier(), origins, async (url, options) => {
		calls.push({ url, options });
		if (url === origins[0])
			return stage === 0 ? response(1, 'r2-1') : new Response(null, { status: 304 });
		return response(2, 'aws-2');
	});
	assert.deepEqual(await client.acquire(), { revision: 1 });
	stage = 1;
	assert.equal(await client.acquire(undefined, requireRevision(2)), 2);
	assert.deepEqual(
		calls.map((call) => call.url),
		[origins[0], origins[0], origins[1]]
	);
	assert.equal(calls[1].options.headers['if-none-match'], 'r2-1');
	assert.equal(calls[2].options.headers['if-none-match'], undefined);
	assert.equal(
		calls.every(({ options }) => options.credentials === 'omit' && options.redirect === 'error'),
		true
	);
	client.close();
});

test('concurrent misses share acquisition and reuse its verified result', async () => {
	let calls = 0;
	let release;
	const waiting = new Promise((resolve) => {
		release = resolve;
	});
	const client = new EvidenceClient(verifier(), origins, async () => {
		calls++;
		await waiting;
		return response(2);
	});
	const requests = Array.from({ length: 20 }, () => client.acquire(undefined, requireRevision(2)));
	release();
	assert.deepEqual(await Promise.all(requests), Array(20).fill(2));
	assert.equal(calls, 1);
	client.close();
});

test('one canceled waiter does not cancel another caller acquisition', async () => {
	let release;
	const waiting = new Promise((resolve) => {
		release = resolve;
	});
	const client = new EvidenceClient(verifier(), origins, async () => {
		await waiting;
		return response(1);
	});
	const first = client.acquire();
	const abort = new AbortController();
	const other = client.acquire(abort.signal);
	abort.abort();
	await assert.rejects(other, { name: 'AbortError' });
	release();
	assert.deepEqual(await first, { revision: 1 });
	client.close();
});

test('invalid delivery preserves usable state but authentic retirement still constrains it', async () => {
	let mode = 'normal';
	const client = new EvidenceClient(verifier(), origins, async () =>
		response(1, undefined, mode === 'normal' ? {} : { invalid: true, retire: mode === 'retire' })
	);
	await client.acquire();
	mode = 'invalid';
	await assert.rejects(client.acquire(), /invalid evidence/);
	assert.equal(client.check(requireRevision(1)), 1);
	client.close();
	const revoked = new EvidenceClient(verifier(), origins, async () =>
		response(1, undefined, mode === 'normal' ? {} : { invalid: true, retire: true })
	);
	mode = 'normal';
	await revoked.acquire();
	mode = 'retire';
	await assert.rejects(revoked.acquire(), /invalid evidence/);
	assert.throws(() => revoked.check(requireRevision(1)), /retired key/);
	revoked.close();
});

test('304 without origin representation fails and failed lookups share a cooldown', async () => {
	let calls = 0;
	const client = new EvidenceClient(verifier(), origins, async () => {
		calls++;
		return new Response(null, { status: 304 });
	});
	await assert.rejects(client.acquire(), /HTTP 304/);
	await assert.rejects(client.acquire(), /cooling down/);
	assert.equal(calls, 2);
	client.close();
});

test('closing during acquisition cancels network work before freeing the verifier', async () => {
	let aborted = 0;
	const core = verifier();
	const client = new EvidenceClient(
		core,
		origins,
		async (_url, { signal }) =>
			new Promise((_resolve, reject) => {
				signal.addEventListener(
					'abort',
					() => {
						aborted++;
						reject(signal.reason);
					},
					{ once: true }
				);
			})
	);
	const loading = client.acquire();
	client.close();
	await assert.rejects(loading, { name: 'AbortError' });
	assert.equal(aborted, 1);
	assert.equal(core.freed, true);
	client.close();
});
