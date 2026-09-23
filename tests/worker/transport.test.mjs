import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { Miniflare, Response } from 'miniflare';

const root = resolve(import.meta.dirname, '../..');

test('packaged Worker core loads and Fetch never follows evidence, setup or inference redirects', async () => {
	const names = [
		'tests/worker/entry.js',
		'bindings/worker/worker.js',
		'bindings/browser/browser.js',
		'pkg/browser/stogas_verifier.js',
		'pkg/browser/stogas_verifier_bg.wasm',
		...(await readdir(resolve(root, 'bindings/shared')))
			.filter((name) => name.endsWith('.js'))
			.map((name) => `bindings/shared/${name}`)
	];
	const modules = Object.fromEntries(
		await Promise.all(
			names.map(async (name) => [
				name,
				{
					type: name.endsWith('.wasm') ? 'wasm' : 'esm',
					contents: await readFile(resolve(root, name), name.endsWith('.wasm') ? undefined : 'utf8')
				}
			])
		)
	);
	const fixture = JSON.parse(
		await readFile(resolve(root, 'tests/fixtures/hardware-session-v1.json'), 'utf8')
	);
	modules['tests/worker/root.js'] = {
		type: 'esm',
		contents: `export default ${JSON.stringify(fixture.root)};`
	};
	const calls = [];
	const runtime = new Miniflare({
		cf: false,
		telemetry: { enabled: false },
		workers: [
			{
				config: {
					name: 'sdk',
					compatibilityDate: '2026-09-21',
					manifest: { mainModule: 'tests/worker/entry.js', modules }
				},
				dev: {
					outboundService: {
						type: 'fetcher',
						handler: async (request) => {
							calls.push({ url: request.url, headers: Object.fromEntries(request.headers) });
							assert.equal(request.headers.has('authorization'), false);
							if (request.url === 'https://aws.example/latest.json') {
								return request.headers.has('if-none-match')
									? new Response(null, { status: 304 })
									: Response.json({ revision: 1 }, { headers: { etag: 'aws-one' } });
							}
							assert.ok(
								['https://r2.example/latest.json', 'https://gateway.example/session'].includes(
									request.url
								)
							);
							return new Response(null, {
								status: 307,
								headers: { location: 'https://attacker.example/' }
							});
						}
					}
				}
			}
		]
	});
	try {
		async function get(path) {
			const response = await runtime.dispatchFetch(`http://sdk${path}`);
			assert.equal(response.status, 200, await response.clone().text());
			return response.json();
		}
		assert.equal((await get('/core')).code, 'invalid_evidence');
		assert.deepEqual(await get('/evidence'), [{ revision: 1 }, { revision: 1 }]);
		assert.deepEqual(
			calls.map((call) => call.url),
			[
				'https://r2.example/latest.json',
				'https://aws.example/latest.json',
				'https://r2.example/latest.json',
				'https://aws.example/latest.json'
			]
		);
		assert.deepEqual(await get('/setup'), { submission: 'not_sent', freed: 1 });
		assert.deepEqual(await get('/channel'), {
			submission: 'execution_unknown',
			freed: 1,
			released: 1
		});
		assert.equal(calls.length, 6);
	} finally {
		await runtime.dispose();
	}
});
