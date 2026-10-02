import { chromium, firefox, webkit, expect, test } from '@playwright/test';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { homedir } from 'node:os';
import { delimiter, resolve } from 'node:path';
import { promisify } from 'node:util';

const root = resolve(import.meta.dirname, '../..');
const environment = {
	...process.env,
	PATH: `${resolve(process.env.CARGO_HOME ?? resolve(homedir(), '.cargo'), 'bin')}${delimiter}${process.env.PATH ?? ''}`,
	CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER: 'wasm-bindgen-test-runner'
};

// Exercise the private adapter and cancellation state without shipping test exports.
// The same optimized Wasm test artifact runs in Node and each real browser engine.
// Match the shipped optimization profile for the full cryptographic vector sets.
for (const cargoPackage of ['stogas-verifier-wasm', 'stogas-verifier']) {
	test(`${cargoPackage}: cryptography contracts hold across JavaScript runtimes`, async () => {
		test.setTimeout(480_000);
		const { stdout } = await promisify(execFile)(
			'cargo',
			[
				'test',
				'--locked',
				'--release',
				'--package',
				cargoPackage,
				'--lib',
				'--target',
				'wasm32-unknown-unknown',
				'--message-format=json'
			],
			{ cwd: root, env: environment, maxBuffer: 16 * 1024 * 1024 }
		);
		const artifact = stdout
			.split('\n')
			.filter((line) => line.startsWith('{'))
			.map((line) => JSON.parse(line))
			.find(
				(item) =>
					item.reason === 'compiler-artifact' &&
					item.target.name === cargoPackage.replaceAll('-', '_') &&
					item.profile.test
			);
		expect(artifact?.executable).toBeTruthy();
		expect(stdout).toMatch(/test result: ok\. [1-9]\d* passed; 0 failed/);
		const server = spawn('wasm-bindgen-test-runner', [artifact.executable], {
			cwd: root,
			env: {
				...environment,
				WASM_BINDGEN_USE_BROWSER: '1',
				NO_HEADLESS: '1',
				WASM_BINDGEN_TEST_ADDRESS: '127.0.0.1:0'
			},
			stdio: ['ignore', 'pipe', 'pipe']
		});
		const exited = once(server, 'exit');
		try {
			const address = await new Promise<string>((resolve, reject) => {
				let output = '';
				const deadline = setTimeout(
					() => reject(new Error(`Wasm test server startup timed out: ${output}`)),
					30_000
				);
				server.on('error', (error) => {
					clearTimeout(deadline);
					reject(error);
				});
				server.on('exit', (code) => {
					clearTimeout(deadline);
					reject(new Error(`Wasm test server exited (${code}): ${output}`));
				});
				server.stderr.on('data', (bytes) => {
					output += bytes.toString();
				});
				server.stdout.on('data', (bytes) => {
					output += bytes.toString();
					const match = output.match(
						/Interactive browsers tests are now available at (http:\/\/127\.0\.0\.1:\d+)/
					);
					if (match) {
						clearTimeout(deadline);
						resolve(match[1]);
					}
				});
			});
			for (const [name, engine] of Object.entries({ chromium, firefox, webkit })) {
				const browser = await engine.launch({ headless: true });
				try {
					const page = await browser.newPage();
					const failures: string[] = [];
					let currentTest = '';
					page.on('console', (message) => {
						if (message.text().startsWith('Invoking test:')) currentTest = message.text();
					});
					page.on('pageerror', (error) => failures.push(error.message));
					await page.goto(address);
					await expect
						.poll(
							async () => {
								if (failures.length) throw new Error(`${name}: ${failures.join('; ')}`);
								return `${currentTest}\n${await page.locator('body').innerText()}`;
							},
							{ message: name, timeout: 120_000 }
						)
						.toContain('test result:');
					const output = await page.locator('body').innerText();
					expect(output, name).toMatch(/test result: ok\. [1-9]\d* passed; 0 failed/);
				} finally {
					await browser.close();
				}
			}
		} finally {
			server.kill();
			await exited;
		}
	});
}
