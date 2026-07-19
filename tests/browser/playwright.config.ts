import { defineConfig } from '@playwright/test';

export default defineConfig({
	fullyParallel: false,
	forbidOnly: true,
	reporter: 'line',
	retries: 0,
	testDir: '.',
	use: {
		browserName: 'chromium',
		headless: true
	},
	workers: 1
});
