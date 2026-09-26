import { defineConfig } from '@playwright/test';

export default defineConfig({
	fullyParallel: true,
	forbidOnly: true,
	reporter: 'line',
	retries: 0,
	testDir: '.',
	use: {
		browserName: 'chromium',
		headless: true
	}
});
