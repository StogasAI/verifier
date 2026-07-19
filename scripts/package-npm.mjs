#!/usr/bin/env node

import { cpSync, copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const npmArguments = process.argv.slice(2);
const destinationIndex = npmArguments.indexOf('--pack-destination');

if (destinationIndex >= 0) {
	const destination = npmArguments[destinationIndex + 1];
	if (!destination) throw new Error('--pack-destination requires a directory');
	if (!isAbsolute(destination))
		npmArguments[destinationIndex + 1] = resolve(repositoryRoot, destination);
}

function pack(directory) {
	const result = spawnSync('npm', ['pack', ...npmArguments], {
		cwd: directory,
		stdio: 'inherit'
	});
	if (result.error) throw result.error;
	if (result.status !== 0) process.exit(result.status ?? 1);
}

pack(repositoryRoot);

const stagingRoot = mkdtempSync(join(tmpdir(), 'stogas-offline-sigstore-'));
try {
	cpSync(resolve(repositoryRoot, 'packages/offline-sigstore'), stagingRoot, { recursive: true });
	copyFileSync(resolve(repositoryRoot, 'LICENSE'), resolve(stagingRoot, 'LICENSE'));
	pack(stagingRoot);
} finally {
	rmSync(stagingRoot, { force: true, recursive: true });
}
