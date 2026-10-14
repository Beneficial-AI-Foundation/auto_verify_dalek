/** Offline inspection only. This command never initializes Pi or reads authentication. */
import { readFileSync } from 'node:fs';
import { qualification } from './policy.mjs';
import { installedSdk } from './sdk-versions.mjs';

const path = process.argv[2] ?? new URL('./profile.example.json', import.meta.url);
const report = qualification(JSON.parse(readFileSync(path, 'utf8')));
try { report.installedVersions = installedSdk(); }
catch (error) { report.installedVersions = null; report.blockers.push(error.code ?? 'sdk_metadata_unavailable'); }
report.callable = report.blockers.length === 0;
console.log(JSON.stringify(report, null, 2));
