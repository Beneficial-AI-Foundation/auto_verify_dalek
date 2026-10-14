import { findPackageJSON } from 'node:module';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { SDK_VERSIONS, reject } from './policy.mjs';

/** Inspect package metadata only; never call the runtime, catalog network, or auth APIs. */
export function installedSdk(base = import.meta.url) {
  const versions = {};
  const entries = {};
  for (const [name, expected] of Object.entries(SDK_VERSIONS)) {
    let file;
    try { file = findPackageJSON(name, base); } catch { reject('sdk_not_installed'); }
    if (!file) reject('sdk_not_installed');
    entries[name] = file;
    const metadata = JSON.parse(readFileSync(file, 'utf8'));
    if (metadata.name !== name || metadata.version !== expected) reject('sdk_version_drift');
    versions[name] = metadata.version;
  }
  for (const entry of Object.values(entries)) {
    if (findPackageJSON('@earendil-works/pi-ai', pathToFileURL(entry)) !== entries['@earendil-works/pi-ai']) {
      reject('multiple_pi_ai_instances');
    }
  }
  return versions;
}
