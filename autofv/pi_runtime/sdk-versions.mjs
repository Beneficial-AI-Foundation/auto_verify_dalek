import { findPackageJSON } from 'node:module';
import { readFileSync, realpathSync } from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { join, relative, isAbsolute } from 'node:path';
import { reject } from './protocol.mjs';
export const SDK_VERSIONS = Object.freeze({'@earendil-works/pi-ai':'1.2.0','@earendil-works/pi-coding-agent':'1.2.0'});
export function installedSdk(base = import.meta.url) {
  if (Number(process.versions.node.split('.')[0]) < 24) reject('node_version_unsupported');
  const entries = {}, result = {};
  let root; try { root = realpathSync(fileURLToPath(new URL('./node_modules/',base))); } catch { reject('sdk_not_installed'); }
  const lock = JSON.parse(readFileSync(new URL('./package-lock.json',base),'utf8'));
  for (const [location,metadata] of Object.entries(lock.packages ?? {})) {
    if (!location) continue;
    if (!location.startsWith('node_modules/') || location.includes('..')) reject('invalid_package_lock');
    let actual, value;
    try {
      actual = realpathSync(fileURLToPath(new URL(location+'/package.json',base)));
      if (relative(root,actual).startsWith('..') || isAbsolute(relative(root,actual))) reject('sdk_resolution_outside_runtime');
      value = JSON.parse(readFileSync(actual,'utf8'));
    } catch { reject('sdk_dependency_missing'); }
    if (value.version !== metadata.version) reject('sdk_version_drift');
  }
  for (const [name,version] of Object.entries(SDK_VERSIONS)) {
    let path; try { path = findPackageJSON(name,base); } catch { reject('sdk_not_installed'); }
    if (!path) reject('sdk_not_installed');
    const actual = realpathSync(path), expected = join(root,...name.split('/'),'package.json');
    if (actual !== expected || relative(root,actual).startsWith('..') || isAbsolute(relative(root,actual))) reject('sdk_resolution_outside_runtime');
    const value = JSON.parse(readFileSync(path,'utf8'));
    if (value.name !== name || value.version !== version) reject('sdk_version_drift');
    entries[name] = path; result[name] = version;
  }
  if (findPackageJSON('@earendil-works/pi-ai',pathToFileURL(entries['@earendil-works/pi-coding-agent'])) !== entries['@earendil-works/pi-ai']) reject('multiple_pi_ai_instances');
  return result;
}
