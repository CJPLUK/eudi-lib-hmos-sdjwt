import { appTasks } from '@ohos/hvigor-ohos-plugin';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

// Auto-fetch sibling TPC deps (transitive closure) when missing; no-op in a
// shared workspace/shell third_party (siblings exist). cjpm uses ../../<dep>.
(function syncSiblingDeps() {
  const DEPS = [
    { name: 'eudi_lib_core_crypto', url: 'https://github.com/CJPLUK/eudi-lib-hmos-core-crypto', ref: 'v0.1.0' },
  ];
  const root = path.resolve(__dirname, '..');
  for (const d of DEPS) {
    const dst = path.join(root, d.name);
    if (fs.existsSync(dst)) continue;
    try {
      console.log(`[deps] cloning ${d.name} -> ${dst}`);
      execSync(`git clone --quiet "${d.url}" "${dst}"`, { stdio: 'inherit' });
      execSync(`git -C "${dst}" fetch --quiet --tags`, { stdio: 'inherit' });
      execSync(`git -C "${dst}" checkout --quiet ${d.ref}`, { stdio: 'inherit' });
    } catch (e) { console.error(`[deps] failed ${d.name}: ${e}`); }
  }
})();

export default { system: appTasks, plugins: [] }
