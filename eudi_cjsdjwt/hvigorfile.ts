import { harTasks } from '@ohos/hvigor-ohos-plugin';
import * as path from 'path';
import * as os from 'os';

// Patch ValidatorStore so cangjieOptions is accepted in build-profile.json5 (HAR module).
// Generates the patched schema in-memory from the standard hvigor schema + Cangjie SDK config.
(function patchCangjieHarSchema() {
  try {
    const fs = require('fs') as typeof import('fs');
    const { ValidatorStore } = require('@ohos/hvigor-ohos-plugin/src/utils/validate/validator-store');
    const { BuildProfileSchemaFileConst } = require('@ohos/hvigor-ohos-plugin/src/const/common-const');

    const stdSchemaPath: string = BuildProfileSchemaFileConst.HAR_MODULE_BUILD_PROFILE_SCHEMA_PATH;
    if (!fs.existsSync(stdSchemaPath)) return;

    // Find Cangjie SDK cangjie-har-schema-config.json
    const homedir = os.homedir();
    const cjSdkCandidates = [
      path.join(homedir, '.cangjie-sdk', '6.1', 'cangjie', 'build-tools', 'tools', 'hvigor', 'cangjie-build-support', 'res', 'cangjie-har-schema-config.json'),
      path.join(homedir, '.cangjie-sdk', '6.0', 'cangjie', 'build-tools', 'tools', 'hvigor', 'cangjie-build-support', 'res', 'cangjie-har-schema-config.json'),
    ];
    const cjHome = process.env['CANGJIE_HOME'];
    if (cjHome) {
      cjSdkCandidates.unshift(path.join(cjHome, 'build-tools', 'tools', 'hvigor', 'cangjie-build-support', 'res', 'cangjie-har-schema-config.json'));
    }
    let cjSchemaConfig: any = null;
    for (const c of cjSdkCandidates) {
      if (fs.existsSync(c)) { cjSchemaConfig = JSON.parse(fs.readFileSync(c, 'utf-8')); break; }
    }
    if (!cjSchemaConfig) {
      // Fallback: inline minimal cangjieOptions definition
      cjSchemaConfig = { cangjieOptionsConfig: { cangjieOptions: { type: 'object', properties: { path: { type: 'string' } }, additionalProperties: true } } };
    }

    const cangjieHarOptions = cjSchemaConfig.cangjieOptionsConfig;

    // Build patched schema in-memory
    const schema = JSON.parse(fs.readFileSync(stdSchemaPath, 'utf-8'));
    // Allow cangjieOptions in buildOption.properties
    const boDef = schema.definitions && schema.definitions.buildOption;
    if (boDef) {
      if (boDef.propertyNames && Array.isArray(boDef.propertyNames.enum) && !boDef.propertyNames.enum.includes('cangjieOptions')) {
        boDef.propertyNames.enum.push('cangjieOptions');
      }
      if (boDef.properties) {
        Object.assign(boDef.properties, cangjieHarOptions);
      }
    }
    // Also patch top-level properties.buildOption if present
    const topBo = schema.properties && schema.properties.buildOption;
    if (topBo) {
      if (topBo.propertyNames && Array.isArray(topBo.propertyNames.enum) && !topBo.propertyNames.enum.includes('cangjieOptions')) {
        topBo.propertyNames.enum.push('cangjieOptions');
      }
    }
    // Patch then.properties.buildOption if present
    if (schema.then && schema.then.properties && schema.then.properties.buildOption) {
      const thenBo = schema.then.properties.buildOption;
      if (thenBo.propertyNames && Array.isArray(thenBo.propertyNames.enum) && !thenBo.propertyNames.enum.includes('cangjieOptions')) {
        thenBo.propertyNames.enum.push('cangjieOptions');
      }
    }

    // Write to a temp file
    const tmpPath = path.join(os.tmpdir(), 'ohos-har-module-build-profile-schema-cj-patched.json');
    fs.writeFileSync(tmpPath, JSON.stringify(schema), 'utf-8');

    const validator = ValidatorStore.addValidator(tmpPath, false);
    ValidatorStore.getValidatorMap().set(`${stdSchemaPath}:false`, validator);
  } catch (_) { /* best-effort */ }
})();

export default {
    system: harTasks,  /* Built-in plugin of Hvigor. It cannot be modified. */
    plugins:[]         /* Custom plugin to extend the functionality of Hvigor. */
}
