import { hapTasks } from '@ohos/hvigor-ohos-plugin';
import * as path from 'path';
import * as os from 'os';

// Patch ValidatorStore so cangjieOptions is accepted in build-profile.json5 (HAP module).
// Generates the patched schema in-memory from the standard hvigor schema + Cangjie SDK config.
(function patchCangjieHapSchema() {
  try {
    const fs = require('fs') as typeof import('fs');
    const { ValidatorStore } = require('@ohos/hvigor-ohos-plugin/src/utils/validate/validator-store');
    const { BuildProfileSchemaFileConst } = require('@ohos/hvigor-ohos-plugin/src/const/common-const');

    const stdSchemaPath: string = BuildProfileSchemaFileConst.HAP_MODULE_BUILD_PROFILE_SCHEMA_PATH;
    if (!fs.existsSync(stdSchemaPath)) return;

    // Find Cangjie SDK cangjie-schema-config.json
    const homedir = os.homedir();
    const cjSdkCandidates = [
      path.join(homedir, '.cangjie-sdk', '6.1', 'cangjie', 'build-tools', 'tools', 'hvigor', 'cangjie-build-support', 'res', 'cangjie-schema-config.json'),
      path.join(homedir, '.cangjie-sdk', '6.0', 'cangjie', 'build-tools', 'tools', 'hvigor', 'cangjie-build-support', 'res', 'cangjie-schema-config.json'),
    ];
    // Also search $CANGJIE_HOME env
    const cjHome = process.env['CANGJIE_HOME'];
    if (cjHome) {
      cjSdkCandidates.unshift(path.join(cjHome, 'build-tools', 'tools', 'hvigor', 'cangjie-build-support', 'res', 'cangjie-schema-config.json'));
    }
    let cjSchemaConfig: any = null;
    for (const c of cjSdkCandidates) {
      if (fs.existsSync(c)) { cjSchemaConfig = JSON.parse(fs.readFileSync(c, 'utf-8')); break; }
    }
    if (!cjSchemaConfig) {
      // Fallback: inline minimal cangjieOptions definition so build works even without SDK config
      cjSchemaConfig = { cangjieOptionsConfig: { cangjieOptions: { type: 'object', properties: { path: { type: 'string' } }, additionalProperties: true } } };
    }

    const cangjieOptionsDef = cjSchemaConfig.cangjieOptionsConfig;

    // Build patched schema in-memory
    const schema = JSON.parse(fs.readFileSync(stdSchemaPath, 'utf-8'));
    // 1. Add cangjieOptions definition
    if (!schema.definitions) schema.definitions = {};
    Object.assign(schema.definitions, cangjieOptionsDef);
    // 2. Allow cangjieOptions in buildOption propertyNames enum
    const boDef = schema.definitions && schema.definitions.buildOption;
    if (boDef) {
      if (boDef.propertyNames && Array.isArray(boDef.propertyNames.enum) && !boDef.propertyNames.enum.includes('cangjieOptions')) {
        boDef.propertyNames.enum.push('cangjieOptions');
      }
      if (boDef.properties && !boDef.properties.cangjieOptions) {
        boDef.properties.cangjieOptions = { $ref: '#/definitions/cangjieOptions' };
      }
    }
    // 3. Allow cangjieOptions in buildOptionSetItems
    const boSetDef = schema.definitions && schema.definitions.buildOptionSetItems;
    if (boSetDef) {
      if (boSetDef.propertyNames && Array.isArray(boSetDef.propertyNames.enum) && !boSetDef.propertyNames.enum.includes('cangjieOptions')) {
        boSetDef.propertyNames.enum.push('cangjieOptions');
      }
      if (boSetDef.properties && !boSetDef.properties.cangjieOptions) {
        boSetDef.properties.cangjieOptions = { $ref: '#/definitions/cangjieOptions' };
      }
    }

    // Write to a temp file (ValidatorStore.addValidator needs a path)
    const tmpPath = path.join(os.tmpdir(), 'ohos-module-build-profile-schema-cj-patched.json');
    fs.writeFileSync(tmpPath, JSON.stringify(schema), 'utf-8');

    const validator = ValidatorStore.addValidator(tmpPath, false);
    ValidatorStore.getValidatorMap().set(`${stdSchemaPath}:false`, validator);
  } catch (_) { /* best-effort */ }
})();

export default {
  system: hapTasks, /* Built-in plugin of Hvigor. It cannot be modified. */
  plugins: []       /* Custom plugin to extend the functionality of Hvigor. */
}
