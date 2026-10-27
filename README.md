# eudi_lib_sdjwt

EU Digital Identity Wallet **SD-JWT** 库的**仓颉(Cangjie)/ HarmonyOS 移植**,移植自欧盟委员会官方参考实现 [eudi-lib-sdjwt-swift](https://github.com/eu-digital-identity-wallet/eudi-lib-sdjwt-swift)。

实现 IETF [Selective Disclosure for JWTs (SD-JWT)](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) 草案:凭证签发、选择性披露呈现、完整验证管线与 Key Binding JWT。

## 功能

- **签发(Issuer)**:claims → `_sd` digest 数组 + disclosures(含 decoy digest、嵌套对象/数组元素递归、128-bit 随机 salt),ES256 签名输出 compact SD-JWT
- **选择性披露(Presentation)**:从已签凭证选取 disclosure 子集,可附 Key Binding JWT(nonce / aud / sd_hash)
- **验证(Verifier)**:JWS 签名验证 + disclosure digest 对账(重复/缺失检测)+ claims 重建 + KB-JWT 校验;所有错误路径收敛为 `VerificationResult(err:)`,不抛裸异常
- **编解码(Codec)**:IETF compact 格式(`jwt~d1~d2~[kbJwt]`)序列化/解析,全边界形态覆盖
- **摘要(Digest)**:sha-256 / sha-384 / sha-512(`_sd_alg` 可选)
- **真实密码学**:ECDSA P-256 签名经 [eudi_lib_core_crypto](https://github.com/CJPLUK/eudi-lib-hmos-core-crypto)(stdx.crypto → OpenSSL),非模拟实现

## 仓库结构(团队统一 cbor 形态:一库一仓 + 测试 entry)

```
eudi_lib_sdjwt/                    ← 独立 DevEco 工程
├── eudi_cjsdjwt/                  ← HAR 模块(交付单元,output-type=dynamic)
│   ├── cjpm.toml                  ← 包名 ohos_app_cangjie_eudi_cjsdjwt
│   └── src/main/cangjie/sdjwt/
│       ├── model/                 ← Disclosure / SdJwt / SignedSdJwt / Jwt / Keys
│       ├── codec/                 ← CompactSerialiser / CompactParser
│       ├── digest/                ← DigestCreator(sha-256/384/512)
│       ├── factory/               ← SdJwtFactory.createPayload(_sd 构造 + decoy)
│       ├── issuer/                ← SdJwtIssuer.issue / presentation(+KB-JWT)
│       ├── verifier/              ← SdJwtVerifier.verifyIssuance / verifyPresentation
│       └── seam/                  ← 密码学接缝层(见下)
├── entry/                         ← 测试面板 HAP(34 个设备 E2E 用例 + demo 按钮)
│   └── libs/
│       ├── stdx/                  ← cangjie-stdx 1.1.3.1(运行时必需,见下)
│       └── arm64-v8a/             ← libsecurec.so + OpenSSL z.so(运行时三件套)
└── third_party/                   ← (gitignored)core-crypto 锁定 clone
```

### seam 密码学接缝层

业务代码只依赖 `sdjwt.seam` 的 5 个接口(`EcdsaP256` / `Jws` / `Digest` / `Base64Url` / `Rng`,签名与 core-crypto 冻结契约逐字对齐),提供两套可切换实现:

| Provider | 用途 |
|---|---|
| `CoreCryptoProvider`(默认) | 委托 eudi_lib_core_crypto **真 ECDSA P-256**(设备实证) |
| `HostCryptoStub` | host 侧测试兜底(HMAC 代理签名,无 stdx 运行时依赖) |

## 下游消费(cjpm path 依赖)

```bash
git clone https://github.com/CJPLUK/eudi-lib-hmos-sdjwt third_party/eudi_lib_sdjwt
cd third_party/eudi_lib_sdjwt && git checkout v0.1.0
```

消费方 `cjpm.toml`:

```toml
[dependencies]
  [dependencies.ohos_app_cangjie_eudi_cjsdjwt]
    path = "../third_party/eudi_lib_sdjwt/eudi_cjsdjwt"
```

```cangjie
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.issuer.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.verifier.*
```

本库自身依赖 `eudi_lib_core_crypto`(third_party clone @ v0.1.0,见 `eudi_cjsdjwt/cjpm.toml`),首次构建前需:

```bash
git clone https://github.com/CJPLUK/eudi-lib-hmos-core-crypto third_party/eudi_lib_core_crypto
cd third_party/eudi_lib_core_crypto && git checkout v0.1.0
```

### ⚠ 设备运行时三件套(缺一必崩,详见团队 lib-packaging-spec §7)

1. **stdx 必须 1.1.3.1 正式版**(`entry/libs/stdx/`,本仓已带)——SDK 自带 beta 版在设备运行时 `index < funcTableSize` cppcrash
2. **libsecurec.so**(`entry/libs/arm64-v8a/`,本仓已带)——所有 libstdx.*.so 的 NEEDED 依赖
3. **OpenSSL z.so 对**(同目录,本仓已带)——stdx.crypto 运行时 dlopen,app 命名空间够不到系统库

hvigor 会把 cjpm path 依赖产物(`libeudi_lib_core_crypto.so`)及以上三件套自动打进 HAP,无需额外配置(已实证)。

## 构建

要求:DevEco Studio(含 OpenHarmony SDK)+ Cangjie SDK(cjc 1.1.3+)。

```bash
source <cangjie-sdk>/build-tools/envsetup.sh
export DEVECO_CANGJIE_HOME=<cangjie-sdk>
export DEVECO_OH_NATIVE_HOME=<DevEco>/sdk/default/openharmony/native
export AARCH64_LIBS=$DEVECO_CANGJIE_HOME/api/lib/linux_ohos_aarch64_cjnative/ohos
export AARCH64_MACRO_LIBS=$DEVECO_CANGJIE_HOME/api/macro/ohos
export AARCH64_KIT_LIBS=$DEVECO_CANGJIE_HOME/api/lib/linux_ohos_aarch64_cjnative/kit
export COMPILE_CONDITION="APILevel_level=24,product=default,APILevel_syscap=<repo>/.idea/.deveco/cangjie/syscap_api_config.json,target=default"
export COMPILE_CONDITION_ENTRY="$COMPILE_CONDITION"

cd eudi_cjsdjwt && cjpm build --target aarch64-linux-ohos   # HAR 模块
cd ../entry    && cjpm build --target aarch64-linux-ohos   # 测试面板
```

整 HAP 打包/上设备建议走 DevEco IDE(assembleHap);测试面板 app 内点 **Run SD-JWT Demo** 即跑通"签发→呈现→验证"全链并显示结果。

## 测试与验证

- **34 个设备端 E2E 用例**(`entry/src/main/cangjie/unittest_engine.cj`,OpenHarmonyTestRunner):model 往返 / codec 4 边界 / digest IETF 已知向量 / factory payload 断言 / issuer↔verifier 端到端 / 4 个负例(篡改 disclosure/签名、缺 `_sd_alg`、KB-JWT nonce 错)/ 真 ECDSA 签验 / 平台行为探针
- **30+ host 单测**(`eudi_cjsdjwt/src/test/cangjie/`)
- digest 与 iOS 原库测试向量逐字节一致;JWS 遵循 RFC 7515 / 7518(ES256 raw r||s 64B)

## 已知平台注意事项(S-018)

aarch64-linux-ohos 设备上,`for (ch in someString)` 迭代产出的 Rune 调用 `toString()` 会返回**十进制码点**("ab"→"9798");host 上正常,host 单测对此失明。本库所有字符串重建均使用 `Rune.intoUtf8Array + String.fromUtf8` 字节精确路径规避。二次开发请遵循同一纪律。

## License

[Apache License 2.0](LICENSE)。本项目为 eudi-lib-sdjwt-swift(© European Commission)的衍生移植,归属声明见 [NOTICE](NOTICE)。
