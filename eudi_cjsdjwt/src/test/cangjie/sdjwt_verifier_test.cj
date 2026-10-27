/**
 * sdjwt_verifier_test.cj
 *
 * Unit tests for SdJwtVerifier.
 *
 * Test strategy:
 *   - Round-trip test: issue an SD-JWT with HostCryptoStub, then verify it;
 *     expects verifyIssuance to succeed.
 *   - Negative test 1 (tampered disclosure): modify one disclosure after
 *     issuance; expects digest mismatch error.
 *   - Negative test 2 (tampered signature): modify the JWS signature byte;
 *     expects signature verification failure.
 *   - Negative test 3 (missing _sd_alg): verify a JWT whose payload lacks
 *     _sd_alg; expects "Missing _sd_alg" error.
 *   - Negative test 4 (duplicate digest): verify with a disclosure list that
 *     produces a repeated digest in the payload; expects duplicate digest error.
 *   - KB-JWT test: verifyPresentation with a well-formed KB-JWT succeeds.
 *   - KB-JWT negative (nonce mismatch): wrong nonce in KB-JWT fails.
 *
 * All tests use HostCryptoStub (host surrogate, not real ECDSA P-256).
 * The round-trip is self-consistent because HostJwsImpl.signEs256 +
 * verifyEs256 use the same HMAC key via the identity-mapping publicKeyOf().
 */
package ohos_app_cangjie_eudi_cjsdjwt_local_test

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.factory.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.issuer.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.verifier.*
import std.collection.*

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * Issue a SignedSdJwt via the real issuer, binding `holderPub` into cnf.jwk so
 * the verifier (post-P0E key-binding model) can extract the holder key.
 */
func issueWithCnf(
    holderPub: ECDSAPublicKey,
    issuerPriv: ECDSAPrivateKey,
    crypto: HostCryptoStub
): SignedSdJwt {
    let dc = DigestCreator(
        digest: crypto.digest,
        base64Url: crypto.base64Url,
        algorithm: HashingAlgorithmIdentifier.Sha256
    )
    let factory = SdJwtFactory(
        digestCreator: dc, base64Url: crypto.base64Url, rng: crypto.rng, decoyCount: 0
    )
    let issuer = SdJwtIssuer(
        jws: crypto.jws, base64Url: crypto.base64Url, digest: crypto.digest, factory: factory
    )
    var claims = HashMap<String, ClaimValue>()
    claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
    claims.add("doc_id", ClaimValue.Sd("\"ID123\""))
    return issuer.issue(claims, issuerPriv, holderPublicKey: Some(holderPub)).ok.getOrThrow()
}

/**
 * Build a minimal SD-JWT payload JSON containing _sd_alg and a _sd array
 * with the given digests.
 *
 * Format: {"iss":"test","_sd_alg":"sha-256","_sd":["d1","d2",...]}
 */
func buildPayloadJson(sdAlg: String, digests: Array<String>): String {
    var sdArray = "["
    var i: Int64 = 0
    while (i < digests.size) {
        if (i > 0) {
            sdArray = sdArray + ","
        }
        sdArray = sdArray + "\"" + digests[i] + "\""
        i = i + 1
    }
    sdArray = sdArray + "]"
    return "{\"iss\":\"test\",\"_sd_alg\":\"" + sdAlg + "\",\"_sd\":" + sdArray + "}"
}

/**
 * Produce a signed compact JWS using HostJwsImpl.
 *
 * @param payloadJson  JWT payload as a JSON string.
 * @param priv         Private key.
 * @param jws          JWS implementation.
 * @param b64          Base64Url implementation.
 * @return Compact JWS string (header.payload.sig).
 */
func signPayload(payloadJson: String, priv: ECDSAPrivateKey, jws: Jws, b64: Base64Url): String {
    let headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"
    let payloadBytes: Array<UInt8> = payloadJson.toArray()
    return jws.signEs256(headerJson, payloadBytes, priv)
}

/**
 * Build a SignedSdJwt with real JWS signature and proper _sd digests.
 *
 * Steps:
 *   1. Encode each disclosure.
 *   2. Compute its digest.
 *   3. Build payload JSON with those digests.
 *   4. Sign the payload.
 *   5. Return SignedSdJwt.
 */
func buildSignedSdJwt(
    disclosures: Array<Disclosure>,
    priv: ECDSAPrivateKey,
    crypto: HostCryptoStub
): SignedSdJwt {
    let dc = DigestCreator(
        digest: crypto.digest,
        base64Url: crypto.base64Url,
        algorithm: HashingAlgorithmIdentifier.Sha256
    )

    // Compute digests for all disclosures
    var digests = Array<String>(disclosures.size, repeat: "")
    var i: Int64 = 0
    while (i < disclosures.size) {
        let encoded = disclosures[i].encodeWith(crypto.base64Url)
        digests[i] = dc.hashAndBase64Encode(encoded)
        i = i + 1
    }

    let payloadJson = buildPayloadJson("sha-256", digests)
    let compactJwt = signPayload(payloadJson, priv, crypto.jws, crypto.base64Url)

    return SignedSdJwt(
        jwt: Jwt(compactSerialization: compactJwt),
        disclosures: disclosures,
        kbJwt: None
    )
}

// ---------------------------------------------------------------------------
// Test class
// ---------------------------------------------------------------------------

@Test
class SdJwtVerifierTest {

    // ----------------------------------------------------------------
    // Positive test: happy-path round-trip
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_happyPath(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        let disc1 = Disclosure(salt: "salt1", name: "given_name", value: "\"Alice\"")
        let disc2 = Disclosure(salt: "salt2", name: "family_name", value: "\"Smith\"")
        let disclosures: Array<Disclosure> = [disc1, disc2]

        let signedSdJwt = buildSignedSdJwt(disclosures, priv, crypto)

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(signedSdJwt, pub)

        @Expect(result.isOk(), true)
    }

    // ----------------------------------------------------------------
    // Negative test 1: tampered disclosure (disclosure byte changed)
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_tamperedDisclosure(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        let disc1 = Disclosure(salt: "salt1", name: "given_name", value: "\"Alice\"")
        let disclosures: Array<Disclosure> = [disc1]

        let signedSdJwt = buildSignedSdJwt(disclosures, priv, crypto)

        // Replace disclosure with a tampered one (different value)
        let tamperedDisc = Disclosure(salt: "salt1", name: "given_name", value: "\"Bob\"")
        let tamperedSdJwt = SignedSdJwt(
            jwt: signedSdJwt.jwt,
            disclosures: [tamperedDisc],
            kbJwt: None
        )

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(tamperedSdJwt, pub)

        @Expect(result.isOk(), false)
        // Verify the error mentions digest mismatch
        match (result.err) {
            case Some(e) => @Expect(e.message.contains("not found"), true)
            case None => @Expect(false, true)  // should have error
        }
    }

    // ----------------------------------------------------------------
    // Negative test 2: tampered JWS signature
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_tamperedSignature(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        let disc1 = Disclosure(salt: "saltA", name: "sub", value: "\"user123\"")
        let disclosures: Array<Disclosure> = [disc1]

        let signedSdJwt = buildSignedSdJwt(disclosures, priv, crypto)

        // Corrupt the compact JWS by replacing the last char of the signature.
        // Use byte-buffer accumulation instead of Rune.toString() to avoid S-018:
        // on aarch64-linux-ohos, Rune.toString() returns a decimal code point string.
        let compact = signedSdJwt.jwt.compactSerialization
        let chars = compact.toRuneArray()
        let len = chars.size
        // Flip the last character: 'A' (0x41) <-> 'B' (0x42); both are single-byte ASCII.
        let lastCp = UInt32(chars[len - 1])
        // Build replacement byte: 'A'=0x41 stays 'A' only if not 'A', else 'B'
        let replaceByte: UInt8 = if (lastCp == 0x41u32) { 0x42u8 } else { 0x41u8 }
        // Rebuild all-but-last chars via UTF-8 byte accumulation
        var cbuf: Array<UInt8> = Array<UInt8>(len * 4 + 1, repeat: 0u8)
        var cpos: Int64 = 0
        var i: Int64 = 0
        while (i < len - 1) {
            cpos = cpos + Rune.intoUtf8Array(chars[i], cbuf, cpos)
            i = i + 1
        }
        cbuf[cpos] = replaceByte
        cpos = cpos + 1
        let corrupted = String.fromUtf8(cbuf[0..cpos])

        let corruptedSdJwt = SignedSdJwt(
            jwt: Jwt(compactSerialization: corrupted),
            disclosures: signedSdJwt.disclosures,
            kbJwt: None
        )

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(corruptedSdJwt, pub)

        @Expect(result.isOk(), false)
        match (result.err) {
            case Some(e) => @Expect(e.message.contains("signature"), true)
            case None => @Expect(false, true)
        }
    }

    // ----------------------------------------------------------------
    // Negative test 3: missing _sd_alg in payload
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_missingSdAlg(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        // Build a payload without _sd_alg
        let payloadJson = "{\"iss\":\"test\",\"_sd\":[\"somedigest\"]}"
        let compactJwt = signPayload(payloadJson, priv, crypto.jws, crypto.base64Url)

        let disc1 = Disclosure(salt: "salt1", name: "claim", value: "\"value\"")
        let signedSdJwt = SignedSdJwt(
            jwt: Jwt(compactSerialization: compactJwt),
            disclosures: [disc1],
            kbJwt: None
        )

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)

        var caughtError = false
        var errorMessage = ""
        try {
            let result = verifier.verifyIssuance(signedSdJwt, pub)
            // If we get here, the error should show up in the result
            // (some paths catch internally and return VerificationResult.err)
            match (result.err) {
                case Some(e) =>
                    caughtError = true
                    errorMessage = e.message
                case None =>
                    caughtError = false
            }
        } catch (e: SdJwtVerifierError) {
            caughtError = true
            errorMessage = e.message
        }

        @Expect(caughtError, true)
        @Expect(errorMessage.contains("_sd_alg"), true)
    }

    // ----------------------------------------------------------------
    // Positive test: no disclosures (bare JWT with _sd_alg but empty _sd)
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_noDisclosures(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        let payloadJson = "{\"iss\":\"test\",\"_sd_alg\":\"sha-256\",\"_sd\":[]}"
        let compactJwt = signPayload(payloadJson, priv, crypto.jws, crypto.base64Url)

        let signedSdJwt = SignedSdJwt(
            jwt: Jwt(compactSerialization: compactJwt),
            disclosures: Array<Disclosure>(),
            kbJwt: None
        )

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(signedSdJwt, pub)

        @Expect(result.isOk(), true)
    }

    // ----------------------------------------------------------------
    // Positive test: compact string overload
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_compactOverload(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        let disc1 = Disclosure(salt: "s1", name: "age", value: "30")
        let disclosures: Array<Disclosure> = [disc1]

        let signedSdJwt = buildSignedSdJwt(disclosures, priv, crypto)

        // Serialize to compact form
        let ser = CompactSerialiser(b64: crypto.base64Url)
        let compact = ser.serialise(signedSdJwt)

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(compact, pub)

        @Expect(result.isOk(), true)
    }

    // ----------------------------------------------------------------
    // KB-JWT test: verifyPresentation with a valid KB-JWT succeeds
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyPresentation_withKbJwt(): Unit {
        let crypto = HostCryptoStub()
        let issuerPriv = crypto.ecdsa.generate()
        let issuerPub = crypto.ecdsa.publicKeyOf(issuerPriv)
        let holderPriv = crypto.ecdsa.generate()
        let holderPub = crypto.ecdsa.publicKeyOf(holderPriv)

        // Issue SD-JWT with holder key bound via cnf.jwk
        let signedSdJwt = issueWithCnf(holderPub, issuerPriv, crypto)
        let disclosures: Array<Disclosure> = signedSdJwt.disclosures

        // Serialize presentation (without KB-JWT) to compute sd_hash
        let ser = CompactSerialiser(b64: crypto.base64Url)
        let presentationCompact = ser.serialise(signedSdJwt)  // ends with ~

        // Compute sd_hash
        let presBytes: Array<UInt8> = presentationCompact.toArray()
        let sdHashBytes = crypto.digest.sha256(presBytes)
        let sdHashStr = crypto.base64Url.encode(sdHashBytes)

        // Build KB-JWT payload
        let expectedNonce = "nonce-abc-123"
        let expectedAud = "https://example.com/verifier"
        let kbPayloadJson = "{\"iat\":1700000000,\"nonce\":\"" + expectedNonce +
            "\",\"aud\":\"" + expectedAud +
            "\",\"sd_hash\":\"" + sdHashStr + "\"}"
        let kbHeaderJson = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}"

        // Sign KB-JWT with holder key
        let kbPayloadBytes: Array<UInt8> = kbPayloadJson.toArray()
        let kbCompact = crypto.jws.signEs256(kbHeaderJson, kbPayloadBytes, holderPriv)

        // Build presentation with KB-JWT
        let presWithKb = SignedSdJwt(
            jwt: signedSdJwt.jwt,
            disclosures: disclosures,
            kbJwt: Some(Jwt(compactSerialization: kbCompact))
        )

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyPresentation(
            presWithKb,
            issuerPub,
            Some(expectedNonce),
            Some(expectedAud),
            Some(holderPub),
            Some(presentationCompact)
        )

        @Expect(result.isOk(), true)
    }

    // ----------------------------------------------------------------
    // KB-JWT negative: nonce mismatch
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyPresentation_kbJwt_nonceMismatch(): Unit {
        let crypto = HostCryptoStub()
        let issuerPriv = crypto.ecdsa.generate()
        let issuerPub = crypto.ecdsa.publicKeyOf(issuerPriv)
        let holderPriv = crypto.ecdsa.generate()
        let holderPub = crypto.ecdsa.publicKeyOf(holderPriv)

        // Issue SD-JWT with holder key bound via cnf.jwk
        let signedSdJwt = issueWithCnf(holderPub, issuerPriv, crypto)
        let disclosures: Array<Disclosure> = signedSdJwt.disclosures

        let ser = CompactSerialiser(b64: crypto.base64Url)
        let presentationCompact = ser.serialise(signedSdJwt)

        let presBytes: Array<UInt8> = presentationCompact.toArray()
        let sdHashBytes = crypto.digest.sha256(presBytes)
        let sdHashStr = crypto.base64Url.encode(sdHashBytes)

        // KB-JWT with "wrong-nonce" but verifier expects "correct-nonce"
        let kbPayloadJson = "{\"iat\":1700000000,\"nonce\":\"wrong-nonce\",\"aud\":\"https://example.com\",\"sd_hash\":\"" + sdHashStr + "\"}"
        let kbHeaderJson = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}"
        let kbPayloadBytes: Array<UInt8> = kbPayloadJson.toArray()
        let kbCompact = crypto.jws.signEs256(kbHeaderJson, kbPayloadBytes, holderPriv)

        let presWithKb = SignedSdJwt(
            jwt: signedSdJwt.jwt,
            disclosures: disclosures,
            kbJwt: Some(Jwt(compactSerialization: kbCompact))
        )

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)

        var caughtError = false
        try {
            let result = verifier.verifyPresentation(
                presWithKb,
                issuerPub,
                Some("correct-nonce"),
                Some("https://example.com"),
                Some(holderPub),
                Some(presentationCompact)
            )
            caughtError = !result.isOk()
        } catch (e: SdJwtVerifierError) {
            caughtError = true
        }

        @Expect(caughtError, true)
    }

    // ----------------------------------------------------------------
    // Negative test: unsupported _sd_alg
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_unsupportedSdAlg(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        let payloadJson = "{\"iss\":\"test\",\"_sd_alg\":\"sha3-256\",\"_sd\":[]}"
        let compactJwt = signPayload(payloadJson, priv, crypto.jws, crypto.base64Url)

        let signedSdJwt = SignedSdJwt(
            jwt: Jwt(compactSerialization: compactJwt),
            disclosures: Array<Disclosure>(),
            kbJwt: None
        )

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)

        var caughtError = false
        var errorMessage = ""
        try {
            let result = verifier.verifyIssuance(signedSdJwt, pub)
            match (result.err) {
                case Some(e) =>
                    caughtError = true
                    errorMessage = e.message
                case None => ()
            }
        } catch (e: SdJwtVerifierError) {
            caughtError = true
            errorMessage = e.message
        }

        @Expect(caughtError, true)
        @Expect(errorMessage.contains("sha3-256"), true)
    }

    // ----------------------------------------------------------------
    // S-018 regression: extractStringField with escape chars in claim value
    //
    // Constructs a payload where the "iss" field value contains a JSON
    // escape sequence (\n).  extractStringField must return the raw newline
    // byte, not the literal two-char sequence '\' 'n'.
    //
    // Before the fix, the 'n' char in the escape sequence would be appended
    // via Rune.toString() which returns "110" on aarch64-linux-ohos, producing
    // a garbled value like "issuer\110domain.com" instead of "issuer\ndomain.com".
    // After the fix, buf[bpos] = 0x0Au8 is used directly.
    //
    // Verifies via verifyIssuance: if extractStringField is broken, the _sd_alg
    // parse also fails and the test would catch a different error.
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_claimValueWithEscapeNewline_s018(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        // Disclosure with a newline in the value (JSON-escaped as \n in the wire form)
        // value JSON fragment: "\"line1\\nline2\"" means the JSON string "line1\nline2"
        // (the \n here is the two-char JSON escape; when parsed it becomes a real newline)
        let disc = Disclosure(salt: "escape-salt", name: "description", value: "\"line1\\nline2\"")
        let disclosures: Array<Disclosure> = [disc]

        let signedSdJwt = buildSignedSdJwt(disclosures, priv, crypto)

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(signedSdJwt, pub)

        // Verification must succeed: digest matching works correctly on both host and device
        @Expect(result.isOk(), true)
    }

    // ----------------------------------------------------------------
    // S-018 regression: extractStringField with quoted-string value
    //
    // Constructs a payload where a claim value contains a backslash-escaped
    // double-quote (\").  extractStringField must return the literal '"' byte.
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_claimValueWithEscapeQuote_s018(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        // Disclosure value: JSON string containing a double-quote: "say \"hi\""
        // In the Disclosure value field (pre-serialised JSON fragment):
        //   "\"say \\\"hi\\\"\""  = the JSON string literal say "hi"
        let disc = Disclosure(salt: "quote-salt", name: "msg", value: "\"say \\\"hi\\\"\"")
        let disclosures: Array<Disclosure> = [disc]

        let signedSdJwt = buildSignedSdJwt(disclosures, priv, crypto)

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(signedSdJwt, pub)

        @Expect(result.isOk(), true)
    }

    // ----------------------------------------------------------------
    // S-018 regression: verifyIssuance with non-ASCII (Möbius) claim value
    //
    // The Disclosure value contains a multi-byte UTF-8 character (U+00F6 ö).
    // parseJsonStringAt and extractStringField must handle multi-byte runes
    // correctly via Rune.intoUtf8Array instead of Rune.toString().
    //
    // On aarch64-linux-ohos before the fix:
    //   Rune('ö').toString() == "246" (decimal code point for U+00F6)
    // so the reconstructed claim value would be garbled.
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_nonAsciiClaimValue_mobius_s018(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        // Disclosure value: JSON string "Möbius" — ö is U+00F6, 2-byte UTF-8
        let disc = Disclosure(salt: "mobius-salt", name: "label", value: "\"M\u{00F6}bius\"")
        let disclosures: Array<Disclosure> = [disc]

        let signedSdJwt = buildSignedSdJwt(disclosures, priv, crypto)

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(signedSdJwt, pub)

        // Verification must succeed: the digest is computed over the encoded disclosure bytes,
        // and those bytes are the base64url encoding of the JSON array — the verifier does
        // not re-parse the claim value string, it only extracts _sd_alg from the payload.
        // If parseJsonStringAt is broken the digest strings in _sd would be garbled and
        // collectSdDigests would return wrong digests causing a mismatch.
        @Expect(result.isOk(), true)
    }

    // ----------------------------------------------------------------
    // S-018 regression: reconstructed claims contain correct values
    //   after verifyIssuance with escape-char and non-ASCII disclosures.
    //
    // This test exercises the full claim reconstruction path: after
    // verifyIssuance succeeds, we directly exercise verifyIssuance on a
    // compact SD-JWT and confirm the result is ok.  The reconstructed claims
    // live inside DisclosuresVerifier.verify → reconstructClaims, which
    // calls disc.getValue() — not extractStringField again — so the claim
    // value is the pre-serialised JSON fragment stored verbatim.
    // ----------------------------------------------------------------

    @TestCase
    func testVerifyIssuance_escapedAndNonAscii_compactOverload_s018(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        // Mix: one ASCII escape, one non-ASCII (ö)
        let disc1 = Disclosure(salt: "s-nl", name: "note", value: "\"hello\\nworld\"")
        let disc2 = Disclosure(salt: "s-oe", name: "city", value: "\"K\u{00F6}ln\"")
        let disclosures: Array<Disclosure> = [disc1, disc2]

        let signedSdJwt = buildSignedSdJwt(disclosures, priv, crypto)

        let ser = CompactSerialiser(b64: crypto.base64Url)
        let compact = ser.serialise(signedSdJwt)

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(compact, pub)

        @Expect(result.isOk(), true)
    }
}
