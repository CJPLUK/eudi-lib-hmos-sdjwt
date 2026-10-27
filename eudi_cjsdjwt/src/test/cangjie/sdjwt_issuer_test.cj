/**
 * sdjwt_issuer_test.cj
 *
 * Unit tests for SdJwtIssuer.issue and SdJwtIssuer.presentation.
 *
 * Test cases:
 *   1. issue() → seam verifyEs256 round-trip passes (header.alg=ES256 verified).
 *   2. Payload from issue() contains _sd and _sd_alg; plain claims not in _sd.
 *   3. presentation() selects correct disclosure subset count.
 *   4. KB-JWT sd_hash can be recomputed and matches.
 *
 * All tests use HostCryptoStub (host surrogate, not real ECDSA P-256).
 * The round-trip is self-consistent because HostJwsImpl.signEs256 +
 * verifyEs256 use the same HMAC key via the identity-mapping publicKeyOf().
 */
package ohos_app_cangjie_eudi_cjsdjwt_local_test

import std.unittest.*
import std.unittest.testmacro.*

import std.collection.*

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.issuer.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.factory.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.verifier.*

// ---------------------------------------------------------------------------
// Helpers shared across tests
// ---------------------------------------------------------------------------

/**
 * Build a SdJwtIssuer backed by HostCryptoStub with Sha256 and zero decoys.
 */
func makeIssuer(): SdJwtIssuer {
    let crypto = HostCryptoStub()
    let dc = DigestCreator(
        digest: crypto.digest,
        base64Url: crypto.base64Url,
        algorithm: HashingAlgorithmIdentifier.Sha256
    )
    let factory = SdJwtFactory(
        digestCreator: dc,
        base64Url: crypto.base64Url,
        rng: crypto.rng,
        decoyCount: 0
    )
    return SdJwtIssuer(
        jws: crypto.jws,
        base64Url: crypto.base64Url,
        digest: crypto.digest,
        factory: factory
    )
}

/**
 * Build a SdJwtIssuer backed by HostCryptoStub returning all crypto together.
 */
func makeIssuerWithCrypto(): (SdJwtIssuer, HostCryptoStub) {
    let crypto = HostCryptoStub()
    let dc = DigestCreator(
        digest: crypto.digest,
        base64Url: crypto.base64Url,
        algorithm: HashingAlgorithmIdentifier.Sha256
    )
    let factory = SdJwtFactory(
        digestCreator: dc,
        base64Url: crypto.base64Url,
        rng: crypto.rng,
        decoyCount: 0
    )
    let issuer = SdJwtIssuer(
        jws: crypto.jws,
        base64Url: crypto.base64Url,
        digest: crypto.digest,
        factory: factory
    )
    return (issuer, crypto)
}

/**
 * Decode the payload JSON from a compact JWS token (base64url(header).base64url(payload).sig).
 */
func decodeJwtPayloadJson(compact: String, b64: Base64Url): String {
    let parts = compact.split(".")
    if (parts.size != 3) {
        return ""
    }
    let payloadBytes = b64.decode(parts[1])
    return String.fromUtf8(payloadBytes)
}

/**
 * Decode the header JSON from a compact JWS token.
 */
func decodeJwtHeaderJson(compact: String, b64: Base64Url): String {
    let parts = compact.split(".")
    if (parts.size != 3) {
        return ""
    }
    let headerBytes = b64.decode(parts[0])
    return String.fromUtf8(headerBytes)
}

/**
 * Return true if the JSON string contains the given field key as a top-level JSON field.
 */
func issuerTestJsonHasKey(json: String, key: String): Bool {
    return json.contains("\"" + key + "\":")
}

// ---------------------------------------------------------------------------
// Test class
// ---------------------------------------------------------------------------

@Test
class SdJwtIssuerTest {

    // ----------------------------------------------------------------
    // Test 1: issue() → verifyEs256 round-trip
    // ----------------------------------------------------------------

    @TestCase
    func testIssue_signatureVerifiesWithSeam(): Unit {
        let (issuer, crypto) = makeIssuerWithCrypto()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("sub", ClaimValue.Sd("\"user-42\""))

        let result = issuer.issue(claims, priv)

        @Expect(result.isOk(), true)

        match (result.ok) {
            case Some(signedSdJwt) =>
                // Verify the JWS signature using the seam verifyEs256
                let compact = signedSdJwt.jwt.compactSerialization
                let sigOk = crypto.jws.verifyEs256(compact, pub)
                @Expect(sigOk, true)
            case None =>
                @Expect(false, true)
        }
    }

    // ----------------------------------------------------------------
    // Test 2: payload contains _sd/_sd_alg; sd claim absent from plaintext
    // ----------------------------------------------------------------

    @TestCase
    func testIssue_payloadContainsSdAndSdAlg(): Unit {
        let (issuer, crypto) = makeIssuerWithCrypto()
        let priv = crypto.ecdsa.generate()

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("given_name", ClaimValue.Sd("\"Alice\""))
        claims.add("family_name", ClaimValue.Sd("\"Smith\""))

        let result = issuer.issue(claims, priv)
        @Expect(result.isOk(), true)

        match (result.ok) {
            case Some(signedSdJwt) =>
                let compact = signedSdJwt.jwt.compactSerialization
                let payloadJson = decodeJwtPayloadJson(compact, crypto.base64Url)

                // _sd array must be present
                @Expect(issuerTestJsonHasKey(payloadJson, "_sd"), true)

                // _sd_alg must be present
                @Expect(issuerTestJsonHasKey(payloadJson, "_sd_alg"), true)

                // SD claims must NOT appear as plaintext keys
                @Expect(issuerTestJsonHasKey(payloadJson, "given_name"), false)
                @Expect(issuerTestJsonHasKey(payloadJson, "family_name"), false)

                // Plain claim must appear verbatim
                @Expect(issuerTestJsonHasKey(payloadJson, "iss"), true)

                // Two disclosures produced
                @Expect(signedSdJwt.disclosures.size, 2)
            case None =>
                @Expect(false, true)
        }
    }

    // ----------------------------------------------------------------
    // Test 2b: header must contain alg=ES256
    // ----------------------------------------------------------------

    @TestCase
    func testIssue_headerContainsAlgES256(): Unit {
        let (issuer, crypto) = makeIssuerWithCrypto()
        let priv = crypto.ecdsa.generate()

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))

        let result = issuer.issue(claims, priv)
        @Expect(result.isOk(), true)

        match (result.ok) {
            case Some(signedSdJwt) =>
                let compact = signedSdJwt.jwt.compactSerialization
                let headerJson = decodeJwtHeaderJson(compact, crypto.base64Url)
                // Header must contain "alg":"ES256"
                @Expect(headerJson.contains("\"alg\":\"ES256\""), true)
            case None =>
                @Expect(false, true)
        }
    }

    // ----------------------------------------------------------------
    // Test 3: presentation() subset disclosure count correct
    // ----------------------------------------------------------------

    @TestCase
    func testPresentation_subsetDisclosureCount(): Unit {
        let (issuer, crypto) = makeIssuerWithCrypto()
        let priv = crypto.ecdsa.generate()

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("given_name", ClaimValue.Sd("\"Alice\""))
        claims.add("family_name", ClaimValue.Sd("\"Smith\""))
        claims.add("email", ClaimValue.Sd("\"alice@example.com\""))

        let issueResult = issuer.issue(claims, priv)
        @Expect(issueResult.isOk(), true)

        match (issueResult.ok) {
            case Some(signedSdJwt) =>
                @Expect(signedSdJwt.disclosures.size, 3)

                // Present only the first disclosure (given_name)
                let toPresent: Array<Disclosure> = [signedSdJwt.disclosures[0]]

                let presResult = issuer.presentation(signedSdJwt, toPresent, None)
                @Expect(presResult.isOk(), true)

                match (presResult.ok) {
                    case Some(pres) =>
                        @Expect(pres.disclosures.size, 1)
                    case None =>
                        @Expect(false, true)
                }
            case None =>
                @Expect(false, true)
        }
    }

    // ----------------------------------------------------------------
    // Test 3b: presentation() with empty subset
    // ----------------------------------------------------------------

    @TestCase
    func testPresentation_emptySubset(): Unit {
        let (issuer, crypto) = makeIssuerWithCrypto()
        let priv = crypto.ecdsa.generate()

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("sub", ClaimValue.Sd("\"user-1\""))

        let issueResult = issuer.issue(claims, priv)
        @Expect(issueResult.isOk(), true)

        match (issueResult.ok) {
            case Some(signedSdJwt) =>
                let toPresent: Array<Disclosure> = Array<Disclosure>()
                let presResult = issuer.presentation(signedSdJwt, toPresent, None)
                @Expect(presResult.isOk(), true)

                match (presResult.ok) {
                    case Some(pres) =>
                        @Expect(pres.disclosures.size, 0)
                    case None =>
                        @Expect(false, true)
                }
            case None =>
                @Expect(false, true)
        }
    }

    // ----------------------------------------------------------------
    // Test 4: KB-JWT sd_hash can be recomputed and matches
    // ----------------------------------------------------------------

    @TestCase
    func testPresentation_kbJwt_sdHashMatches(): Unit {
        let (issuer, crypto) = makeIssuerWithCrypto()
        let issuerPriv = crypto.ecdsa.generate()
        let holderPriv = crypto.ecdsa.generate()

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("doc_id", ClaimValue.Sd("\"ID-12345\""))

        let issueResult = issuer.issue(claims, issuerPriv)
        @Expect(issueResult.isOk(), true)

        match (issueResult.ok) {
            case Some(signedSdJwt) =>
                let nonce = "test-nonce-xyz"
                let aud = "https://verifier.example.com"
                let iat: Int64 = 1700000000

                // Build the presentation without KB-JWT first to compute expected sd_hash
                let ser = CompactSerialiser(b64: crypto.base64Url)
                let presWithoutKb = SignedSdJwt(
                    jwt: signedSdJwt.jwt,
                    disclosures: signedSdJwt.disclosures,
                    kbJwt: None
                )
                let expectedPresentationCompact = ser.serialise(presWithoutKb)

                // Compute expected sd_hash
                let presBytes: Array<UInt8> = expectedPresentationCompact.toArray()
                let hashBytes = crypto.digest.sha256(presBytes)
                let expectedSdHash = crypto.base64Url.encode(hashBytes)

                // Now build presentation with KB-JWT via issuer
                let kbParams = KbJwtParams(
                    nonce: nonce,
                    aud: aud,
                    iat: iat,
                    holderPriv: holderPriv
                )
                let presResult = issuer.presentation(
                    signedSdJwt,
                    signedSdJwt.disclosures,
                    Some(kbParams)
                )
                @Expect(presResult.isOk(), true)

                match (presResult.ok) {
                    case Some(pres) =>
                        match (pres.kbJwt) {
                            case Some(kbJwt) =>
                                // Decode KB-JWT payload and check sd_hash
                                let kbPayloadJson = decodeJwtPayloadJson(
                                    kbJwt.compactSerialization,
                                    crypto.base64Url
                                )
                                // sd_hash must be present in KB-JWT payload
                                @Expect(issuerTestJsonHasKey(kbPayloadJson, "sd_hash"), true)
                                // sd_hash value must match what we computed
                                @Expect(kbPayloadJson.contains(expectedSdHash), true)
                            case None =>
                                // KB-JWT must be present
                                @Expect(false, true)
                        }
                    case None =>
                        @Expect(false, true)
                }
            case None =>
                @Expect(false, true)
        }
    }

    // ----------------------------------------------------------------
    // Test 5: Full end-to-end: issue → present → verifyPresentation
    // ----------------------------------------------------------------

    @TestCase
    func testEndToEnd_issueAndVerify(): Unit {
        let (issuer, crypto) = makeIssuerWithCrypto()
        let issuerPriv = crypto.ecdsa.generate()
        let issuerPub = crypto.ecdsa.publicKeyOf(issuerPriv)
        let holderPriv = crypto.ecdsa.generate()
        let holderPub = crypto.ecdsa.publicKeyOf(holderPriv)

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("given_name", ClaimValue.Sd("\"Alice\""))
        claims.add("family_name", ClaimValue.Sd("\"Smith\""))

        // Issue
        let issueResult = issuer.issue(claims, issuerPriv, holderPublicKey: Some(holderPub))
        @Expect(issueResult.isOk(), true)

        match (issueResult.ok) {
            case Some(signedSdJwt) =>
                // Present with one disclosure and KB-JWT
                let ser = CompactSerialiser(b64: crypto.base64Url)
                let presWithoutKb = SignedSdJwt(
                    jwt: signedSdJwt.jwt,
                    disclosures: [signedSdJwt.disclosures[0]],
                    kbJwt: None
                )
                let presentationCompact = ser.serialise(presWithoutKb)

                let nonce = "verifier-nonce-abc"
                let aud = "https://verifier.example.com"

                let kbParams = KbJwtParams(
                    nonce: nonce,
                    aud: aud,
                    iat: 1700000000,
                    holderPriv: holderPriv
                )
                let presResult = issuer.presentation(
                    signedSdJwt,
                    [signedSdJwt.disclosures[0]],
                    Some(kbParams)
                )
                @Expect(presResult.isOk(), true)

                match (presResult.ok) {
                    case Some(pres) =>
                        // Verify presentation with verifier
                        let verifier = SdJwtVerifier(
                            jws: crypto.jws,
                            b64: crypto.base64Url,
                            digest: crypto.digest
                        )
                        let verifyResult = verifier.verifyPresentation(
                            pres,
                            issuerPub,
                            Some(nonce),
                            Some(aud),
                            Some(holderPub),
                            Some(presentationCompact)
                        )
                        @Expect(verifyResult.isOk(), true)
                    case None =>
                        @Expect(false, true)
                }
            case None =>
                @Expect(false, true)
        }
    }
}
