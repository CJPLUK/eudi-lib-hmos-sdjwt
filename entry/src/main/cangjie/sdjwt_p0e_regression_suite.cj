/**
 * sdjwt_p0e_regression_suite.cj
 *
 * Regression suite for the P0-E iOS-parity security fixes:
 *
 *   Fix 1  KB-JWT holder key MUST come from the issuer-signed cnf.jwk, not from
 *          a presentation-time parameter.  A KB-JWT signed by any key other than
 *          the issuer-bound holder key is rejected (PoP / key-binding bypass
 *          closed).  Mirrors iOS SignedSDJWT.extractHoldersPublicKey +
 *          KeyBindingVerifier.
 *   Fix 2  KB-JWT sd_hash is computed with the issuer-declared _sd_alg algorithm
 *          (sha-256 / sha-384 / sha-512), not a hard-wired sha-256.
 *   Fix 3  DisclosuresVerifier.verifyDigestsStructure: a digest sitting in an
 *          object "_sd" array MUST decode to a 3-element [salt,key,value]
 *          disclosure; a digest behind a {"...": d} array marker MUST decode to
 *          a 2-element [salt,value] disclosure.  Kind/arity mismatch is rejected.
 *
 * All tests use HostCryptoStub (host surrogate).  publicKeyOf() is an identity
 * mapping there, and the JWK codec round-trips the key losslessly, so the
 * holder key extracted from cnf.jwk byte-equals the bound key — exactly the
 * property the key-binding check relies on.
 */
package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.*

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.factory.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.issuer.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.verifier.*

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func p0eMakeIssuer(crypto: HostCryptoStub, alg: HashingAlgorithmIdentifier): SdJwtIssuer {
    let dc = DigestCreator(digest: crypto.digest, base64Url: crypto.base64Url, algorithm: alg)
    let factory = SdJwtFactory(
        digestCreator: dc, base64Url: crypto.base64Url, rng: crypto.rng, decoyCount: 0
    )
    return SdJwtIssuer(
        jws: crypto.jws, base64Url: crypto.base64Url, digest: crypto.digest, factory: factory
    )
}

/**
 * Sign a KB-JWT for `presentationCompact` with the given holder private key,
 * computing sd_hash with `alg` (the issuer's _sd_alg).
 */
func p0eBuildKbJwt(
    crypto: HostCryptoStub,
    presentationCompact: String,
    nonce: String,
    aud: String,
    holderPriv: ECDSAPrivateKey,
    alg: HashingAlgorithmIdentifier
): Jwt {
    let dc = DigestCreator(digest: crypto.digest, base64Url: crypto.base64Url, algorithm: alg)
    let sdHash = dc.hashAndBase64Encode(presentationCompact)
    let kbPayloadJson = "{\"iat\":1700000000,\"nonce\":\"" + nonce +
        "\",\"aud\":\"" + aud + "\",\"sd_hash\":\"" + sdHash + "\"}"
    let kbHeaderJson = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}"
    let kbCompact = crypto.jws.signEs256(kbHeaderJson, kbPayloadJson.toArray(), holderPriv)
    return Jwt(compactSerialization: kbCompact)
}

@Test
class SdjwtP0ERegressionTest {

    // -----------------------------------------------------------------------
    // Fix 1 — cnf binding POSITIVE: KB signed by the bound holder key passes.
    // -----------------------------------------------------------------------

    @TestCase
    func testCnfBinding_positive_correctHolderKey_passes(): Unit {
        let crypto = HostCryptoStub()
        let issuer = p0eMakeIssuer(crypto, HashingAlgorithmIdentifier.Sha256)
        let issuerPriv = crypto.ecdsa.generate()
        let issuerPub = crypto.ecdsa.publicKeyOf(issuerPriv)
        let holderPriv = crypto.ecdsa.generate()
        let holderPub = crypto.ecdsa.publicKeyOf(holderPriv)

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("doc_id", ClaimValue.Sd("\"ID123\""))

        // Issue binding the holder key into cnf.jwk.
        let issued = issuer.issue(claims, issuerPriv, holderPublicKey: Some(holderPub)).ok.getOrThrow()

        // Present (no disclosures revealed) and attach a KB-JWT signed by the
        // CORRECT holder key.
        let ser = CompactSerialiser(b64: crypto.base64Url)
        let presNoKb = SignedSdJwt(jwt: issued.jwt, disclosures: Array<Disclosure>(), kbJwt: None)
        let presentationCompact = ser.serialise(presNoKb)
        let nonce = "p0e-nonce-1"
        let aud = "https://verifier.example.com"
        let kbJwt = p0eBuildKbJwt(crypto, presentationCompact, nonce, aud, holderPriv,
            HashingAlgorithmIdentifier.Sha256)
        let pres = SignedSdJwt(jwt: issued.jwt, disclosures: Array<Disclosure>(), kbJwt: Some(kbJwt))

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        // holderPublicKey parameter is intentionally None to prove it is ignored:
        // the verifier must source the key from cnf.jwk.
        let result = verifier.verifyPresentation(
            pres, issuerPub, Some(nonce), Some(aud), None, Some(presentationCompact)
        )
        @Expect(result.isOk(), true)
    }

    // -----------------------------------------------------------------------
    // Fix 1 — cnf binding NEGATIVE (the bypass-closed evidence):
    // issue binds holderA's cnf, but the KB-JWT is signed by attacker holderB.
    // verifyPresentation MUST reject (KB key != cnf-bound key).
    // -----------------------------------------------------------------------

    @TestCase
    func testCnfBinding_negative_attackerKey_rejected(): Unit {
        let crypto = HostCryptoStub()
        let issuer = p0eMakeIssuer(crypto, HashingAlgorithmIdentifier.Sha256)
        let issuerPriv = crypto.ecdsa.generate()
        let issuerPub = crypto.ecdsa.publicKeyOf(issuerPriv)

        // holderA is the legitimately-bound holder; holderB is the attacker.
        let holderAPriv = crypto.ecdsa.generate()
        let holderAPub = crypto.ecdsa.publicKeyOf(holderAPriv)
        let holderBPriv = crypto.ecdsa.generate()

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("doc_id", ClaimValue.Sd("\"ID123\""))

        // Issuer binds holderA's key into cnf.jwk.
        let issued = issuer.issue(claims, issuerPriv, holderPublicKey: Some(holderAPub)).ok.getOrThrow()

        let ser = CompactSerialiser(b64: crypto.base64Url)
        let presNoKb = SignedSdJwt(jwt: issued.jwt, disclosures: Array<Disclosure>(), kbJwt: None)
        let presentationCompact = ser.serialise(presNoKb)
        let nonce = "p0e-nonce-2"
        let aud = "https://verifier.example.com"

        // Attacker signs the KB-JWT with holderB's key.
        let kbJwt = p0eBuildKbJwt(crypto, presentationCompact, nonce, aud, holderBPriv,
            HashingAlgorithmIdentifier.Sha256)
        let pres = SignedSdJwt(jwt: issued.jwt, disclosures: Array<Disclosure>(), kbJwt: Some(kbJwt))

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        // Even if the (now-ignored) holderPublicKey param is set to the attacker
        // key, the decision must still reject — the cnf-bound key governs.
        var gotError = false
        try {
            let result = verifier.verifyPresentation(
                pres, issuerPub, Some(nonce), Some(aud), None, Some(presentationCompact)
            )
            gotError = !result.isOk()
        } catch (e: SdJwtVerifierError) {
            gotError = true
        }
        @Expect(gotError, true)
    }

    // -----------------------------------------------------------------------
    // Fix 1 — fail-closed: KB-JWT present but issuer payload binds no cnf.jwk.
    // -----------------------------------------------------------------------

    @TestCase
    func testCnfBinding_failClosed_missingCnf_rejected(): Unit {
        let crypto = HostCryptoStub()
        let issuer = p0eMakeIssuer(crypto, HashingAlgorithmIdentifier.Sha256)
        let issuerPriv = crypto.ecdsa.generate()
        let issuerPub = crypto.ecdsa.publicKeyOf(issuerPriv)
        let holderPriv = crypto.ecdsa.generate()

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("doc_id", ClaimValue.Sd("\"ID123\""))

        // Issue WITHOUT binding any holder key (no cnf in payload).
        let issued = issuer.issue(claims, issuerPriv).ok.getOrThrow()

        let ser = CompactSerialiser(b64: crypto.base64Url)
        let presNoKb = SignedSdJwt(jwt: issued.jwt, disclosures: Array<Disclosure>(), kbJwt: None)
        let presentationCompact = ser.serialise(presNoKb)
        let nonce = "p0e-nonce-3"
        let aud = "https://verifier.example.com"
        let kbJwt = p0eBuildKbJwt(crypto, presentationCompact, nonce, aud, holderPriv,
            HashingAlgorithmIdentifier.Sha256)
        let pres = SignedSdJwt(jwt: issued.jwt, disclosures: Array<Disclosure>(), kbJwt: Some(kbJwt))

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        var gotError = false
        var msg = ""
        try {
            let result = verifier.verifyPresentation(
                pres, issuerPub, Some(nonce), Some(aud), None, Some(presentationCompact)
            )
            gotError = !result.isOk()
            match (result.err) {
                case Some(e) => msg = e.message
                case None => ()
            }
        } catch (e: SdJwtVerifierError) {
            gotError = true
            msg = e.message
        }
        @Expect(gotError, true)
        @Expect(msg.contains("cnf"), true)
    }

    // -----------------------------------------------------------------------
    // Fix 2 — sd_hash uses _sd_alg (sha-384), not hard-wired sha-256.
    // A full sha-384 issue→present→verify cycle passes, AND the sha-384 sd_hash
    // differs from the sha-256 one (so the algorithm choice is load-bearing).
    // -----------------------------------------------------------------------

    @TestCase
    func testSdHash_usesSdAlg_sha384_cyclePasses(): Unit {
        let crypto = HostCryptoStub()
        let issuer = p0eMakeIssuer(crypto, HashingAlgorithmIdentifier.Sha384)
        let issuerPriv = crypto.ecdsa.generate()
        let issuerPub = crypto.ecdsa.publicKeyOf(issuerPriv)
        let holderPriv = crypto.ecdsa.generate()
        let holderPub = crypto.ecdsa.publicKeyOf(holderPriv)

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("doc_id", ClaimValue.Sd("\"ID123\""))

        let issued = issuer.issue(claims, issuerPriv, holderPublicKey: Some(holderPub)).ok.getOrThrow()

        // The issuer's own presentation() must build the KB sd_hash with sha-384.
        let ser = CompactSerialiser(b64: crypto.base64Url)
        let presNoKb = SignedSdJwt(jwt: issued.jwt, disclosures: Array<Disclosure>(), kbJwt: None)
        let presentationCompact = ser.serialise(presNoKb)
        let nonce = "p0e-nonce-4"
        let aud = "https://verifier.example.com"
        let kbParams = KbJwtParams(nonce: nonce, aud: aud, iat: 1700000000, holderPriv: holderPriv)
        let pres = issuer.presentation(issued, Array<Disclosure>(), Some(kbParams)).ok.getOrThrow()

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyPresentation(
            pres, issuerPub, Some(nonce), Some(aud), None, Some(presentationCompact)
        )
        @Expect(result.isOk(), true)

        // The sha-384 and sha-256 sd_hash of the same input must differ — proving
        // the algorithm is actually consulted (a hard-wired sha-256 would have
        // produced a mismatching sd_hash and the cycle above would have failed).
        let dc256 = DigestCreator(digest: crypto.digest, base64Url: crypto.base64Url, algorithm: HashingAlgorithmIdentifier.Sha256)
        let dc384 = DigestCreator(digest: crypto.digest, base64Url: crypto.base64Url, algorithm: HashingAlgorithmIdentifier.Sha384)
        @Expect(dc256.hashAndBase64Encode(presentationCompact) != dc384.hashAndBase64Encode(presentationCompact), true)
    }

    // -----------------------------------------------------------------------
    // Fix 2 — negative: KB sd_hash computed with the WRONG algorithm (sha-256)
    // while the issuer declared sha-384 → verifier rejects.
    // -----------------------------------------------------------------------

    @TestCase
    func testSdHash_wrongAlg_rejected(): Unit {
        let crypto = HostCryptoStub()
        let issuer = p0eMakeIssuer(crypto, HashingAlgorithmIdentifier.Sha384)
        let issuerPriv = crypto.ecdsa.generate()
        let issuerPub = crypto.ecdsa.publicKeyOf(issuerPriv)
        let holderPriv = crypto.ecdsa.generate()
        let holderPub = crypto.ecdsa.publicKeyOf(holderPriv)

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("doc_id", ClaimValue.Sd("\"ID123\""))

        let issued = issuer.issue(claims, issuerPriv, holderPublicKey: Some(holderPub)).ok.getOrThrow()

        let ser = CompactSerialiser(b64: crypto.base64Url)
        let presNoKb = SignedSdJwt(jwt: issued.jwt, disclosures: Array<Disclosure>(), kbJwt: None)
        let presentationCompact = ser.serialise(presNoKb)
        let nonce = "p0e-nonce-5"
        let aud = "https://verifier.example.com"
        // Build KB-JWT with sha-256 sd_hash, but the payload declared sha-384.
        let kbJwt = p0eBuildKbJwt(crypto, presentationCompact, nonce, aud, holderPriv,
            HashingAlgorithmIdentifier.Sha256)
        let pres = SignedSdJwt(jwt: issued.jwt, disclosures: Array<Disclosure>(), kbJwt: Some(kbJwt))

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        var gotError = false
        try {
            let result = verifier.verifyPresentation(
                pres, issuerPub, Some(nonce), Some(aud), None, Some(presentationCompact)
            )
            gotError = !result.isOk()
        } catch (e: SdJwtVerifierError) {
            gotError = true
        }
        @Expect(gotError, true)
    }

    // -----------------------------------------------------------------------
    // Fix 3 — verifyDigestsStructure POSITIVE: a normally-issued object claim
    // (3-element disclosure behind an object "_sd" entry) verifies.
    // -----------------------------------------------------------------------

    @TestCase
    func testDigestStructure_objectClaim_correctArity_passes(): Unit {
        let crypto = HostCryptoStub()
        let issuer = p0eMakeIssuer(crypto, HashingAlgorithmIdentifier.Sha256)
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("given_name", ClaimValue.Sd("\"Alice\""))   // object _sd entry → 3-element

        let issued = issuer.issue(claims, priv).ok.getOrThrow()
        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(issued, pub)
        @Expect(result.isOk(), true)
    }

    // -----------------------------------------------------------------------
    // Fix 3 — verifyDigestsStructure NEGATIVE: a 2-element (array-kind)
    // disclosure whose digest is planted in an object "_sd" array (which
    // expects 3-element disclosures) → structural mismatch → reject.
    // -----------------------------------------------------------------------

    @TestCase
    func testDigestStructure_kindMismatch_rejected(): Unit {
        let crypto = HostCryptoStub()
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)
        let dc = DigestCreator(digest: crypto.digest, base64Url: crypto.base64Url, algorithm: HashingAlgorithmIdentifier.Sha256)

        // A 2-element ARRAY disclosure [salt, value].
        let arrayDisc = Disclosure(salt: "salt-arr", value: "\"FR\"")
        let encoded = arrayDisc.encodeWith(crypto.base64Url)
        let digest = dc.hashAndBase64Encode(encoded)

        // Plant that digest into an OBJECT "_sd" array (which requires 3-element
        // disclosures).  This is the malformed/forged structure the fix rejects.
        let payloadJson = "{\"iss\":\"test\",\"_sd_alg\":\"sha-256\",\"_sd\":[\"" + digest + "\"]}"
        let headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"
        let compactJwt = crypto.jws.signEs256(headerJson, payloadJson.toArray(), priv)
        let signed = SignedSdJwt(
            jwt: Jwt(compactSerialization: compactJwt),
            disclosures: [arrayDisc],
            kbJwt: None
        )

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        var gotError = false
        var msg = ""
        try {
            let result = verifier.verifyIssuance(signed, pub)
            gotError = !result.isOk()
            match (result.err) {
                case Some(e) => msg = e.message
                case None => ()
            }
        } catch (e: SdJwtVerifierError) {
            gotError = true
            msg = e.message
        }
        @Expect(gotError, true)
        @Expect(msg.contains("structure mismatch"), true)
    }
}
