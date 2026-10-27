package ohos_app_cangjie_eudi_cjsdjwt

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.issuer.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.verifier.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.factory.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec.*
import std.collection.*

/**
 * runSdJwtDemo
 *
 * End-to-end SD-JWT demo function for the test panel.
 *
 * Steps:
 *   1. Construct claims: iss (plain), given_name (sd), sub (sd).
 *   2. Issue a SignedSdJwt via SdJwtIssuer.
 *   3. Build a presentation with one disclosure subset + KB-JWT.
 *   4. Verify issuance with SdJwtVerifier.verifyIssuance.
 *   5. Verify presentation with SdJwtVerifier.verifyPresentation.
 *   6. Return a summary string indicating success or failure.
 *
 * All errors are caught and returned as strings; no exceptions escape.
 */
public func runSdJwtDemo(): String {
    try {
        let crypto = CoreCryptoProvider()

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

        let issuerPriv = crypto.ecdsa.generate()
        let issuerPub = crypto.ecdsa.publicKeyOf(issuerPriv)
        let holderPriv = crypto.ecdsa.generate()
        let holderPub = crypto.ecdsa.publicKeyOf(holderPriv)

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("given_name", ClaimValue.Sd("\"Alice\""))
        claims.add("sub", ClaimValue.Sd("\"user-42\""))

        // Bind the holder public key via cnf.jwk so the verifier can enforce
        // key binding (KB-JWT must be signed by the cnf-bound holder key).
        let issueResult = issuer.issue(claims, issuerPriv, holderPublicKey: Some(holderPub))
        if (!issueResult.isOk()) {
            match (issueResult.err) {
                case Some(e) => return "ERR issue: " + e.message
                case None => return "ERR issue: unknown"
            }
        }

        let signedSdJwt: SignedSdJwt = match (issueResult.ok) {
            case Some(v) => v
            case None => return "ERR issue: ok is None"
        }

        let totalDisclosures = signedSdJwt.disclosures.size

        let toPresent: Array<Disclosure> = if (totalDisclosures > 0) {
            [signedSdJwt.disclosures[0]]
        } else {
            Array<Disclosure>()
        }

        let ser = CompactSerialiser(b64: crypto.base64Url)
        let presWithoutKb = SignedSdJwt(
            jwt: signedSdJwt.jwt,
            disclosures: toPresent,
            kbJwt: None
        )
        let presentationCompact = ser.serialise(presWithoutKb)

        let kbParams = KbJwtParams(
            nonce: "demo-nonce-2026",
            aud: "https://verifier.example.com",
            iat: 1749600000,
            holderPriv: holderPriv
        )
        let presResult = issuer.presentation(signedSdJwt, toPresent, Some(kbParams))
        if (!presResult.isOk()) {
            match (presResult.err) {
                case Some(e) => return "ERR presentation: " + e.message
                case None => return "ERR presentation: unknown"
            }
        }

        let presentation: SignedSdJwt = match (presResult.ok) {
            case Some(v) => v
            case None => return "ERR presentation: ok is None"
        }

        let verifier = SdJwtVerifier(
            jws: crypto.jws,
            b64: crypto.base64Url,
            digest: crypto.digest
        )

        let issuanceVerifyResult = verifier.verifyIssuance(signedSdJwt, issuerPub)
        let issuanceStatus: String = if (issuanceVerifyResult.isOk()) {
            "PASS"
        } else {
            match (issuanceVerifyResult.err) {
                case Some(e) => "FAIL(" + e.message + ")"
                case None => "FAIL(unknown)"
            }
        }

        let presentationVerifyResult = verifier.verifyPresentation(
            presentation,
            issuerPub,
            Some("demo-nonce-2026"),
            Some("https://verifier.example.com"),
            Some(holderPub),
            Some(presentationCompact)
        )
        let presentationStatus: String = if (presentationVerifyResult.isOk()) {
            "PASS"
        } else {
            match (presentationVerifyResult.err) {
                case Some(e) => "FAIL(" + e.message + ")"
                case None => "FAIL(unknown)"
            }
        }

        return "OK: disclosures=" + totalDisclosures.toString() +
            ", presented=" + toPresent.size.toString() +
            ", verifyIssuance=" + issuanceStatus +
            ", verifyPresentation=" + presentationStatus
    } catch (e: Exception) {
        return "ERR exception: " + e.message
    }
}
