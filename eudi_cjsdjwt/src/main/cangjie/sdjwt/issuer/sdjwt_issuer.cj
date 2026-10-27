/**
 * sdjwt_issuer.cj
 *
 * SD-JWT issuance and presentation.
 *
 * Corresponds to:
 *   Sources/Issuer/SDJWTIssuer.swift  (issue / presentation)
 *
 * Design notes:
 *   - issue(): builds SD-JWT payload via SdJwtFactory, produces JWS compact
 *     token via Jws.signEs256, returns SignedSdJwt.
 *   - presentation(): selects a subset of disclosures from a signed SD-JWT
 *     and optionally attaches a Key Binding JWT.  The KB-JWT sd_hash is
 *     computed as sha256(presentationCompact) where presentationCompact is
 *     the compact SD-JWT without the KB-JWT suffix (ends with "~"), matching
 *     the KeyBindingVerifier expectation in sdjwt_verifier.cj.
 *   - All public API errors are returned via IssueResult / PresentResult
 *     (no unhandled exceptions escape the public boundary).
 *   - No stdx imports; all functionality uses std.* and the crypto seam.
 *   - Disclosure identity: disclosures to present are matched against the
 *     original disclosure list by comparing base64url-encoded forms so that
 *     the caller can pass decoded Disclosure objects or re-encode them.
 *
 * Functional contract (fc_sdjwt_issuer_issuance):
 *   issue()        -> IssueResult
 *                     ok: SignedSdJwt with jwt signed using ES256,
 *                         payload containing _sd/_sd_alg, disclosures attached
 *                     err: Some(SdJwtError) on failure
 *   presentation() -> PresentResult
 *                     ok: SignedSdJwt with selected disclosures subset,
 *                         optionally KB-JWT attached
 *                     err: Some(SdJwtError) on failure
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.issuer

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.factory.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest.*
import std.collection.*

// ---------------------------------------------------------------------------
// IssueResult  — return type for issue()
// ---------------------------------------------------------------------------

/**
 * Result of SdJwtIssuer.issue.
 *
 * Exactly one of ok / err is Some.
 */
public class IssueResult {
    public let ok: Option<SignedSdJwt>
    public let err: Option<SdJwtError>

    /** Successful issuance. */
    public init(ok!: SignedSdJwt) {
        this.ok = Some(ok)
        this.err = None
    }

    /** Failed issuance. */
    public init(err!: SdJwtError) {
        this.ok = None
        this.err = Some(err)
    }

    /** True if issuance succeeded. */
    public func isOk(): Bool {
        match (ok) {
            case Some(_) => true
            case None => false
        }
    }
}

// ---------------------------------------------------------------------------
// PresentResult  — return type for presentation()
// ---------------------------------------------------------------------------

/**
 * Result of SdJwtIssuer.presentation.
 *
 * Exactly one of ok / err is Some.
 */
public class PresentResult {
    public let ok: Option<SignedSdJwt>
    public let err: Option<SdJwtError>

    /** Successful presentation construction. */
    public init(ok!: SignedSdJwt) {
        this.ok = Some(ok)
        this.err = None
    }

    /** Failed presentation construction. */
    public init(err!: SdJwtError) {
        this.ok = None
        this.err = Some(err)
    }

    /** True if presentation construction succeeded. */
    public func isOk(): Bool {
        match (ok) {
            case Some(_) => true
            case None => false
        }
    }
}

// ---------------------------------------------------------------------------
// SdJwtIssuer
// ---------------------------------------------------------------------------

/**
 * SD-JWT issuer implementing the issuance and presentation pipeline.
 *
 * Mirrors Sources/Issuer/SDJWTIssuer.swift.
 *
 * Usage:
 *   let crypto = HostCryptoStub()
 *   let dc = DigestCreator(digest: crypto.digest, base64Url: crypto.base64Url,
 *                          algorithm: HashingAlgorithmIdentifier.Sha256)
 *   let factory = SdJwtFactory(digestCreator: dc, base64Url: crypto.base64Url,
 *                              rng: crypto.rng, decoyCount: 0)
 *   let issuer = SdJwtIssuer(jws: crypto.jws, base64Url: crypto.base64Url,
 *                            digest: crypto.digest, factory: factory)
 *
 *   var claims = HashMap<String, ClaimValue>()
 *   claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
 *   claims.add("sub", ClaimValue.Sd("\"user-42\""))
 *
 *   let result = issuer.issue(claims, priv)
 *   if (result.isOk()) {
 *       let signedSdJwt = result.ok.getOrThrow()
 *       // compact = CompactSerialiser.serialise(signedSdJwt)
 *   }
 */
public class SdJwtIssuer {

    let _jws: Jws
    let _base64Url: Base64Url
    let _digest: Digest
    let _factory: SdJwtFactory

    /**
     * Construct a SdJwtIssuer.
     *
     * @param jws        JWS seam implementation (sign/verify ES256).
     * @param base64Url  Base64Url seam implementation.
     * @param digest     Digest seam implementation for KB-JWT sd_hash.
     * @param factory    SdJwtFactory used to build the SD-JWT payload.
     */
    public init(
        jws!: Jws,
        base64Url!: Base64Url,
        digest!: Digest,
        factory!: SdJwtFactory
    ) {
        _jws = jws
        _base64Url = base64Url
        _digest = digest
        _factory = factory
    }

    // -----------------------------------------------------------------------
    // issue
    // -----------------------------------------------------------------------

    /**
     * Issue a signed SD-JWT.
     *
     * Steps:
     *   1. Invoke SdJwtFactory.createPayload(claims) to produce the payload
     *      JSON string and associated Disclosure objects.
     *   2. Encode the payload JSON as UTF-8 bytes.
     *   3. Build the JWS JOSE header: {"alg":"ES256","typ":"vc+sd-jwt"}.
     *   4. Call Jws.signEs256(headerJson, payloadBytes, priv) to obtain the
     *      compact JWS token (header.payload.signature).
     *   5. Wrap in SignedSdJwt(jwt, disclosures, kbJwt: None).
     *
     * The returned SignedSdJwt can be serialised with CompactSerialiser.serialise.
     *
     * @param claims  Map of claim names to ClaimValue descriptors.
     * @param priv    Issuer's private key for signing.
     * @return IssueResult — ok(SignedSdJwt) on success, err on failure.
     */
    public func issue(
        claims: HashMap<String, ClaimValue>,
        priv: ECDSAPrivateKey
    ): IssueResult {
        return issue(claims, priv, holderPublicKey: None, typ: "vc+sd-jwt")
    }

    /**
     * Issue a signed SD-JWT, binding a holder public key via the cnf.jwk claim.
     *
     * SECURITY (key binding): when `holderPublicKey` is Some, the issuer writes
     *   "cnf": {"jwk": {"kty":"EC","crv":"P-256","x":..,"y":..}}
     * into the SIGNED payload.  The verifier later extracts this key from the
     * signature-verified payload and uses it (and only it) to check the KB-JWT —
     * so a presentation whose KB-JWT is signed by any other key is rejected.
     * Mirrors iOS SignedSDJWT.extractHoldersPublicKey().
     *
     * @param claims          Claim descriptors.
     * @param priv            Issuer's private key for signing.
     * @param holderPublicKey Holder's public key to bind (Some), or None for an
     *                        SD-JWT without key binding.
     * @return IssueResult.
     */
    public func issue(
        claims: HashMap<String, ClaimValue>,
        priv: ECDSAPrivateKey,
        holderPublicKey!: Option<ECDSAPublicKey>
    ): IssueResult {
        return issue(claims, priv, holderPublicKey: holderPublicKey, typ: "vc+sd-jwt")
    }

    /**
     * Issue a signed SD-JWT with a custom typ header value.
     *
     * Allows callers to override the JWT "typ" claim (e.g., "JWT", "vc+sd-jwt").
     *
     * @param claims  Map of claim names to ClaimValue descriptors.
     * @param priv    Issuer's private key for signing.
     * @param typ     Value of the "typ" header claim.
     * @return IssueResult.
     */
    public func issue(
        claims: HashMap<String, ClaimValue>,
        priv: ECDSAPrivateKey,
        typ!: String
    ): IssueResult {
        return issue(claims, priv, holderPublicKey: None, typ: typ)
    }

    /**
     * Issue a signed SD-JWT with a custom typ header value and optional holder
     * key binding (cnf.jwk).
     *
     * @param claims          Map of claim names to ClaimValue descriptors.
     * @param priv            Issuer's private key for signing.
     * @param holderPublicKey Holder's public key to bind (Some) or None.
     * @param typ             Value of the "typ" header claim.
     * @return IssueResult.
     */
    public func issue(
        claims: HashMap<String, ClaimValue>,
        priv: ECDSAPrivateKey,
        holderPublicKey!: Option<ECDSAPublicKey>,
        typ!: String
    ): IssueResult {
        try {
            let factoryResult = _factory.createPayload(claims)
            // Inject the holder cnf.jwk binding into the SIGNED payload, if any.
            let payloadJson = match (holderPublicKey) {
                case Some(holderPub) =>
                    let codec = JwkCodec(b64: _base64Url)
                    let jwk = codec.fromPublicKey(holderPub)
                    let cnfJson = "{\"" + Keys.jwk + "\":" + jwk.toJson() + "}"
                    injectCnf(factoryResult.payloadJson, cnfJson)
                case None => factoryResult.payloadJson
            }
            let payloadBytes: Array<UInt8> = payloadJson.toArray()
            let headerJson = buildJoseHeader(alg: "ES256", typ: typ)
            let compactJwt = _jws.signEs256(headerJson, payloadBytes, priv)
            let signedSdJwt = SignedSdJwt(
                jwt: Jwt(compactSerialization: compactJwt),
                disclosures: factoryResult.disclosures,
                kbJwt: None
            )
            return IssueResult(ok: signedSdJwt)
        } catch (e: Exception) {
            return IssueResult(err: SdJwtError("Issue failed: " + e.message))
        }
    }

    /**
     * Insert a "cnf":<cnfJson> member into a JSON object string.
     *
     * The factory payload is a JSON object "{...}" (non-empty: it always carries
     * _sd_alg).  We splice "cnf":<cnfJson>, after the opening brace.
     *
     * @param payloadJson  The factory-produced object JSON (starts with '{').
     * @param cnfJson      The cnf value object JSON (e.g. {"jwk":{...}}).
     * @return The payload with the cnf member added.
     */
    private func injectCnf(payloadJson: String, cnfJson: String): String {
        let chars = payloadJson.toRuneArray()
        // Locate the first '{'.
        var i: Int64 = 0
        while (i < chars.size && UInt32(chars[i]) != 0x7Bu32) {
            i = i + 1
        }
        if (i >= chars.size) {
            // Not an object (should never happen); fall back to wrapping.
            return payloadJson
        }
        let head = payloadJson[0..i + 1]          // up to and including '{'
        let tail = payloadJson[i + 1..payloadJson.size]
        let cnfMember = "\"" + Keys.cnf + "\":" + cnfJson
        // Empty object "{}" → no trailing comma; otherwise add comma before rest.
        let trimmedTail = tail.trimAscii()
        if (trimmedTail == "}") {
            return head + cnfMember + tail
        }
        return head + cnfMember + "," + tail
    }

    // -----------------------------------------------------------------------
    // presentation
    // -----------------------------------------------------------------------

    /**
     * Construct a selective-disclosure presentation from an issued SD-JWT.
     *
     * Steps:
     *   1. Filter disclosures: keep only those in disclosuresToPresent.
     *      Matching is by base64url-encoded form (canonical identity).
     *   2. Build a presentation SignedSdJwt with the filtered disclosures.
     *   3. If kbJwtParams is Some, compute sd_hash and sign a KB-JWT:
     *      a. Serialise the presentation (without KB-JWT) to compact form.
     *      b. sd_hash = base64url(sha256(utf8(presentationCompact))).
     *      c. Build KB-JWT payload with nonce, aud, iat, sd_hash.
     *      d. Build KB-JWT header with alg=ES256, typ=kb+jwt.
     *      e. Sign KB-JWT with the holder's private key.
     *      f. Attach to the presentation as kbJwt.
     *
     * The sd_hash computation uses the presentationCompact that ends with "~"
     * (produced by CompactSerialiser before KB-JWT is appended), which is the
     * same input the KeyBindingVerifier in sdjwt_verifier.cj expects.
     *
     * @param signedSdJwt          The issued SignedSdJwt from issue().
     * @param disclosuresToPresent  Subset of disclosures to reveal.
     * @param kbJwtParams           Optional key-binding parameters.
     * @return PresentResult — ok(SignedSdJwt) on success, err on failure.
     */
    public func presentation(
        signedSdJwt: SignedSdJwt,
        disclosuresToPresent: Array<Disclosure>,
        kbJwtParams: Option<KbJwtParams>
    ): PresentResult {
        try {
            // Step 1: Filter disclosures to the requested subset
            let selectedDisclosures = filterDisclosures(
                all: signedSdJwt.disclosures,
                requested: disclosuresToPresent
            )

            // Step 2: Build presentation without KB-JWT
            var presentation = SignedSdJwt(
                jwt: signedSdJwt.jwt,
                disclosures: selectedDisclosures,
                kbJwt: None
            )

            // Step 3: Optionally attach KB-JWT
            match (kbJwtParams) {
                case Some(params) =>
                    let ser = CompactSerialiser(b64: _base64Url)
                    let presentationCompact = ser.serialise(presentation)
                    let kbJwt = buildKbJwt(
                        presentationCompact: presentationCompact,
                        nonce: params.nonce,
                        aud: params.aud,
                        iat: params.iat,
                        holderPriv: params.holderPriv
                    )
                    presentation = presentation.withKbJwt(kbJwt)
                case None => ()
            }

            return PresentResult(ok: presentation)
        } catch (e: Exception) {
            return PresentResult(err: SdJwtError("Presentation failed: " + e.message))
        }
    }

    // -----------------------------------------------------------------------
    // Internal: disclosure filtering
    // -----------------------------------------------------------------------

    /**
     * Filter the full disclosure list to those matching the requested subset.
     *
     * Matching is performed on the canonical base64url-encoded form so that
     * callers can pass the same Disclosure objects received from issue() or
     * independently reconstructed objects.
     *
     * Disclosures in `requested` that are not found in `all` are silently
     * ignored (the presentation simply omits them).
     *
     * @param all       All disclosures from the issued SD-JWT.
     * @param requested Subset requested for this presentation.
     * @return Array of disclosures from `all` whose encoded form matches any
     *         entry in `requested`.
     */
    private func filterDisclosures(
        all!: Array<Disclosure>,
        requested!: Array<Disclosure>
    ): Array<Disclosure> {
        // Build a set of encoded forms for the requested disclosures
        var requestedEncoded = ArrayList<String>()
        var ri: Int64 = 0
        while (ri < requested.size) {
            let enc = requested[ri].encodeWith(_base64Url)
            requestedEncoded.add(enc)
            ri = ri + 1
        }

        // Collect matching disclosures from `all` preserving order
        var result = ArrayList<Disclosure>()
        var ai: Int64 = 0
        while (ai < all.size) {
            let enc = all[ai].encodeWith(_base64Url)
            var found = false
            var k: Int64 = 0
            while (k < requestedEncoded.size) {
                if (requestedEncoded[k] == enc) {
                    found = true
                    break
                }
                k = k + 1
            }
            if (found) {
                result.add(all[ai])
            }
            ai = ai + 1
        }
        return result.toArray()
    }

    // -----------------------------------------------------------------------
    // Internal: KB-JWT construction
    // -----------------------------------------------------------------------

    /**
     * Build and sign a Key Binding JWT.
     *
     * The KB-JWT payload includes:
     *   - nonce: caller-supplied nonce string
     *   - aud:   caller-supplied audience string
     *   - iat:   caller-supplied issued-at timestamp (Unix seconds, Int64)
     *   - sd_hash: base64url(sha256(utf8(presentationCompact)))
     *
     * The KB-JWT header is {"alg":"ES256","typ":"kb+jwt"}.
     *
     * @param presentationCompact  Compact SD-JWT without KB-JWT (ends with "~").
     * @param nonce                Nonce value.
     * @param aud                  Audience value.
     * @param iat                  Issued-at time as Unix seconds integer.
     * @param holderPriv           Holder's private key.
     * @return Jwt wrapping the compact KB-JWT string.
     */
    private func buildKbJwt(
        presentationCompact!: String,
        nonce!: String,
        aud!: String,
        iat!: Int64,
        holderPriv!: ECDSAPrivateKey
    ): Jwt {
        // Compute sd_hash with the SAME algorithm the factory used for the
        // payload's _sd_alg (sha-256/384/512), via the factory's DigestCreator —
        // NOT a hard-wired sha256.  Mirrors iOS SignedSDJWT delineatedCompactSerialisation.
        let sdHash = _factory.digestCreator().hashAndBase64Encode(presentationCompact)

        // Build KB-JWT payload JSON
        let kbPayloadJson = buildKbJwtPayload(nonce: nonce, aud: aud, iat: iat, sdHash: sdHash)
        let kbPayloadBytes: Array<UInt8> = kbPayloadJson.toArray()

        // Build KB-JWT header JSON
        let kbHeaderJson = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}"

        // Sign KB-JWT
        let kbCompact = _jws.signEs256(kbHeaderJson, kbPayloadBytes, holderPriv)
        return Jwt(compactSerialization: kbCompact)
    }

    /**
     * Build the KB-JWT payload JSON string.
     *
     * Format:
     *   {"iat":<iat>,"nonce":"<nonce>","aud":"<aud>","sd_hash":"<sdHash>"}
     *
     * Values are assumed to be free of characters requiring JSON escaping
     * (nonce/aud are URL-safe strings; sd_hash is base64url).
     */
    private func buildKbJwtPayload(
        nonce!: String,
        aud!: String,
        iat!: Int64,
        sdHash!: String
    ): String {
        return "{\"iat\":" + iat.toString() + ",\"nonce\":\"" + nonce +
            "\",\"aud\":\"" + aud +
            "\",\"sd_hash\":\"" + sdHash + "\"}"
    }

    // -----------------------------------------------------------------------
    // Internal: JOSE header builder
    // -----------------------------------------------------------------------

    /**
     * Build a minimal JWS JOSE header JSON string.
     *
     * Format: {"alg":"<alg>","typ":"<typ>"}
     *
     * @param alg  Algorithm identifier (e.g., "ES256").
     * @param typ  Type claim (e.g., "vc+sd-jwt", "JWT").
     * @return JSON header string.
     */
    private func buildJoseHeader(alg!: String, typ!: String): String {
        return "{\"alg\":\"" + alg + "\",\"typ\":\"" + typ + "\"}"
    }
}

// ---------------------------------------------------------------------------
// KbJwtParams  — parameters for Key Binding JWT construction
// ---------------------------------------------------------------------------

/**
 * Parameters for constructing a Key Binding JWT in presentation().
 *
 * The holder signs the KB-JWT with their private key to prove possession
 * of the key bound to the credential (cnf claim).
 */
public class KbJwtParams {
    /** Nonce value (provided by the verifier). */
    public let nonce: String

    /** Audience (verifier's identifier). */
    public let aud: String

    /** Issued-at timestamp (Unix seconds). */
    public let iat: Int64

    /** Holder's private key used to sign the KB-JWT. */
    public let holderPriv: ECDSAPrivateKey

    /**
     * Construct KbJwtParams.
     *
     * @param nonce      Verifier-supplied nonce.
     * @param aud        Verifier identifier (audience).
     * @param iat        Issued-at time in Unix seconds.
     * @param holderPriv Holder's ECDSA P-256 private key.
     */
    public init(
        nonce!: String,
        aud!: String,
        iat!: Int64,
        holderPriv!: ECDSAPrivateKey
    ) {
        this.nonce = nonce
        this.aud = aud
        this.iat = iat
        this.holderPriv = holderPriv
    }
}
