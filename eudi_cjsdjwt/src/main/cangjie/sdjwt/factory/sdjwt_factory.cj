/**
 * sdjwt_factory.cj
 *
 * SD-JWT payload construction: replaces selectively-disclosable claims with
 * _sd digest arrays and produces the corresponding Disclosure objects.
 *
 * Corresponds to:
 *   - Sources/Factory/SDJWTFactory.swift  (createSDJWTPayload)
 *   - Sources/Builders/SDJWTBuilder.swift (claims DSL — lowered to explicit builder)
 *
 * Design notes:
 *   - ClaimValue enum replaces Swift's @resultBuilder SdElement DSL.
 *     The iOS @resultBuilder is not available in Cangjie; callers build a
 *     HashMap<String, ClaimValue> explicitly instead.
 *   - Supported claim kinds:
 *       Plain(json)          — always-visible claim; value embedded verbatim
 *       Sd(json)             — selectively-disclosable leaf; replaced by _sd digest
 *       SdObject(claims)     — nested object whose sub-claims are processed recursively
 *       SdArray(elements)    — array whose elements may be individually disclosed
 *   - Salt generation: Rng.bytes(16) → base64url (128 random bits per IETF draft §7.1)
 *   - Decoy digests: hashes of random 16-byte salts with no associated Disclosure;
 *     count is fixed at construction time (default 0).
 *   - JSON construction: hand-built strings (no stdx dependency; mirrors approach
 *     used in sdjwt_types.cj).
 *   - _sd_alg is injected from DigestCreator.algIdentifier().
 *   - No duplicate-digest validation is performed here; the issuer layer is
 *     responsible for end-to-end structural checks if required.
 *
 * Functional contract (fc_sdjwt_factory_payload_construction):
 *   createPayload(claims) → (payloadJson: String, disclosures: Array<Disclosure>)
 *   where payloadJson is a JSON object string containing:
 *     - All Plain claims verbatim
 *     - "_sd": [ digest1, digest2, ... ] for Sd claims
 *     - "_sd_alg": "<alg_string>"
 *     - Nested SdObject values (recursively processed)
 *     - Array values with individually-disclosed elements
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.factory

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest.*
import std.collection.*

// ---------------------------------------------------------------------------
// ClaimValue — explicit builder replacement for @resultBuilder SdElement DSL
// ---------------------------------------------------------------------------

/**
 * Represents a single claim in the SD-JWT claims set.
 *
 * Replaces the Swift @resultBuilder SdElement enum:
 *   .plain  → Plain
 *   .flat   → Sd
 *   .object → SdObject
 *   .array  → SdArray
 *
 * Recursive variants (.recursiveObject / .recursiveArray) are not
 * included in this initial implementation: they require a two-pass
 * encode (encode-then-disclose the sub-structure), which goes beyond
 * the contract scope for fc_sdjwt_factory_payload_construction.
 */
public enum ClaimValue {
    /**
     * Always-visible (plain) claim.
     * The value is a pre-serialized JSON fragment (string, number, boolean,
     * object, or array).
     */
    | Plain(String)

    /**
     * Selectively-disclosable object property.
     * Replaced by a digest entry in the _sd array; callers can later
     * reveal it by including the Disclosure in the SD-JWT.
     * The value is a pre-serialized JSON fragment.
     */
    | Sd(String)

    /**
     * Nested object claim whose sub-claims are processed recursively.
     * The object itself is always present in the payload; individual
     * sub-claims may be selectively disclosed.
     */
    | SdObject(HashMap<String, ClaimValue>)

    /**
     * Array claim.
     * Each element is either a plain value or a selectively-disclosable
     * element wrapped in {"...": <digest>} per the SD-JWT spec.
     */
    | SdArray(ArrayList<ClaimValue>)
}

// ---------------------------------------------------------------------------
// FactoryResult — return type of createPayload
// ---------------------------------------------------------------------------

/**
 * Result of SdJwtFactory.createPayload.
 *
 * payloadJson  — the JWT payload as a JSON object string, ready to be
 *                base64url-encoded and signed.
 * disclosures  — all Disclosure objects produced during claim processing,
 *                in the order they were created.
 */
public class FactoryResult {
    public let payloadJson: String
    public let disclosures: Array<Disclosure>

    public init(payloadJson!: String, disclosures!: Array<Disclosure>) {
        this.payloadJson = payloadJson
        this.disclosures = disclosures
    }
}

// ---------------------------------------------------------------------------
// SdJwtFactory
// ---------------------------------------------------------------------------

/**
 * Constructs SD-JWT payloads from a claims map.
 *
 * Usage:
 *   let crypto = HostCryptoStub()
 *   let dc = DigestCreator(digest: crypto.digest, base64Url: crypto.base64Url,
 *                          algorithm: HashingAlgorithmIdentifier.Sha256)
 *   let factory = SdJwtFactory(digestCreator: dc, rng: crypto.rng, decoyCount: 2)
 *
 *   var claims = HashMap<String, ClaimValue>()
 *   claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
 *   claims.add("sub", ClaimValue.Sd("\"user-42\""))
 *   claims.add("given_name", ClaimValue.Sd("\"Alice\""))
 *
 *   let result = factory.createPayload(claims)
 *   // result.payloadJson contains _sd array + _sd_alg; "sub" and "given_name"
 *   // are absent from the JSON; result.disclosures has 2 entries.
 */
public class SdJwtFactory {

    let _digestCreator: DigestCreator
    let _base64Url: Base64Url
    let _rng: Rng
    let _decoyCount: Int64

    /**
     * Construct a factory.
     *
     * @param digestCreator  DigestCreator for hashing disclosures.
     * @param base64Url      Base64Url seam for encoding Disclosure objects.
     * @param rng            Random byte source for salt generation.
     * @param decoyCount     Number of decoy digests to add to each _sd array
     *                       (default 0).  Decoys are random digests with no
     *                       corresponding Disclosure.
     */
    public init(
        digestCreator!: DigestCreator,
        base64Url!: Base64Url,
        rng!: Rng,
        decoyCount!: Int64
    ) {
        _digestCreator = digestCreator
        _base64Url = base64Url
        _rng = rng
        _decoyCount = decoyCount
    }

    /**
     * Expose the DigestCreator used by this factory so that downstream layers
     * (e.g. the issuer's KB-JWT sd_hash computation) hash with the SAME
     * algorithm that produced the payload's _sd_alg, instead of hard-wiring
     * sha-256.
     */
    public func digestCreator(): DigestCreator {
        return _digestCreator
    }

    /**
     * Build the SD-JWT payload JSON and produce all associated Disclosures.
     *
     * Steps:
     *   1. Process each claim in `claims` according to its ClaimValue kind.
     *   2. Collect Sd/SdArray digests into the top-level _sd array.
     *   3. Add _sd_alg claim.
     *   4. Optionally add decoy digests.
     *   5. Assemble and return payloadJson + disclosures.
     *
     * @param claims  Map of claim names to ClaimValue descriptors.
     * @return FactoryResult with payloadJson and disclosures.
     */
    public func createPayload(claims: HashMap<String, ClaimValue>): FactoryResult {
        var allDisclosures = ArrayList<Disclosure>()
        var sdDigests = ArrayList<String>()
        var plainEntries = ArrayList<(String, String)>()

        for ((key, val) in claims) {
            let entry = processTopLevelClaim(
                key: key,
                value: val,
                disclosures: allDisclosures,
                sdDigests: sdDigests
            )
            match (entry) {
                case Some(jsonKv) => plainEntries.add(jsonKv)
                case None => ()
            }
        }

        addDecoys(sdDigests: sdDigests)

        let payloadJson = buildPayloadJson(
            plainEntries: plainEntries,
            sdDigests: sdDigests,
            algStr: _digestCreator.algIdentifier()
        )

        return FactoryResult(
            payloadJson: payloadJson,
            disclosures: allDisclosures.toArray()
        )
    }

    // -----------------------------------------------------------------------
    // Internal: top-level claim processing
    // -----------------------------------------------------------------------

    /**
     * Process a single top-level claim.
     *
     * Returns Some((key, jsonValueFragment)) for plain/object/array claims
     * that should be embedded directly in the payload, or None for Sd claims
     * whose digest goes into _sd.
     */
    private func processTopLevelClaim(
        key!: String,
        value!: ClaimValue,
        disclosures!: ArrayList<Disclosure>,
        sdDigests!: ArrayList<String>
    ): Option<(String, String)> {
        match (value) {
            case Plain(json) =>
                return Some((key, json))

            case Sd(json) =>
                let salt = generateSalt()
                let disc = Disclosure(salt: salt, name: key, value: json)
                let encoded = disc.encodeWith(_base64Url)
                let digest = _digestCreator.hashAndBase64Encode(encoded)
                disclosures.add(disc)
                sdDigests.add(digest)
                return None

            case SdObject(subClaims) =>
                let subJson = processNestedObject(
                    subClaims: subClaims,
                    disclosures: disclosures
                )
                return Some((key, subJson))

            case SdArray(elements) =>
                let arrayJson = processArray(
                    elements: elements,
                    disclosures: disclosures
                )
                return Some((key, arrayJson))
        }
    }

    // -----------------------------------------------------------------------
    // Internal: nested object processing
    // -----------------------------------------------------------------------

    /**
     * Process a nested SdObject claim.
     *
     * The nested object is always present in the payload; individual
     * sub-claims may be selectively disclosed (Sd) or plain (Plain).
     * Sub-objects and sub-arrays are handled recursively.
     *
     * Returns the nested object as a JSON object string.
     */
    private func processNestedObject(
        subClaims!: HashMap<String, ClaimValue>,
        disclosures!: ArrayList<Disclosure>
    ): String {
        var nestedSdDigests = ArrayList<String>()
        var nestedPlainEntries = ArrayList<(String, String)>()

        for ((key, val) in subClaims) {
            let entry = processTopLevelClaim(
                key: key,
                value: val,
                disclosures: disclosures,
                sdDigests: nestedSdDigests
            )
            match (entry) {
                case Some(kv) => nestedPlainEntries.add(kv)
                case None => ()
            }
        }

        return buildObjectJson(
            plainEntries: nestedPlainEntries,
            sdDigests: nestedSdDigests
        )
    }

    // -----------------------------------------------------------------------
    // Internal: array processing
    // -----------------------------------------------------------------------

    /**
     * Process an SdArray claim.
     *
     * Each element:
     *   - Plain(json)      → embedded verbatim as a plain array element
     *   - Sd(json)         → replaced by {"...": <digest>}; disclosure added
     *   - SdObject(claims) → recursively encoded (sub-claims selectively
     *     disclosable via nested _sd; their disclosures threaded into the shared
     *     list) and embedded verbatim; the element itself is present
     *   - SdArray(elems)   → recursively encoded (elements selectively
     *     disclosable) and embedded verbatim; the element itself is present
     *
     * Returns the array as a JSON array string.
     */
    private func processArray(
        elements!: ArrayList<ClaimValue>,
        disclosures!: ArrayList<Disclosure>
    ): String {
        var parts = ArrayList<String>()
        for (elem in elements) {
            match (elem) {
                case Plain(json) =>
                    parts.add(json)
                case Sd(json) =>
                    let salt = generateSalt()
                    let disc = Disclosure(salt: salt, value: json)
                    let encoded = disc.encodeWith(_base64Url)
                    let digest = _digestCreator.hashAndBase64Encode(encoded)
                    disclosures.add(disc)
                    parts.add("{" + jsonQuote(Keys.dots) + ":" + jsonQuote(digest) + "}")
                case SdObject(subClaims) =>
                    // Nested selectively-disclosable OBJECT at an array element:
                    // recursively encode it (its sub-claims get their own _sd and
                    // their disclosures are threaded into the shared list) and embed
                    // the result verbatim — the element itself is present. Same
                    // semantics as a top-level SdObject claim (processTopLevelClaim).
                    parts.add(processNestedObject(subClaims: subClaims, disclosures: disclosures))
                case SdArray(subElements) =>
                    // Nested selectively-disclosable ARRAY at an array element:
                    // recurse, same semantics as a top-level SdArray claim.
                    parts.add(processArray(elements: subElements, disclosures: disclosures))
            }
        }
        return buildJsonArray(parts)
    }

    // -----------------------------------------------------------------------
    // Internal: decoy generation
    // -----------------------------------------------------------------------

    /**
     * Append `_decoyCount` random decoy digests to sdDigests.
     *
     * Decoys are hashes of random 16-byte salts; they look identical to
     * real disclosure digests but have no associated Disclosure object.
     * Callers (and verifiers) cannot distinguish decoys from undisclosed
     * real disclosures.
     */
    private func addDecoys(sdDigests!: ArrayList<String>) {
        var i: Int64 = 0
        while (i < _decoyCount) {
            let salt = generateSalt()
            let fakeDisc = Disclosure(salt: salt, value: "\"_decoy\"")
            let encoded = fakeDisc.encodeWith(_base64Url)
            let digest = _digestCreator.hashAndBase64Encode(encoded)
            sdDigests.add(digest)
            i = i + 1
        }
    }

    // -----------------------------------------------------------------------
    // Internal: salt generation
    // -----------------------------------------------------------------------

    /**
     * Generate a base64url-encoded 16-byte random salt.
     *
     * Per IETF SD-JWT draft §7.1: "salt values MUST be random byte strings
     * of sufficient entropy" — 128 bits (16 bytes) is the recommended minimum.
     */
    private func generateSalt(): String {
        let rawBytes = _rng.bytes(16)
        return _base64Url.encode(rawBytes)
    }

    // -----------------------------------------------------------------------
    // Internal: JSON builders (hand-built; no stdx dep)
    // -----------------------------------------------------------------------

    /**
     * Build the top-level payload JSON object string.
     *
     * Structure:
     *   {
     *     "<plain-key>": <plain-value>,
     *     ...,
     *     "_sd": ["<digest1>", "<digest2>", ...],   (omitted if empty)
     *     "_sd_alg": "<alg>"
     *   }
     *
     * Note: key ordering is intentionally not mandated by the SD-JWT spec.
     * _sd_alg is always present.
     */
    private func buildPayloadJson(
        plainEntries!: ArrayList<(String, String)>,
        sdDigests!: ArrayList<String>,
        algStr!: String
    ): String {
        var fields = ArrayList<String>()

        for ((k, v) in plainEntries) {
            fields.add(jsonQuote(k) + ":" + v)
        }

        if (sdDigests.size > 0) {
            var digestItems = ArrayList<String>()
            for (d in sdDigests) {
                digestItems.add(jsonQuote(d))
            }
            fields.add(jsonQuote(Keys.sd) + ":" + buildJsonArray(digestItems))
        }

        fields.add(jsonQuote(Keys.sdAlg) + ":" + jsonQuote(algStr))

        return buildJsonObject(fields)
    }

    /**
     * Build a nested object JSON string (for SdObject processing).
     *
     * Like buildPayloadJson but without the _sd_alg field.
     */
    private func buildObjectJson(
        plainEntries!: ArrayList<(String, String)>,
        sdDigests!: ArrayList<String>
    ): String {
        var fields = ArrayList<String>()

        for ((k, v) in plainEntries) {
            fields.add(jsonQuote(k) + ":" + v)
        }

        if (sdDigests.size > 0) {
            var digestItems = ArrayList<String>()
            for (d in sdDigests) {
                digestItems.add(jsonQuote(d))
            }
            fields.add(jsonQuote(Keys.sd) + ":" + buildJsonArray(digestItems))
        }

        return buildJsonObject(fields)
    }

    /**
     * Build a JSON object string from a list of pre-formatted "key:value" field strings.
     */
    private func buildJsonObject(fields: ArrayList<String>): String {
        if (fields.size == 0) {
            return "{}"
        }
        var result = "{"
        var i: Int64 = 0
        while (i < fields.size) {
            if (i > 0) {
                result = result + ","
            }
            result = result + fields[i]
            i = i + 1
        }
        result = result + "}"
        return result
    }

    /**
     * Build a JSON array string from a list of pre-formatted element strings.
     */
    private func buildJsonArray(items: ArrayList<String>): String {
        if (items.size == 0) {
            return "[]"
        }
        var result = "["
        var i: Int64 = 0
        while (i < items.size) {
            if (i > 0) {
                result = result + ","
            }
            result = result + items[i]
            i = i + 1
        }
        result = result + "]"
        return result
    }

    /**
     * Wrap a string in JSON double quotes.
     *
     * Input strings are expected to be ASCII-clean identifiers, claim names,
     * or base64url digests — no special character escaping is needed for these.
     * General JSON string escaping is handled in Disclosure.escapeJsonString.
     */
    private func jsonQuote(s: String): String {
        return "\"" + s + "\""
    }
}
