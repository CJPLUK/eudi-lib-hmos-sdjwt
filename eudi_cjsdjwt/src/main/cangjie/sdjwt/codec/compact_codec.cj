/**
 * compact_codec.cj
 *
 * SD-JWT compact serialization and parsing.
 *
 * IETF SD-JWT compact format (draft-ietf-oauth-selective-disclosure-jwt):
 *   <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~[<KB-JWT>]
 *
 * Boundary rules:
 *   - No kbJwt, no disclosures:     jwt~
 *   - No kbJwt, with disclosures:   jwt~d1~d2~
 *   - With kbJwt, no disclosures:   jwt~kbjwt
 *   - With kbJwt, with disclosures: jwt~d1~d2~kbjwt
 *
 * Corresponds to:
 *   Sources/Serializer/CompactSerialiser.swift
 *   Sources/Parser/CompactParser.swift (parseCombined)
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import std.collection.*

// ---------------------------------------------------------------------------
// CompactSerialiser
// ---------------------------------------------------------------------------

/**
 * Serialises a SignedSdJwt to the IETF SD-JWT compact string format.
 *
 * Format: jwt~[d1~d2~...~][kbjwt]
 *   - Disclosures (if any) are base64url-encoded and each followed by ~.
 *   - When kbJwt is absent the compact string ends with ~.
 *   - When kbJwt is present it appears last with no trailing ~.
 */
public class CompactSerialiser {
    let b64: Base64Url

    /**
     * Create a CompactSerialiser backed by the supplied Base64Url implementation.
     *
     * @param b64  Base64Url seam instance used to encode disclosures.
     */
    public init(b64!: Base64Url) {
        this.b64 = b64
    }

    /**
     * Serialise a SignedSdJwt to compact SD-JWT string.
     *
     * Round-trip invariant: CompactParser.parse(serialise(x), b64) produces
     * a structurally equivalent SignedSdJwt for all valid inputs.
     *
     * @param sdJwt  The signed SD-JWT to serialise.
     * @return Compact SD-JWT string.
     */
    public func serialise(sdJwt: SignedSdJwt): String {
        var result = sdJwt.jwt.compactSerialization
        // Append each disclosure followed by ~
        var i = 0
        while (i < sdJwt.disclosures.size) {
            let encoded = sdJwt.disclosures[i].encodeWith(b64)
            result = result + Keys.disclosureSeparator + encoded
            i = i + 1
        }
        // Always append ~; then optionally append kbJwt (which has no trailing ~)
        result = result + Keys.disclosureSeparator
        match (sdJwt.kbJwt) {
            case Some(kb) =>
                result = result + kb.compactSerialization
            case None => ()
        }
        return result
    }
}

// ---------------------------------------------------------------------------
// CompactParser
// ---------------------------------------------------------------------------

/**
 * Parses an IETF SD-JWT compact string back into a SignedSdJwt.
 *
 * Parsing rules (mirrors CompactParser.parseCombined in Swift):
 *   1. Split the string on ~ keeping empty trailing segments.
 *   2. parts[0] is always the issuer-signed JWT.
 *   3. If the original string ends with ~, the last segment is empty =>
 *      no kbJwt; disclosures are parts[1 .. parts.size-2].
 *   4. If the original string does NOT end with ~, the last segment is the
 *      kbJwt; disclosures are parts[1 .. parts.size-2].
 *   5. Disclosures are decoded from base64url using the supplied Base64Url impl.
 */
public class CompactParser {
    let b64: Base64Url

    /**
     * Create a CompactParser backed by the supplied Base64Url implementation.
     *
     * @param b64  Base64Url seam instance used to decode disclosures.
     */
    public init(b64!: Base64Url) {
        this.b64 = b64
    }

    /**
     * Parse a compact SD-JWT string into a SignedSdJwt.
     *
     * @param compact  The ~ -separated compact SD-JWT string.
     * @return Parsed SignedSdJwt.
     * @throws SdJwtVerifierError if the format is invalid.
     */
    public func parse(compact: String): SignedSdJwt {
        // Split on ~ keeping empty trailing element produced by trailing ~
        let parts = compact.split(Keys.disclosureSeparator)
        if (parts.size < 2) {
            throw SdJwtVerifierError("Invalid compact SD-JWT: must have at least one ~ separator")
        }

        let jwtStr = parts[0]

        // Determine whether a KB-JWT is present.
        // A trailing ~ means the last part is an empty string => no kbJwt.
        // No trailing ~ means the last part is the kbJwt string.
        let hasTrailingTilde = compact.endsWith(Keys.disclosureSeparator)

        // Disclosures occupy parts[1 .. parts.size-2] in both cases
        // (the last element is either empty-from-trailing-~ or kbJwt).
        let kbJwtOption: Option<Jwt>
        if (hasTrailingTilde) {
            kbJwtOption = None
        } else {
            let kbStr = parts[parts.size - 1]
            kbJwtOption = Some(Jwt(compactSerialization: kbStr))
        }

        // Collect and decode disclosure segments
        var disclosures = ArrayList<Disclosure>()
        var idx = 1
        let discEnd = parts.size - 1  // exclusive; last element is empty or kbJwt
        while (idx < discEnd) {
            let seg = parts[idx]
            if (!seg.isEmpty()) {
                let disc = Disclosure.decodeWith(seg, b64)
                disclosures.add(disc)
            }
            idx = idx + 1
        }

        let discArray = disclosures.toArray()
        return SignedSdJwt(
            jwt: Jwt(compactSerialization: jwtStr),
            disclosures: discArray,
            kbJwt: kbJwtOption
        )
    }
}
