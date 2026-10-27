/**
 * sdjwt_verifier.cj
 *
 * SD-JWT verification pipeline.
 *
 * Corresponds to:
 *   Sources/Verifier/SDJWTVerifier.swift     (verifyIssuance / verifyPresentation)
 *   Sources/Verifier/DisclosuresVerifier.swift  (digest reconciliation)
 *   Sources/Verifier/KeyBindingVerifier.swift   (KB-JWT nonce/aud/sd_hash)
 *
 * Design notes:
 *   - JWS signature verification delegates entirely to the seam Jws.verifyEs256
 *     interface; no direct crypto is performed in this package.
 *   - DisclosuresVerifier: extracts the hash algorithm from the JWT payload
 *     (_sd_alg claim), computes the digest of each disclosure, then confirms
 *     every disclosure digest is reachable from the payload's _sd arrays or
 *     the array-element "..." wrapper objects (recursive, supports nesting).
 *     Duplicate digests → error.  Missing _sd_alg → error.
 *   - Claims reconstruction: after digest matching, each object-property
 *     disclosure is injected back into the payload JSON under its claim name.
 *     Array-element disclosures replace the {"...": <digest>} sentinel.
 *   - KeyBindingVerifier: checks typ=kb+jwt, extracts nonce and aud from
 *     the KB-JWT payload, verifies them against expected values, then checks
 *     that the sd_hash equals the base64url-encoded SHA-256 of the compact
 *     presentation string (the issuer-signed JWT part with disclosures).
 *   - All JSON parsing uses a minimal hand-rolled parser (no stdx dependency;
 *     cjpm.toml is a forbidden file).
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.verifier

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec.*
import std.collection.*
import std.overflow.*
import stdx.encoding.json.*

// ---------------------------------------------------------------------------
// VerificationResult  (replaces Swift Result<SignedSdJwt, Error>)
// ---------------------------------------------------------------------------

/**
 * Result of a verification operation.
 *
 * ok:  Some(signedSdJwt) — verification passed
 * err: Some(SdJwtVerifierError) — verification failed
 *
 * Exactly one of ok / err is Some.
 */
public class VerificationResult {
    public let ok: Option<SignedSdJwt>
    public let err: Option<SdJwtVerifierError>

    /**
     * The fully recreated claim tree (mirrors iOS recreateSdJwtClaims).
     *
     * On a successful verifyIssuance / verifyPresentation, this carries the
     * issuer payload with every presented disclosure resolved back into place:
     *   - object "_sd" digests replaced by their [salt, name, value] claim,
     *   - array {"...": digest} markers replaced by their [salt, value] element,
     *   - undisclosed array markers omitted,
     *   - "_sd" / "_sd_alg" book-keeping keys stripped,
     *   - recursion into already-disclosed values (recursive disclosure).
     * Serialised as a JSON string so downstream consumers can re-parse it with
     * stdx.encoding.json (or any JSON reader).  None when verification failed.
     */
    public let recreatedClaims: Option<String>

    public init(ok!: SignedSdJwt) {
        this.ok = Some(ok)
        this.err = None
        this.recreatedClaims = None
    }

    public init(ok!: SignedSdJwt, recreatedClaims!: String) {
        this.ok = Some(ok)
        this.err = None
        this.recreatedClaims = Some(recreatedClaims)
    }

    public init(err!: SdJwtVerifierError) {
        this.ok = None
        this.err = Some(err)
        this.recreatedClaims = None
    }

    public func isOk(): Bool {
        match (ok) {
            case Some(_) => true
            case None => false
        }
    }
}

// ---------------------------------------------------------------------------
// DisclosureDigestMap  — maps digest string → Disclosure
// ---------------------------------------------------------------------------

/**
 * Maps each base64url-encoded disclosure digest to its Disclosure object.
 *
 * Built once from the disclosure list using the algorithm specified in the
 * JWT payload's _sd_alg claim.  All lookup is O(1) via HashMap.
 */
class DisclosureDigestMap {
    let _map: HashMap<String, Disclosure>
    let _digestCreator: DigestCreator

    init(digestCreator!: DigestCreator, b64!: Base64Url, disclosures!: Array<Disclosure>) {
        _digestCreator = digestCreator
        _map = HashMap<String, Disclosure>()
        var i: Int64 = 0
        while (i < disclosures.size) {
            let disc = disclosures[i]
            let encoded = disc.encodeWith(b64)
            let digest = digestCreator.hashAndBase64Encode(encoded)
            _map.add(digest, disc)
            i = i + 1
        }
    }

    func lookup(digest: String): Option<Disclosure> {
        return _map.get(digest)
    }

    func size(): Int64 {
        return _map.size
    }

    func containsDigest(digest: String): Bool {
        return _map.contains(digest)
    }

    func allDigests(): Array<String> {
        var result = ArrayList<String>()
        for ((k, _) in _map) {
            result.add(k)
        }
        return result.toArray()
    }
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers for the verifier
// ---------------------------------------------------------------------------

/**
 * Extract the string value of a top-level JSON object field.
 *
 * Searches for `"fieldName":` in the JSON object string and extracts the
 * following JSON string value.  Returns None if the field is absent or
 * not a string.
 *
 * This is intentionally a minimal implementation used only for extracting
 * simple string-valued claims from JWT payloads (e.g., _sd_alg, nonce, aud,
 * sd_hash, typ).  It handles basic JSON strings without nested objects or
 * arrays in the value position.
 */
func extractStringField(json: String, fieldName: String): Option<String> {
    let needle = "\"" + fieldName + "\""
    let chars = json.toRuneArray()
    let needleChars = needle.toRuneArray()
    let nLen = needleChars.size
    let jLen = chars.size

    var i: Int64 = 0
    while (i <= jLen - nLen) {
        var matched = true
        var k: Int64 = 0
        while (k < nLen) {
            if (UInt32(chars[i + k]) != UInt32(needleChars[k])) {
                matched = false
                break
            }
            k = k + 1
        }
        if (matched) {
            // Skip whitespace and colon after field name
            var pos: Int64 = i + nLen
            while (pos < jLen && (UInt32(chars[pos]) == 0x20u32 || UInt32(chars[pos]) == 0x09u32 || UInt32(chars[pos]) == 0x0Au32 || UInt32(chars[pos]) == 0x0Du32)) {
                pos = pos + 1
            }
            if (pos >= jLen || UInt32(chars[pos]) != 0x3Au32) {
                i = i + 1
                continue
            }
            pos = pos + 1 // skip ':'
            // Skip whitespace
            while (pos < jLen && (UInt32(chars[pos]) == 0x20u32 || UInt32(chars[pos]) == 0x09u32 || UInt32(chars[pos]) == 0x0Au32 || UInt32(chars[pos]) == 0x0Du32)) {
                pos = pos + 1
            }
            if (pos >= jLen || UInt32(chars[pos]) != 0x22u32) {
                return None  // value is not a string
            }
            // Parse the JSON string value.
            // Use a UTF-8 byte buffer instead of Rune.toString() to avoid S-018:
            // on aarch64-linux-ohos, Rune.toString() returns the decimal code point
            // ("115" for 's') rather than the character ("s").
            pos = pos + 1 // skip opening quote
            // Pre-allocate: each rune needs at most 4 UTF-8 bytes; escape sequences
            // produce at most 4 bytes (\b, \n, \r, \t) or 1 byte (/); conservative
            // upper bound is (jLen - pos) * 4.
            var buf: Array<UInt8> = Array<UInt8>((jLen - pos) * 4 + 4, repeat: 0u8)
            var bpos: Int64 = 0
            var inEscape = false
            while (pos < jLen) {
                let cp = UInt32(chars[pos])
                if (inEscape) {
                    if (cp == 0x22u32) {
                        // \" -> double-quote byte
                        buf[bpos] = 0x22u8
                        bpos = bpos + 1
                    } else if (cp == 0x5Cu32) {
                        // \\ -> backslash byte
                        buf[bpos] = 0x5Cu8
                        bpos = bpos + 1
                    } else if (cp == 0x2Fu32) {
                        // \/ -> solidus byte
                        buf[bpos] = 0x2Fu8
                        bpos = bpos + 1
                    } else if (cp == 0x62u32) {
                        // \b -> backspace (U+0008)
                        buf[bpos] = 0x08u8
                        bpos = bpos + 1
                    } else if (cp == 0x66u32) {
                        // \f -> form feed (U+000C)
                        buf[bpos] = 0x0Cu8
                        bpos = bpos + 1
                    } else if (cp == 0x6Eu32) {
                        // \n -> newline (U+000A)
                        buf[bpos] = 0x0Au8
                        bpos = bpos + 1
                    } else if (cp == 0x72u32) {
                        // \r -> carriage return (U+000D)
                        buf[bpos] = 0x0Du8
                        bpos = bpos + 1
                    } else if (cp == 0x74u32) {
                        // \t -> horizontal tab (U+0009)
                        buf[bpos] = 0x09u8
                        bpos = bpos + 1
                    }
                    inEscape = false
                } else if (cp == 0x5Cu32) {
                    inEscape = true
                } else if (cp == 0x22u32) {
                    // end of string — return the accumulated bytes as a String
                    return Some(String.fromUtf8(buf[0..bpos]))
                } else {
                    // ordinary rune: encode to UTF-8 bytes (device-safe, no Rune.toString())
                    bpos = bpos + Rune.intoUtf8Array(chars[pos], buf, bpos)
                }
                pos = pos + 1
            }
            return None // unterminated string
        }
        i = i + 1
    }
    return None
}

/**
 * Check whether a JSON object string contains a given key.
 */
func jsonObjectHasKey(json: String, key: String): Bool {
    match (extractStringField(json, key)) {
        case Some(_) => true
        case None => false
    }
}

/**
 * Extract the raw JSON substring of an object-valued field.
 *
 * Searches for `"fieldName":` and, if the value position is an opening brace
 * '{', returns the full balanced object substring (including the braces).
 * Returns None if the field is absent or its value is not an object.
 *
 * Used to drill into the nested `cnf` → `jwk` objects when extracting the
 * holder's public key from the issuer-signed payload (mirrors iOS
 * SignedSDJWT.extractHoldersPublicKey reading payload[cnf]["jwk"]).
 *
 * Depth-aware: tracks brace/bracket nesting and string state so that braces
 * inside string values do not terminate the object early.
 */
func extractObjectField(json: String, fieldName: String): Option<String> {
    let needle = "\"" + fieldName + "\""
    let chars = json.toRuneArray()
    let needleChars = needle.toRuneArray()
    let nLen = needleChars.size
    let jLen = chars.size

    var i: Int64 = 0
    while (i <= jLen - nLen) {
        var matched = true
        var k: Int64 = 0
        while (k < nLen) {
            if (UInt32(chars[i + k]) != UInt32(needleChars[k])) {
                matched = false
                break
            }
            k = k + 1
        }
        if (matched) {
            var pos: Int64 = i + nLen
            // Skip whitespace then expect ':'
            while (pos < jLen && isJsonWhitespace(UInt32(chars[pos]))) {
                pos = pos + 1
            }
            if (pos >= jLen || UInt32(chars[pos]) != 0x3Au32) {
                i = i + 1
                continue
            }
            pos = pos + 1 // skip ':'
            while (pos < jLen && isJsonWhitespace(UInt32(chars[pos]))) {
                pos = pos + 1
            }
            // Expect '{'
            if (pos >= jLen || UInt32(chars[pos]) != 0x7Bu32) {
                return None
            }
            // Scan a balanced object, depth-aware, honouring string literals.
            let objStart = pos
            var depth: Int64 = 0
            var inStr = false
            var escaped = false
            while (pos < jLen) {
                let cp = UInt32(chars[pos])
                if (escaped) {
                    escaped = false
                } else if (inStr) {
                    if (cp == 0x5Cu32) {
                        escaped = true
                    } else if (cp == 0x22u32) {
                        inStr = false
                    }
                } else {
                    if (cp == 0x22u32) {
                        inStr = true
                    } else if (cp == 0x7Bu32) {
                        depth = depth + 1
                    } else if (cp == 0x7Du32) {
                        depth = depth - 1
                        if (depth == 0) {
                            return Some(runeRangeToString(chars, objStart, pos + 1))
                        }
                    }
                }
                pos = pos + 1
            }
            return None  // unterminated object
        }
        i = i + 1
    }
    return None
}

/**
 * Reconstruct a String from a sub-range [from, to) of a Rune array using
 * UTF-8 byte accumulation (device-safe; avoids Rune.toString() S-018).
 */
func runeRangeToString(chars: Array<Rune>, from: Int64, to: Int64): String {
    var totalBytes: Int64 = 0
    var i = from
    while (i < to) {
        totalBytes = totalBytes + Rune.utf8Size(chars[i])
        i = i + 1
    }
    var buf: Array<UInt8> = Array<UInt8>(totalBytes, repeat: 0u8)
    var pos: Int64 = 0
    i = from
    while (i < to) {
        pos = pos + Rune.intoUtf8Array(chars[i], buf, pos)
        i = i + 1
    }
    return String.fromUtf8(buf)
}

/**
 * Extract the holder's public-key JWK from an already-verified issuer payload.
 *
 * Reads payload[cnf][jwk], parses kty/crv/x/y (and the optional "_raw" marker),
 * and reconstructs the seam ECDSAPublicKey via JwkCodec.
 *
 * Mirrors iOS Sources/Issuer/SignedSDJWT.swift extractHoldersPublicKey():
 * fail-closed — throws SdJwtVerifierError if cnf or cnf.jwk is missing or
 * malformed (so a presentation that carries a KB-JWT but whose issuer payload
 * does not bind a holder key is rejected, never silently accepted).
 *
 * @param payloadJson  The decoded, signature-verified issuer JWT payload JSON.
 * @param b64          Base64Url seam (for JWK x/y decoding).
 * @return The holder ECDSAPublicKey bound by the issuer.
 * @throws SdJwtVerifierError if the cnf.jwk binding is absent or unparseable.
 */
func extractHoldersPublicKey(payloadJson: String, b64: Base64Url): ECDSAPublicKey {
    let cnfJson: String = match (extractObjectField(payloadJson, Keys.cnf)) {
        case Some(s) => s
        case None => throw SdJwtVerifierError("Key binding failed: missing cnf claim in issuer payload")
    }
    let jwkJson: String = match (extractObjectField(cnfJson, Keys.jwk)) {
        case Some(s) => s
        case None => throw SdJwtVerifierError("Key binding failed: missing cnf.jwk in issuer payload")
    }
    let xStr: String = match (extractStringField(jwkJson, "x")) {
        case Some(s) => s
        case None => throw SdJwtVerifierError("Key binding failed: cnf.jwk missing 'x'")
    }
    let yStr: String = match (extractStringField(jwkJson, "y")) {
        case Some(s) => s
        case None => throw SdJwtVerifierError("Key binding failed: cnf.jwk missing 'y'")
    }
    let ktyStr: String = match (extractStringField(jwkJson, "kty")) {
        case Some(s) => s
        case None => "EC"
    }
    let crvStr: String = match (extractStringField(jwkJson, "crv")) {
        case Some(s) => s
        case None => "P-256"
    }
    // The "_raw" marker (present for non-SPKI host keys) selects the lossless
    // concat reconstruction path; its absence selects the SPKI-DER rebuild.
    let isRaw: Bool = jsonObjectHasKey(jwkJson, "_raw")
    let jwk = Jwk(kty: ktyStr, crv: crvStr, x: xStr, y: yStr, raw: isRaw)
    let codec = JwkCodec(b64: b64)
    return codec.toPublicKey(jwk)
}

/**
 * Collect all digest strings from _sd arrays in a JSON payload.
 *
 * Recursively traverses the JSON object string to collect every element
 * of every "_sd" array.  Also collects array-element digests from
 * {"...": "<digest>"} objects nested in arrays.
 *
 * Returns an ArrayList<String> containing all found digest strings.
 *
 * Implementation: character-level scan looking for "\"_sd\"" and then
 * collecting quoted strings from the array that follows.
 */
func collectSdDigests(payloadJson: String): ArrayList<String> {
    var result = ArrayList<String>()
    collectSdDigestsFrom(payloadJson.toRuneArray(), 0, payloadJson.toRuneArray().size, result)
    return result
}

/**
 * Digest kind discriminator for structural validation.
 *
 * Mirrors iOS DigestType (DigestCreator.swift):
 *   object — digest found inside an "_sd" array → MUST decode to a 3-element
 *            object-property disclosure [salt, key, value]  (components == 3).
 *   array  — digest found inside a {"...": d} array-element marker → MUST decode
 *            to a 2-element array disclosure [salt, value]    (components == 2).
 */
enum DigestKind {
    | DkObject
    | DkArray

    /** Expected disclosure element count for this kind (iOS DigestType.components). */
    func components(): Int64 {
        match (this) {
            case DkObject => 3
            case DkArray => 2
        }
    }

    func name(): String {
        match (this) {
            case DkObject => "object"
            case DkArray => "array"
        }
    }
}

/**
 * A payload digest paired with the structural kind of the location it was
 * found in (object _sd array vs array-element "..." marker).
 */
class PayloadDigest {
    let digest: String
    let kind: DigestKind

    init(digest!: String, kind!: DigestKind) {
        this.digest = digest
        this.kind = kind
    }
}

/**
 * Kind-aware variant of collectSdDigests: returns each payload digest tagged
 * with whether it came from an object "_sd" array (DkObject) or an array-element
 * {"...": d} marker (DkArray).  Feeds verifyDigestsStructure.
 */
func collectSdDigestsWithKind(payloadJson: String): ArrayList<PayloadDigest> {
    var result = ArrayList<PayloadDigest>()
    let chars = payloadJson.toRuneArray()
    collectSdDigestsWithKindFrom(chars, 0, chars.size, result)
    return result
}

func collectSdDigestsWithKindFrom(chars: Array<Rune>, start: Int64, end: Int64, result: ArrayList<PayloadDigest>): Unit {
    var i: Int64 = start
    while (i < end) {
        let cp = UInt32(chars[i])
        if (cp == 0x22u32) {
            // "_sd" key → object-property digests
            if (i + 4 < end &&
                UInt32(chars[i + 1]) == 0x5Fu32 &&
                UInt32(chars[i + 2]) == 0x73u32 &&
                UInt32(chars[i + 3]) == 0x64u32 &&
                UInt32(chars[i + 4]) == 0x22u32) {
                var pos: Int64 = i + 5
                while (pos < end && UInt32(chars[pos]) != 0x3Au32) {
                    pos = pos + 1
                }
                pos = pos + 1
                while (pos < end && isJsonWhitespace(UInt32(chars[pos]))) {
                    pos = pos + 1
                }
                if (pos < end && UInt32(chars[pos]) == 0x5Bu32) {
                    pos = pos + 1
                    while (pos < end && UInt32(chars[pos]) != 0x5Du32) {
                        while (pos < end && isJsonWhitespace(UInt32(chars[pos]))) {
                            pos = pos + 1
                        }
                        if (pos < end && UInt32(chars[pos]) == 0x22u32) {
                            let strResult = parseJsonStringAt(chars, pos + 1, end)
                            result.add(PayloadDigest(digest: strResult.value, kind: DigestKind.DkObject))
                            pos = strResult.nextPos
                        } else if (pos < end && UInt32(chars[pos]) == 0x5Du32) {
                            break
                        } else {
                            pos = pos + 1
                        }
                        while (pos < end && (isJsonWhitespace(UInt32(chars[pos])) || UInt32(chars[pos]) == 0x2Cu32)) {
                            pos = pos + 1
                        }
                    }
                }
                i = pos
                continue
            }
            // "..." key → array-element digest
            if (i + 4 < end &&
                UInt32(chars[i + 1]) == 0x2Eu32 &&
                UInt32(chars[i + 2]) == 0x2Eu32 &&
                UInt32(chars[i + 3]) == 0x2Eu32 &&
                UInt32(chars[i + 4]) == 0x22u32) {
                var pos: Int64 = i + 5
                while (pos < end && UInt32(chars[pos]) != 0x3Au32) {
                    pos = pos + 1
                }
                pos = pos + 1
                while (pos < end && isJsonWhitespace(UInt32(chars[pos]))) {
                    pos = pos + 1
                }
                if (pos < end && UInt32(chars[pos]) == 0x22u32) {
                    let strResult = parseJsonStringAt(chars, pos + 1, end)
                    result.add(PayloadDigest(digest: strResult.value, kind: DigestKind.DkArray))
                    i = strResult.nextPos
                    continue
                }
            }
        }
        i = i + 1
    }
}

/**
 * Recursive helper: scan a JSON fragment (chars[start..end]) for _sd arrays.
 *
 * Collects digest strings from:
 *   1. "_sd": ["digest1", "digest2", ...] arrays at any nesting level.
 *   2. {"...": "digest"} objects (array-element disclosure markers).
 */
func collectSdDigestsFrom(chars: Array<Rune>, start: Int64, end: Int64, result: ArrayList<String>): Unit {
    var i: Int64 = start
    while (i < end) {
        let cp = UInt32(chars[i])
        // Look for "_sd" key or "..." key
        if (cp == 0x22u32) {
            // Check for "_sd" key
            if (i + 4 < end &&
                UInt32(chars[i + 1]) == 0x5Fu32 &&  // '_'
                UInt32(chars[i + 2]) == 0x73u32 &&  // 's'
                UInt32(chars[i + 3]) == 0x64u32 &&  // 'd'
                UInt32(chars[i + 4]) == 0x22u32) {  // '"'
                // Skip past "_sd" and find the ':'
                var pos: Int64 = i + 5
                while (pos < end && UInt32(chars[pos]) != 0x3Au32) {
                    pos = pos + 1
                }
                pos = pos + 1 // skip ':'
                // Skip whitespace
                while (pos < end && isJsonWhitespace(UInt32(chars[pos]))) {
                    pos = pos + 1
                }
                // Expect '['
                if (pos < end && UInt32(chars[pos]) == 0x5Bu32) {
                    pos = pos + 1 // skip '['
                    // Collect all string elements
                    while (pos < end && UInt32(chars[pos]) != 0x5Du32) {
                        // Skip whitespace
                        while (pos < end && isJsonWhitespace(UInt32(chars[pos]))) {
                            pos = pos + 1
                        }
                        if (pos < end && UInt32(chars[pos]) == 0x22u32) {
                            // Parse string
                            let strResult = parseJsonStringAt(chars, pos + 1, end)
                            let digestStr = strResult.value
                            let afterPos = strResult.nextPos
                            result.add(digestStr)
                            pos = afterPos
                        } else if (pos < end && UInt32(chars[pos]) == 0x5Du32) {
                            break
                        } else {
                            pos = pos + 1 // skip non-string, non-]
                        }
                        // Skip comma
                        while (pos < end && (isJsonWhitespace(UInt32(chars[pos])) || UInt32(chars[pos]) == 0x2Cu32)) {
                            pos = pos + 1
                        }
                    }
                }
                i = pos
                continue
            }
            // Check for "..." key (array-element marker)
            if (i + 4 < end &&
                UInt32(chars[i + 1]) == 0x2Eu32 &&  // '.'
                UInt32(chars[i + 2]) == 0x2Eu32 &&  // '.'
                UInt32(chars[i + 3]) == 0x2Eu32 &&  // '.'
                UInt32(chars[i + 4]) == 0x22u32) {  // '"'
                // Skip past "..." and find ':'
                var pos: Int64 = i + 5
                while (pos < end && UInt32(chars[pos]) != 0x3Au32) {
                    pos = pos + 1
                }
                pos = pos + 1 // skip ':'
                // Skip whitespace
                while (pos < end && isJsonWhitespace(UInt32(chars[pos]))) {
                    pos = pos + 1
                }
                // Expect '"'
                if (pos < end && UInt32(chars[pos]) == 0x22u32) {
                    let strResult = parseJsonStringAt(chars, pos + 1, end)
                    result.add(strResult.value)
                    i = strResult.nextPos
                    continue
                }
            }
        }
        // Recurse into nested objects and arrays (any '{' or '[')
        i = i + 1
    }
}

func isJsonWhitespace(cp: UInt32): Bool {
    return cp == 0x20u32 || cp == 0x09u32 || cp == 0x0Au32 || cp == 0x0Du32
}

/**
 * Result type for parseJsonStringAt.
 */
class StringParseResult {
    let value: String
    let nextPos: Int64

    init(value!: String, nextPos!: Int64) {
        this.value = value
        this.nextPos = nextPos
    }
}

/**
 * Parse a JSON string starting just after the opening quote at `start`.
 *
 * Returns the unescaped string content and the position after the closing
 * quote.
 *
 * Uses UTF-8 byte accumulation instead of Rune.toString() to avoid S-018:
 * on aarch64-linux-ohos, Rune.toString() returns the decimal code point
 * ("115" for 's') rather than the character ("s").
 */
func parseJsonStringAt(chars: Array<Rune>, start: Int64, end: Int64): StringParseResult {
    // Pre-allocate buffer: each rune needs at most 4 UTF-8 bytes.
    let maxBytes: Int64 = (end - start) * 4 + 4
    var buf: Array<UInt8> = Array<UInt8>(maxBytes, repeat: 0u8)
    var bpos: Int64 = 0
    var i: Int64 = start
    var inEscape = false
    while (i < end) {
        let cp = UInt32(chars[i])
        if (inEscape) {
            if (cp == 0x22u32) {
                // \" -> double-quote byte
                buf[bpos] = 0x22u8
                bpos = bpos + 1
            } else if (cp == 0x5Cu32) {
                // \\ -> backslash byte
                buf[bpos] = 0x5Cu8
                bpos = bpos + 1
            } else if (cp == 0x6Eu32) {
                // \n -> newline byte
                buf[bpos] = 0x0Au8
                bpos = bpos + 1
            } else if (cp == 0x74u32) {
                // \t -> horizontal tab byte
                buf[bpos] = 0x09u8
                bpos = bpos + 1
            } else if (cp == 0x72u32) {
                // \r -> carriage return byte
                buf[bpos] = 0x0Du8
                bpos = bpos + 1
            }
            inEscape = false
        } else if (cp == 0x5Cu32) {
            inEscape = true
        } else if (cp == 0x22u32) {
            // closing quote — return accumulated bytes as String, position after quote
            return StringParseResult(value: String.fromUtf8(buf[0..bpos]), nextPos: i + 1)
        } else {
            // ordinary rune: encode to UTF-8 bytes (device-safe, no Rune.toString())
            bpos = bpos + Rune.intoUtf8Array(chars[i], buf, bpos)
        }
        i = i + 1
    }
    return StringParseResult(value: String.fromUtf8(buf[0..bpos]), nextPos: end)
}

// ---------------------------------------------------------------------------
// base64url decode a JWT part (header or payload) to a JSON string
// ---------------------------------------------------------------------------

/**
 * Decode the payload part (index 1) of a compact JWS token.
 *
 * Splits on "." and base64url-decodes parts[1].
 *
 * @param compact  Three-part compact JWS.
 * @param b64      Base64Url implementation.
 * @return Decoded payload JSON string.
 * @throws SdJwtVerifierError if the compact string is malformed.
 */
func decodeJwtPayload(compact: String, b64: Base64Url): String {
    let parts = compact.split(".")
    if (parts.size != 3) {
        throw SdJwtVerifierError("Invalid compact JWS: expected 3 dot-separated parts")
    }
    let payloadBytes = b64.decode(parts[1])
    return String.fromUtf8(payloadBytes)
}

/**
 * Decode the header part (index 0) of a compact JWS token.
 */
func decodeJwtHeader(compact: String, b64: Base64Url): String {
    let parts = compact.split(".")
    if (parts.size != 3) {
        throw SdJwtVerifierError("Invalid compact JWS: expected 3 dot-separated parts")
    }
    let headerBytes = b64.decode(parts[0])
    return String.fromUtf8(headerBytes)
}

// ---------------------------------------------------------------------------
// HashingAlgorithmIdentifier from string
// ---------------------------------------------------------------------------

/**
 * Parse an _sd_alg string into a HashingAlgorithmIdentifier.
 *
 * @throws SdJwtVerifierError if the algorithm is not supported.
 */
func parseHashingAlgorithm(algStr: String): HashingAlgorithmIdentifier {
    if (algStr == "sha-256") {
        return HashingAlgorithmIdentifier.Sha256
    } else if (algStr == "sha-384") {
        return HashingAlgorithmIdentifier.Sha384
    } else if (algStr == "sha-512") {
        return HashingAlgorithmIdentifier.Sha512
    } else {
        throw SdJwtVerifierError("Unsupported _sd_alg: " + algStr)
    }
}

// ---------------------------------------------------------------------------
// DisclosuresVerifier  (internal helper class)
// ---------------------------------------------------------------------------

/**
 * Verifies disclosures against the JWT payload.
 *
 * Steps:
 *   1. Extract _sd_alg from payload; error if absent or unsupported.
 *   2. Build a digest → Disclosure map.
 *   3. Collect all digest strings appearing in _sd arrays (recursive).
 *   4. Verify no two digests in the payload are identical (uniqueness).
 *   5. Verify every disclosure's digest is found in the payload digests.
 *   6. Reconstruct claims: inject each object-property disclosure as a
 *      plain claim in the output claims map; record array-element disclosures.
 *
 * Returns a DisclosuresVerifyResult with the recreated claims JSON string.
 */
class DisclosuresVerifier {
    let _jws: Jws
    let _b64: Base64Url
    let _digest: Digest

    init(jws!: Jws, b64!: Base64Url, digest!: Digest) {
        _jws = jws
        _b64 = b64
        _digest = digest
    }

    func verify(signedSdJwt: SignedSdJwt): DisclosuresVerifyResult {
        let payloadJson = decodeJwtPayload(signedSdJwt.jwt.compactSerialization, _b64)

        // Step 1: Extract _sd_alg
        let algStrOpt = extractStringField(payloadJson, Keys.sdAlg)
        let algStr: String = match (algStrOpt) {
            case Some(s) => s
            case None => throw SdJwtVerifierError("Missing _sd_alg claim in JWT payload")
        }
        let algId = parseHashingAlgorithm(algStr)

        // Step 2: Build digest creator and digest map
        let dc = DigestCreator(digest: _digest, base64Url: _b64, algorithm: algId)
        let digestMap = DisclosureDigestMap(digestCreator: dc, b64: _b64, disclosures: signedSdJwt.disclosures)

        // Step 3: Collect all digest strings from payload
        let payloadDigests = collectSdDigests(payloadJson)

        // Step 4: Check uniqueness of payload digests
        let seen = HashMap<String, Bool>()
        var pi: Int64 = 0
        while (pi < payloadDigests.size) {
            let d = payloadDigests[pi]
            if (seen.contains(d)) {
                throw SdJwtVerifierError("Duplicate digest found in payload _sd arrays: " + d)
            }
            seen.add(d, true)
            pi = pi + 1
        }

        // Step 5: Verify each disclosure is found in the payload
        let disclosures = signedSdJwt.disclosures
        var di: Int64 = 0
        while (di < disclosures.size) {
            let disc = disclosures[di]
            let encoded = disc.encodeWith(_b64)
            let discDigest = dc.hashAndBase64Encode(encoded)
            var foundInPayload = false
            var pi2: Int64 = 0
            while (pi2 < payloadDigests.size) {
                if (payloadDigests[pi2] == discDigest) {
                    foundInPayload = true
                    break
                }
                pi2 = pi2 + 1
            }
            if (!foundInPayload) {
                throw SdJwtVerifierError("Disclosure digest not found in payload: " + encoded)
            }
            di = di + 1
        }

        // Step 5b: verifyDigestsStructure — for each disclosure whose digest is
        // present in the payload, assert that the disclosure's element count
        // matches the structural kind of where the digest was found:
        //   object "_sd" array entry → 3-element [salt, key, value] disclosure
        //   array  "..." marker      → 2-element [salt, value] disclosure
        // Mirrors iOS DisclosuresVerifier.verifyDigestsStructure (digestType.components).
        let kindedDigests = collectSdDigestsWithKind(payloadJson)
        let digestKindMap = HashMap<String, DigestKind>()
        var ki: Int64 = 0
        while (ki < kindedDigests.size) {
            let pd = kindedDigests[ki]
            digestKindMap.add(pd.digest, pd.kind)
            ki = ki + 1
        }
        var si: Int64 = 0
        while (si < disclosures.size) {
            let disc = disclosures[si]
            let encoded = disc.encodeWith(_b64)
            let discDigest = dc.hashAndBase64Encode(encoded)
            match (digestKindMap.get(discDigest)) {
                case Some(kind) =>
                    // Decode the disclosure to count its JSON-array elements,
                    // then compare to the expected component count for the kind.
                    let decoded = Disclosure.decodeWith(encoded, _b64)
                    let actualComponents: Int64 = if (decoded.isObjectClaim()) { 3 } else { 2 }
                    if (actualComponents != kind.components()) {
                        throw SdJwtVerifierError(
                            "Disclosure structure mismatch: digest found in " + kind.name() +
                            " position expects " + kind.components().toString() +
                            " components but disclosure has " + actualComponents.toString())
                    }
                case None => ()  // digest not in payload (already rejected by step 5)
            }
            si = si + 1
        }

        // Step 6: Reconstruct claims.
        //   (a) Legacy flat map (kept for backward compatibility / callers that
        //       only need top-level disclosed claim names).
        //   (b) Full recursive JSON tree (mirrors iOS resolveNode): nested
        //       objects/arrays, recursive disclosures, and "undisclosed →
        //       omit" semantics are all honoured.  This is the authoritative
        //       reconstruction exposed via VerificationResult.recreatedClaims.
        let recreatedClaims = reconstructClaims(payloadJson, disclosures, dc, _b64)
        let recreatedTree = recreateClaimsTree(payloadJson, disclosures, dc, _b64)
        let recreatedTreeJson = recreatedTree.toString()

        return DisclosuresVerifyResult(
            payloadJson: payloadJson,
            recreatedClaims: recreatedClaims,
            recreatedTreeJson: recreatedTreeJson
        )
    }

    /**
     * Reconstruct claims by injecting disclosures back into the payload.
     *
     * For object-property disclosures: add "name": value pairs to the result.
     * Returns a simple claims representation as a string map.
     */
    private func reconstructClaims(
        payloadJson: String,
        disclosures: Array<Disclosure>,
        dc: DigestCreator,
        b64: Base64Url
    ): HashMap<String, String> {
        let claims = HashMap<String, String>()

        // Extract standard top-level claims from payload
        let standardClaims = ["iss", "sub", "iat", "exp", "nbf", "jti", "aud", "cnf"]
        var sci: Int64 = 0
        while (sci < standardClaims.size) {
            let claimName = standardClaims[sci]
            match (extractStringField(payloadJson, claimName)) {
                case Some(v) => claims.add(claimName, v)
                case None => ()
            }
            sci = sci + 1
        }

        // Inject object-property disclosures as claims
        var di: Int64 = 0
        while (di < disclosures.size) {
            let disc = disclosures[di]
            match (disc.getName()) {
                case Some(name) =>
                    claims.add(name, disc.getValue())
                case None => ()  // array-element; no claim name injection
            }
            di = di + 1
        }

        return claims
    }
}

/**
 * Result of the disclosures verification step.
 */
class DisclosuresVerifyResult {
    let payloadJson: String
    /** Legacy flat top-level claim map (backward compatibility). */
    let recreatedClaims: HashMap<String, String>
    /** Full recursive reconstruction, serialised JSON (iOS resolveNode parity). */
    let recreatedTreeJson: String

    init(payloadJson!: String, recreatedClaims!: HashMap<String, String>, recreatedTreeJson!: String) {
        this.payloadJson = payloadJson
        this.recreatedClaims = recreatedClaims
        this.recreatedTreeJson = recreatedTreeJson
    }
}

// ---------------------------------------------------------------------------
// Recursive claim-tree reconstruction (mirrors iOS SdJwtUtils.resolveNode)
// ---------------------------------------------------------------------------

/**
 * Rebuild the full claim tree by resolving every disclosure back into the
 * issuer payload, recursively.  Direct port of the iOS reference
 * `SdJwtUtils.resolveNestedSdClaims` / `resolveNode`
 * (eudi-lib-ios-wallet-kit Services/SdJwtUtils.swift L79-130).
 *
 * Algorithm:
 *   1. Build a hash → decoded-disclosure-JSON map.  The key is the disclosure
 *      digest computed with the issuer-declared _sd_alg (same DigestCreator the
 *      DisclosuresVerifier used); the value is the JsonValue parse of the raw
 *      (base64url-decoded) disclosure JSON array — a 3-element [salt,name,value]
 *      for object claims or a 2-element [salt,value] for array elements.
 *   2. Parse the issuer payload JSON and walk it:
 *        object: for each digest in "_sd", look up the disclosure and inject
 *                value under name; drop "_sd"/"_sd_alg"; recurse into children.
 *        array : for each {"...": digest} element, look up the disclosure and
 *                substitute its value (recursing into it); omit the element if
 *                no disclosure was presented; recurse into ordinary elements.
 *   3. Values injected from disclosures are themselves recursed into, so a
 *      recursive disclosure (a disclosed object/array that itself carries
 *      "_sd"/"...") is fully resolved.
 *
 * @return The resolved claim tree as a JsonValue.  On any JSON-parse failure of
 *         the payload, returns the payload's JsonValue unchanged (fail-soft —
 *         the security decision is already made by DisclosuresVerifier.verify).
 */
func recreateClaimsTree(
    payloadJson: String,
    disclosures: Array<Disclosure>,
    dc: DigestCreator,
    b64: Base64Url
): JsonValue {
    // Step 1: hash → decoded disclosure JSON
    let hashToDisclosure = HashMap<String, JsonValue>()
    var i: Int64 = 0
    while (i < disclosures.size) {
        let disc = disclosures[i]
        let encoded = disc.encodeWith(b64)
        let digest = dc.hashAndBase64Encode(encoded)
        let rawBytes = b64.decode(encoded)
        let discJsonStr = String.fromUtf8(rawBytes)
        try {
            let dv = JsonValue.fromStr(discJsonStr)
            hashToDisclosure.add(digest, dv)
        } catch (e: Exception) {
            // Malformed disclosure JSON — skip; verify() already digest-matched.
            ()
        }
        i = i + 1
    }

    // Step 2: parse payload and resolve
    let rootOpt: Option<JsonValue> = try {
        Some(JsonValue.fromStr(payloadJson))
    } catch (e: Exception) {
        None
    }
    match (rootOpt) {
        case Some(root) => return resolveJsonNode(root, hashToDisclosure)
        case None =>
            // Could not parse payload; return an empty object rather than throw.
            return JsonObject()
    }
}

/**
 * Recursively resolve a single JSON node against the disclosure map.
 * Mirrors iOS `resolveNode`.
 */
func resolveJsonNode(node: JsonValue, hashToDisclosure: HashMap<String, JsonValue>): JsonValue {
    // Object case
    match (node as JsonObject) {
        case Some(obj) => return resolveJsonObject(obj, hashToDisclosure)
        case None => ()
    }
    // Array case
    match (node as JsonArray) {
        case Some(arr) => return resolveJsonArray(arr, hashToDisclosure)
        case None => ()
    }
    // Scalar (string / number / bool / null): unchanged.
    return node
}

/**
 * Resolve an object node: expand its "_sd" digest array into real claims, drop
 * the "_sd" / "_sd_alg" book-keeping keys, then recurse into every child.
 */
func resolveJsonObject(obj: JsonObject, hashToDisclosure: HashMap<String, JsonValue>): JsonValue {
    let result = JsonObject()

    // First, expand the "_sd" array (if any) into injected claims.  These
    // injected name/value pairs are resolved recursively so that a recursive
    // disclosure (disclosed value that itself contains "_sd"/"...") is handled.
    match (obj.get(Keys.sd)) {
        case Some(sdField) =>
            match (sdField as JsonArray) {
                case Some(sdArr) =>
                    var k: Int64 = 0
                    while (k < sdArr.size()) {
                        match (sdArr.get(k)) {
                            case Some(hashJv) =>
                                match (hashJv as JsonString) {
                                    case Some(hashStr) =>
                                        match (hashToDisclosure.get(hashStr.getValue())) {
                                            case Some(disclosure) =>
                                                // Object disclosure: [salt, name, value]
                                                match (disclosure as JsonArray) {
                                                    case Some(dArr) =>
                                                        if (dArr.size() >= 3) {
                                                            let nameOpt = jsonArrayStringAt(dArr, 1)
                                                            match ((nameOpt, dArr.get(2))) {
                                                                case (Some(name), Some(valueJv)) =>
                                                                    result.put(name, resolveJsonNode(valueJv, hashToDisclosure))
                                                                case _ => ()
                                                            }
                                                        }
                                                    case None => ()
                                                }
                                            case None => ()  // digest with no presented disclosure → not disclosed
                                        }
                                    case None => ()
                                }
                            case None => ()
                        }
                        k = k + 1
                    }
                case None => ()
            }
        case None => ()
    }

    // Then copy over the remaining ordinary keys (skipping book-keeping and any
    // key already injected above), recursing into each value.
    let fields = obj.getFields()
    for ((key, value) in fields) {
        if (key == Keys.sd || key == Keys.sdAlg) {
            continue
        }
        if (result.containsKey(key)) {
            // An injected disclosure already produced this key; keep the
            // disclosed value (matches iOS: dict[claimName] = claimValue set
            // before the recursive copy, then overwritten by recursion of the
            // same value — net effect identical).
            continue
        }
        result.put(key, resolveJsonNode(value, hashToDisclosure))
    }

    return result
}

/**
 * Resolve an array node: replace {"...": digest} markers with the disclosed
 * element (recursively), omit undisclosed markers, recurse into ordinary
 * elements.  Mirrors the iOS `compactMap` over array elements.
 */
func resolveJsonArray(arr: JsonArray, hashToDisclosure: HashMap<String, JsonValue>): JsonValue {
    let result = JsonArray()
    var i: Int64 = 0
    while (i < arr.size()) {
        match (arr.get(i)) {
            case Some(elem) =>
                let dotsDigestOpt = arrayMarkerDigest(elem)
                match (dotsDigestOpt) {
                    case Some(digest) =>
                        // Selectively-disclosable array element {"...": digest}.
                        match (hashToDisclosure.get(digest)) {
                            case Some(disclosure) =>
                                // Array disclosure: [salt, value]
                                match (disclosure as JsonArray) {
                                    case Some(dArr) =>
                                        if (dArr.size() >= 2) {
                                            match (dArr.get(1)) {
                                                case Some(valueJv) =>
                                                    result.add(resolveJsonNode(valueJv, hashToDisclosure))
                                                case None => ()
                                            }
                                        }
                                    case None => ()
                                }
                            case None => ()  // undisclosed → omit (do not append)
                        }
                    case None =>
                        // Ordinary element: recurse.
                        result.add(resolveJsonNode(elem, hashToDisclosure))
                }
            case None => ()
        }
        i = i + 1
    }
    return result
}

/**
 * If `elem` is a single-key object of the form {"...": "<digest>"}, return
 * Some(digest); otherwise None.  Matches iOS `element["..."].string`.
 */
func arrayMarkerDigest(elem: JsonValue): Option<String> {
    match (elem as JsonObject) {
        case Some(obj) =>
            match (obj.get("...")) {
                case Some(v) =>
                    match (v as JsonString) {
                        case Some(s) => return Some(s.getValue())
                        case None => return None
                    }
                case None => return None
            }
        case None => return None
    }
}

/**
 * Read element `idx` of a JsonArray as a String, if it is a JsonString.
 */
func jsonArrayStringAt(arr: JsonArray, idx: Int64): Option<String> {
    match (arr.get(idx)) {
        case Some(v) =>
            match (v as JsonString) {
                case Some(s) => return Some(s.getValue())
                case None => return None
            }
        case None => return None
    }
}

// ---------------------------------------------------------------------------
// KeyBindingVerifier  (internal helper class)
// ---------------------------------------------------------------------------

/**
 * Verifies a Key Binding JWT (KB-JWT).
 *
 * Checks:
 *   1. typ header claim == "kb+jwt"
 *   2. nonce claim matches expected nonce
 *   3. aud claim matches expected audience
 *   4. sd_hash matches base64url(hash_{_sd_alg}(compact_presentation)),
 *      where the hash algorithm is the SAME one named by the issuer payload's
 *      _sd_alg claim (sha-256 / sha-384 / sha-512) — NOT hard-wired sha-256.
 *      Mirrors iOS SignedSDJWT.swift delineatedCompactSerialisation, which uses
 *      a DigestCreator derived from the SD-JWT's own _sd_alg.
 *   5. JWS signature verifies against the holder public key that was extracted
 *      from the issuer-signed cnf.jwk (passed in as holderPublicKey).  The
 *      caller MUST source this key from the verified issuer payload, never from
 *      a presentation-time parameter — that is the key-binding security
 *      invariant (a KB-JWT signed with any other key is rejected).
 */
class KeyBindingVerifier {
    let _jws: Jws
    let _b64: Base64Url
    let _digest: Digest

    init(jws!: Jws, b64!: Base64Url, digest!: Digest) {
        _jws = jws
        _b64 = b64
        _digest = digest
    }

    /**
     * Verify the KB-JWT.
     *
     * @param kbJwt              The compact KB-JWT string.
     * @param expectedNonce      Expected nonce value.
     * @param expectedAud        Expected audience string.
     * @param presentationCompact The compact SD-JWT presentation (without KB-JWT
     *                           trailing kbJwt; i.e., jwt~d1~d2~ form).
     * @param holderPublicKey    Holder public key extracted from the issuer's
     *                           verified cnf.jwk binding.
     * @param sdHashAlg          Hash algorithm identifier (from issuer payload's
     *                           _sd_alg) used to compute the sd_hash.
     * @throws SdJwtVerifierError on any verification failure.
     */
    func verify(
        kbJwt: String,
        expectedNonce: String,
        expectedAud: String,
        presentationCompact: String,
        holderPublicKey: ECDSAPublicKey,
        sdHashAlg: HashingAlgorithmIdentifier
    ): Unit {
        // Step 1: Check typ header
        let headerJson = decodeJwtHeader(kbJwt, _b64)
        match (extractStringField(headerJson, "typ")) {
            case Some(typ) =>
                if (typ != "kb+jwt") {
                    throw SdJwtVerifierError("KB-JWT typ must be 'kb+jwt', got: " + typ)
                }
            case None =>
                throw SdJwtVerifierError("KB-JWT header missing typ claim")
        }

        // Step 2: Decode KB-JWT payload
        let kbPayloadJson = decodeJwtPayload(kbJwt, _b64)

        // Step 3: Check nonce
        match (extractStringField(kbPayloadJson, Keys.nonce)) {
            case Some(nonce) =>
                if (nonce != expectedNonce) {
                    throw SdJwtVerifierError("KB-JWT nonce mismatch: expected '" + expectedNonce + "' got '" + nonce + "'")
                }
            case None =>
                throw SdJwtVerifierError("KB-JWT missing nonce claim")
        }

        // Step 4: Check aud
        match (extractStringField(kbPayloadJson, Keys.aud)) {
            case Some(aud) =>
                if (aud != expectedAud) {
                    throw SdJwtVerifierError("KB-JWT aud mismatch: expected '" + expectedAud + "' got '" + aud + "'")
                }
            case None =>
                throw SdJwtVerifierError("KB-JWT missing aud claim")
        }

        // Step 5: Check sd_hash — computed with the issuer-declared _sd_alg
        // algorithm (NOT hard-wired sha-256), matching the iOS port.
        let sdHashCreator = DigestCreator(digest: _digest, base64Url: _b64, algorithm: sdHashAlg)
        let expectedSdHash = sdHashCreator.hashAndBase64Encode(presentationCompact)
        match (extractStringField(kbPayloadJson, Keys.sdHash)) {
            case Some(sdHash) =>
                if (sdHash != expectedSdHash) {
                    throw SdJwtVerifierError("KB-JWT sd_hash mismatch")
                }
            case None =>
                throw SdJwtVerifierError("KB-JWT missing sd_hash claim")
        }

        // Step 6: Verify KB-JWT signature
        let sigOk = _jws.verifyEs256(kbJwt, holderPublicKey)
        if (!sigOk) {
            throw SdJwtVerifierError("KB-JWT signature verification failed")
        }
    }
}

// ---------------------------------------------------------------------------
// SdJwtVerifier  (public API)
// ---------------------------------------------------------------------------

/**
 * SD-JWT verifier implementing the full verification pipeline.
 *
 * Mirrors Sources/Verifier/SDJWTVerifier.swift.
 *
 * Usage:
 *   let crypto = HostCryptoStub()
 *   let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
 *
 *   let result = verifier.verifyIssuance(signedSdJwt, issuerPublicKey)
 *   if (result.isOk()) { ... }
 */
public class SdJwtVerifier {

    let _jws: Jws
    let _b64: Base64Url
    let _digest: Digest

    /**
     * Construct a SdJwtVerifier.
     *
     * @param jws     JWS seam implementation for signature verification.
     * @param b64     Base64Url seam implementation.
     * @param digest  Digest seam implementation for disclosure hashing.
     */
    public init(jws!: Jws, b64!: Base64Url, digest!: Digest) {
        _jws = jws
        _b64 = b64
        _digest = digest
    }

    // -----------------------------------------------------------------------
    // verifyIssuance
    // -----------------------------------------------------------------------

    /**
     * Verify the issuance of an SD-JWT.
     *
     * Verification steps:
     *   1. Verify the issuer's JWS signature (via seam Jws.verifyEs256).
     *   2. Extract _sd_alg; error if absent.
     *   3. Compute each disclosure's digest and confirm it is found in the
     *      payload's _sd arrays (recursively).
     *   4. Check no duplicate digests in payload.
     *   5. Reconstruct claims (inject disclosed values back into payload).
     *
     * @param signedSdJwt      The SignedSdJwt to verify (pre-parsed).
     * @param issuerPublicKey  Public key of the issuer.
     * @return VerificationResult — ok(signedSdJwt) on success, err on failure.
     */
    public func verifyIssuance(
        signedSdJwt: SignedSdJwt,
        issuerPublicKey: ECDSAPublicKey
    ): VerificationResult {
        // Step 1: Verify issuer JWS signature
        let sigOk = _jws.verifyEs256(signedSdJwt.jwt.compactSerialization, issuerPublicKey)
        if (!sigOk) {
            return VerificationResult(err: SdJwtVerifierError("Issuer JWS signature verification failed"))
        }

        // Steps 2-5: Disclosures verification.  The verify() call returns the
        // fully recreated claim tree (iOS recreateSdJwtClaims parity); we no
        // longer discard it — it is surfaced via VerificationResult.recreatedClaims.
        let discVerifier = DisclosuresVerifier(jws: _jws, b64: _b64, digest: _digest)
        let discResult: DisclosuresVerifyResult
        try {
            discResult = discVerifier.verify(signedSdJwt)
        } catch (e: SdJwtVerifierError) {
            return VerificationResult(err: e)
        }

        return VerificationResult(ok: signedSdJwt, recreatedClaims: discResult.recreatedTreeJson)
    }

    /**
     * Convenience overload: parse a compact SD-JWT string, then verify issuance.
     *
     * @param compactSdJwt     Compact SD-JWT string (jwt~d1~...~).
     * @param issuerPublicKey  Issuer's public key.
     * @return VerificationResult.
     */
    public func verifyIssuance(
        compactSdJwt: String,
        issuerPublicKey: ECDSAPublicKey
    ): VerificationResult {
        let parser = CompactParser(b64: _b64)
        let signedSdJwt = parser.parse(compactSdJwt)
        return verifyIssuance(signedSdJwt, issuerPublicKey)
    }

    // -----------------------------------------------------------------------
    // verifyPresentation
    // -----------------------------------------------------------------------

    /**
     * Verify the presentation of an SD-JWT, optionally including KB-JWT.
     *
     * In addition to the issuance verification steps, if a KB-JWT is present:
     *   6. Verify KB-JWT typ = "kb+jwt".
     *   7. Verify KB-JWT nonce matches expectedNonce.
     *   8. Verify KB-JWT aud matches expectedAud.
     *   9. Verify KB-JWT sd_hash = base64url(sha256(compact_presentation)).
     *  10. Verify KB-JWT signature against the holder's public key.
     *
     * @param signedSdJwt      The SignedSdJwt to verify.
     * @param issuerPublicKey  Issuer's public key.
     * @param expectedNonce    Expected nonce in the KB-JWT (required if kbJwt present).
     * @param expectedAud      Expected audience in the KB-JWT (required if kbJwt present).
     * @param holderPublicKey  DEPRECATED / IGNORED.  Retained only for source
     *                         compatibility with existing call sites.  The holder
     *                         public key used to verify the KB-JWT is ALWAYS the
     *                         one bound by the issuer in the verified cnf.jwk
     *                         claim — never this parameter.  Passing a key here
     *                         has no effect on the security decision.
     * @param presentationCompact The compact presentation string used to compute sd_hash.
     * @return VerificationResult.
     */
    public func verifyPresentation(
        signedSdJwt: SignedSdJwt,
        issuerPublicKey: ECDSAPublicKey,
        expectedNonce: Option<String>,
        expectedAud: Option<String>,
        holderPublicKey: Option<ECDSAPublicKey>,
        presentationCompact: Option<String>
    ): VerificationResult {
        // Run issuance verification first (signature + disclosures)
        let issuanceResult = verifyIssuance(signedSdJwt, issuerPublicKey)
        if (!issuanceResult.isOk()) {
            return issuanceResult
        }

        // The caller-supplied holderPublicKey is intentionally ignored; the
        // holder key is taken from the issuer-signed cnf.jwk below.  Silence the
        // unused-parameter without weakening the contract.
        let _ = holderPublicKey

        // KB-JWT verification if present
        try {
            match (signedSdJwt.kbJwt) {
                case Some(kbJwt) =>
                    let kbVerifier = KeyBindingVerifier(jws: _jws, b64: _b64, digest: _digest)
                    let nonce: String = match (expectedNonce) {
                        case Some(n) => n
                        case None => throw SdJwtVerifierError("expectedNonce required when KB-JWT is present")
                    }
                    let aud: String = match (expectedAud) {
                        case Some(a) => a
                        case None => throw SdJwtVerifierError("expectedAud required when KB-JWT is present")
                    }
                    let presCompact: String = match (presentationCompact) {
                        case Some(c) => c
                        case None => throw SdJwtVerifierError("presentationCompact required when KB-JWT is present")
                    }
                    // Decode the issuer payload (already signature-verified above)
                    // and pull the holder public key from its cnf.jwk binding.
                    // fail-closed if the binding is absent/malformed.
                    let payloadJson = decodeJwtPayload(signedSdJwt.jwt.compactSerialization, _b64)
                    let holderKeyFromCnf = extractHoldersPublicKey(payloadJson, _b64)
                    // sd_hash uses the issuer-declared _sd_alg algorithm.
                    let algStr: String = match (extractStringField(payloadJson, Keys.sdAlg)) {
                        case Some(s) => s
                        case None => throw SdJwtVerifierError("Missing _sd_alg claim in JWT payload")
                    }
                    let algId = parseHashingAlgorithm(algStr)
                    kbVerifier.verify(
                        kbJwt.compactSerialization,
                        nonce,
                        aud,
                        presCompact,
                        holderKeyFromCnf,
                        algId
                    )
                case None => ()  // no KB-JWT; presentation without key binding
            }
        } catch (e: SdJwtVerifierError) {
            return VerificationResult(err: e)
        }

        // Carry forward the recreated claim tree produced during issuance
        // verification so presentation callers also receive it.
        match (issuanceResult.recreatedClaims) {
            case Some(tree) => return VerificationResult(ok: signedSdJwt, recreatedClaims: tree)
            case None => return VerificationResult(ok: signedSdJwt)
        }
    }

    /**
     * Convenience overload: parse a compact SD-JWT string, then verify presentation.
     *
     * @param compactSdJwt      Compact SD-JWT string (jwt~d1~...~kbjwt or jwt~d1~...~).
     * @param issuerPublicKey   Issuer's public key.
     * @param expectedNonce     Expected nonce (required if KB-JWT present).
     * @param expectedAud       Expected audience (required if KB-JWT present).
     * @param holderPublicKey   Holder's public key (required if KB-JWT present).
     * @return VerificationResult.
     */
    public func verifyPresentation(
        compactSdJwt: String,
        issuerPublicKey: ECDSAPublicKey,
        expectedNonce: Option<String>,
        expectedAud: Option<String>,
        holderPublicKey: Option<ECDSAPublicKey>
    ): VerificationResult {
        let parser = CompactParser(b64: _b64)
        let signedSdJwt = parser.parse(compactSdJwt)
        // Compute the presentation compact for sd_hash: the part before the KB-JWT
        // Per SD-JWT spec: sd_hash = base64url(sha256( presentation_without_kbjwt ))
        // The presentation without KB-JWT ends with ~ (trailing separator).
        let presCompact: Option<String> = match (signedSdJwt.kbJwt) {
            case Some(_) =>
                // Strip the KB-JWT suffix: find last ~ and take everything up to it (inclusive)
                let lastTildeIdx = lastIndexOf(compactSdJwt, "~")
                if (lastTildeIdx >= 0) {
                    Some(compactSdJwt[0..lastTildeIdx + 1])
                } else {
                    None
                }
            case None => None
        }
        return verifyPresentation(
            signedSdJwt,
            issuerPublicKey,
            expectedNonce,
            expectedAud,
            holderPublicKey,
            presCompact
        )
    }
}

// ---------------------------------------------------------------------------
// lastIndexOf helper
// ---------------------------------------------------------------------------

/**
 * Return the index of the last occurrence of `needle` in `haystack`,
 * or -1 if not found.
 */
func lastIndexOf(haystack: String, needle: String): Int64 {
    let hChars = haystack.toRuneArray()
    let nChars = needle.toRuneArray()
    let hLen = hChars.size
    let nLen = nChars.size
    if (nLen == 0 || nLen > hLen) {
        return -1
    }
    var i: Int64 = hLen - nLen
    while (i >= 0) {
        var matched = true
        var k: Int64 = 0
        while (k < nLen) {
            if (UInt32(hChars[i + k]) != UInt32(nChars[k])) {
                matched = false
                break
            }
            k = k + 1
        }
        if (matched) {
            return i
        }
        i = i - 1
    }
    return -1
}
