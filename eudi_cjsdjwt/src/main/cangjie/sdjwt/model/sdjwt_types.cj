/**
 * sdjwt_types.cj
 *
 * Core SD-JWT data model types.
 *
 * Corresponds to:
 *   - Sources/Issuer/SDJWT.swift   (SDJWT struct)
 *   - Sources/Issuer/SignedSDJWT.swift  (SignedSDJWT struct)
 *   - Sources/Types/Types.swift    (Keys enum, error types)
 *
 * Design notes:
 *   - Disclosure encapsulates BOTH the structured form (salt/name/value) and
 *     the encoded base64url form.  Encoding/decoding uses the Base64Url seam
 *     interface so downstream packages are backend-agnostic.
 *   - JSON array serialization is implemented inline (no stdx dependency):
 *     salt and name fields are always base64url strings (no escaping needed
 *     in practice), and the value field is stored as a pre-serialized JSON
 *     fragment which is embedded verbatim.  Decoding uses a minimal depth-
 *     aware JSON array splitter sufficient for [salt, name?, value] form.
 *   - No hand-rolled base64: all base64url operations go through Base64Url seam.
 *   - No stdx import: the HAR cjpm.toml does not declare a stdx dependency
 *     and cjpm.toml is a forbidden file; all functionality is implemented with
 *     std.* only.
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import std.collection.*

// ---------------------------------------------------------------------------
// SD-JWT reserved claim name constants  (Keys enum in Swift)
// ---------------------------------------------------------------------------

/**
 * SD-JWT / JWT reserved field name constants.
 *
 * Mirrors Sources/Types/Types.swift  `enum Keys`.
 */
public class Keys {
    /** Digests array for selectively-disclosable object properties.  "_sd" */
    public static let sd: String = "_sd"

    /** Array-element digest entry ({"...": <digest>} per SD-JWT spec).  "..." */
    public static let dots: String = "..."

    /** Hash algorithm identifier claim.  "_sd_alg" */
    public static let sdAlg: String = "_sd_alg"

    /** SD-JWT hash in KB-JWT.  "sd_hash" */
    public static let sdHash: String = "sd_hash"

    /** Issuer claim.  "iss" */
    public static let iss: String = "iss"

    /** Issued-at claim.  "iat" */
    public static let iat: String = "iat"

    /** Subject claim.  "sub" */
    public static let sub: String = "sub"

    /** Expiration time claim.  "exp" */
    public static let exp: String = "exp"

    /** JWT ID claim.  "jti" */
    public static let jti: String = "jti"

    /** Not-before claim.  "nbf" */
    public static let nbf: String = "nbf"

    /** Audience claim.  "aud" */
    public static let aud: String = "aud"

    /** Confirmation claim (key binding).  "cnf" */
    public static let cnf: String = "cnf"

    /** JWK inside cnf.  "jwk" */
    public static let jwk: String = "jwk"

    /** Nonce claim in KB-JWT.  "nonce" */
    public static let nonce: String = "nonce"

    /** Separator character in compact serialization.  "~" */
    public static let disclosureSeparator: String = "~"

    /** Default hash algorithm.  "sha-256" */
    public static let defaultSdAlg: String = "sha-256"
}

// ---------------------------------------------------------------------------
// Error types  (SDJWTError / SDJWTVerifierError in Swift)
// ---------------------------------------------------------------------------

/**
 * Base error for SD-JWT construction and processing problems.
 */
public class SdJwtError <: Exception {
    public init(message: String) {
        super(message)
    }
}

/**
 * Error that occurs during SD-JWT verification.
 */
public class SdJwtVerifierError <: Exception {
    public init(message: String) {
        super(message)
    }
}

// ---------------------------------------------------------------------------
// Disclosure  (typealias Disclosure = String in Swift; richer model here)
// ---------------------------------------------------------------------------

/**
 * SD-JWT Disclosure.
 *
 * Encapsulates either:
 *   Object property:  [salt, name, value]   (three-element JSON array)
 *   Array element:    [salt, value]          (two-element JSON array)
 *
 * Per IETF draft-ietf-oauth-selective-disclosure-jwt.
 *
 * Encoding uses the seam Base64Url interface so callers remain independent of
 * the concrete crypto backend.
 *
 * JSON array construction: escapes salt/name as JSON strings (they are base64url
 * so no special characters are expected) and embeds value verbatim as a
 * pre-serialized JSON fragment.  Decoding uses a depth-aware comma splitter to
 * extract the elements from the JSON array.
 */
public class Disclosure {

    // Structured fields
    let _salt: String
    let _name: Option<String>    // None => array-element disclosure
    let _value: String           // pre-serialized JSON fragment

    // -----------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------

    /**
     * Create an object-property disclosure.
     *
     * @param salt   Random salt string (base64url-encoded from Rng.bytes).
     * @param name   Claim name (JSON object key).
     * @param value  JSON-serialized claim value (e.g., "\"Alice\"", "42", "true").
     */
    public init(salt!: String, name!: String, value!: String) {
        this._salt = salt
        this._name = Some(name)
        this._value = value
    }

    /**
     * Create an array-element disclosure.
     *
     * @param salt   Random salt string.
     * @param value  JSON-serialized element value.
     */
    public init(salt!: String, value!: String) {
        this._salt = salt
        this._name = None
        this._value = value
    }

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /** Return the salt string. */
    public func getSalt(): String {
        return _salt
    }

    /**
     * Return the claim name.
     *
     * @return Some(name) for object-property disclosures; None for array elements.
     */
    public func getName(): Option<String> {
        return _name
    }

    /** Return the value as a pre-serialized JSON fragment. */
    public func getValue(): String {
        return _value
    }

    /** True if this is an object-property disclosure (three-element form). */
    public func isObjectClaim(): Bool {
        match (_name) {
            case Some(_) => true
            case None => false
        }
    }

    // -----------------------------------------------------------------
    // Encoding: structured form → base64url string
    // -----------------------------------------------------------------

    /**
     * Serialize this disclosure to the base64url-encoded JSON array string
     * required by the SD-JWT specification.
     *
     * Object property:  base64url( ["salt", "name", value] )
     * Array element:    base64url( ["salt", value] )
     *
     * @param b64  Base64Url seam implementation.
     * @return     Base64url-encoded disclosure string.
     */
    public func encodeWith(b64: Base64Url): String {
        let jsonStr = buildJsonArrayStr()
        let utf8Bytes = jsonStr.toArray()
        return b64.encode(utf8Bytes)
    }

    // -----------------------------------------------------------------
    // Decoding: base64url string → structured form
    // -----------------------------------------------------------------

    /**
     * Decode a base64url-encoded disclosure back to a Disclosure instance.
     *
     * Inverse of encodeWith().  Validates array length (2 or 3 elements).
     *
     * @param encoded  Base64url disclosure string (from compact token).
     * @param b64      Base64Url seam implementation.
     * @return         Decoded Disclosure.
     * @throws SdJwtVerifierError if the format is wrong.
     */
    public static func decodeWith(encoded: String, b64: Base64Url): Disclosure {
        let rawBytes = b64.decode(encoded)
        let jsonStr = String.fromUtf8(rawBytes)
        return parseDisclosureJson(jsonStr, encoded)
    }

    // -----------------------------------------------------------------
    // Internal: JSON array builder
    // -----------------------------------------------------------------

    /**
     * Build the JSON array string for serialization.
     *
     * Object: ["salt","name",value]
     * Array:  ["salt",value]
     *
     * salt and name are JSON-string-escaped; value is verbatim JSON fragment.
     */
    private func buildJsonArrayStr(): String {
        match (_name) {
            case Some(n) =>
                return "[" + escapeJsonString(_salt) + "," + escapeJsonString(n) + "," + _value + "]"
            case None =>
                return "[" + escapeJsonString(_salt) + "," + _value + "]"
        }
    }

    /**
     * Wrap a string in JSON double quotes with proper escaping.
     *
     * Escapes: \\ → \\\\, \" → \", control chars → \uXXXX, other chars
     * via Rune.intoUtf8Array so no Rune.toString() is ever called.
     *
     * Device-safe: avoids Rune.toString() (S-016 — returns decimal code
     * point on aarch64-linux-ohos) throughout the entire encode path.
     */
    private static func escapeJsonString(s: String): String {
        let runes = s.toRuneArray()
        // Worst case: every rune is a control char → 6 bytes (\uXXXX) + 2 for quotes
        var buf: Array<UInt8> = Array<UInt8>(runes.size * 6 + 2, repeat: 0u8)
        var pos: Int64 = 0
        // Opening double-quote
        buf[pos] = 0x22u8
        pos = pos + 1
        var i: Int64 = 0
        while (i < runes.size) {
            let ch = runes[i]
            let cp = UInt32(ch)
            if (cp == 0x5Cu32) {
                // backslash → \\
                buf[pos] = 0x5Cu8
                pos = pos + 1
                buf[pos] = 0x5Cu8
                pos = pos + 1
            } else if (cp == 0x22u32) {
                // double-quote → \"
                buf[pos] = 0x5Cu8
                pos = pos + 1
                buf[pos] = 0x22u8
                pos = pos + 1
            } else if (cp < 0x20u32) {
                // control character → \uXXXX (6 bytes, all ASCII)
                hexEscapeInto(cp, buf, pos)
                pos = pos + 6
            } else {
                // ordinary rune → UTF-8 bytes (device-safe, no Rune.toString())
                pos = pos + Rune.intoUtf8Array(ch, buf, pos)
            }
            i = i + 1
        }
        // Closing double-quote
        buf[pos] = 0x22u8
        pos = pos + 1
        return String.fromUtf8(buf[0..pos])
    }

    /**
     * Write 6 ASCII bytes for \uXXXX into buf starting at offset.
     *
     * Device-safe: constructs hex digit bytes via UInt8 arithmetic only,
     * with no Rune.toString() calls (S-016 guard).
     */
    private static func hexEscapeInto(cp: UInt32, buf: Array<UInt8>, offset: Int64): Unit {
        buf[offset]     = 0x5Cu8  // '\'
        buf[offset + 1] = 0x75u8  // 'u'
        buf[offset + 2] = hexDigitByte((cp >> 12u32) & 0xFu32)
        buf[offset + 3] = hexDigitByte((cp >> 8u32)  & 0xFu32)
        buf[offset + 4] = hexDigitByte((cp >> 4u32)  & 0xFu32)
        buf[offset + 5] = hexDigitByte(cp             & 0xFu32)
    }

    /**
     * Return the ASCII byte for hex digit n (0..15).
     *
     * n < 10  → '0'..'9' (0x30..0x39)
     * n >= 10 → 'a'..'f' (0x61..0x66)
     */
    private static func hexDigitByte(n: UInt32): UInt8 {
        if (n < 10u32) {
            return 0x30u8 + UInt8(n)
        } else {
            return 0x61u8 + UInt8(n) - 10u8
        }
    }

    // -----------------------------------------------------------------
    // Internal: minimal JSON array parser for decode
    // -----------------------------------------------------------------

    /**
     * Parse a JSON array ["salt", "name"?, value] into a Disclosure.
     *
     * @param json     The raw JSON array string.
     * @param encoded  The original base64url string (for error reporting).
     * @return         Decoded Disclosure.
     * @throws SdJwtVerifierError on malformed input.
     */
    private static func parseDisclosureJson(json: String, encoded: String): Disclosure {
        let trimmed = json.trimAscii()
        let chars = trimmed.toRuneArray()
        let len = chars.size
        if (len < 4 || UInt32(chars[0]) != 0x5Bu32 || UInt32(chars[len - 1]) != 0x5Du32) {
            throw SdJwtVerifierError("Invalid disclosure array: " + encoded)
        }
        let elements = splitJsonElements(chars, 1, len - 1)
        if (elements.size == 3) {
            let salt = parseJsonStringElement(elements[0], encoded)
            let name = parseJsonStringElement(elements[1], encoded)
            let value = elements[2].trimAscii()
            return Disclosure(salt: salt, name: name, value: value)
        } else if (elements.size == 2) {
            let salt = parseJsonStringElement(elements[0], encoded)
            let value = elements[1].trimAscii()
            return Disclosure(salt: salt, value: value)
        } else {
            throw SdJwtVerifierError("Invalid disclosure array size: " + encoded)
        }
    }

    /**
     * Depth-aware split of JSON array contents on top-level commas.
     */
    private static func splitJsonElements(chars: Array<Rune>, start: Int64, end: Int64): ArrayList<String> {
        var elements = ArrayList<String>()
        var depth = 0
        var inStr = false
        var escaped = false
        var elemStart = start
        var i = start
        while (i < end) {
            let cp = UInt32(chars[i])
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
                } else if (cp == 0x7Bu32 || cp == 0x5Bu32) {
                    depth = depth + 1
                } else if (cp == 0x7Du32 || cp == 0x5Du32) {
                    depth = depth - 1
                } else if (cp == 0x2Cu32 && depth == 0) {
                    let elem = runeSliceToString(chars, elemStart, i)
                    elements.add(elem)
                    elemStart = i + 1
                }
            }
            i = i + 1
        }
        let lastElem = runeSliceToString(chars, elemStart, end)
        elements.add(lastElem)
        return elements
    }

    /**
     * Build a String from a sub-range of a Rune array.
     *
     * Uses UTF-8 byte accumulation via Rune.intoUtf8Array + String.fromUtf8
     * instead of Rune.toString() to avoid S-016: on the aarch64-linux-ohos
     * target, Rune.toString() may return the decimal integer code point value
     * (e.g. r's'.toString() => "115") rather than the character ("s").
     * String.fromUtf8 is the guaranteed-correct reconstruction path.
     */
    private static func runeSliceToString(chars: Array<Rune>, from: Int64, to: Int64): String {
        // First pass: compute total byte length
        var totalBytes: Int64 = 0
        var i = from
        while (i < to) {
            totalBytes = totalBytes + Rune.utf8Size(chars[i])
            i = i + 1
        }
        // Second pass: fill UTF-8 byte array
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
     * Parse a JSON string element ("...") and return the unescaped value.
     *
     * Character accumulation uses UTF-8 byte buffers + String.fromUtf8 instead
     * of Rune.toString() to avoid S-016 (decimal code-point output on device).
     */
    private static func parseJsonStringElement(fragment: String, encoded: String): String {
        let trimmed = fragment.trimAscii()
        let chars = trimmed.toRuneArray()
        let len = chars.size
        if (len < 2 || UInt32(chars[0]) != 0x22u32 || UInt32(chars[len - 1]) != 0x22u32) {
            throw SdJwtVerifierError("Disclosure element is not a JSON string: " + encoded)
        }
        // Accumulate decoded UTF-8 bytes; pre-allocate generously (len * 4 worst case)
        var buf: Array<UInt8> = Array<UInt8>(len * 4, repeat: 0u8)
        var pos: Int64 = 0
        var i = 1
        while (i < len - 1) {
            let cp = UInt32(chars[i])
            if (cp == 0x5Cu32) {
                i = i + 1
                if (i >= len - 1) {
                    throw SdJwtVerifierError("Truncated escape in disclosure: " + encoded)
                }
                let next = UInt32(chars[i])
                if (next == 0x5Cu32) {
                    buf[pos] = 0x5Cu8
                    pos = pos + 1
                } else if (next == 0x22u32) {
                    buf[pos] = 0x22u8
                    pos = pos + 1
                } else if (next == 0x75u32) {
                    if (i + 4 >= len) {
                        throw SdJwtVerifierError("Truncated \\uXXXX in disclosure: " + encoded)
                    }
                    let h0 = hexDigitValue(UInt32(chars[i + 1]), encoded)
                    let h1 = hexDigitValue(UInt32(chars[i + 2]), encoded)
                    let h2 = hexDigitValue(UInt32(chars[i + 3]), encoded)
                    let h3 = hexDigitValue(UInt32(chars[i + 4]), encoded)
                    let codePoint = (h0 << 12u32) | (h1 << 8u32) | (h2 << 4u32) | h3
                    pos = pos + Rune.intoUtf8Array(Rune(codePoint), buf, pos)
                    i = i + 4
                } else {
                    throw SdJwtVerifierError("Unknown escape in disclosure: " + encoded)
                }
            } else {
                pos = pos + Rune.intoUtf8Array(chars[i], buf, pos)
            }
            i = i + 1
        }
        return String.fromUtf8(buf[0..pos])
    }

    /**
     * Convert a single hex character code point to its numeric value.
     */
    private static func hexDigitValue(cp: UInt32, encoded: String): UInt32 {
        if (cp >= 0x30u32 && cp <= 0x39u32) {
            return cp - 0x30u32
        } else if (cp >= 0x41u32 && cp <= 0x46u32) {
            return cp - 0x41u32 + 10u32
        } else if (cp >= 0x61u32 && cp <= 0x66u32) {
            return cp - 0x61u32 + 10u32
        } else {
            throw SdJwtVerifierError("Invalid hex digit in \\uXXXX escape: " + encoded)
        }
    }
}

// ---------------------------------------------------------------------------
// Jwt  (compact JWS string wrapper)
// ---------------------------------------------------------------------------

/**
 * A JWT represented as a compact JWS string (header.payload.signature).
 *
 * Lightweight value holder; parsing and verification are done by
 * sdjwt.codec and sdjwt.verifier respectively.
 */
public class Jwt {
    /** The raw compact JWS token (three dot-separated base64url parts). */
    public let compactSerialization: String

    /**
     * Wrap a compact JWS string.
     *
     * @param compactSerialization  Dot-separated compact JWS token.
     */
    public init(compactSerialization!: String) {
        this.compactSerialization = compactSerialization
    }
}

// ---------------------------------------------------------------------------
// SdJwt  (SDJWT struct in Swift — pre-signing form)
// ---------------------------------------------------------------------------

/**
 * Unserialized SD-JWT before signing.
 *
 * Mirrors Sources/Issuer/SDJWT.swift  `struct SDJWT`.
 */
public class SdJwt {
    /** JWT (may be compact JWS after signing). */
    public let jwt: Jwt

    /** All disclosures associated with this SD-JWT. */
    public let disclosures: Array<Disclosure>

    /** Optional Key Binding JWT. */
    public let kbJwt: Option<Jwt>

    /**
     * Construct an SdJwt.
     *
     * @param jwt          JWT wrapper.
     * @param disclosures  Disclosure array (may be empty).
     * @param kbJwt        Optional Key Binding JWT.
     */
    public init(jwt!: Jwt, disclosures!: Array<Disclosure>, kbJwt!: Option<Jwt>) {
        this.jwt = jwt
        this.disclosures = disclosures
        this.kbJwt = kbJwt
    }
}

// ---------------------------------------------------------------------------
// SignedSdJwt  (SignedSDJWT struct in Swift — post-signing form)
// ---------------------------------------------------------------------------

/**
 * Signed SD-JWT ready for compact serialization.
 *
 * Mirrors Sources/Issuer/SignedSDJWT.swift  `struct SignedSDJWT`.
 */
public class SignedSdJwt {
    /** Signed compact JWS token. */
    public let jwt: Jwt

    /** Disclosures that accompany this SD-JWT. */
    public let disclosures: Array<Disclosure>

    /** Optional Key Binding JWT compact string. */
    public let kbJwt: Option<Jwt>

    /**
     * Construct a SignedSdJwt.
     *
     * @param jwt          Signed Jwt wrapper.
     * @param disclosures  Array of Disclosure objects.
     * @param kbJwt        Optional Key Binding JWT.
     */
    public init(jwt!: Jwt, disclosures!: Array<Disclosure>, kbJwt!: Option<Jwt>) {
        this.jwt = jwt
        this.disclosures = disclosures
        this.kbJwt = kbJwt
    }

    /**
     * Build a presentation by selecting a subset of disclosures.
     *
     * @param selectedDisclosures  Subset to include.
     * @return New SignedSdJwt with the selected disclosures.
     */
    public func present(selectedDisclosures: Array<Disclosure>): SignedSdJwt {
        return SignedSdJwt(jwt: jwt, disclosures: selectedDisclosures, kbJwt: kbJwt)
    }

    /**
     * Attach a Key Binding JWT to produce a KB-bound presentation.
     *
     * @param kb  The signed KB-JWT.
     * @return New SignedSdJwt with the KB-JWT attached.
     */
    public func withKbJwt(kb: Jwt): SignedSdJwt {
        return SignedSdJwt(jwt: jwt, disclosures: disclosures, kbJwt: Some(kb))
    }
}
