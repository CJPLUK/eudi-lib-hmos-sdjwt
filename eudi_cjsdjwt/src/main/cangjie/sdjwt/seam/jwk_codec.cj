/**
 * jwk_codec.cj
 *
 * JWK <-> ECDSAPublicKey interconversion for the SD-JWT key-binding (cnf.jwk)
 * security path.
 *
 * Corresponds to (iOS):
 *   Sources/Issuer/SignedSDJWT.swift  extractHoldersPublicKey()  (cnf.jwk → JWK)
 *   the JWK EC public-key model (kty/crv/x/y) from JOSE.
 *
 * Why this lives in the seam package
 * ----------------------------------
 * The seam owns the opaque ECDSAPublicKey wrapper.  The concrete contents of
 * `ECDSAPublicKey.rawBytes` depend on which backend produced it:
 *
 *   - CoreEcdsaP256Impl (real ECDSA, stdx-backed): rawBytes is the X.509
 *     SubjectPublicKeyInfo (SPKI) DER of a P-256 public key.  A P-256 SPKI DER
 *     is exactly 91 bytes:
 *        <26-byte fixed AlgorithmIdentifier+BIT STRING prefix> || 0x04 || X(32) || Y(32)
 *     so the uncompressed EC point (0x04‖X‖Y, 65 bytes) is the trailing 65 bytes.
 *
 *   - HostEcdsaP256Impl (host surrogate, HMAC-based): rawBytes is the 32-byte
 *     identity key material (publicKeyOf is an identity mapping).  There is no
 *     real curve point here.
 *
 * To make the cnf-binding work under BOTH backends, the JWK round-trip is
 * *lossless*: pubkey → JWK → pubkey reproduces the exact original rawBytes, so
 * the verifier's `extractHoldersPublicKey` yields a key whose getRawBytes()
 * byte-equals the key the issuer bound — which is precisely what the key-binding
 * security check needs (KB signing key MUST equal the issuer-bound cnf key).
 *
 *   - Real SPKI (91 bytes, P-256): x = X(32), y = Y(32) are the true affine
 *     coordinates (iOS-faithful JWK); decode rebuilds the byte-identical 91-byte
 *     SPKI DER from the fixed prefix + 0x04‖x‖y, so stdx decodeDer accepts it.
 *   - Otherwise (host 32-byte material, or any other length): the rawBytes are
 *     split at the midpoint into x‖y and re-concatenated on decode, recovering
 *     the exact original bytes.  A `kid`-free marker distinguishes the two forms
 *     so decode is unambiguous.
 *
 * No stdx import here — base64url goes through the Base64Url seam.
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam

import std.collection.*

// ---------------------------------------------------------------------------
// P-256 SPKI DER fixed prefix
// ---------------------------------------------------------------------------

/**
 * The fixed 26-byte X.509 SubjectPublicKeyInfo prefix for an uncompressed
 * P-256 (prime256v1 / secp256r1) public key.  Hex:
 *   30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00
 * Followed by 0x04 || X(32) || Y(32) for a total SPKI DER length of 91 bytes.
 */
let P256_SPKI_PREFIX: Array<UInt8> = [
    0x30u8, 0x59u8, 0x30u8, 0x13u8, 0x06u8, 0x07u8, 0x2au8, 0x86u8,
    0x48u8, 0xceu8, 0x3du8, 0x02u8, 0x01u8, 0x06u8, 0x08u8, 0x2au8,
    0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x03u8, 0x01u8, 0x07u8, 0x03u8,
    0x42u8, 0x00u8
]

let P256_SPKI_LEN: Int64 = 91   // 26 prefix + 1 (0x04) + 32 (X) + 32 (Y)

/**
 * Marker prepended to the JWK `kty` field selector path is not used; instead we
 * distinguish the two encodings by the presence of a sentinel key in the JWK:
 *   - true P-256 point form: {"kty":"EC","crv":"P-256","x":..,"y":..}
 *   - raw lossless form:     {"kty":"EC","crv":"P-256","x":..,"y":..,"_raw":"1"}
 * The "_raw" marker tells the decoder to concatenate x‖y back into rawBytes
 * verbatim rather than wrap them in an SPKI DER.
 */
let JWK_RAW_MARKER: String = "_raw"

// ---------------------------------------------------------------------------
// Jwk — structured EC public-key model
// ---------------------------------------------------------------------------

/**
 * Minimal JWK model for an EC P-256 public key.
 *
 * Fields:
 *   kty  — key type, always "EC" for these keys.
 *   crv  — curve, always "P-256".
 *   x    — base64url of the X coordinate (or first rawBytes half in raw form).
 *   y    — base64url of the Y coordinate (or second rawBytes half in raw form).
 *   raw  — true when x‖y are an opaque lossless split of a non-SPKI key blob.
 */
public class Jwk {
    public let kty: String
    public let crv: String
    public let x: String
    public let y: String
    public let raw: Bool

    public init(kty!: String, crv!: String, x!: String, y!: String, raw!: Bool) {
        this.kty = kty
        this.crv = crv
        this.x = x
        this.y = y
        this.raw = raw
    }

    /**
     * Serialize to a canonical JWK JSON object string suitable for embedding
     * under the SD-JWT `cnf` claim:
     *   {"kty":"EC","crv":"P-256","x":"<b64u>","y":"<b64u>"}
     * (plus "_raw":"1" when this is the lossless non-SPKI form).
     *
     * x/y are base64url (no special characters), so no JSON escaping is needed.
     */
    public func toJson(): String {
        var s = "{\"kty\":\"" + kty + "\",\"crv\":\"" + crv +
            "\",\"x\":\"" + x + "\",\"y\":\"" + y + "\""
        if (raw) {
            s = s + ",\"" + JWK_RAW_MARKER + "\":\"1\""
        }
        s = s + "}"
        return s
    }
}

// ---------------------------------------------------------------------------
// JwkCodec — pubkey <-> JWK (lossless), backed by the Base64Url seam
// ---------------------------------------------------------------------------

/**
 * Converts between the opaque seam ECDSAPublicKey and the structured Jwk model.
 *
 * All base64url operations go through the injected Base64Url seam so the codec
 * is backend-agnostic and avoids any hand-rolled base64.
 */
public class JwkCodec {
    let _b64: Base64Url

    public init(b64!: Base64Url) {
        _b64 = b64
    }

    /**
     * Build a Jwk from an ECDSAPublicKey.
     *
     * @param pub  Holder public key (any backend).
     * @return Jwk carrying the key losslessly.
     */
    public func fromPublicKey(pub: ECDSAPublicKey): Jwk {
        let rawBytes = pub.getRawBytes()
        if (isP256Spki(rawBytes)) {
            // Real ECDSA path: extract the true affine coordinates.
            // Point = trailing 65 bytes (0x04 || X(32) || Y(32)); X/Y are the
            // last 64 bytes.
            let xStart = P256_SPKI_LEN - 64
            let xBytes = rawBytes[xStart..xStart + 32]
            let yBytes = rawBytes[xStart + 32..P256_SPKI_LEN]
            return Jwk(
                kty: "EC",
                crv: "P-256",
                x: _b64.encode(xBytes),
                y: _b64.encode(yBytes),
                raw: false
            )
        }
        // Lossless fallback (host surrogate / non-SPKI material): split the raw
        // bytes at the midpoint so decode can re-concatenate them exactly.
        let n = rawBytes.size
        let half = n / 2
        let firstHalf = rawBytes[0..half]
        let secondHalf = rawBytes[half..n]
        return Jwk(
            kty: "EC",
            crv: "P-256",
            x: _b64.encode(firstHalf),
            y: _b64.encode(secondHalf),
            raw: true
        )
    }

    /**
     * Reconstruct an ECDSAPublicKey from a Jwk.
     *
     * @param jwk  The parsed JWK.
     * @return ECDSAPublicKey whose rawBytes byte-equal the key that produced jwk.
     */
    public func toPublicKey(jwk: Jwk): ECDSAPublicKey {
        let xBytes = _b64.decode(jwk.x)
        let yBytes = _b64.decode(jwk.y)
        if (jwk.raw) {
            // Lossless form: rawBytes = x || y verbatim.
            let combined = concatBytes(xBytes, yBytes)
            return ECDSAPublicKey(rawBytes: combined)
        }
        // True P-256 point form: rebuild the 91-byte SPKI DER from the fixed
        // prefix + 0x04 || X || Y.
        let spki = buildP256Spki(xBytes, yBytes)
        return ECDSAPublicKey(rawBytes: spki)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Test whether rawBytes is a P-256 SubjectPublicKeyInfo DER:
     * length 91 and matching the fixed AlgorithmIdentifier prefix with the
     * uncompressed-point indicator 0x04 immediately after the prefix.
     */
    private func isP256Spki(rawBytes: Array<UInt8>): Bool {
        if (rawBytes.size != P256_SPKI_LEN) {
            return false
        }
        var i: Int64 = 0
        while (i < P256_SPKI_PREFIX.size) {
            if (rawBytes[i] != P256_SPKI_PREFIX[i]) {
                return false
            }
            i = i + 1
        }
        // Byte right after the prefix must be the uncompressed-point tag 0x04.
        return rawBytes[P256_SPKI_PREFIX.size] == 0x04u8
    }

    /**
     * Build a 91-byte P-256 SPKI DER from 32-byte X and 32-byte Y coordinates.
     *
     * Layout: P256_SPKI_PREFIX (26) || 0x04 || X(32) || Y(32).
     * If X or Y are not exactly 32 bytes they are right-aligned (left zero-pad)
     * or truncated from the left to 32 bytes so the output is always 91 bytes.
     */
    private func buildP256Spki(x: Array<UInt8>, y: Array<UInt8>): Array<UInt8> {
        let xNorm = normalize32(x)
        let yNorm = normalize32(y)
        var out: Array<UInt8> = Array<UInt8>(P256_SPKI_LEN, repeat: 0u8)
        var pos: Int64 = 0
        var i: Int64 = 0
        while (i < P256_SPKI_PREFIX.size) {
            out[pos] = P256_SPKI_PREFIX[i]
            pos = pos + 1
            i = i + 1
        }
        out[pos] = 0x04u8  // uncompressed point indicator
        pos = pos + 1
        i = 0
        while (i < 32) {
            out[pos] = xNorm[i]
            pos = pos + 1
            i = i + 1
        }
        i = 0
        while (i < 32) {
            out[pos] = yNorm[i]
            pos = pos + 1
            i = i + 1
        }
        return out
    }

    /**
     * Right-align `src` into a fresh 32-byte array (left zero-pad if shorter,
     * keep the rightmost 32 bytes if longer).
     */
    private func normalize32(src: Array<UInt8>): Array<UInt8> {
        var out: Array<UInt8> = Array<UInt8>(32, repeat: 0u8)
        let n = src.size
        if (n >= 32) {
            var i: Int64 = 0
            while (i < 32) {
                out[i] = src[n - 32 + i]
                i = i + 1
            }
        } else {
            var i: Int64 = 0
            while (i < n) {
                out[32 - n + i] = src[i]
                i = i + 1
            }
        }
        return out
    }

    /**
     * Concatenate two byte arrays into a fresh array.
     */
    private func concatBytes(a: Array<UInt8>, b: Array<UInt8>): Array<UInt8> {
        var out: Array<UInt8> = Array<UInt8>(a.size + b.size, repeat: 0u8)
        var i: Int64 = 0
        while (i < a.size) {
            out[i] = a[i]
            i = i + 1
        }
        var j: Int64 = 0
        while (j < b.size) {
            out[a.size + j] = b[j]
            j = j + 1
        }
        return out
    }
}
