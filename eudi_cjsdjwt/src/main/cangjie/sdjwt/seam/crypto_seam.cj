/**
 * crypto_seam.cj
 *
 * Crypto seam interfaces for SD-JWT.  Signature matches the A1-frozen
 * core-crypto blueprint contracts exactly so that downstream features
 * (sdjwt_digest / factory / issuer / verifier) require zero change when
 * the real core-crypto module is delivered.
 *
 * This file owns:
 *   - Interface declarations: Digest, Base64Url, Jws, EcdsaP256, Rng
 *   - Key value types: ECDSAPrivateKey, ECDSAPublicKey (opaque wrappers)
 *
 * HostCryptoStub (host_crypto_stub.cj) provides the in-process
 * implementation backed by stdx.crypto.* for unit-testing on the host
 * build target.
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam

// ---------------------------------------------------------------------------
// Opaque key-handle types
// ---------------------------------------------------------------------------

/**
 * Opaque handle for an ECDSA P-256 private key.
 *
 * Carries the raw 32-byte scalar (big-endian) so that the seam layer can
 * hand it to whichever backend is active without leaking the stdx type into
 * the callers.
 */
public class ECDSAPrivateKey {
    let rawBytes: Array<UInt8>

    public init(rawBytes!: Array<UInt8>) {
        this.rawBytes = rawBytes
    }

    public func getRawBytes(): Array<UInt8> {
        return rawBytes
    }
}

/**
 * Opaque handle for an ECDSA P-256 public key.
 *
 * Carries the uncompressed point encoding (65 bytes: 0x04 || X || Y) or
 * the raw 64-byte concatenation depending on context.  Backends decode
 * from getRawBytes() as needed.
 */
public class ECDSAPublicKey {
    let rawBytes: Array<UInt8>

    public init(rawBytes!: Array<UInt8>) {
        this.rawBytes = rawBytes
    }

    public func getRawBytes(): Array<UInt8> {
        return rawBytes
    }
}

// ---------------------------------------------------------------------------
// Digest interface
// ---------------------------------------------------------------------------

/**
 * Hash primitives used for SD-JWT disclosure hashing.
 * Method signatures are identical to core-crypto A1 blueprint.
 */
public interface Digest {
    /**
     * Compute SHA-256 of `data`.
     *
     * @param data  Input bytes.
     * @return 32-byte hash.
     */
    func sha256(data: Array<UInt8>): Array<UInt8>

    /**
     * Compute SHA-384 of `data`.
     *
     * @param data  Input bytes.
     * @return 48-byte hash.
     */
    func sha384(data: Array<UInt8>): Array<UInt8>

    /**
     * Compute SHA-512 of `data`.
     *
     * @param data  Input bytes.
     * @return 64-byte hash.
     */
    func sha512(data: Array<UInt8>): Array<UInt8>
}

// ---------------------------------------------------------------------------
// Base64Url interface
// ---------------------------------------------------------------------------

/**
 * JOSE-style base64url encoding with no padding (RFC 4648 §5).
 */
public interface Base64Url {
    /**
     * Encode `data` to base64url string (no '=' padding).
     *
     * @param data  Raw bytes.
     * @return Base64url-encoded string.
     */
    func encode(data: Array<UInt8>): String

    /**
     * Decode a base64url string back to bytes.
     *
     * Tolerates both padded and unpadded input.
     *
     * @param text  Base64url string.
     * @return Decoded bytes.
     */
    func decode(text: String): Array<UInt8>
}

// ---------------------------------------------------------------------------
// Jws interface
// ---------------------------------------------------------------------------

/**
 * JWS compact-serialization sign/verify for ES256 (RFC 7515 + RFC 7518).
 */
public interface Jws {
    /**
     * Produce a JWS compact token using ES256.
     *
     * The implementation MUST:
     *   1. Build the JWS Signing Input: base64url(headerJson) + "." + base64url(payload)
     *   2. Compute SHA-256 of the signing input bytes.
     *   3. Sign with ECDSA P-256 (raw r||s, 64 bytes).
     *   4. Return: signingInput + "." + base64url(rawSignature)
     *
     * @param headerJson  Serialized JSON object for the JOSE header, e.g. '{"alg":"ES256"}'.
     * @param payload     Raw payload bytes.
     * @param priv        Private key handle.
     * @return RFC 7515 compact serialization string.
     */
    func signEs256(headerJson: String, payload: Array<UInt8>, priv: ECDSAPrivateKey): String

    /**
     * Verify a JWS compact token produced by signEs256.
     *
     * @param compact  Three-part dot-separated compact JWS.
     * @param pub      Public key handle.
     * @return true if signature verifies and the header declares alg=ES256.
     */
    func verifyEs256(compact: String, pub: ECDSAPublicKey): Bool
}

// ---------------------------------------------------------------------------
// EcdsaP256 interface
// ---------------------------------------------------------------------------

/**
 * Low-level ECDSA P-256 key-management and raw sign/verify primitives.
 *
 * The `sign` method returns the raw 64-byte r||s signature (not DER), so
 * that JWS and other consumers receive the exact encoding mandated by
 * RFC 7518 §3.4.
 */
public interface EcdsaP256 {
    /**
     * Generate a fresh ECDSA P-256 key pair and return the private key handle.
     */
    func generate(): ECDSAPrivateKey

    /**
     * Derive the public key from a private key handle.
     */
    func publicKeyOf(priv: ECDSAPrivateKey): ECDSAPublicKey

    /**
     * Sign `message` with `priv` using ECDSA P-256.
     *
     * The implementation computes SHA-256 of `message` internally and
     * returns a 64-byte raw r||s signature.
     *
     * @param priv     Private key handle.
     * @param message  Input to be hashed-then-signed.
     * @return 64-byte raw r||s signature.
     */
    func sign(priv: ECDSAPrivateKey, message: Array<UInt8>): Array<UInt8>

    /**
     * Verify a 64-byte raw r||s signature against `message`.
     *
     * @param pub        Public key handle.
     * @param message    Original input.
     * @param rawSig     64-byte raw r||s signature.
     * @return true if valid.
     */
    func verify(pub: ECDSAPublicKey, message: Array<UInt8>, rawSig: Array<UInt8>): Bool

    /**
     * Convert a DER-encoded ECDSA signature to the 64-byte raw r||s format.
     *
     * ASN.1 layout: SEQUENCE { INTEGER r, INTEGER s }
     * Each INTEGER is big-endian with an optional leading 0x00 padding byte
     * when the high bit is set.  The output is always exactly 64 bytes:
     *   out[0..32]  = r, zero-padded on the left to 32 bytes
     *   out[32..64] = s, zero-padded on the left to 32 bytes
     *
     * @param der  DER-encoded signature (variable length, 70–72 bytes typical).
     * @return 64-byte raw r||s.
     */
    func derToRaw(der: Array<UInt8>): Array<UInt8>

    /**
     * Convert a 64-byte raw r||s signature to DER encoding.
     *
     * Input is always exactly 64 bytes:
     *   raw[0..32]  = r (big-endian, zero-padded)
     *   raw[32..64] = s (big-endian, zero-padded)
     * Leading zero bytes are stripped; a single 0x00 prefix is added when the
     * high bit of the leading byte is set (DER INTEGER sign convention).
     *
     * @param raw  64-byte raw r||s signature.
     * @return DER-encoded SEQUENCE { INTEGER r, INTEGER s }.
     */
    func rawToDer(raw: Array<UInt8>): Array<UInt8>
}

// ---------------------------------------------------------------------------
// Rng interface
// ---------------------------------------------------------------------------

/**
 * Cryptographically-secure random byte generation.
 */
public interface Rng {
    /**
     * Return `count` cryptographically-random bytes.
     *
     * @param count  Number of bytes requested.
     * @return Array of `count` random bytes.
     */
    func bytes(count: Int64): Array<UInt8>
}
