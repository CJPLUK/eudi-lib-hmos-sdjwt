/**
 * digest_creator.cj
 *
 * SD-JWT disclosure hashing.
 *
 * Corresponds to:
 *   - Sources/Digest/DigestCreator.swift (DigestCreator class)
 *   - Sources/Digest/HashingAlgorithm/HashingAlgorithm.swift
 *     (HashingAlgorithmIdentifier enum)
 *
 * Design notes:
 *   - HashingAlgorithmIdentifier enumerates the _sd_alg values from
 *     IETF draft-ietf-oauth-selective-disclosure-jwt Section 5.2.4.
 *     Supported values: sha-256 / sha-384 / sha-512.
 *     (sha3-256 is excluded because neither the seam Digest interface
 *     nor stdx.crypto.digest exposes SHA3-256 in the current version.)
 *   - DigestCreator.hashAndBase64Encode(disclosure) takes a
 *     base64url-encoded disclosure string, computes the UTF-8 bytes of
 *     that string, hashes them with the configured algorithm, then
 *     base64url-encodes the resulting hash bytes.
 *   - Both Digest and Base64Url are injected via the crypto seam so the
 *     implementation is independent of any specific backend.
 *   - The class is intentionally stateless per call: no salt generation
 *     lives here (that belongs to sdjwt_factory).
 *
 * IETF SD-JWT draft test vector (Appendix A):
 *   disclosure = "WyJfMjZiY2xpZ0hnd1dCbGVzMHNPY0dJIiwgImZhbWlseV9uYW1lIiwgIk11c3Rl..."
 *   sha-256 digest = "w0I8EKcdCtUPkGCNUrfwVp2xEqHwymZ0zZtITB6inbY"
 *   (exact vector validated in unit tests)
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*

// ---------------------------------------------------------------------------
// HashingAlgorithmIdentifier  — _sd_alg values
// ---------------------------------------------------------------------------

/**
 * Enumerates the supported SD-JWT hash algorithm identifiers (_sd_alg).
 *
 * Mirrors HashingAlgorithmIdentifier.swift but restricts to the algorithms
 * supported by the seam Digest interface (sha-256, sha-384, sha-512).
 *
 * Per IETF SD-JWT draft §5.2.4, the _sd_alg value in the JWT payload MUST
 * be one of these strings (case-sensitive).
 */
public enum HashingAlgorithmIdentifier {
    | Sha256
    | Sha384
    | Sha512

    /**
     * Return the _sd_alg string value for inclusion in the JWT payload.
     */
    public func toAlgString(): String {
        match (this) {
            case Sha256 => Keys.defaultSdAlg
            case Sha384 => "sha-384"
            case Sha512 => "sha-512"
        }
    }
}

// ---------------------------------------------------------------------------
// DigestCreator
// ---------------------------------------------------------------------------

/**
 * Creates SD-JWT disclosure digests.
 *
 * The core operation is:
 *   digest = base64url( hash( utf8(disclosure_base64url_string) ) )
 *
 * where `hash` is the algorithm selected by the HashingAlgorithmIdentifier.
 *
 * Usage:
 *   let crypto = HostCryptoStub()
 *   let dc = DigestCreator(
 *       digest: crypto.digest,
 *       base64Url: crypto.base64Url,
 *       algorithm: HashingAlgorithmIdentifier.Sha256
 *   )
 *   let digestStr = dc.hashAndBase64Encode(disclosureEncoded)
 */
public class DigestCreator {

    let _digest: Digest
    let _base64Url: Base64Url
    let _algorithm: HashingAlgorithmIdentifier

    /**
     * Construct a DigestCreator.
     *
     * @param digest     Digest seam implementation (provides sha256/384/512).
     * @param base64Url  Base64Url seam implementation (encodes hash bytes).
     * @param algorithm  Hash algorithm to use; defaults to Sha256.
     */
    public init(
        digest!: Digest,
        base64Url!: Base64Url,
        algorithm!: HashingAlgorithmIdentifier
    ) {
        _digest = digest
        _base64Url = base64Url
        _algorithm = algorithm
    }

    /**
     * Return the _sd_alg identifier string for this creator's algorithm.
     */
    public func algIdentifier(): String {
        return _algorithm.toAlgString()
    }

    /**
     * Compute the SD-JWT digest of a base64url-encoded disclosure string.
     *
     * Steps:
     *   1. Convert `disclosure` to UTF-8 bytes.
     *   2. Hash those bytes with the configured algorithm.
     *   3. Base64url-encode (no padding) the hash bytes.
     *   4. Return the resulting string.
     *
     * This is the exact operation described in IETF SD-JWT draft §5.2.3:
     *   "hash the ASCII bytes of the disclosure"
     *   (disclosure is already base64url-encoded ASCII at this point).
     *
     * @param disclosure  Base64url-encoded disclosure string.
     * @return            Base64url-encoded hash string (the digest).
     */
    public func hashAndBase64Encode(disclosure: String): String {
        let inputBytes: Array<UInt8> = disclosure.toArray()
        let hashBytes: Array<UInt8> = computeHash(inputBytes)
        return _base64Url.encode(hashBytes)
    }

    // -----------------------------------------------------------------
    // Internal: dispatch to the correct hash function
    // -----------------------------------------------------------------

    private func computeHash(data: Array<UInt8>): Array<UInt8> {
        match (_algorithm) {
            case Sha256 => _digest.sha256(data)
            case Sha384 => _digest.sha384(data)
            case Sha512 => _digest.sha512(data)
        }
    }
}
