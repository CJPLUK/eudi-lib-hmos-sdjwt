/**
 * core_crypto_adapter.cj
 *
 * Adapts the five seam interfaces (Digest, Base64Url, Jws, EcdsaP256, Rng)
 * to the real eudi_lib_core_crypto static-class implementations backed by
 * stdx.crypto.* (OpenSSL).  ES256 becomes true ECDSA P-256.
 *
 * Key-type mapping design
 * -----------------------
 * seam.ECDSAPrivateKey.rawBytes  — stores the DER bytes of the stdx priv key
 * seam.ECDSAPublicKey.rawBytes   — stores the DER bytes of the stdx pub key
 *
 * Callers in the SD-JWT business layer treat these as completely opaque handles.
 * Each crypto call reconstructs the stdx key from rawBytes, performs the
 * operation, and (for key-output operations) encodes the result back to DER.
 *
 * Import strategy
 * ---------------
 * eudi_lib_core_crypto exports classes named Digest, Base64Url, Jws, EcdsaP256,
 * Rng — all of which conflict with the seam interfaces of the same names already
 * in scope in this package.  We resolve this by importing the whole package under
 * an alias (CC) and importing only the specific types we need from stdx under
 * non-conflicting aliases.
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam

import eudi_lib_core_crypto as CC
import stdx.crypto.keys.ECDSAPrivateKey as StdxPrivKey
import stdx.crypto.keys.ECDSAPublicKey  as StdxPubKey
import stdx.crypto.common.DerBlob

// ---------------------------------------------------------------------------
// Internal helpers — seam <-> stdx key round-trip via DER
// ---------------------------------------------------------------------------

func decodePrivDer(rawBytes: Array<UInt8>): StdxPrivKey {
    return StdxPrivKey.decodeDer(DerBlob(rawBytes))
}

func decodePubDer(rawBytes: Array<UInt8>): StdxPubKey {
    return StdxPubKey.decodeDer(DerBlob(rawBytes))
}

// ---------------------------------------------------------------------------
// CoreDigestImpl
// ---------------------------------------------------------------------------

public class CoreDigestImpl <: Digest {
    public func sha256(data: Array<UInt8>): Array<UInt8> {
        return CC.Digest.sha256(data)
    }

    public func sha384(data: Array<UInt8>): Array<UInt8> {
        return CC.Digest.sha384(data)
    }

    public func sha512(data: Array<UInt8>): Array<UInt8> {
        return CC.Digest.sha512(data)
    }
}

// ---------------------------------------------------------------------------
// CoreBase64UrlImpl
// ---------------------------------------------------------------------------

public class CoreBase64UrlImpl <: Base64Url {
    public func encode(data: Array<UInt8>): String {
        return CC.Base64Url.encode(data)
    }

    public func decode(text: String): Array<UInt8> {
        return CC.Base64Url.decode(text)
    }
}

// ---------------------------------------------------------------------------
// CoreRngImpl
// ---------------------------------------------------------------------------

public class CoreRngImpl <: Rng {
    public func bytes(count: Int64): Array<UInt8> {
        return CC.Rng.bytes(count)
    }
}

// ---------------------------------------------------------------------------
// CoreEcdsaP256Impl
// ---------------------------------------------------------------------------

/**
 * Real ECDSA P-256 backed by eudi_lib_core_crypto.EcdsaP256.
 *
 * Key lifecycle:
 *   generate()     CC.EcdsaP256.generate() → encode DER → seam ECDSAPrivateKey
 *   publicKeyOf()  decode rawBytes → CC.EcdsaP256.publicKeyOf() → encode DER → seam ECDSAPublicKey
 *   sign()         decode priv rawBytes → CC.EcdsaP256.sign()
 *   verify()       decode pub rawBytes  → CC.EcdsaP256.verify()
 *   derToRaw/rawToDer  pure byte ops via CC.EcdsaP256
 */
public class CoreEcdsaP256Impl <: EcdsaP256 {

    public func generate(): ECDSAPrivateKey {
        let stdxPriv = CC.EcdsaP256.generate()
        let derBlob  = stdxPriv.encodeToDer()
        return ECDSAPrivateKey(rawBytes: derBlob.body)
    }

    public func publicKeyOf(priv: ECDSAPrivateKey): ECDSAPublicKey {
        let stdxPriv = decodePrivDer(priv.getRawBytes())
        let stdxPub  = CC.EcdsaP256.publicKeyOf(stdxPriv)
        let derBlob  = stdxPub.encodeToDer()
        return ECDSAPublicKey(rawBytes: derBlob.body)
    }

    public func sign(priv: ECDSAPrivateKey, message: Array<UInt8>): Array<UInt8> {
        let stdxPriv = decodePrivDer(priv.getRawBytes())
        return CC.EcdsaP256.sign(stdxPriv, message)
    }

    public func verify(pub: ECDSAPublicKey, message: Array<UInt8>,
            rawSig: Array<UInt8>): Bool {
        let stdxPub = decodePubDer(pub.getRawBytes())
        return CC.EcdsaP256.verify(stdxPub, message, rawSig)
    }

    public func derToRaw(der: Array<UInt8>): Array<UInt8> {
        return CC.EcdsaP256.derToRaw(der)
    }

    public func rawToDer(raw: Array<UInt8>): Array<UInt8> {
        return CC.EcdsaP256.rawToDer(raw)
    }
}

// ---------------------------------------------------------------------------
// CoreJwsImpl
// ---------------------------------------------------------------------------

public class CoreJwsImpl <: Jws {
    public func signEs256(headerJson: String, payload: Array<UInt8>,
            priv: ECDSAPrivateKey): String {
        let stdxPriv = decodePrivDer(priv.getRawBytes())
        return CC.Jws.signEs256(headerJson, payload, stdxPriv)
    }

    public func verifyEs256(compact: String, pub: ECDSAPublicKey): Bool {
        let stdxPub = decodePubDer(pub.getRawBytes())
        return CC.Jws.verifyEs256(compact, stdxPub)
    }
}

// ---------------------------------------------------------------------------
// CoreCryptoProvider — aggregate (mirrors HostCryptoStub shape)
// ---------------------------------------------------------------------------

/**
 * Drop-in replacement for HostCryptoStub backed by true ECDSA P-256 via
 * eudi_lib_core_crypto / stdx.crypto.
 *
 *   let crypto = CoreCryptoProvider()
 *   let priv   = crypto.ecdsa.generate()
 *   let pub    = crypto.ecdsa.publicKeyOf(priv)
 *   let jwt    = crypto.jws.signEs256("{\"alg\":\"ES256\"}", "payload".toArray(), priv)
 *   let ok     = crypto.jws.verifyEs256(jwt, pub)
 *
 * Note: stdx.crypto is available on the aarch64-linux-ohos device target.
 * Host (darwin) builds compile but CoreCryptoProvider methods will throw at
 * runtime if the stdx host library is absent.  Use HostCryptoStub for
 * host-side unit tests; use CoreCryptoProvider for device E2E tests.
 */
public class CoreCryptoProvider {
    public let digest: CoreDigestImpl
    public let base64Url: CoreBase64UrlImpl
    public let rng: CoreRngImpl
    public let ecdsa: CoreEcdsaP256Impl
    public let jws: CoreJwsImpl

    public init() {
        digest    = CoreDigestImpl()
        base64Url = CoreBase64UrlImpl()
        rng       = CoreRngImpl()
        ecdsa     = CoreEcdsaP256Impl()
        jws       = CoreJwsImpl()
    }
}
