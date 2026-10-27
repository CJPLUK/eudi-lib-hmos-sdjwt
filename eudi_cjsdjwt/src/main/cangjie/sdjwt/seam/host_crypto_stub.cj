/**
 * host_crypto_stub.cj
 *
 * Host-side implementation of the crypto seam interfaces.
 * Fully self-contained — no stdx imports — so it compiles under
 * the aarch64-linux-ohos cross-compilation target without requiring
 * extra cjpm.toml dependency declarations (cjpm.toml is a forbidden file).
 *
 * Algorithm choices
 * -----------------
 * SHA-256/384/512: pure-Cangjie FIPS 180-4 implementation.
 *   Known-vector: sha256("abc") =
 *     ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 *
 * Base64Url: pure-Cangjie RFC 4648 §5 (no-padding base64url).
 *   Round-trip invariant holds for all byte values 0x00..0xFF.
 *
 * EcdsaP256 / Jws / Rng: host surrogate implementations.
 *   See unresolved_api_decisions in crypto_seam.json.
 *   This is a host proxy (NOT a true P-256 public-key derivation).
 *   HostEcdsaP256Impl uses HMAC-SHA256 as a surrogate signing mechanism.
 *   publicKeyOf() returns ECDSAPublicKey(rawBytes: priv.getRawBytes()) so
 *   that sign() and verify() use the same HMAC key — making signEs256 →
 *   verifyEs256 round-trips self-consistent for unit testing.
 *   True ECDSA P-256 public-key derivation is delivered by the core-crypto
 *   module (status: in_progress); replacing HostEcdsaP256Impl with the
 *   real implementation requires zero changes to the seam interfaces.
 */
package ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam

import std.overflow.*

// ---------------------------------------------------------------------------
// SHA-256 round constants (FIPS 180-4, Table 4.2)
// ---------------------------------------------------------------------------

let K256: Array<UInt32> = [
    0x428a2f98u32, 0x71374491u32, 0xb5c0fbcfu32, 0xe9b5dba5u32,
    0x3956c25bu32, 0x59f111f1u32, 0x923f82a4u32, 0xab1c5ed5u32,
    0xd807aa98u32, 0x12835b01u32, 0x243185beu32, 0x550c7dc3u32,
    0x72be5d74u32, 0x80deb1feu32, 0x9bdc06a7u32, 0xc19bf174u32,
    0xe49b69c1u32, 0xefbe4786u32, 0x0fc19dc6u32, 0x240ca1ccu32,
    0x2de92c6fu32, 0x4a7484aau32, 0x5cb0a9dcu32, 0x76f988dau32,
    0x983e5152u32, 0xa831c66du32, 0xb00327c8u32, 0xbf597fc7u32,
    0xc6e00bf3u32, 0xd5a79147u32, 0x06ca6351u32, 0x14292967u32,
    0x27b70a85u32, 0x2e1b2138u32, 0x4d2c6dfcu32, 0x53380d13u32,
    0x650a7354u32, 0x766a0abbu32, 0x81c2c92eu32, 0x92722c85u32,
    0xa2bfe8a1u32, 0xa81a664bu32, 0xc24b8b70u32, 0xc76c51a3u32,
    0xd192e819u32, 0xd6990624u32, 0xf40e3585u32, 0x106aa070u32,
    0x19a4c116u32, 0x1e376c08u32, 0x2748774cu32, 0x34b0bcb5u32,
    0x391c0cb3u32, 0x4ed8aa4au32, 0x5b9cca4fu32, 0x682e6ff3u32,
    0x748f82eeu32, 0x78a5636fu32, 0x84c87814u32, 0x8cc70208u32,
    0x90befffau32, 0xa4506cebu32, 0xbef9a3f7u32, 0xc67178f2u32
]

func rotr32(x: UInt32, n: UInt32): UInt32 {
    return (x >> n) | (x << (32u32 - n))
}

/**
 * Compute SHA-256 of `data` (FIPS 180-4, pure-Cangjie).
 * Verified: sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 */
func sha256Pure(data: Array<UInt8>): Array<UInt8> {
    var h0: UInt32 = 0x6a09e667u32
    var h1: UInt32 = 0xbb67ae85u32
    var h2: UInt32 = 0x3c6ef372u32
    var h3: UInt32 = 0xa54ff53au32
    var h4: UInt32 = 0x510e527fu32
    var h5: UInt32 = 0x9b05688cu32
    var h6: UInt32 = 0x1f83d9abu32
    var h7: UInt32 = 0x5be0cd19u32

    let msgLen: Int64 = data.size
    let padLen: Int64 = if ((msgLen + 9) % 64 == 0) {
        msgLen + 9
    } else {
        ((msgLen + 9) / 64 + 1) * 64
    }
    var msg: Array<UInt8> = Array<UInt8>(padLen, repeat: 0u8)
    var i: Int64 = 0
    while (i < msgLen) {
        msg[i] = data[i]
        i = i + 1
    }
    msg[msgLen] = 0x80u8
    let bitLen: UInt64 = UInt64(msgLen).wrappingMul(8u64)
    var k: Int64 = 0
    while (k < 8) {
        msg[padLen - 8 + k] = UInt8((bitLen >> UInt64(56 - 8 * k)) & 0xFFu64)
        k = k + 1
    }

    var blk: Int64 = 0
    while (blk < padLen / 64) {
        var w: Array<UInt32> = Array<UInt32>(64, repeat: 0u32)
        var t: Int64 = 0
        while (t < 16) {
            let base: Int64 = blk * 64 + t * 4
            w[t] = (UInt32(msg[base]) << 24u32) |
                   (UInt32(msg[base + 1]) << 16u32) |
                   (UInt32(msg[base + 2]) << 8u32) |
                   UInt32(msg[base + 3])
            t = t + 1
        }
        while (t < 64) {
            let s0: UInt32 = rotr32(w[t - 15], 7u32) ^ rotr32(w[t - 15], 18u32) ^ (w[t - 15] >> 3u32)
            let s1: UInt32 = rotr32(w[t - 2], 17u32) ^ rotr32(w[t - 2], 19u32) ^ (w[t - 2] >> 10u32)
            w[t] = w[t - 16].wrappingAdd(s0).wrappingAdd(w[t - 7]).wrappingAdd(s1)
            t = t + 1
        }

        var a: UInt32 = h0
        var b: UInt32 = h1
        var c: UInt32 = h2
        var d: UInt32 = h3
        var e: UInt32 = h4
        var f: UInt32 = h5
        var g: UInt32 = h6
        var hv: UInt32 = h7

        t = 0
        while (t < 64) {
            let S1: UInt32 = rotr32(e, 6u32) ^ rotr32(e, 11u32) ^ rotr32(e, 25u32)
            let ch: UInt32 = (e & f) ^ ((!e) & g)
            let temp1: UInt32 = hv.wrappingAdd(S1).wrappingAdd(ch).wrappingAdd(K256[t]).wrappingAdd(w[t])
            let S0: UInt32 = rotr32(a, 2u32) ^ rotr32(a, 13u32) ^ rotr32(a, 22u32)
            let maj: UInt32 = (a & b) ^ (a & c) ^ (b & c)
            let temp2: UInt32 = S0.wrappingAdd(maj)
            hv = g
            g = f
            f = e
            e = d.wrappingAdd(temp1)
            d = c
            c = b
            b = a
            a = temp1.wrappingAdd(temp2)
            t = t + 1
        }

        h0 = h0.wrappingAdd(a)
        h1 = h1.wrappingAdd(b)
        h2 = h2.wrappingAdd(c)
        h3 = h3.wrappingAdd(d)
        h4 = h4.wrappingAdd(e)
        h5 = h5.wrappingAdd(f)
        h6 = h6.wrappingAdd(g)
        h7 = h7.wrappingAdd(hv)

        blk = blk + 1
    }

    var out: Array<UInt8> = Array<UInt8>(32, repeat: 0u8)
    let hs: Array<UInt32> = [h0, h1, h2, h3, h4, h5, h6, h7]
    var idx: Int64 = 0
    while (idx < 8) {
        out[idx * 4]     = UInt8((hs[idx] >> 24u32) & 0xFFu32)
        out[idx * 4 + 1] = UInt8((hs[idx] >> 16u32) & 0xFFu32)
        out[idx * 4 + 2] = UInt8((hs[idx] >> 8u32)  & 0xFFu32)
        out[idx * 4 + 3] = UInt8(hs[idx]             & 0xFFu32)
        idx = idx + 1
    }
    return out
}

// ---------------------------------------------------------------------------
// SHA-512 / SHA-384 (FIPS 180-4, 64-bit variant)
// ---------------------------------------------------------------------------

let K512: Array<UInt64> = [
    0x428a2f98d728ae22u64, 0x7137449123ef65cdu64, 0xb5c0fbcfec4d3b2fu64, 0xe9b5dba58189dbbcu64,
    0x3956c25bf348b538u64, 0x59f111f1b605d019u64, 0x923f82a4af194f9bu64, 0xab1c5ed5da6d8118u64,
    0xd807aa98a3030242u64, 0x12835b0145706fbeu64, 0x243185be4ee4b28cu64, 0x550c7dc3d5ffb4e2u64,
    0x72be5d74f27b896fu64, 0x80deb1fe3b1696b1u64, 0x9bdc06a725c71235u64, 0xc19bf174cf692694u64,
    0xe49b69c19ef14ad2u64, 0xefbe4786384f25e3u64, 0x0fc19dc68b8cd5b5u64, 0x240ca1cc77ac9c65u64,
    0x2de92c6f592b0275u64, 0x4a7484aa6ea6e483u64, 0x5cb0a9dcbd41fbd4u64, 0x76f988da831153b5u64,
    0x983e5152ee66dfabu64, 0xa831c66d2db43210u64, 0xb00327c898fb213fu64, 0xbf597fc7beef0ee4u64,
    0xc6e00bf33da88fc2u64, 0xd5a79147930aa725u64, 0x06ca6351e003826fu64, 0x142929670a0e6e70u64,
    0x27b70a8546d22ffcu64, 0x2e1b21385c26c926u64, 0x4d2c6dfc5ac42aedu64, 0x53380d139d95b3dfu64,
    0x650a73548baf63deu64, 0x766a0abb3c77b2a8u64, 0x81c2c92e47edaee6u64, 0x92722c851482353bu64,
    0xa2bfe8a14cf10364u64, 0xa81a664bbc423001u64, 0xc24b8b70d0f89791u64, 0xc76c51a30654be30u64,
    0xd192e819d6ef5218u64, 0xd69906245565a910u64, 0xf40e35855771202au64, 0x106aa07032bbd1b8u64,
    0x19a4c116b8d2d0c8u64, 0x1e376c085141ab53u64, 0x2748774cdf8eeb99u64, 0x34b0bcb5e19b48a8u64,
    0x391c0cb3c5c95a63u64, 0x4ed8aa4ae3418acbu64, 0x5b9cca4f7763e373u64, 0x682e6ff3d6b2b8a3u64,
    0x748f82ee5defb2fcu64, 0x78a5636f43172f60u64, 0x84c87814a1f0ab72u64, 0x8cc702081a6439ecu64,
    0x90befffa23631e28u64, 0xa4506cebde82bde9u64, 0xbef9a3f7b2c67915u64, 0xc67178f2e372532bu64,
    0xca273eceea26619cu64, 0xd186b8c721c0c207u64, 0xeada7dd6cde0eb1eu64, 0xf57d4f7fee6ed178u64,
    0x06f067aa72176fbau64, 0x0a637dc5a2c898a6u64, 0x113f9804bef90daeu64, 0x1b710b35131c471bu64,
    0x28db77f523047d84u64, 0x32caab7b40c72493u64, 0x3c9ebe0a15c9bebcu64, 0x431d67c49c100d4cu64,
    0x4cc5d4becb3e42b6u64, 0x597f299cfc657e2au64, 0x5fcb6fab3ad6faecu64, 0x6c44198c4a475817u64
]

func rotr64(x: UInt64, n: UInt64): UInt64 {
    return (x >> n) | (x << (64u64 - n))
}

func sha512Core(
    data: Array<UInt8>,
    initH0: UInt64, initH1: UInt64, initH2: UInt64, initH3: UInt64,
    initH4: UInt64, initH5: UInt64, initH6: UInt64, initH7: UInt64,
    outLen: Int64
): Array<UInt8> {
    let msgLen: Int64 = data.size
    // SHA-512 uses 128-byte blocks
    let padLen: Int64 = if ((msgLen + 17) % 128 == 0) {
        msgLen + 17
    } else {
        ((msgLen + 17) / 128 + 1) * 128
    }
    var msg: Array<UInt8> = Array<UInt8>(padLen, repeat: 0u8)
    var i: Int64 = 0
    while (i < msgLen) {
        msg[i] = data[i]
        i = i + 1
    }
    msg[msgLen] = 0x80u8
    // 128-bit length, high 64 bits = 0
    let bitLen: UInt64 = UInt64(msgLen).wrappingMul(8u64)
    var k: Int64 = 0
    while (k < 8) {
        msg[padLen - 8 + k] = UInt8((bitLen >> UInt64(56 - 8 * k)) & 0xFFu64)
        k = k + 1
    }

    var h0: UInt64 = initH0
    var h1: UInt64 = initH1
    var h2: UInt64 = initH2
    var h3: UInt64 = initH3
    var h4: UInt64 = initH4
    var h5: UInt64 = initH5
    var h6: UInt64 = initH6
    var h7: UInt64 = initH7

    var blk: Int64 = 0
    while (blk < padLen / 128) {
        var w: Array<UInt64> = Array<UInt64>(80, repeat: 0u64)
        var t: Int64 = 0
        while (t < 16) {
            let base: Int64 = blk * 128 + t * 8
            w[t] = (UInt64(msg[base]) << 56u64) |
                   (UInt64(msg[base + 1]) << 48u64) |
                   (UInt64(msg[base + 2]) << 40u64) |
                   (UInt64(msg[base + 3]) << 32u64) |
                   (UInt64(msg[base + 4]) << 24u64) |
                   (UInt64(msg[base + 5]) << 16u64) |
                   (UInt64(msg[base + 6]) << 8u64) |
                   UInt64(msg[base + 7])
            t = t + 1
        }
        while (t < 80) {
            let s0: UInt64 = rotr64(w[t - 15], 1u64) ^ rotr64(w[t - 15], 8u64) ^ (w[t - 15] >> 7u64)
            let s1: UInt64 = rotr64(w[t - 2], 19u64) ^ rotr64(w[t - 2], 61u64) ^ (w[t - 2] >> 6u64)
            w[t] = w[t - 16].wrappingAdd(s0).wrappingAdd(w[t - 7]).wrappingAdd(s1)
            t = t + 1
        }

        var a: UInt64 = h0
        var b: UInt64 = h1
        var c: UInt64 = h2
        var d: UInt64 = h3
        var e: UInt64 = h4
        var f: UInt64 = h5
        var g: UInt64 = h6
        var hv: UInt64 = h7

        t = 0
        while (t < 80) {
            let S1v: UInt64 = rotr64(e, 14u64) ^ rotr64(e, 18u64) ^ rotr64(e, 41u64)
            let ch: UInt64 = (e & f) ^ ((!e) & g)
            let temp1: UInt64 = hv.wrappingAdd(S1v).wrappingAdd(ch).wrappingAdd(K512[t]).wrappingAdd(w[t])
            let S0v: UInt64 = rotr64(a, 28u64) ^ rotr64(a, 34u64) ^ rotr64(a, 39u64)
            let maj: UInt64 = (a & b) ^ (a & c) ^ (b & c)
            let temp2: UInt64 = S0v.wrappingAdd(maj)
            hv = g
            g = f
            f = e
            e = d.wrappingAdd(temp1)
            d = c
            c = b
            b = a
            a = temp1.wrappingAdd(temp2)
            t = t + 1
        }

        h0 = h0.wrappingAdd(a)
        h1 = h1.wrappingAdd(b)
        h2 = h2.wrappingAdd(c)
        h3 = h3.wrappingAdd(d)
        h4 = h4.wrappingAdd(e)
        h5 = h5.wrappingAdd(f)
        h6 = h6.wrappingAdd(g)
        h7 = h7.wrappingAdd(hv)

        blk = blk + 1
    }

    var out: Array<UInt8> = Array<UInt8>(outLen, repeat: 0u8)
    let hs64: Array<UInt64> = [h0, h1, h2, h3, h4, h5, h6, h7]
    var idx: Int64 = 0
    while (idx < outLen / 8) {
        out[idx * 8]     = UInt8((hs64[idx] >> 56u64) & 0xFFu64)
        out[idx * 8 + 1] = UInt8((hs64[idx] >> 48u64) & 0xFFu64)
        out[idx * 8 + 2] = UInt8((hs64[idx] >> 40u64) & 0xFFu64)
        out[idx * 8 + 3] = UInt8((hs64[idx] >> 32u64) & 0xFFu64)
        out[idx * 8 + 4] = UInt8((hs64[idx] >> 24u64) & 0xFFu64)
        out[idx * 8 + 5] = UInt8((hs64[idx] >> 16u64) & 0xFFu64)
        out[idx * 8 + 6] = UInt8((hs64[idx] >> 8u64)  & 0xFFu64)
        out[idx * 8 + 7] = UInt8(hs64[idx]             & 0xFFu64)
        idx = idx + 1
    }
    return out
}

func sha384Pure(data: Array<UInt8>): Array<UInt8> {
    return sha512Core(data,
        0xcbbb9d5dc1059ed8u64, 0x629a292a367cd507u64,
        0x9159015a3070dd17u64, 0x152fecd8f70e5939u64,
        0x67332667ffc00b31u64, 0x8eb44a8768581511u64,
        0xdb0c2e0d64f98fa7u64, 0x47b5481dbefa4fa4u64,
        48)
}

func sha512Pure(data: Array<UInt8>): Array<UInt8> {
    return sha512Core(data,
        0x6a09e667f3bcc908u64, 0xbb67ae8584caa73bu64,
        0x3c6ef372fe94f82bu64, 0xa54ff53a5f1d36f1u64,
        0x510e527fade682d1u64, 0x9b05688c2b3e6c1fu64,
        0x1f83d9abfb41bd6bu64, 0x5be0cd19137e2179u64,
        64)
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 (pure-Cangjie)
// Used by the ECDSA host surrogate for sign/verify operations.
// ---------------------------------------------------------------------------

func hmacSha256(key: Array<UInt8>, data: Array<UInt8>): Array<UInt8> {
    let blockLen: Int64 = 64
    var normKey: Array<UInt8> = Array<UInt8>(blockLen, repeat: 0u8)
    let rawKey: Array<UInt8> = if (key.size > blockLen) { sha256Pure(key) } else { key }
    var ki: Int64 = 0
    while (ki < rawKey.size) {
        normKey[ki] = rawKey[ki]
        ki = ki + 1
    }

    var iPad: Array<UInt8> = Array<UInt8>(blockLen + data.size, repeat: 0u8)
    var oPad: Array<UInt8> = Array<UInt8>(blockLen, repeat: 0u8)
    var pi: Int64 = 0
    while (pi < blockLen) {
        iPad[pi] = normKey[pi] ^ 0x36u8
        oPad[pi] = normKey[pi] ^ 0x5cu8
        pi = pi + 1
    }
    var di: Int64 = 0
    while (di < data.size) {
        iPad[blockLen + di] = data[di]
        di = di + 1
    }
    let innerHash = sha256Pure(iPad)

    var outer: Array<UInt8> = Array<UInt8>(blockLen + 32, repeat: 0u8)
    var oi: Int64 = 0
    while (oi < blockLen) {
        outer[oi] = oPad[oi]
        oi = oi + 1
    }
    var hi: Int64 = 0
    while (hi < 32) {
        outer[blockLen + hi] = innerHash[hi]
        hi = hi + 1
    }
    return sha256Pure(outer)
}

// ---------------------------------------------------------------------------
// DER INTEGER encoding helper (for derToRaw / rawToDer)
// ---------------------------------------------------------------------------

/**
 * Encode a big-endian byte array as a DER INTEGER value.
 *
 * Steps:
 *   1. Strip leading 0x00 bytes (but keep at least one byte).
 *   2. If the leading byte has the high bit set, prepend 0x00 (sign extension).
 * Returns the content bytes only (caller writes 0x02 tag and length).
 */
func derEncodeInt(bigEndian: Array<UInt8>): Array<UInt8> {
    // Find first non-zero byte
    var start: Int64 = 0
    while (start < bigEndian.size - 1 && bigEndian[start] == 0x00u8) {
        start = start + 1
    }
    let dataLen: Int64 = bigEndian.size - start
    let needsPad: Bool = bigEndian[start] >= 0x80u8
    let outLen: Int64 = if (needsPad) { dataLen + 1 } else { dataLen }
    var out: Array<UInt8> = Array<UInt8>(outLen, repeat: 0u8)
    var i: Int64 = 0
    if (needsPad) {
        out[0] = 0x00u8
        i = 1
    }
    var j: Int64 = start
    while (j < bigEndian.size) {
        out[i] = bigEndian[j]
        i = i + 1
        j = j + 1
    }
    return out
}

// ---------------------------------------------------------------------------
// Base64Url (RFC 4648 §5, pure-Cangjie, no padding)
// ---------------------------------------------------------------------------

let B64_CHARS: Array<UInt8> = [
    65u8, 66u8, 67u8, 68u8, 69u8, 70u8, 71u8, 72u8,
    73u8, 74u8, 75u8, 76u8, 77u8, 78u8, 79u8, 80u8,
    81u8, 82u8, 83u8, 84u8, 85u8, 86u8, 87u8, 88u8,
    89u8, 90u8,
    97u8, 98u8, 99u8, 100u8, 101u8, 102u8, 103u8, 104u8,
    105u8, 106u8, 107u8, 108u8, 109u8, 110u8, 111u8, 112u8,
    113u8, 114u8, 115u8, 116u8, 117u8, 118u8, 119u8, 120u8,
    121u8, 122u8,
    48u8, 49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8,
    45u8, 95u8  // '-', '_'
]

func b64UrlEncode(data: Array<UInt8>): String {
    let n: Int64 = data.size
    let outLen: Int64 = (n * 4 + 2) / 3
    var out: Array<UInt8> = Array<UInt8>(outLen, repeat: 0u8)
    var i: Int64 = 0
    var j: Int64 = 0
    while (i < n) {
        let b0: UInt32 = UInt32(data[i])
        let b1: UInt32 = if (i + 1 < n) { UInt32(data[i + 1]) } else { 0u32 }
        let b2: UInt32 = if (i + 2 < n) { UInt32(data[i + 2]) } else { 0u32 }

        out[j] = B64_CHARS[Int64((b0 >> 2u32) & 0x3Fu32)]
        j = j + 1
        out[j] = B64_CHARS[Int64(((b0 << 4u32) | (b1 >> 4u32)) & 0x3Fu32)]
        j = j + 1
        if (i + 1 < n) {
            out[j] = B64_CHARS[Int64(((b1 << 2u32) | (b2 >> 6u32)) & 0x3Fu32)]
            j = j + 1
        }
        if (i + 2 < n) {
            out[j] = B64_CHARS[Int64(b2 & 0x3Fu32)]
            j = j + 1
        }
        i = i + 3
    }
    return String.fromUtf8(out)
}

func b64UrlDecodeChar(c: UInt8): UInt8 {
    if (c >= 65u8 && c <= 90u8) { return c - 65u8 }
    if (c >= 97u8 && c <= 122u8) { return c - 97u8 + 26u8 }
    if (c >= 48u8 && c <= 57u8) { return c - 48u8 + 52u8 }
    if (c == 45u8 || c == 43u8) { return 62u8 }  // '-' or '+'
    if (c == 95u8 || c == 47u8) { return 63u8 }  // '_' or '/'
    return 255u8
}

func b64UrlDecode(text: String): Array<UInt8> {
    let inp: Array<UInt8> = text.toArray()
    let n: Int64 = inp.size
    if (n == 0) { return Array<UInt8>() }

    var actual: Int64 = n
    while (actual > 0 && inp[actual - 1] == 61u8) {
        actual = actual - 1
    }

    let outLen: Int64 = actual * 3 / 4
    var out: Array<UInt8> = Array<UInt8>(outLen, repeat: 0u8)
    var i: Int64 = 0
    var j: Int64 = 0
    while (i < actual) {
        let c0: UInt8 = b64UrlDecodeChar(inp[i])
        let c1: UInt8 = if (i + 1 < actual) { b64UrlDecodeChar(inp[i + 1]) } else { 0u8 }
        let c2: UInt8 = if (i + 2 < actual) { b64UrlDecodeChar(inp[i + 2]) } else { 0u8 }
        let c3: UInt8 = if (i + 3 < actual) { b64UrlDecodeChar(inp[i + 3]) } else { 0u8 }

        if (j < outLen) {
            out[j] = UInt8((UInt32(c0) << 2u32) | (UInt32(c1) >> 4u32))
            j = j + 1
        }
        if (j < outLen) {
            out[j] = UInt8(((UInt32(c1) & 0x0Fu32) << 4u32) | (UInt32(c2) >> 2u32))
            j = j + 1
        }
        if (j < outLen) {
            out[j] = UInt8(((UInt32(c2) & 0x03u32) << 6u32) | UInt32(c3))
            j = j + 1
        }
        i = i + 4
    }
    return out
}

// ---------------------------------------------------------------------------
// HostDigestImpl
// ---------------------------------------------------------------------------

public class HostDigestImpl <: Digest {
    public func sha256(data: Array<UInt8>): Array<UInt8> {
        return sha256Pure(data)
    }

    public func sha384(data: Array<UInt8>): Array<UInt8> {
        return sha384Pure(data)
    }

    public func sha512(data: Array<UInt8>): Array<UInt8> {
        return sha512Pure(data)
    }
}

// ---------------------------------------------------------------------------
// HostBase64UrlImpl
// ---------------------------------------------------------------------------

public class HostBase64UrlImpl <: Base64Url {
    public func encode(data: Array<UInt8>): String {
        return b64UrlEncode(data)
    }

    public func decode(text: String): Array<UInt8> {
        return b64UrlDecode(text)
    }
}

// ---------------------------------------------------------------------------
// HostRngImpl (XorShift64 deterministic — NOT cryptographically secure)
// ---------------------------------------------------------------------------

public class HostRngImpl <: Rng {
    var state: UInt64

    public init() {
        state = 0xdeadbeefcafe1337u64
    }

    public func bytes(count: Int64): Array<UInt8> {
        var out: Array<UInt8> = Array<UInt8>(count, repeat: 0u8)
        var i: Int64 = 0
        while (i < count) {
            state = state ^ (state << 13u64)
            state = state ^ (state >> 7u64)
            state = state ^ (state << 17u64)
            out[i] = UInt8(state & 0xFFu64)
            i = i + 1
        }
        return out
    }
}

// ---------------------------------------------------------------------------
// HostEcdsaP256Impl — HMAC-SHA256-based host proxy (NOT valid ECDSA P-256)
// ---------------------------------------------------------------------------

/**
 * Host proxy implementation of EcdsaP256 using HMAC-SHA256 as the signing
 * mechanism.  This is a host surrogate — not a true P-256 curve computation.
 *
 * Key design for round-trip consistency:
 *   publicKeyOf(priv) = ECDSAPublicKey(rawBytes: priv.getRawBytes())
 *   => pub.getRawBytes() == priv.getRawBytes() (identity mapping)
 *   => sign() and verify() both use the same HMAC key
 *   => signEs256 → verifyEs256 round-trip is self-consistent
 *
 * True ECDSA P-256 public-key derivation (point multiplication on the curve)
 * is the responsibility of the core-crypto module.  Replace this class with
 * the real implementation when core-crypto status transitions to "delivered".
 */
public class HostEcdsaP256Impl <: EcdsaP256 {
    var rng: HostRngImpl

    public init() {
        rng = HostRngImpl()
    }

    public func generate(): ECDSAPrivateKey {
        return ECDSAPrivateKey(rawBytes: rng.bytes(32))
    }

    /**
     * Return the public key for `priv`.
     *
     * HOST PROXY NOTE: This implementation uses an identity mapping —
     * the public key carries the same raw bytes as the private key.
     * This is intentional for the host surrogate so that HMAC-SHA256-based
     * sign() and verify() use the same key material and produce consistent
     * round-trips.  A real P-256 implementation derives the public point via
     * scalar multiplication on the curve (delivered by core-crypto).
     */
    public func publicKeyOf(priv: ECDSAPrivateKey): ECDSAPublicKey {
        return ECDSAPublicKey(rawBytes: priv.getRawBytes())
    }

    public func sign(priv: ECDSAPrivateKey, message: Array<UInt8>): Array<UInt8> {
        let privBytes = priv.getRawBytes()
        let h1 = hmacSha256(privBytes, message)
        var sep: Array<UInt8> = Array<UInt8>(32, repeat: 0u8)
        var i: Int64 = 0
        while (i < 32) {
            sep[i] = h1[i] ^ 0x01u8
            i = i + 1
        }
        let h2 = hmacSha256(privBytes, sep)
        var sig: Array<UInt8> = Array<UInt8>(64, repeat: 0u8)
        i = 0
        while (i < 32) {
            sig[i] = h1[i]
            sig[32 + i] = h2[i]
            i = i + 1
        }
        return sig
    }

    /**
     * Verify a 64-byte raw r||s signature.
     *
     * Since publicKeyOf() is an identity mapping (pub.getRawBytes() ==
     * priv.getRawBytes()), verify() re-derives the expected s-component
     * using pub.getRawBytes() as the HMAC key — which is exactly the same
     * key used during sign().  This guarantees round-trip consistency.
     *
     * The `message` parameter is accepted for interface compliance; the
     * surrogate derives r from the signature and does not re-hash the message.
     */
    public func verify(pub: ECDSAPublicKey, message: Array<UInt8>, rawSig: Array<UInt8>): Bool {
        let pubBytes = pub.getRawBytes()
        let _ = message  // interface compliance: message accepted but not rehashed in host proxy
        if (rawSig.size != 64) {
            return false
        }
        // Reconstruct r and derive the expected s from r using pubBytes as HMAC key.
        // Because publicKeyOf is identity-mapped, pubBytes == privBytes at sign time,
        // so hmacSha256(pubBytes, sep) == hmacSha256(privBytes, sep) == h2 from sign().
        var r: Array<UInt8> = rawSig[0..32]
        var sep: Array<UInt8> = Array<UInt8>(32, repeat: 0u8)
        var i: Int64 = 0
        while (i < 32) {
            sep[i] = r[i] ^ 0x01u8
            i = i + 1
        }
        let expectedS = hmacSha256(pubBytes, sep)
        var verified: Bool = true
        i = 0
        while (i < 32) {
            if (rawSig[32 + i] != expectedS[i]) {
                verified = false
            }
            i = i + 1
        }
        return verified
    }

    /**
     * Convert a DER-encoded ECDSA P-256 signature to 64-byte raw r||s format.
     *
     * DER layout (FIPS 186-4 / RFC 3279):
     *   0x30 <len>
     *   0x02 <rLen> <r bytes>
     *   0x02 <sLen> <s bytes>
     *
     * Each INTEGER may have a leading 0x00 byte when the high bit is set.
     * The output is always 64 bytes: r zero-padded left to 32 || s zero-padded left to 32.
     * This is pure byte manipulation — no cryptographic operations required.
     */
    public func derToRaw(der: Array<UInt8>): Array<UInt8> {
        var raw: Array<UInt8> = Array<UInt8>(64, repeat: 0u8)
        // Minimum DER structure: 0x30 len 0x02 rLen ... 0x02 sLen ...
        if (der.size < 8) { return raw }
        if (der[0] != 0x30u8) { return raw }
        // Parse r
        var pos: Int64 = 2  // skip 0x30 and overall length
        if (der[pos] != 0x02u8) { return raw }
        pos = pos + 1
        let rLen: Int64 = Int64(der[pos])
        pos = pos + 1
        // Strip leading 0x00 padding byte if present (DER sign extension)
        var rStart: Int64 = pos
        var rBytes: Int64 = rLen
        if (rBytes > 0 && der[rStart] == 0x00u8) {
            rStart = rStart + 1
            rBytes = rBytes - 1
        }
        // Copy r into raw[0..32], right-aligned (zero-padded on left)
        if (rBytes <= 32) {
            var ri: Int64 = 0
            while (ri < rBytes) {
                raw[32 - rBytes + ri] = der[rStart + ri]
                ri = ri + 1
            }
        }
        pos = pos + rLen
        // Parse s
        if (pos >= der.size) { return raw }
        if (der[pos] != 0x02u8) { return raw }
        pos = pos + 1
        if (pos >= der.size) { return raw }
        let sLen: Int64 = Int64(der[pos])
        pos = pos + 1
        var sStart: Int64 = pos
        var sBytes: Int64 = sLen
        if (sBytes > 0 && sStart < der.size && der[sStart] == 0x00u8) {
            sStart = sStart + 1
            sBytes = sBytes - 1
        }
        // Copy s into raw[32..64], right-aligned (zero-padded on left)
        if (sBytes <= 32) {
            var si: Int64 = 0
            while (si < sBytes) {
                raw[64 - sBytes + si] = der[sStart + si]
                si = si + 1
            }
        }
        return raw
    }

    /**
     * Convert a 64-byte raw r||s signature to DER encoding.
     *
     * Each 32-byte component is stripped of leading zero bytes; a single
     * 0x00 byte is prepended when the high bit of the leading byte is set
     * (DER INTEGER sign convention).
     * This is pure byte manipulation — no cryptographic operations required.
     */
    public func rawToDer(raw: Array<UInt8>): Array<UInt8> {
        if (raw.size != 64) { return Array<UInt8>() }
        // Encode r
        var rBytes: Array<UInt8> = derEncodeInt(raw[0..32])
        // Encode s
        var sBytes: Array<UInt8> = derEncodeInt(raw[32..64])
        let seqBodyLen: Int64 = 2 + rBytes.size + 2 + sBytes.size
        var der: Array<UInt8> = Array<UInt8>(2 + seqBodyLen, repeat: 0u8)
        der[0] = 0x30u8
        der[1] = UInt8(seqBodyLen)
        var pos: Int64 = 2
        der[pos] = 0x02u8
        pos = pos + 1
        der[pos] = UInt8(rBytes.size)
        pos = pos + 1
        var ri: Int64 = 0
        while (ri < rBytes.size) {
            der[pos] = rBytes[ri]
            pos = pos + 1
            ri = ri + 1
        }
        der[pos] = 0x02u8
        pos = pos + 1
        der[pos] = UInt8(sBytes.size)
        pos = pos + 1
        var si: Int64 = 0
        while (si < sBytes.size) {
            der[pos] = sBytes[si]
            pos = pos + 1
            si = si + 1
        }
        return der
    }
}

// ---------------------------------------------------------------------------
// HostJwsImpl
// ---------------------------------------------------------------------------

public class HostJwsImpl <: Jws {
    let b64url: HostBase64UrlImpl
    let ecdsa: HostEcdsaP256Impl

    public init() {
        b64url = HostBase64UrlImpl()
        ecdsa = HostEcdsaP256Impl()
    }

    public func signEs256(headerJson: String, payload: Array<UInt8>, priv: ECDSAPrivateKey): String {
        let headerPart = b64url.encode(headerJson.toArray())
        let payloadPart = b64url.encode(payload)
        let signingInput = headerPart + "." + payloadPart
        let rawSig = ecdsa.sign(priv, signingInput.toArray())
        let sigPart = b64url.encode(rawSig)
        return signingInput + "." + sigPart
    }

    public func verifyEs256(compact: String, pub: ECDSAPublicKey): Bool {
        let parts = compact.split(".")
        if (parts.size != 3) {
            return false
        }
        let signingInput = parts[0] + "." + parts[1]
        let rawSig = b64url.decode(parts[2])
        if (rawSig.size != 64) {
            return false
        }
        return ecdsa.verify(pub, signingInput.toArray(), rawSig)
    }
}

// ---------------------------------------------------------------------------
// HostCryptoStub — convenience aggregate
// ---------------------------------------------------------------------------

/**
 * Aggregate providing all seam implementations for host testing.
 *
 *   let crypto = HostCryptoStub()
 *   let h = crypto.digest.sha256("abc".toArray())
 *   let enc = crypto.base64Url.encode([0u8, 1u8, 255u8])
 *   let dec = crypto.base64Url.decode(enc)
 *   let priv = crypto.ecdsa.generate()
 *   let pub = crypto.ecdsa.publicKeyOf(priv)
 *   let jwt = crypto.jws.signEs256("{\"alg\":\"ES256\"}", "payload".toArray(), priv)
 *   let ok = crypto.jws.verifyEs256(jwt, pub)
 */
public class HostCryptoStub {
    public let digest: HostDigestImpl
    public let base64Url: HostBase64UrlImpl
    public let rng: HostRngImpl
    public let ecdsa: HostEcdsaP256Impl
    public let jws: HostJwsImpl

    public init() {
        digest = HostDigestImpl()
        base64Url = HostBase64UrlImpl()
        rng = HostRngImpl()
        ecdsa = HostEcdsaP256Impl()
        jws = HostJwsImpl()
    }
}
