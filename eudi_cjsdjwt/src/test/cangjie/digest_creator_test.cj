/**
 * digest_creator_test.cj
 *
 * Unit tests for DigestCreator using known disclosure→digest vectors.
 *
 * Test vectors sourced from the iOS reference implementation tests
 * (Tests/Issuance/DigestTest.swift in eudi-lib-sdjwt-swift):
 *
 * Vector 1 (family_name with spaces):
 *   disclosure = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
 *   (decodes to: ["6qMQvRL5haj", "family_name", "Möbius"] with spaces after commas)
 *   sha-256 digest = "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY"
 *
 * Vector 2 (array element, country code):
 *   disclosure = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0"
 *   (decodes to: ["lklxF5jMYlGTPUovMNIvCA", "FR"] with space after comma)
 *   sha-256 digest = "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"
 *
 * Both vectors verified against the eudi-lib-sdjwt-swift iOS implementation
 * (Tests/Issuance/DigestTest.swift, testDigestCreationg_* methods).
 *
 * The HostCryptoStub provides the seam implementations used in all tests.
 */
package ohos_app_cangjie_eudi_cjsdjwt_local_test

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*

@Test
class DigestCreatorTest {

    // ----------------------------------------------------------------
    // Known disclosure→digest vectors from iOS reference implementation
    // ----------------------------------------------------------------

    @TestCase
    func testVector_familyName_sha256(): Unit {
        let crypto = HostCryptoStub()
        let dc = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha256
        )
        let disclosure = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
        let expected = "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY"
        let result = dc.hashAndBase64Encode(disclosure)
        @Expect(result, expected)
    }

    @TestCase
    func testVector_arrayElement_countryCode_sha256(): Unit {
        let crypto = HostCryptoStub()
        let dc = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha256
        )
        let disclosure = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0"
        let expected = "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"
        let result = dc.hashAndBase64Encode(disclosure)
        @Expect(result, expected)
    }

    @TestCase
    func testAlgIdentifier_sha256(): Unit {
        let crypto = HostCryptoStub()
        let dc = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha256
        )
        @Expect(dc.algIdentifier(), "sha-256")
    }

    @TestCase
    func testAlgIdentifier_sha384(): Unit {
        let crypto = HostCryptoStub()
        let dc = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha384
        )
        @Expect(dc.algIdentifier(), "sha-384")
    }

    @TestCase
    func testAlgIdentifier_sha512(): Unit {
        let crypto = HostCryptoStub()
        let dc = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha512
        )
        @Expect(dc.algIdentifier(), "sha-512")
    }

    @TestCase
    func testSha384_producesNonEmptyDigest(): Unit {
        let crypto = HostCryptoStub()
        let dc = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha384
        )
        let disclosure = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
        let result = dc.hashAndBase64Encode(disclosure)
        @Expect(result.size > 0, true)
    }

    @TestCase
    func testSha512_producesNonEmptyDigest(): Unit {
        let crypto = HostCryptoStub()
        let dc = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha512
        )
        let disclosure = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
        let result = dc.hashAndBase64Encode(disclosure)
        @Expect(result.size > 0, true)
    }

    @TestCase
    func testDifferentAlgorithmsProduceDifferentDigests(): Unit {
        let crypto = HostCryptoStub()
        let dc256 = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha256
        )
        let dc384 = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha384
        )
        let disclosure = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
        let d256 = dc256.hashAndBase64Encode(disclosure)
        let d384 = dc384.hashAndBase64Encode(disclosure)
        @Expect(d256 != d384, true)
    }

    @TestCase
    func testSameDisclosureSameDigest(): Unit {
        let crypto = HostCryptoStub()
        let dc = DigestCreator(
            digest: crypto.digest,
            base64Url: crypto.base64Url,
            algorithm: HashingAlgorithmIdentifier.Sha256
        )
        let disclosure = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
        let d1 = dc.hashAndBase64Encode(disclosure)
        let d2 = dc.hashAndBase64Encode(disclosure)
        @Expect(d1, d2)
    }
}
