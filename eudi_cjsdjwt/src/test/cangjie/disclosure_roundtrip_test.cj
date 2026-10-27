/**
 * disclosure_roundtrip_test.cj
 *
 * Unit tests for Disclosure.encodeWith / decodeWith round-trip correctness.
 *
 * These tests cover both the encode and decode paths:
 *   - getSalt(), getName(), getValue() must return the original values after
 *     encodeWith(b64) -> decodeWith(encoded, b64).
 *   - The raw JSON produced by encodeWith must be byte-for-byte RFC 8259
 *     compliant (verified by base64url-decoding the token and inspecting the
 *     JSON string directly).
 *
 * Bug fixed: HI-SDJWT-001 — on aarch64-linux-ohos, Rune.toString() returned
 * decimal ASCII code points instead of the character string (e.g. "115" for
 * 's'), causing getSalt()/getName() to return concatenated decimal codes like
 * "116101115116451159710811645979899" instead of "test-salt-abc".
 *
 * Fix: escapeJsonString, hexEscape, runeSliceToString, and
 * parseJsonStringElement all use Rune.intoUtf8Array + String.fromUtf8
 * throughout the encode and decode paths.
 *
 * Note: whether individual round-trip tests pass on pre-fix code depends on
 * the platform behaviour of Rune.toString().  The encode-side JSON conformance
 * test (EncodeJsonConformanceTest) provides a direct, deterministic check of
 * the encode output independent of round-trip self-consistency.
 * Authoritative regression judgement for device behaviour uses E2E tests.
 */
package ohos_app_cangjie_eudi_cjsdjwt_local_test

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*

// ---------------------------------------------------------------------------
// Three-element (object-property) disclosure round-trips
// ---------------------------------------------------------------------------

@Test
class DisclosureThreeElementRoundTripTest {

    /**
     * Basic ASCII salt and name — the canonical repro case for HI-SDJWT-001.
     *
     * On aarch64-linux-ohos with the pre-fix Rune.toString() behaviour,
     * getSalt() may have returned "116101115116451159710811645979899"
     * (decimal ASCII codes for "test-salt-abc") instead of "test-salt-abc".
     * Host behaviour depends on the platform's Rune.toString() implementation.
     */
    @TestCase
    func testThreeElement_asciiSaltAndName_roundTrip(): Unit {
        let b64 = HostBase64UrlImpl()
        let orig = Disclosure(salt: "test-salt-abc", name: "given_name", value: "\"Alice\"")
        let encoded = orig.encodeWith(b64)
        let decoded = Disclosure.decodeWith(encoded, b64)
        @Expect(decoded.getSalt(), "test-salt-abc")
        match (decoded.getName()) {
            case Some(n) => @Expect(n, "given_name")
            case None => @Expect(false)
        }
        @Expect(decoded.getValue(), "\"Alice\"")
    }

    /**
     * Short single-character salt and name — the compact codec failure case.
     *
     * On aarch64-linux-ohos with the pre-fix Rune.toString() behaviour,
     * getSalt() may have returned "11549" (115=s, 49=1) for "s1".
     * Host behaviour depends on the platform's Rune.toString() implementation.
     */
    @TestCase
    func testThreeElement_shortSalt_roundTrip(): Unit {
        let b64 = HostBase64UrlImpl()
        let orig = Disclosure(salt: "s1", name: "sub", value: "\"user42\"")
        let encoded = orig.encodeWith(b64)
        let decoded = Disclosure.decodeWith(encoded, b64)
        @Expect(decoded.getSalt(), "s1")
        match (decoded.getName()) {
            case Some(n) => @Expect(n, "sub")
            case None => @Expect(false)
        }
        @Expect(decoded.getValue(), "\"user42\"")
    }

    /**
     * Numeric JSON value — getValue() must survive decode unchanged.
     *
     * On aarch64-linux-ohos with the pre-fix Rune.toString() behaviour,
     * getSalt() may have returned "1101171094511597108116" (ASCII for "num-salt").
     * Host behaviour depends on the platform's Rune.toString() implementation.
     */
    @TestCase
    func testThreeElement_numericValue_roundTrip(): Unit {
        let b64 = HostBase64UrlImpl()
        let orig = Disclosure(salt: "num-salt", name: "age", value: "42")
        let encoded = orig.encodeWith(b64)
        let decoded = Disclosure.decodeWith(encoded, b64)
        @Expect(decoded.getSalt(), "num-salt")
        match (decoded.getName()) {
            case Some(n) => @Expect(n, "age")
            case None => @Expect(false)
        }
        @Expect(decoded.getValue(), "42")
    }

    /**
     * Boolean JSON value.
     *
     * On aarch64-linux-ohos with the pre-fix Rune.toString() behaviour,
     * getSalt() may have returned "981111111084511597108116" (ASCII for "bool-salt"),
     * getName() may have returned "118101114105102105101100" (ASCII for "verified").
     * Host behaviour depends on the platform's Rune.toString() implementation.
     */
    @TestCase
    func testThreeElement_boolValue_roundTrip(): Unit {
        let b64 = HostBase64UrlImpl()
        let orig = Disclosure(salt: "bool-salt", name: "verified", value: "true")
        let encoded = orig.encodeWith(b64)
        let decoded = Disclosure.decodeWith(encoded, b64)
        @Expect(decoded.getSalt(), "bool-salt")
        match (decoded.getName()) {
            case Some(n) => @Expect(n, "verified")
            case None => @Expect(false)
        }
        @Expect(decoded.getValue(), "true")
    }

    /**
     * Non-ASCII (multi-byte UTF-8) salt — "Möbius".
     * Tests that the UTF-8 byte accumulation in runeSliceToString and
     * parseJsonStringElement correctly reconstructs multi-byte characters.
     * This case would also have been broken pre-fix (only worse than ASCII).
     */
    @TestCase
    func testThreeElement_nonAsciiSalt_roundTrip(): Unit {
        let b64 = HostBase64UrlImpl()
        let orig = Disclosure(salt: "Möbius", name: "label", value: "\"test\"")
        let encoded = orig.encodeWith(b64)
        let decoded = Disclosure.decodeWith(encoded, b64)
        @Expect(decoded.getSalt(), "Möbius")
        match (decoded.getName()) {
            case Some(n) => @Expect(n, "label")
            case None => @Expect(false)
        }
        @Expect(decoded.getValue(), "\"test\"")
    }

    /**
     * All three fields assertion in one test — mirrors the E2E
     * ModelDisclosureRoundTripE2EUT.testThreeElement_encodeDecodeRoundTrip.
     */
    @TestCase
    func testThreeElement_allFieldsAsserted_roundTrip(): Unit {
        let b64 = HostBase64UrlImpl()
        let salt = "test-salt-abc"
        let name = "given_name"
        let value = "\"Alice\""
        let orig = Disclosure(salt: salt, name: name, value: value)
        let encoded = orig.encodeWith(b64)
        let decoded = Disclosure.decodeWith(encoded, b64)
        // All three fields must match
        @Expect(decoded.getSalt(), salt)
        match (decoded.getName()) {
            case Some(n) => @Expect(n, name)
            case None => @Expect(false)
        }
        @Expect(decoded.getValue(), value)
        @Expect(decoded.isObjectClaim())
    }
}

// ---------------------------------------------------------------------------
// Two-element (array-element) disclosure round-trips
// ---------------------------------------------------------------------------

@Test
class DisclosureTwoElementRoundTripTest {

    /**
     * Array-element disclosure — salt only (no name field).
     *
     * On aarch64-linux-ohos with the pre-fix Rune.toString() behaviour,
     * getSalt() may have returned "9711411497121451159710811645120121122"
     * (ASCII for "array-salt-xyz").
     * Host behaviour depends on the platform's Rune.toString() implementation.
     */
    @TestCase
    func testTwoElement_asciiSalt_roundTrip(): Unit {
        let b64 = HostBase64UrlImpl()
        let orig = Disclosure(salt: "array-salt-xyz", value: "\"countryCode\"")
        let encoded = orig.encodeWith(b64)
        let decoded = Disclosure.decodeWith(encoded, b64)
        @Expect(decoded.getSalt(), "array-salt-xyz")
        @Expect(decoded.getName().isNone())
        @Expect(decoded.getValue(), "\"countryCode\"")
        @Expect(!decoded.isObjectClaim())
    }

    /**
     * Two-element with numeric value.
     */
    @TestCase
    func testTwoElement_numericValue_roundTrip(): Unit {
        let b64 = HostBase64UrlImpl()
        let orig = Disclosure(salt: "arr-s", value: "99")
        let encoded = orig.encodeWith(b64)
        let decoded = Disclosure.decodeWith(encoded, b64)
        @Expect(decoded.getSalt(), "arr-s")
        @Expect(decoded.getName().isNone())
        @Expect(decoded.getValue(), "99")
    }
}

// ---------------------------------------------------------------------------
// Encoding idempotence: encodeWith output must not change on second encode
// ---------------------------------------------------------------------------

@Test
class DisclosureEncodeIdempotenceTest {

    /**
     * Encoding the same disclosure twice must produce the same token.
     * (Guard against any state mutation in the encoder.)
     */
    @TestCase
    func testEncodeIdempotence_sameOutput(): Unit {
        let b64 = HostBase64UrlImpl()
        let orig = Disclosure(salt: "idempotent-salt", name: "claim", value: "\"value\"")
        let enc1 = orig.encodeWith(b64)
        let enc2 = orig.encodeWith(b64)
        @Expect(enc1, enc2)
    }

    /**
     * Decode of a decoded disclosure must equal the first decode.
     * (decode(encode(decode(encode(x)))) == decode(encode(x)))
     */
    @TestCase
    func testDecodeOfDecode_stable(): Unit {
        let b64 = HostBase64UrlImpl()
        let orig = Disclosure(salt: "double-salt", name: "field", value: "\"hello\"")
        let enc1 = orig.encodeWith(b64)
        let dec1 = Disclosure.decodeWith(enc1, b64)
        let enc2 = dec1.encodeWith(b64)
        let dec2 = Disclosure.decodeWith(enc2, b64)
        @Expect(dec2.getSalt(), orig.getSalt())
        match (dec2.getName()) {
            case Some(n) => @Expect(n, "field")
            case None => @Expect(false)
        }
        @Expect(dec2.getValue(), orig.getValue())
    }
}

// ---------------------------------------------------------------------------
// Encode-side JSON conformance: verify raw JSON bytes match RFC 8259
// ---------------------------------------------------------------------------

/**
 * White-box verification of escapeJsonString and hexEscape via the encode path.
 *
 * Strategy: encode a Disclosure, base64url-decode the token back to raw bytes,
 * convert to a String, and assert the JSON is byte-for-byte RFC 8259 compliant.
 *
 * These tests are deterministic on both host and device: the expected string
 * is derived from the RFC 8259 escaping rules, not from any previous output.
 * They detect both the pre-fix Rune.toString() decimal-code bug and any future
 * regression in the encode path.
 */
@Test
class EncodeJsonConformanceTest {

    /**
     * Name containing multi-byte UTF-8 (M + o-umlaut U+00F6 + bius),
     * a line-feed (U+000A), and SOH control character (U+0001).
     *
     * RFC 8259 §7 requires:
     *   - code points >= U+0020 (except backslash and quote) pass through
     *     as their UTF-8 byte encoding
     *   - code points < U+0020 are serialised as \uXXXX (lowercase hex)
     *
     * Escaping trace for name = M + o-umlaut + b-i-u-s + LF + SOH:
     *   M       (U+004D >= U+0020) -> UTF-8 byte 0x4D
     *   o-umlaut(U+00F6 >= U+0020) -> UTF-8 bytes 0xC3 0xB6
     *   b,i,u,s (ASCII >= U+0020)  -> UTF-8 bytes as-is
     *   LF      (U+000A < U+0020)  -> 6-byte ASCII sequence: \u000a
     *   SOH     (U+0001 < U+0020)  -> 6-byte ASCII sequence: \u0001
     *
     * Expected raw JSON: ["s","Mo-umlaut-bius\u000a\u0001","v"]
     * where o-umlaut is the literal two-byte UTF-8 encoding of U+00F6.
     */
    @TestCase
    func testEncode_unicodeAndControlChars_rfc8259Compliant(): Unit {
        let b64 = HostBase64UrlImpl()
        // name: M + o-umlaut (U+00F6) + bius + LF + SOH (U+0001)
        let name = "M\u{00F6}bius\n\u{0001}"
        let orig = Disclosure(salt: "s", name: name, value: "\"v\"")
        let encoded = orig.encodeWith(b64)
        let jsonBytes = b64.decode(encoded)
        let jsonStr = String.fromUtf8(jsonBytes)
        // expected: ["s","Mo-umlaut-bius\u000a\u0001","v"]
        // \\u000a in Cangjie literal = 2 chars: backslash + 'u000a' literal text
        let expected = "[\"s\",\"M\u{00F6}bius\\u000a\\u0001\",\"v\"]"
        @Expect(jsonStr, expected)
    }

    /**
     * Name containing a backslash followed by a double-quote.
     *
     * RFC 8259 §7:
     *   backslash (U+005C) -> two-byte sequence: backslash backslash
     *   double-quote (U+0022) -> two-byte sequence: backslash double-quote
     *
     * name input: 2 codepoints: backslash then double-quote
     * Expected raw JSON name field (6 bytes incl. surrounding quotes):
     *   double-quote  backslash backslash  backslash double-quote  double-quote
     * Full expected raw JSON: ["s","\\\"" ,"v"]
     *   (i.e. the 4 chars between the outer double-quotes are: \ \ \ ")
     */
    @TestCase
    func testEncode_backslashAndQuote_rfc8259Compliant(): Unit {
        let b64 = HostBase64UrlImpl()
        // one backslash + one double-quote as the name
        let name = "\\" + "\""
        let orig = Disclosure(salt: "s", name: name, value: "\"v\"")
        let encoded = orig.encodeWith(b64)
        let jsonBytes = b64.decode(encoded)
        let jsonStr = String.fromUtf8(jsonBytes)
        // raw JSON: ["s","\\\"","v"]
        // name field in raw JSON has 4 bytes between outer quotes: \ \ \ "
        // Cangjie literal: each \ -> \\ and each " -> \"
        // So 3 raw backslashes = 6 literal chars: \\\\\\
        // followed by 1 raw double-quote = 2 literal chars: \"
        let expected = "[\"s\",\"\\\\\\\"\",\"v\"]"
        @Expect(jsonStr, expected)
    }
}
