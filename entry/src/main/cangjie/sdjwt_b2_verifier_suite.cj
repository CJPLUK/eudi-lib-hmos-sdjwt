/**
 * sdjwt_b2_verifier_suite.cj
 *
 * B2 (verifier half) regression suite: recursive JSON-tree claim
 * reconstruction.
 *
 * Background
 * ----------
 * The old verifier produced a FLAT HashMap<String,String> from
 * reconstructClaims: it only copied a whitelist of top-level claims plus
 * add(name, value) for named disclosures.  It dropped array-element (un-named)
 * disclosures, never recursed into already-disclosed objects/arrays, and never
 * filled the {"...": digest} array markers — so nested / array structure could
 * not be reconstructed at all.
 *
 * The fix (mirroring iOS SdJwtUtils.resolveNode) adds
 * SdJwtVerifier → DisclosuresVerifier.verify → recreateClaimsTree, a recursive
 * resolver that:
 *   - object: replaces "_sd" digests with [salt,name,value] claims, strips
 *     "_sd"/"_sd_alg", recurses into children;
 *   - array : replaces {"...": digest} with the [salt,value] element, recurses,
 *     and OMITS markers whose disclosure was not presented;
 *   - recurses into the injected (disclosed) values too (recursive disclosure).
 * The serialised tree is surfaced via VerificationResult.recreatedClaims.
 *
 * These tests are end-to-end round-trips: issue a credential with nested /
 * array selectively-disclosable structure (the factory issuer half is already
 * fixed so nested array elements encode), verify, then re-parse
 * VerificationResult.recreatedClaims with stdx.encoding.json and assert the
 * nested values are correctly restored — something the old flat map could not
 * do.  A partial-disclosure case proves the "undisclosed → omit / absent"
 * semantics.
 *
 * Package: ohos_app_cangjie_entry (entry unittest engine).
 */
package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.*

import stdx.encoding.json.*

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.digest.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.factory.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.issuer.*
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.verifier.*

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func b2MakeIssuer(crypto: HostCryptoStub, alg: HashingAlgorithmIdentifier): SdJwtIssuer {
    let dc = DigestCreator(digest: crypto.digest, base64Url: crypto.base64Url, algorithm: alg)
    let factory = SdJwtFactory(
        digestCreator: dc, base64Url: crypto.base64Url, rng: crypto.rng, decoyCount: 0
    )
    return SdJwtIssuer(
        jws: crypto.jws, base64Url: crypto.base64Url, digest: crypto.digest, factory: factory
    )
}

/** Parse the recreated-claims JSON string from a successful VerificationResult. */
func b2ParseRecreated(result: VerificationResult): JsonObject {
    match (result.recreatedClaims) {
        case Some(jsonStr) =>
            let v = JsonValue.fromStr(jsonStr)
            match (v as JsonObject) {
                case Some(obj) => return obj
                case None => throw Exception("recreatedClaims root is not a JSON object: " + jsonStr)
            }
        case None => throw Exception("VerificationResult carried no recreatedClaims")
    }
}

/** Get a nested JsonObject field, or throw. */
func b2GetObject(obj: JsonObject, key: String): JsonObject {
    match (obj.get(key)) {
        case Some(v) =>
            match (v as JsonObject) {
                case Some(o) => return o
                case None => throw Exception("field '" + key + "' is not an object")
            }
        case None => throw Exception("missing field '" + key + "'")
    }
}

/** Get a nested JsonArray field, or throw. */
func b2GetArray(obj: JsonObject, key: String): JsonArray {
    match (obj.get(key)) {
        case Some(v) =>
            match (v as JsonArray) {
                case Some(a) => return a
                case None => throw Exception("field '" + key + "' is not an array")
            }
        case None => throw Exception("missing field '" + key + "'")
    }
}

/** Read a string-valued object field; None if absent or not a string. */
func b2OptString(obj: JsonObject, key: String): Option<String> {
    match (obj.get(key)) {
        case Some(v) =>
            match (v as JsonString) {
                case Some(s) => return Some(s.getValue())
                case None => return None
            }
        case None => return None
    }
}

/** Read element idx of an array as a JsonObject, or throw. */
func b2ArrayObjectAt(arr: JsonArray, idx: Int64): JsonObject {
    match (arr.get(idx)) {
        case Some(v) =>
            match (v as JsonObject) {
                case Some(o) => return o
                case None => throw Exception("array element is not an object")
            }
        case None => throw Exception("array index out of range")
    }
}

@Test
class SdjwtB2VerifierTest {

    // -----------------------------------------------------------------------
    // Case 1 — nested OBJECT reconstruction:
    //   address: SdObject({ locality: Sd("Beijing"), country: Plain("CN") })
    // After verify, the recreated tree must contain address.locality == "Beijing"
    // and the always-present plain address.country == "CN".  The flat map could
    // never have produced address.locality (it dropped into-object recursion).
    // -----------------------------------------------------------------------

    @TestCase
    func testNestedObjectClaim_recursivelyReconstructed(): Unit {
        let crypto = HostCryptoStub()
        let issuer = b2MakeIssuer(crypto, HashingAlgorithmIdentifier.Sha256)
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        var addr = HashMap<String, ClaimValue>()
        addr.add("locality", ClaimValue.Sd("\"Beijing\""))
        addr.add("country", ClaimValue.Plain("\"CN\""))

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("address", ClaimValue.SdObject(addr))

        let issued = issuer.issue(claims, priv).ok.getOrThrow()

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(issued, pub)
        @Expect(result.isOk(), true)

        let root = b2ParseRecreated(result)
        let addrObj = b2GetObject(root, "address")
        // locality was selectively disclosed and must be resolved back in.
        @Expect(b2OptString(addrObj, "locality"), Some("Beijing"))
        // plain sub-claim is always present.
        @Expect(b2OptString(addrObj, "country"), Some("CN"))
        // book-keeping keys must be stripped from the resolved object.
        @Expect(addrObj.containsKey("_sd"), false)
    }

    // -----------------------------------------------------------------------
    // Case 2 — nested object INSIDE an array element:
    //   nationalities: SdArray([ SdObject({ country: Sd("US") }) ])
    // After verify, recreated tree must yield nationalities[0].country == "US".
    // -----------------------------------------------------------------------

    @TestCase
    func testNestedObjectInArrayElement_recursivelyReconstructed(): Unit {
        let crypto = HostCryptoStub()
        let issuer = b2MakeIssuer(crypto, HashingAlgorithmIdentifier.Sha256)
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        var inner = HashMap<String, ClaimValue>()
        inner.add("country", ClaimValue.Sd("\"US\""))
        var arr = ArrayList<ClaimValue>()
        arr.add(ClaimValue.SdObject(inner))

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("nationalities", ClaimValue.SdArray(arr))

        let issued = issuer.issue(claims, priv).ok.getOrThrow()

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(issued, pub)
        @Expect(result.isOk(), true)

        let root = b2ParseRecreated(result)
        let nats = b2GetArray(root, "nationalities")
        @Expect(nats.size(), 1)
        let elem0 = b2ArrayObjectAt(nats, 0)
        @Expect(b2OptString(elem0, "country"), Some("US"))
        @Expect(elem0.containsKey("_sd"), false)
    }

    // -----------------------------------------------------------------------
    // Case 3 — selectively-disclosable ARRAY ELEMENT ({"...": d}) restoration:
    //   countries: SdArray([ Sd("FR"), Plain("DE") ])
    // Presenting BOTH → array == ["FR","DE"] (order: disclosed marker resolves
    // in place, plain element stays).
    // -----------------------------------------------------------------------

    @TestCase
    func testArrayElementDisclosure_resolvedInPlace(): Unit {
        let crypto = HostCryptoStub()
        let issuer = b2MakeIssuer(crypto, HashingAlgorithmIdentifier.Sha256)
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        var elements = ArrayList<ClaimValue>()
        elements.add(ClaimValue.Sd("\"FR\""))
        elements.add(ClaimValue.Plain("\"DE\""))

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("countries", ClaimValue.SdArray(elements))

        let issued = issuer.issue(claims, priv).ok.getOrThrow()

        // Verify the full (all-disclosure) issued credential.
        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(issued, pub)
        @Expect(result.isOk(), true)

        let root = b2ParseRecreated(result)
        let arr = b2GetArray(root, "countries")
        // Both elements present: the disclosed "FR" marker resolved + plain "DE".
        @Expect(arr.size(), 2)
        var sawFr = false
        var sawDe = false
        var i: Int64 = 0
        while (i < arr.size()) {
            match (arr.get(i)) {
                case Some(v) =>
                    match (v as JsonString) {
                        case Some(s) =>
                            if (s.getValue() == "FR") { sawFr = true }
                            if (s.getValue() == "DE") { sawDe = true }
                        case None => ()
                    }
                case None => ()
            }
            i = i + 1
        }
        @Expect(sawFr, true)
        @Expect(sawDe, true)
    }

    // -----------------------------------------------------------------------
    // Case 4 — partial disclosure (OMIT semantics).  Issue two top-level Sd
    // claims (given_name, family_name) plus a selectively-disclosable array
    // element; present ONLY family_name.  The recreated tree must:
    //   - contain family_name,
    //   - NOT contain given_name (object: undisclosed property simply absent),
    //   - drop the undisclosed array element (array: omitted, not null).
    // This is exactly what the old flat map could not express.
    // -----------------------------------------------------------------------

    @TestCase
    func testPartialDisclosure_undisclosedOmitted(): Unit {
        let crypto = HostCryptoStub()
        let issuer = b2MakeIssuer(crypto, HashingAlgorithmIdentifier.Sha256)
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        var countryElems = ArrayList<ClaimValue>()
        countryElems.add(ClaimValue.Sd("\"FR\""))   // selectively-disclosable array element

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("given_name", ClaimValue.Sd("\"Alice\""))
        claims.add("family_name", ClaimValue.Sd("\"Smith\""))
        claims.add("countries", ClaimValue.SdArray(countryElems))

        let issued = issuer.issue(claims, priv).ok.getOrThrow()

        // Select only the family_name disclosure to present.
        var toPresent = ArrayList<Disclosure>()
        var di: Int64 = 0
        while (di < issued.disclosures.size) {
            let d = issued.disclosures[di]
            match (d.getName()) {
                case Some(n) => if (n == "family_name") { toPresent.add(d) }
                case None => ()  // array-element disclosure (FR) intentionally NOT presented
            }
            di = di + 1
        }
        @Expect(toPresent.size, 1)

        let presented = issuer.presentation(issued, toPresent.toArray(), None).ok.getOrThrow()

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(presented, pub)
        @Expect(result.isOk(), true)

        let root = b2ParseRecreated(result)
        // Disclosed property present.
        @Expect(b2OptString(root, "family_name"), Some("Smith"))
        // Undisclosed object property absent.
        @Expect(root.containsKey("given_name"), false)
        // Undisclosed array element omitted → countries is an empty array.
        let arr = b2GetArray(root, "countries")
        @Expect(arr.size(), 0)
    }

    // -----------------------------------------------------------------------
    // Case 5 — backward compatibility: a simple top-level Sd claim still
    // verifies and the recreated tree contains it.  Confirms the new path does
    // not regress the ordinary flat case the previous reconstructClaims served.
    // -----------------------------------------------------------------------

    @TestCase
    func testTopLevelSdClaim_backwardCompatibleFlatCase(): Unit {
        let crypto = HostCryptoStub()
        let issuer = b2MakeIssuer(crypto, HashingAlgorithmIdentifier.Sha256)
        let priv = crypto.ecdsa.generate()
        let pub = crypto.ecdsa.publicKeyOf(priv)

        var claims = HashMap<String, ClaimValue>()
        claims.add("iss", ClaimValue.Plain("\"https://issuer.example.com\""))
        claims.add("doc_id", ClaimValue.Sd("\"ID123\""))

        let issued = issuer.issue(claims, priv).ok.getOrThrow()

        let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
        let result = verifier.verifyIssuance(issued, pub)
        @Expect(result.isOk(), true)

        let root = b2ParseRecreated(result)
        @Expect(b2OptString(root, "doc_id"), Some("ID123"))
        // Plain top-level claim retained.
        @Expect(b2OptString(root, "iss"), Some("https://issuer.example.com"))
    }
}
