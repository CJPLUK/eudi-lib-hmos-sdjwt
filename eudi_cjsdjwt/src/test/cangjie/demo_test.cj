/**
 * demo_test.cj
 *
 * Unit test for the runSdJwtDemo public function in the HAR root package.
 *
 * Verifies that runSdJwtDemo() completes the full issue → present → verify
 * pipeline and returns a string containing the success marker "OK".
 */
package ohos_app_cangjie_eudi_cjsdjwt_local_test

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjsdjwt.runSdJwtDemo

@Test
class RunSdJwtDemoTest {

    @TestCase
    func testRunSdJwtDemo_returnsOk(): Unit {
        let result = runSdJwtDemo()
        @Expect(result.startsWith("OK:"), true)
    }

    @TestCase
    func testRunSdJwtDemo_containsVerifyPass(): Unit {
        let result = runSdJwtDemo()
        @Expect(result.contains("verifyIssuance=PASS"), true)
    }

    @TestCase
    func testRunSdJwtDemo_containsPresentationPass(): Unit {
        let result = runSdJwtDemo()
        @Expect(result.contains("verifyPresentation=PASS"), true)
    }
}
