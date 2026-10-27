package ohos_app_cangjie_eudi_cjsdjwt_local_test

import std.unittest.*
import std.unittest.testmacro.*

@Test
class TestExample00 {
    @TestCase
    func test00(): Unit {
        let a = "abc"
        let b = "b"
        @Expect(a.contains(b))
        @Expect(a, a)
    }
}
