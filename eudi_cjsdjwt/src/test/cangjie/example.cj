/**
 * Created on 2025/2/26
 */
package ohos_app_cangjie_eudi_cjsdjwt_local_test

import std.unittest.*
import std.unittest.testmacro.*

func unittest() {
    let a = "abc"
    let b = "b"
    @Expect(a.contains(b))
    @Expect(a, a)
}