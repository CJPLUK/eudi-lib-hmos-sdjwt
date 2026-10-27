package ohos_app_cangjie_entry.page
import kit.ArkUI.*
import ohos.arkui.state_macro_manage.Entry
import ohos.arkui.state_macro_manage.Component
import ohos.arkui.state_macro_manage.State

import ohos_app_cangjie_eudi_cjsdjwt.runSdJwtDemo

@Entry
@Component
public class EntryView {
    @State
    var resultText: String = "Press the button to run SD-JWT demo"

    func build() {
        Column {
            Button("Run SD-JWT Demo")
                .onClick({
                    evt => this.resultText = runSdJwtDemo()
                })
                .fontSize(18)
                .width(80.percent)
                .height(50.vp)
                .margin(top: 40.vp)
            Text(this.resultText)
                .fontSize(14)
                .width(90.percent)
                .margin(top: 24.vp)
        }
        .width(100.percent)
        .height(100.percent)
        .justifyContent(FlexAlign.Start)
        .padding(top: 80.vp)
    }
}
