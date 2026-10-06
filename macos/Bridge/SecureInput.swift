// SPDX-License-Identifier: GPL-3.0-only
import AppKit

// Accessed only on the AppKit main thread. Secrets never enter MyGo's text editor.
private enum SecureInputState {
    static var alert: NSAlert?
    static var field: NSSecureTextField?
    static var cancelled = false
}

@_cdecl("mygo_secure_input")
public func mygoSecureInput(_ kind: Int32, _ detail: UnsafePointer<CChar>?,
                            _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int) -> Int32 {
    guard kind == 0 || kind == 1, let detail, let output, capacity >= 8192 else { return -2 }
    let context = String(cString: detail)
    guard context.utf8.count <= 4096 else { return -2 }
    let show: () -> Int32 = {
        guard SecureInputState.alert == nil else { return -2 }
        let alert = NSAlert()
        alert.messageText = kind == 0 ? "输入主密码" : "输入 TOTP 验证码"
        alert.informativeText = context
        alert.addButton(withTitle: "继续")
        alert.addButton(withTitle: "取消")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 380, height: 28))
        field.placeholderString = kind == 0 ? "主密码只用于本次登录" : "6 位验证码"
        field.setAccessibilityLabel(kind == 0 ? "主密码" : "TOTP 验证码")
        alert.accessoryView = field
        alert.window.initialFirstResponder = field
        if let editor = alert.window.fieldEditor(true, for: field) as? NSTextView { editor.allowsUndo = false }
        SecureInputState.alert = alert; SecureInputState.field = field; SecureInputState.cancelled = false
        defer {
            field.stringValue = ""
            field.currentEditor()?.undoManager?.removeAllActions()
            alert.window.orderOut(nil)
            SecureInputState.alert = nil; SecureInputState.field = nil
        }
        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        guard response == .alertFirstButtonReturn, !SecureInputState.cancelled else { return -1 }
        var bytes = Data(field.stringValue.utf8)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        guard !bytes.isEmpty, bytes.count <= (kind == 0 ? 8192 : 6) else { return -2 }
        bytes.copyBytes(to: output, count: bytes.count)
        return Int32(bytes.count)
    }
    return Thread.isMainThread ? show() : DispatchQueue.main.sync(execute: show)
}

@_cdecl("mygo_cancel_secure_input")
public func mygoCancelSecureInput() {
    DispatchQueue.main.async {
        guard SecureInputState.alert != nil else { return }
        SecureInputState.cancelled = true
        SecureInputState.field?.stringValue = ""
        SecureInputState.field?.currentEditor()?.undoManager?.removeAllActions()
        NSApp.abortModal()
    }
}
