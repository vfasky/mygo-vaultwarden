// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import XCTest
@testable import CredentialModel

final class SensitiveClipboardTests: XCTestCase {
    private final class FakeBoard: SensitivePasteboard {
        var changeCount = 0
        var owner: String?
        var value: String?
        func replace(secret: String, owner: String) -> Bool {
            changeCount += 1; self.owner = owner; value = secret; return true
        }
        func clear() { changeCount += 1; owner = nil; value = nil }
        func external(_ text: String) { changeCount += 1; owner = nil; value = text }
    }
    func testOldTimerCannotClearLaterCopyEvenSameValue() throws {
        let board = FakeBoard(), clipboard: SensitiveClipboard
        clipboard = SensitiveClipboard(board: board)
        let first = try clipboard.copy("fixture")
        let second = try clipboard.copy("fixture")
        XCTAssertNotEqual(first.owner, second.owner)
        clipboard.clear(ifOwned: first)
        XCTAssertEqual(board.value, "fixture")
        clipboard.clear(ifOwned: second)
        XCTAssertNil(board.value)
    }
    func testExternalSameAndDifferentValuesSurviveCleanup() throws {
        for text in ["fixture", "external"] {
            let board = FakeBoard(), clipboard: SensitiveClipboard
            clipboard = SensitiveClipboard(board: board)
            let receipt = try clipboard.copy("fixture")
            board.external(text)
            clipboard.clear(ifOwned: receipt)
            XCTAssertEqual(board.value, text)
            XCTAssertNil(clipboard.receipt)
        }
    }
    func testOwnerAndCountBothRequired() throws {
        let board = FakeBoard(), clipboard: SensitiveClipboard
        clipboard = SensitiveClipboard(board: board)
        _ = try clipboard.copy("fixture")
        board.changeCount += 1 // external writer copied all pasteboard types
        clipboard.clear()
        XCTAssertEqual(board.value, "fixture")
        _ = try clipboard.copy("fixture")
        board.owner = "other"
        clipboard.clear()
        XCTAssertEqual(board.value, "fixture")
    }
    func testLimitsAndExplicitRevocation() throws {
        let board = FakeBoard(), clipboard: SensitiveClipboard
        clipboard = SensitiveClipboard(board: board)
        XCTAssertThrowsError(try clipboard.copy(""))
        XCTAssertThrowsError(try clipboard.copy(String(repeating: "密", count: 22000)))
        XCTAssertEqual(board.changeCount, 0)
        _ = try clipboard.copy("fixture")
        clipboard.clear()
        XCTAssertNil(board.value)
    }
    func testNativeNamedPasteboard() throws {
        // Never use .general in tests; this name belongs solely to this test.
        let native = NSPasteboard(name: NSPasteboard.Name("org.mygo.tests.\(UUID().uuidString)"))
        defer { native.releaseGlobally() }
        let clipboard = SensitiveClipboard(board: NativeSensitivePasteboard(native))
        let first = try clipboard.copy("fixture")
        XCTAssertEqual(native.string(forType: .string), "fixture")
        XCTAssertNotNil(native.string(forType: NativeSensitivePasteboard.ownerType))
        native.clearContents()
        native.setString("fixture", forType: .string)
        clipboard.clear(ifOwned: first)
        XCTAssertEqual(native.string(forType: .string), "fixture")
        _ = try clipboard.copy("fixture-second")
        clipboard.clear()
        XCTAssertNil(native.string(forType: .string))
    }
}
