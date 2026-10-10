// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import XCTest
@testable import CredentialModel

final class L10nTests: XCTestCase {
    func testPreferredLanguageSelection() {
        XCTAssertEqual(L10n.select(preferredLanguages: ["zh-Hans-CN"]), .chinese)
        XCTAssertEqual(L10n.select(preferredLanguages: ["en-GB"]), .english)
        XCTAssertEqual(L10n.select(preferredLanguages: ["ja", "zh"]), .chinese)
        XCTAssertEqual(L10n.select(preferredLanguages: ["ja"]), .english)
        XCTAssertEqual(L10n.select(preferredLanguages: []), .english)
        XCTAssertEqual(L10n.select(preferredLanguages: ["en-GB", "zh-Hans"]), .english)
        XCTAssertEqual(L10n.select(preferredLanguages: ["zh-Hans", "en-GB"]), .chinese)
        XCTAssertEqual(L10n.select(preferredLanguages: [" EN_us \n"]), .english)
        XCTAssertEqual(L10n.select(preferredLanguages: ["zho", "english"]), .english)
    }

    func testEnvironmentOverride() {
        XCTAssertEqual(L10n.select(preferredLanguages: ["en"], override: "zh"), .chinese)
        XCTAssertEqual(L10n.select(preferredLanguages: ["zh"], override: "en"), .english)
        XCTAssertEqual(L10n.select(preferredLanguages: ["en"], override: " ZH_hans "), .chinese)
        XCTAssertEqual(L10n.select(preferredLanguages: ["zh"], override: "ja"), .chinese)
        XCTAssertEqual(L10n.select(preferredLanguages: ["zh"], override: ""), .chinese)
        XCTAssertEqual(L10n.language, L10n.select(preferredLanguages: Locale.preferredLanguages,
                                                override: ProcessInfo.processInfo.environment["MYGO_VAULTWARDEN_LANG"]))
    }

    func testTranslationsAndFormatting() {
        XCTAssertEqual(L10n.t("autofill.cancel", language: .chinese), "取消")
        XCTAssertEqual(L10n.t("autofill.cancel", language: .english), "Cancel")
        XCTAssertEqual(L10n.t("uncatalogued", language: .english), "uncatalogued")
        XCTAssertEqual(L10n.t("uncatalogued", language: .chinese), "uncatalogued")
        let format = "snapshot.err_keychain"
        XCTAssertEqual(String(format: L10n.t(format, language: .english), Int32(-50)),
                       "System Keychain operation failed (-50).")
        XCTAssertEqual(String(format: L10n.t(format, language: .chinese), Int32(-50)),
                       "系统钥匙串操作失败（-50）。")
    }

    func testCatalogEntries() throws {
        let format = try NSRegularExpression(pattern: #"%%|%(?:\d+\$)?[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|ll|[hljztL])?[diuoxXfFeEgGaAcCsSpn@]"#)
        func placeholders(_ text: String) -> [String] {
            format.matches(in: text, range: NSRange(text.startIndex..., in: text)).map {
                String(text[Range($0.range, in: text)!])
            }.filter { $0 != "%%" }
        }
        XCTAssertFalse(L10n.messages.isEmpty)
        for (key, message) in L10n.messages {
            XCTAssertNotNil(key.range(of: #"^[a-z][a-z0-9]*(\.[a-z0-9]+(_[a-z0-9]+)*)+$"#, options: .regularExpression), key)
            XCTAssertTrue(["autofill", "bridge", "snapshot", "auth"].contains(String(key.split(separator: ".")[0])), key)
            XCTAssertFalse(message.zh.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, key)
            XCTAssertFalse(message.en.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, key)
            XCTAssertNil(message.en.range(of: #"\p{sc=Han}"#, options: .regularExpression), key)
            XCTAssertEqual(placeholders(message.zh), placeholders(message.en), key)
            XCTAssertEqual(L10n.t(key, language: .chinese), message.zh, key)
            XCTAssertEqual(L10n.t(key, language: .english), message.en, key)
        }
    }

    func testCatalogCoversAllLiteralCallSites() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let call = try NSRegularExpression(pattern: #"L10n\s*\.\s*t\s*\(\s*"([^"\n]*)""#)
        let chineseText = try NSRegularExpression(pattern: #"zh: "(?:[^"\\]|\\.)*""#)
        var used = Set<String>()
        let files = try XCTUnwrap(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil))
        for case let url as URL in files {
            if [".build", "Tests"].contains(url.lastPathComponent) { files.skipDescendants(); continue }
            guard url.pathExtension == "swift" else { continue }
            let source = try String(contentsOf: url, encoding: .utf8)
            for match in call.matches(in: source, range: NSRange(source.startIndex..., in: source)) {
                let key = String(source[Range(match.range(at: 1), in: source)!])
                used.insert(key)
                XCTAssertNotNil(L10n.messages[key], "Missing translation in \(url.lastPathComponent): \(key)")
                XCTAssertNil(key.range(of: #"\p{sc=Han}"#, options: .regularExpression), key)
            }
            // Only the catalog's explicitly labelled Chinese values may contain Han text.
            let outsideChineseText = url == root.appendingPathComponent("Shared/SnapshotTypes.swift")
                ? chineseText.stringByReplacingMatches(in: source, range: NSRange(source.startIndex..., in: source), withTemplate: "")
                : source
            XCTAssertNil(outsideChineseText.range(of: #"\p{sc=Han}"#, options: .regularExpression), url.path)
        }
        XCTAssertFalse(used.isEmpty)
        XCTAssertEqual(used, Set(L10n.messages.keys), "Catalog entries must have production call sites")
    }
}
