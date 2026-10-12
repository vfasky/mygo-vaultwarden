// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import CredentialModel

final class TOTPTests: XCTestCase {
    private func base32(_ input: String) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var result = "", buffer: UInt32 = 0, bits = 0
        for byte in input.utf8 {
            buffer = (buffer << 8) | UInt32(byte); bits += 8
            while bits >= 5 { bits -= 5; result.append(alphabet[Int((buffer >> bits) & 31)]) }
        }
        if bits > 0 { result.append(alphabet[Int((buffer << (5 - bits)) & 31)]) }
        while result.count % 8 != 0 { result.append("=") }
        return result
    }
    private func escape(_ input: String) -> String { input.addingPercentEncoding(withAllowedCharacters: .alphanumerics)! }
    func testRFC6238() throws {
        let times: [TimeInterval] = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
        let vectors = [
            ("SHA1", "12345678901234567890", ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]),
            ("SHA256", "12345678901234567890123456789012", ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"]),
            ("SHA512", "1234567890123456789012345678901234567890123456789012345678901234", ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"])
        ]
        for (algorithm, secret, codes) in vectors {
            for (index, time) in times.enumerated() {
                let input = "otpauth://totp/test?secret=\(base32(secret).replacingOccurrences(of: "=", with: ""))&algorithm=\(algorithm)&digits=8"
                let result = try TOTP.generate(input, now: Date(timeIntervalSince1970: time))
                XCTAssertEqual(result.code, codes[index]); XCTAssertEqual(result.validUntil.timeIntervalSince1970, (floor(time / 30) + 1) * 30)
            }
        }
    }
    func testSteamAndExpiry() throws {
        let now = Date(timeIntervalSince1970: 1672531200)
        XCTAssertEqual(try TOTP.generate("StEam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", now: now).code, "7W6CJ")
        let before = try TOTP.generate("wqiq25brkzycjvyp", now: now.addingTimeInterval(29.999999))
        XCTAssertEqual(before.code, "194506"); XCTAssertEqual(before.validUntil, now.addingTimeInterval(30))
        let after = try TOTP.generate("wqiq25brkzycjvyp", now: before.validUntil)
        XCTAssertNotEqual(after.code, before.code); XCTAssertEqual(after.validUntil, now.addingTimeInterval(60))
    }
    func testDisplayCompatibility() throws {
        let secret = base32("12345678901234567890123456789012")
        let chars = Array(secret)
        let grouped = (String(chars[0..<8]) + " \t" + String(chars[8..<16]) + "\r\n" + String(chars[16..<24]) + "\u{a0}" + String(chars[24...])).lowercased()
        let now = Date(timeIntervalSince1970: 59)
        for input in [
            "otpauth://totp/test?secret=\(escape(grouped))&algorithm=sha256&digits=8&image=https%3A%2F%2Fexample.invalid%2Ficon.png",
            "otpauth://totp/test?secret=\(escape(grouped.replacingOccurrences(of: "=", with: "")))&algorithm=SHA256&digits=8&image=a&image=b&future=anything"
        ] {
            let result = try TOTP.generate(input, now: now)
            XCTAssertEqual(result.code, "46119246"); XCTAssertEqual(result.validUntil.timeIntervalSince1970, 60)
        }
        for prefix in ["", "steam://"] {
            let want = try TOTP.generate(prefix + secret, now: now), got = try TOTP.generate(prefix + grouped, now: now)
            XCTAssertEqual(got.code, want.code); XCTAssertEqual(got.validUntil, want.validUntil)
        }
    }
    func testRecognizedParametersRemainStrict() {
        let secret = base32("public test vector"), now = Date(timeIntervalSince1970: 59)
        for query in ["&secret=" + secret, "&issuer=a&issuer=b", "&algorithm=SHA1&algorithm=SHA256", "&digits=6&digits=8", "&period=30&period=60", "&algorithm=MD5", "&algorithm=", "&digits=5", "&digits=9", "&period=0", "&period=301", "&period=not-a-number"] {
            XCTAssertThrowsError(try TOTP.generate("otpauth://totp/test?secret=\(escape(secret))" + query + "&image=ignored", now: now))
        }
        for secret in ["MZ======", "MY=====", "MY=======", "MY=AAAAA", "M!Y======", " \t\n"] {
            XCTAssertThrowsError(try TOTP.generate(secret, now: now))
        }
    }
    func testRejectsAmbiguousParameters() {
        for input in ["", "ABCD123", "PIUD1IS!EQYA=", "otpauth://hotp/a?secret=WQIQ25BRKZYCJVYP", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&algorithm=MD5", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&digits=10", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&period=0", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&period=301", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&secret=PIUDISEQYA", "otpauth://user@totp/a?secret=WQIQ25BRKZYCJVYP", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP#fragment"] {
            XCTAssertThrowsError(try TOTP.generate(input, now: Date(timeIntervalSince1970: 100)))
        }
    }
    func testLimitsAndCustomPeriod() throws {
        for time: TimeInterval in [-1, 253402300500, .infinity, .nan] {
            XCTAssertThrowsError(try TOTP.generate("MY======", now: Date(timeIntervalSince1970: time)))
        }
        let now = Date(timeIntervalSince1970: 59)
        for input in [String(repeating: "A", count: 4097), base32(String(repeating: "a", count: 1025)), "ß", "otpauth://totp/%zz?secret=MY", "otpauth://totp/a?secret=MY&image=%zz", "otpauth://totp/a?secret=MY&image=a;b"] {
            XCTAssertThrowsError(try TOTP.generate(input, now: now))
        }
        for input in ["otpauth://totp:/a?secret=MY", "otpauth://%74otp/a?secret=MY", "otpauth://totp/a?secret=MY&digits=+6", "otpauth://totp/a?secret=MY#fragment"] {
            XCTAssertThrowsError(try TOTP.generate(input, now: now))
        }
        for suffix in ["&image=%FF", "&issuer=%FF", "&digits=%2B6&period=%2B30", "&ignored=a+b", "#"] {
            XCTAssertNoThrow(try TOTP.generate("otpauth://totp/a?secret=MY" + suffix, now: now))
        }
        XCTAssertNoThrow(try TOTP.generate("MY", now: Date(timeIntervalSince1970: 253402300499)))
        XCTAssertNoThrow(try TOTP.generate(base32(String(repeating: "a", count: 1024)), now: now))
        let result = try TOTP.generate("otpauth://totp/a?secret=MY&period=60&digits=7", now: now)
        XCTAssertEqual(result.code.count, 7); XCTAssertEqual(result.validUntil.timeIntervalSince1970, 60)
    }
}
