// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit

// Matches internal/vaultwarden/totp. Codes and seeds must never enter logs.
enum TOTP {
    enum Failure: Error { case invalidInput }
    private static func space(_ scalar: Unicode.Scalar) -> Bool {
        (9...13).contains(scalar.value) || [0x20, 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000].contains(scalar.value) || (0x2000...0x200a).contains(scalar.value)
    }
    private static func unescape(_ value: Substring, form: Bool = false) throws -> String {
        let bytes = Array(value.utf8)
        var decoded = [UInt8](), index = 0
        func hex(_ byte: UInt8) -> UInt8? {
            switch byte {
            case 48...57: return byte - 48
            case 65...70: return byte - 55
            case 97...102: return byte - 87
            default: return nil
            }
        }
        while index < bytes.count {
            if bytes[index] == 37 {
                guard index + 2 < bytes.count, let high = hex(bytes[index + 1]), let low = hex(bytes[index + 2]) else { throw Failure.invalidInput }
                decoded.append(high * 16 + low); index += 3
            } else { decoded.append(form && bytes[index] == 43 ? 32 : bytes[index]); index += 1 }
        }
        // Go permits arbitrary query bytes; invalid UTF-8 cannot form a base32 key.
        return String(decoding: decoded, as: UTF8.self)
    }
    private static func number(_ value: String) throws -> Int {
        let bytes = Array(value.utf8)
        let digits = bytes.first == 43 || bytes.first == 45 ? bytes.dropFirst() : bytes[...]
        guard !digits.isEmpty, digits.allSatisfy({ (48...57).contains($0) }), let result = Int(value) else { throw Failure.invalidInput }
        return result
    }
    static func generate(_ input: String, now: Date) throws -> (code: String, validUntil: Date) {
        let timestamp = floor(now.timeIntervalSince1970)
        guard !input.isEmpty, input.utf8.count <= 4096, timestamp.isFinite,
              timestamp >= 0, timestamp <= 253402300499 else { throw Failure.invalidInput }
        var scalars = input.unicodeScalars[...]
        while let first = scalars.first, space(first) { scalars = scalars.dropFirst() }
        while let last = scalars.last, space(last) { scalars = scalars.dropLast() }
        var secret = String(scalars)
        var period = 30, digits = 6, algorithm = "SHA1"
        let steam = secret.lowercased().hasPrefix("steam://")
        if steam { secret = String(secret.dropFirst(8)) }
        else if secret.lowercased().hasPrefix("otpauth://") {
            // Parse raw URI fields and form queries to preserve Go's escape,
            // '+' and semicolon handling rather than Foundation's URL repair.
            guard !secret.utf8.contains(where: { $0 < 32 || $0 == 127 }) else { throw Failure.invalidInput }
            let fragments = secret.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
            guard fragments.count == 1 || fragments[1].isEmpty else { throw Failure.invalidInput }
            let beforeFragment = fragments[0]
            let authority = beforeFragment.dropFirst(10).prefix { $0 != "/" && $0 != "?" }
            guard authority.lowercased() == "totp" else { throw Failure.invalidInput }
            let resource = beforeFragment.dropFirst(10 + authority.count)
            guard resource.hasPrefix("/") else { throw Failure.invalidInput }
            let path = resource.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)[0]
            guard !path.isEmpty else { throw Failure.invalidInput }
            _ = try unescape(path)
            let query = beforeFragment.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).dropFirst().first ?? ""
            var values: [String: String] = [:]
            for pair in query.split(separator: "&") {
                guard !pair.contains(";") else { throw Failure.invalidInput }
                let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                let key = try unescape(parts[0], form: true), value = try unescape(parts.count == 2 ? parts[1] : "", form: true)
                if ["secret", "issuer", "algorithm", "digits", "period"].contains(key) {
                    guard values[key] == nil else { throw Failure.invalidInput }
                    values[key] = value
                }
            }
            secret = values["secret"] ?? ""
            if let value = values["algorithm"] { algorithm = value.uppercased() }
            if let value = values["digits"] { digits = try number(value) }
            if let value = values["period"] { period = try number(value) }
            guard (6...8).contains(digits), (1...300).contains(period) else { throw Failure.invalidInput }
        }
        guard ["SHA1", "SHA256", "SHA512"].contains(algorithm) else { throw Failure.invalidInput }
        secret = secret.unicodeScalars.filter { !space($0) }.map {
            let upper = String($0).uppercased()
            return upper.unicodeScalars.count == 1 ? upper : String($0)
        }.joined()
        let encoded = Array(secret.utf8), alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        let unpadded = encoded.prefix { $0 != 61 }
        let remainder = unpadded.count % 8
        guard [0, 2, 4, 5, 7].contains(remainder),
              encoded.dropFirst(unpadded.count).allSatisfy({ $0 == 61 }),
              encoded.count == unpadded.count || (encoded.count % 8 == 0 && encoded.count - unpadded.count == (8 - remainder) % 8) else { throw Failure.invalidInput }
        var key = [UInt8](), buffer: UInt32 = 0, bits = 0
        defer { _ = key.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        for byte in unpadded {
            guard let value = alphabet.firstIndex(of: byte) else { throw Failure.invalidInput }
            buffer = (buffer << 5) | UInt32(value); bits += 5
            if bits >= 8 { bits -= 8; key.append(UInt8((buffer >> bits) & 255)) }
        }
        guard !key.isEmpty, key.count <= 1024, buffer & ((1 << bits) - 1) == 0 else { throw Failure.invalidInput }
        let counter = UInt64(timestamp) / UInt64(period)
        var bigEndian = counter.bigEndian
        let message = withUnsafeBytes(of: &bigEndian) { Data($0) }, symmetricKey = SymmetricKey(data: key)
        var digest: [UInt8]
        switch algorithm {
        case "SHA256": digest = Array(HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey))
        case "SHA512": digest = Array(HMAC<SHA512>.authenticationCode(for: message, using: symmetricKey))
        default: digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetricKey))
        }
        defer { _ = digest.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        let offset = Int(digest.last! & 15)
        var value = digest[offset..<offset+4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } & 0x7fffffff
        let code: String
        if steam {
            let alphabet = Array("23456789BCDFGHJKMNPQRTVWXY")
            var result = ""
            for _ in 0..<5 { result.append(alphabet[Int(value % UInt32(alphabet.count))]); value /= UInt32(alphabet.count) }
            code = result
        } else {
            let modulus = (0..<digits).reduce(UInt32(1)) { value, _ in value * 10 }
            code = String(format: "%0*d", digits, value % modulus)
        }
        return (code, Date(timeIntervalSince1970: Double((counter + 1) * UInt64(period))))
    }
}
