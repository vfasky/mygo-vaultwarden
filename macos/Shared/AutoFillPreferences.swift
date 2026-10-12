// SPDX-License-Identifier: GPL-3.0-only
import Foundation

// Non-secret AutoFill preferences shared by the main app bridge and the
// extension through the snapshot App Group's defaults.
enum AutoFillPreferences {
    static let copyTOTPKey = "autofillCopyTOTP"

    private static func defaults() -> UserDefaults? {
        guard let group = try? SnapshotConfiguration.current().group else { return nil }
        return UserDefaults(suiteName: group)
    }
    // Absent means the default: copy the verification code after a fill.
    static var copyTOTP: Bool {
        guard let defaults = defaults(), defaults.object(forKey: copyTOTPKey) != nil else { return true }
        return defaults.bool(forKey: copyTOTPKey)
    }
    static func setCopyTOTP(_ enabled: Bool) throws {
        guard let defaults = defaults() else { throw SnapshotError.configuration }
        defaults.set(enabled, forKey: copyTOTPKey)
    }
}
