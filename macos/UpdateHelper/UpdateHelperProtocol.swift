// SPDX-License-Identifier: GPL-3.0-only
import Foundation

// The update helper is an XPC service without App Sandbox inside the app.
// Files the sandboxed app writes carry a quarantine flag that only a process
// outside the sandbox can remove, so an update the app installed would not
// open. The app starts the helper from its current bundle at launch and asks
// it to repair the installed bundle before it quits (docs/updates.md).
enum UpdateHelperService {
    static let name = "yz.sh.mygo-vaultwarden.update-helper"
    static let appIdentifier = "yz.sh.mygo-vaultwarden"
}

// Results of repairInstalledApp.
enum UpdateHelperResult: Int32 {
    case unchanged = 0       // the installed app carries no quarantine
    case repaired = 1        // quarantine removed from a verified app
    case notApp = -1         // the helper is not inside an app bundle
    case untrusted = -2      // the installed app fails the signature check
    case incomplete = -3     // some files kept their quarantine
}

@objc(MyGoUpdateHelperProtocol)
protocol UpdateHelperProtocol {
    // Never answered while the app runs: the open reply keeps the helper, and
    // the code it was started from, alive across an update of the bundle.
    func hold(_ reply: @escaping () -> Void)
    func repairInstalledApp(_ reply: @escaping (Int32) -> Void)
}
