// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import Foundation

// All accesses, including timers, run on the main thread. Snapshot authentication
// is performed inside the same main-thread operation by the bridge, without any
// prior snapshot file lock held by its worker. No secret is retained here.
protocol SensitivePasteboard {
    var changeCount: Int { get }
    var owner: String? { get }
    func replace(secret: String, owner: String) -> Bool
    func clear()
}

final class NativeSensitivePasteboard: SensitivePasteboard {
    static let ownerType = NSPasteboard.PasteboardType("org.mygo.vaultwarden.secret-owner")
    private let board: NSPasteboard
    init(_ board: NSPasteboard) { self.board = board }
    var changeCount: Int { board.changeCount }
    var owner: String? { board.string(forType: Self.ownerType) }
    func replace(secret: String, owner: String) -> Bool {
        let item = NSPasteboardItem()
        guard item.setString(secret, forType: .string),
              item.setString(owner, forType: Self.ownerType),
              item.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")),
              item.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType")) else { return false }
        board.clearContents()
        return board.writeObjects([item])
    }
    func clear() { board.clearContents() }
}

final class SensitiveClipboard {
    struct Receipt: Equatable {
        let owner: String
        let count: Int
    }
    private let board: SensitivePasteboard
    private(set) var receipt: Receipt?
    init(board: SensitivePasteboard) { self.board = board }

    // The caller authorizes while holding its authenticated snapshot lease.
    // Concealed/transient are hints only; other processes can still read secrets.
    @discardableResult
    func copy(_ secret: String) throws -> Receipt {
        precondition(Thread.isMainThread)
        guard !secret.isEmpty, secret.utf8.count <= 65536 else { throw SnapshotError.invalidInput }
        let owner = UUID().uuidString
        guard board.replace(secret: secret, owner: owner) else { throw SnapshotError.configuration }
        let next = Receipt(owner: owner, count: board.changeCount)
        receipt = next
        return next
    }

    // changeCount + random owner protect same-value external writes and old
    // timers. NSPasteboard has no cross-process atomic compare-and-clear; this
    // is best effort and cannot promise to defeat a concurrent external write.
    func clear(ifOwned expected: Receipt? = nil) {
        precondition(Thread.isMainThread)
        guard let current = receipt, expected == nil || expected == current else { return }
        receipt = nil
        guard board.changeCount == current.count, board.owner == current.owner,
              board.changeCount == current.count else { return }
        board.clear()
    }
}
