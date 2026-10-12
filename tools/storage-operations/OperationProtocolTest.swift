// SPDX-License-Identifier: GPL-3.0-only
// Compile with macos/Bridge/StorageOperation.generated.swift and run at repository root.
import Foundation

@main
struct OperationProtocolTest {
    struct Entry: Decodable { let name: String; let control: Bool? }
    static func main() throws {
        let schema = try Data(contentsOf: URL(fileURLWithPath: "tools/storage-operations/operations.json"))
        let entries = try JSONDecoder().decode([Entry].self, from: schema)
        precondition(Set(entries.map(\.name)) == Set(StorageOperation.allCases.map(\.rawValue)))
        for entry in entries {
            let data = try JSONEncoder().encode(entry.name)
            let operation = try JSONDecoder().decode(StorageOperation.self, from: data)
            precondition(operation.rawValue == entry.name)
            precondition(operation.allowsTransfer == !(entry.control ?? false))
            let encoded = try JSONEncoder().encode(operation)
            precondition(encoded == data)
        }
        for unknown in ["", "STATUS", "unsupported-test-operation", "__transfer_v1", "activate"] {
            let data = try JSONEncoder().encode(unknown)
            do {
                _ = try JSONDecoder().decode(StorageOperation.self, from: data)
                fatalError("unknown operation accepted")
            } catch is DecodingError { }
        }
        print("\(StorageOperation.allCases.count) Swift operation wire names, transfer policy and unknown rejection passed")
    }
}
