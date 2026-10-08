// SPDX-License-Identifier: GPL-3.0-only
import XCTest
import LocalAuthentication
@testable import CredentialModel

private final class SwitchMemoryKeys: SnapshotKeyStore {
    var values:[String:Data]=[:]
    var cancelled=false
    var failCreate=false
    var onAuthentication:(() throws -> Void)?
    func create(id:String,key:Data)throws{if failCreate{throw SnapshotError.configuration};values[id]=key}
    func read(id:String,context:LAContext,allowUI:Bool)throws->Data{
        if allowUI { if cancelled{throw SnapshotError.cancelled};try onAuthentication?() }
        guard let key=values[id] else{throw SnapshotError.unavailable};return key
    }
    func delete(id:String)throws{values[id]=nil}
}
final class AccountSwitchTests:XCTestCase {
    private var keys:SwitchMemoryKeys!
    var store:SnapshotStore!
    var directory:URL!
    let oldScope=SnapshotScope(server:"https://old.example.invalid",account:"old")
    let newScope=SnapshotScope(server:"https://new.example.invalid",account:"new")
    var material:PasswordUnlockMaterial{PasswordUnlockMaterial(config:PasswordUnlockConfig(email:"fixture@example.invalid",kdf:PasswordUnlockKDF(kdf:0,kdfIterations:5000,kdfMemory:0,kdfParallelism:0,salt:nil)),key:Data(repeating:7,count:32))}
    var nextMaterial:PasswordUnlockMaterial{var m=material;m.key=Data(repeating:8,count:32);return m}
    let session=Data("fixture-session".utf8)
    func vault(_ scope:SnapshotScope)->VaultData{VaultData(version:1,scope:scope,sync:Data("{\"profile\":{\"id\":\"\(scope.account)\",\"organizations\":[]},\"ciphers\":[]}".utf8))}
    override func setUpWithError()throws{
        directory=FileManager.default.temporaryDirectory.appendingPathComponent("account-switch-\(UUID().uuidString)")
        keys=SwitchMemoryKeys();store=try SnapshotStore(directory:directory,keys:keys)
    }
    override func tearDownWithError()throws{try FileManager.default.removeItem(at:directory)}
    func original(_ protected:Bool=false)throws->SnapshotLease{
        var v=vault(oldScope)
        if protected {v.version=2;v.pendingPolicyMutations=[PendingPolicyMutation(organizationId:"org-1",policyType:15,mutationId:"mutation-1")]}
        return try store.publish([],scope:oldScope,expected:store.state().revision,passwordUnlock:material,session:session,vault:v)
    }
    func binding(_ old:SnapshotLease)->AccountSwitchBinding{AccountSwitchBinding(operationID:String(repeating:"a",count:32),source:oldScope,sourceSnapshotID:old.header.id,target:newScope)}
    func switchAccount(_ old:SnapshotLease)throws->SnapshotLease{
        try store.publishBoundAccount([],binding:binding(old),expected:old.revision,material:nextMaterial,session:session,vault:vault(newScope))
    }
    func testForeignSwitchRetainsEncryptedOldUntilConfirmed()throws{
        let old=try original()
        XCTAssertThrowsError(try store.publish([],scope:newScope,expected:old.revision,passwordUnlock:nextMaterial,session:session,vault:vault(newScope)))
        let next=try switchAccount(old)
        let pending=try store.state()
        XCTAssertEqual(pending.format,3);XCTAssertTrue(pending.accountSwitchPending)
        XCTAssertNotNil(keys.values[old.header.keyID]);XCTAssertNotNil(keys.values[next.header.keyID])
        XCTAssertEqual(try store.files.accountSwitchRecord(pending)?.oldSnapshot?.header.id,old.header.id)
        XCTAssertThrowsError(try store.unlockWithPassword(scope:newScope,expected:pending.revision,unlockKey:nextMaterial.key))
        XCTAssertThrowsError(try store.logout(expected:pending.revision))
        XCTAssertThrowsError(try switchAccount(old))
        try store.lock()
        let inspection=try store.inspectAccountSwitch(expected:store.state().revision,operationID:binding(old).operationID)
        XCTAssertEqual(inspection.1.binding,binding(old));XCTAssertEqual(inspection.1.phase,"pending")
        let done=try store.confirmAccountSwitch(expected:inspection.0.revision,operationID:binding(old).operationID,unlockKey:nextMaterial.key)
        XCTAssertEqual(done.1.phase,"confirmed");XCTAssertFalse(try store.state().accountSwitchPending)
        XCTAssertNil(try store.files.accountSwitchRecord(store.state())?.oldSnapshot)
        XCTAssertTrue(try store.state().retiredKeys.contains(old.header.keyID))
        try store.retryCleanup()
        XCTAssertNil(keys.values[old.header.keyID]);XCTAssertNotNil(keys.values[next.header.keyID])
        XCTAssertNoThrow(try store.unlockWithPassword(scope:newScope,expected:store.state().revision,unlockKey:nextMaterial.key))
        XCTAssertThrowsError(try store.unlockWithPassword(scope:oldScope,expected:store.state().revision,unlockKey:material.key))
        XCTAssertNoThrow(try store.confirmAccountSwitch(expected:store.state().revision,operationID:binding(old).operationID,unlockKey:nextMaterial.key))
    }
    func testCancellationProtectionAndAuthenticationCASKeepOld()throws{
        let old=try original()
        let before=try Data(contentsOf:directory.appendingPathComponent("snapshot-v1.json"))
        keys.cancelled=true
        XCTAssertThrowsError(try switchAccount(old))
        XCTAssertEqual(try Data(contentsOf:directory.appendingPathComponent("snapshot-v1.json")),before)
        keys.cancelled=false
        keys.onAuthentication={self.keys.onAuthentication=nil;try self.store.lock()}
        XCTAssertThrowsError(try switchAccount(old))
        XCTAssertEqual(try store.state().snapshot?.header.id,old.header.id)
        XCTAssertNotNil(keys.values[old.header.keyID])
    }
    func testOldProtectionNeverCrossesToNewScope()throws{
        let old=try original(true)
        let before=try Data(contentsOf:directory.appendingPathComponent("snapshot-v1.json"))
        XCTAssertThrowsError(try switchAccount(old)){XCTAssertEqual($0 as? SnapshotError,.protectedAccountSwitch)}
        XCTAssertEqual(try Data(contentsOf:directory.appendingPathComponent("snapshot-v1.json")),before)
        XCTAssertNil(try store.state().accountSwitch)
    }
    func testPrewriteFailureAndUncertainCommitKeepBothKeysAndSameOperation()throws{
        let old=try original()
        keys.failCreate=true
        XCTAssertThrowsError(try switchAccount(old))
        XCTAssertEqual(try store.state().snapshot?.header.id,old.header.id)
        XCTAssertNotNil(keys.values[old.header.keyID])
        keys.failCreate=false
        let current=try store.state()
        let updated=SnapshotLease(revision:current.revision,header:old.header,expiresAt:ProcessInfo.processInfo.systemUptime+60,credentials:[])
        var writes=0
        store.files.afterRenameForTesting={writes+=1;if writes==2{throw SnapshotError.configuration}}
        XCTAssertThrowsError(try switchAccount(updated))
        store.files.afterRenameForTesting=nil
        let unknown=try store.state()
        XCTAssertEqual(unknown.snapshot?.header.scope,newScope);XCTAssertTrue(unknown.accountSwitchPending)
        XCTAssertNotNil(keys.values[old.header.keyID]);XCTAssertNotNil(keys.values[unknown.snapshot!.header.keyID])
        let query=try store.inspectAccountSwitch(expected:unknown.revision,operationID:binding(old).operationID)
        XCTAssertEqual(query.1.binding,binding(old))
        XCTAssertThrowsError(try switchAccount(updated))
        _ = try store.confirmAccountSwitch(expected:query.0.revision,operationID:query.1.binding.operationID,unlockKey:nextMaterial.key)
        try store.retryCleanup();XCTAssertNil(keys.values[old.header.keyID])
    }
    func testConfirmUnknownIsIdempotentAndEnvelopeTamperingFailsClosed()throws{
        let old=try original();let next=try switchAccount(old)
        store.files.afterRenameForTesting={throw SnapshotError.configuration}
        XCTAssertThrowsError(try store.confirmAccountSwitch(expected:next.revision,operationID:binding(old).operationID,unlockKey:nextMaterial.key))
        store.files.afterRenameForTesting=nil
        let state=try store.state()
        XCTAssertFalse(state.accountSwitchPending)
        XCTAssertNotNil(keys.values[state.snapshot!.header.keyID])
        XCTAssertNoThrow(try store.confirmAccountSwitch(expected:state.revision,operationID:binding(old).operationID,unlockKey:nextMaterial.key))
        var bad=state
        bad.accountSwitch=AccountSwitchEnvelope(version:1,pending:true,sealed:state.accountSwitch!.sealed)
        XCTAssertThrowsError(try store.files.write(bad))
        XCTAssertEqual(try store.state().revision,state.revision)
    }
}
