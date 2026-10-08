// SPDX-License-Identifier: GPL-3.0-only
import XCTest
import LocalAuthentication
@testable import CredentialModel

private final class TargetMemoryKeys: SnapshotKeyStore {
    var values: [String: Data] = [:]
    var failCreate = false
    var cancelUI = false
    func create(id: String, key: Data) throws { if failCreate { throw SnapshotError.configuration }; values[id] = key }
    func read(id: String, context: LAContext, allowUI: Bool) throws -> Data { if allowUI && cancelUI { throw SnapshotError.cancelled }; guard let key = values[id] else { throw SnapshotError.unavailable }; return key }
    func delete(id: String) throws { values[id] = nil }
}
final class TargetRecoveryTests: XCTestCase {
    private var keys: TargetMemoryKeys!
    var store: SnapshotStore!
    var directory: URL!
    let actor = SnapshotScope(server: "https://target.example.invalid", account: "actor")
    var target: SnapshotScope { SnapshotScope(server: actor.server, account: "target") }
    var material: PasswordUnlockMaterial { PasswordUnlockMaterial(config: PasswordUnlockConfig(email: "fixture@example.invalid", kdf: PasswordUnlockKDF(kdf: 0, kdfIterations: 5000, kdfMemory: 0, kdfParallelism: 0, salt: nil)), key: Data(repeating: 44, count: 32)) }
    let session = Data("fresh-fixture-session".utf8)
    func vault(_ scope: SnapshotScope) -> VaultData { VaultData(version: 1, scope: scope, sync: Data("{\"profile\":{\"id\":\"\(scope.account)\",\"organizations\":[]},\"ciphers\":[]}".utf8)) }
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("target-recovery-\(UUID().uuidString)")
        keys = TargetMemoryKeys()
        store = try SnapshotStore(directory: directory, keys: keys)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }
    func publish(_ scope: SnapshotScope) throws -> SnapshotLease { try store.publish([], scope: scope, expected: store.state().revision, passwordUnlock: material, session: session, vault: vault(scope)) }
    func record(_ target: SnapshotScope, required: Bool = true, id: String = String(repeating: "a", count: 32)) throws -> (TargetRecoveryBinding, Data) {
        var object: [String: Any] = ["OperationID": id, "Actor": ["server":actor.server,"account":actor.account], "Target":["server":target.server,"account":target.account], "Kind":required ? "administrator-recovery" : "emergency-invite", "PreviousRevision":"authorization-revision", "AuthorizationEpoch":7, "RequireTargetLogin":required, "TargetEmail":"never-plaintext@example.invalid", "ConfirmedImpact":"private-impact"]
        // Storage tests inject structural evidence; real remote cryptography is
        // independently exercised by the Go fresh-login verifier tests.
        if required { object["Verification"] = ["Version":1,"ResetPassword":true,"ResetMFA":true,"RemoveNonOwnerMemberships":false,"ExpectedUserKeySHA256":targetDigest(Data("fixture-user-key".utf8)),"ExpectedMasterWrapperSHA256":targetDigest(Data("fixture-wrapper".utf8))] }
        let summary = try JSONSerialization.data(withJSONObject: object)
        return (TargetRecoveryBinding(operationId: id, actor: actor, target: target, storageRevision: try store.state().revision, hostEpoch: 3, authorizationEpoch: 7, summaryHash: targetDigest(summary)),summary)
    }
    @discardableResult func begin(_ binding: TargetRecoveryBinding, _ summary: Data) throws -> TargetRecoveryRecord {
        try store.targetRecovery(operation: "targetRecoveryBegin", scope: actor, expected: store.state().revision, unlockKey: material.key, binding: binding, summary: summary, phase: nil).1[0]
    }
    func proof(_ binding: TargetRecoveryBinding) throws -> TargetRecoveryResolution {
        let hash = targetDigest(Data("verified-authority-evidence".utf8))
        return TargetRecoveryResolution(kind:"target-observed-effects-v1",binding: binding, expectedRevision: try store.state().revision, target: binding.target, vaultHash: targetDigest(vault(binding.target).sync), sessionHash: targetDigest(session), unlockHash: targetDigest(material.key), authorityHash: hash, keyHash: hash, membershipHash: hash, mfaHash: hash, confirmationHash: hash, authenticationEpoch: 9)
    }
    func testResultProvenanceSurvivesVerificationPublicationAndReopen() throws {
        _ = try publish(actor)
        let (binding, summary) = try record(target)
        _ = try begin(binding, summary)
        _ = try store.targetRecovery(operation:"targetRecoveryResult",scope:actor,expected:store.state().revision,unlockKey:material.key,binding:binding,summary:nil,phase:"confirmed")
        XCTAssertThrowsError(try store.targetRecovery(operation:"targetRecoveryResult",scope:actor,expected:store.state().revision,unlockKey:material.key,binding:binding,summary:nil,phase:"unknown"))
        var p = try proof(binding); p.kind = "target-confirmed-email-fallback-v1"
        _ = try store.targetRecovery(operation:"targetRecoveryVerify",scope:actor,expected:p.expectedRevision,unlockKey:material.key,binding:binding,summary:nil,phase:nil,resolution:p,vault:vault(target),session:session,material:material)
        store = try SnapshotStore(directory:directory,keys:keys)
        var row = try store.files.targetRecords(store.state())[0]
        XCTAssertEqual(row.phase,"verified"); XCTAssertEqual(row.originalResult,TargetRecoveryOriginalResult(version:1,phase:"confirmed"))
        try store.logout(expected:store.state().revision)
        _ = try publish(target)
        store = try SnapshotStore(directory:directory,keys:keys)
        row = try store.files.targetRecords(store.state())[0]
        XCTAssertEqual(row.phase,"resolved"); XCTAssertEqual(row.originalResult,TargetRecoveryOriginalResult(version:1,phase:"confirmed"))
    }
    func testDiscoveryNondispatchAndEmailEvidenceAreNotInterchangeable() throws {
        _ = try publish(actor)
        for (index, phase) in ["prepared","unknown","not-dispatched","confirmed"].enumerated() {
            let (binding, summary) = try record(target,id:String(repeating:String(index),count:32))
            _ = try begin(binding,summary)
            if phase != "prepared" { _ = try store.targetRecovery(operation:"targetRecoveryResult",scope:actor,expected:store.state().revision,unlockKey:material.key,binding:binding,summary:nil,phase:phase) }
            if phase == "unknown" { XCTAssertThrowsError(try store.targetRecovery(operation:"targetRecoveryResult",scope:actor,expected:store.state().revision,unlockKey:material.key,binding:binding,summary:nil,phase:"confirmed")) }
            for kind in ["target-discovery-v1","target-authenticated-nondispatch-v1","target-confirmed-email-fallback-v1"] {
                var p = try proof(binding); p.kind = kind
                let allowed = (kind == "target-authenticated-nondispatch-v1" && phase == "not-dispatched") || (kind == "target-confirmed-email-fallback-v1" && phase == "confirmed")
                let before = try store.state().revision
                let action = { try self.store.targetRecovery(operation:"targetRecoveryVerify",scope:self.actor,expected:p.expectedRevision,unlockKey:self.material.key,binding:binding,summary:nil,phase:nil,resolution:p,vault:self.vault(self.target),session:self.session,material:self.material) }
                if allowed { XCTAssertNoThrow(try action()) } else { XCTAssertThrowsError(try action()); XCTAssertEqual(try store.state().revision,before) }
                let row = try store.files.targetRecords(store.state()).first { $0.binding == binding }
                XCTAssertEqual(row?.originalResult?.phase,phase == "prepared" ? nil : phase)
            }
        }
    }
    func testLegacyAndMalformedExpectationsDoNotBecomeVerification() throws {
        _ = try publish(actor)
        let (base, original) = try record(target)
        var object = try JSONSerialization.jsonObject(with:original) as! [String:Any]
        object["Verification"] = nil
        let legacy = try JSONSerialization.data(withJSONObject:object)
        let binding = TargetRecoveryBinding(operationId:base.operationId,actor:base.actor,target:base.target,storageRevision:base.storageRevision,hostEpoch:base.hostEpoch,authorizationEpoch:base.authorizationEpoch,summaryHash:targetDigest(legacy))
        _ = try begin(binding,legacy)
        _ = try store.targetRecovery(operation:"targetRecoveryResult",scope:actor,expected:store.state().revision,unlockKey:material.key,binding:binding,summary:nil,phase:"confirmed")
        XCTAssertNil(try store.files.targetRecords(store.state())[0].originalResult)
        let p = try proof(binding)
        XCTAssertThrowsError(try store.targetRecovery(operation:"targetRecoveryVerify",scope:actor,expected:p.expectedRevision,unlockKey:material.key,binding:binding,summary:nil,phase:nil,resolution:p,vault:vault(target),session:session,material:material))
        for (index, mode) in ["version","missing","flags","hash","unknown"].enumerated() {
            let (b, source) = try record(target,id:String(repeating:String(index),count:32))
            var raw = try JSONSerialization.jsonObject(with:source) as! [String:Any]
            var expected = raw["Verification"] as! [String:Any]
            switch mode {
            case "version": expected["Version"] = 2
            case "missing": expected["ResetMFA"] = nil
            case "flags": expected["RemoveNonOwnerMemberships"] = true
            case "hash": expected["ExpectedUserKeySHA256"] = "not-a-witness"
            default: expected["UnrecognizedIntent"] = true
            }
            raw["Verification"] = expected
            let changed = try JSONSerialization.data(withJSONObject:raw)
            let bad = TargetRecoveryBinding(operationId:b.operationId,actor:b.actor,target:b.target,storageRevision:b.storageRevision,hostEpoch:b.hostEpoch,authorizationEpoch:b.authorizationEpoch,summaryHash:targetDigest(changed))
            let revision = try store.state().revision
            XCTAssertThrowsError(try begin(bad,changed)); XCTAssertEqual(try store.state().revision,revision)
        }
    }
    func testSelfBarrierSurvivesLockLogoutReopenAndFreshRecovery() throws {
        let old = try publish(actor)
        let (binding, summary) = try record(actor)
        XCTAssertFalse(try begin(binding, summary).noLocalTarget)
        XCTAssertThrowsError(try store.withCurrentLease(old) {})
        XCTAssertThrowsError(try store.unlockWithPassword(scope: actor, expected: store.state().revision, unlockKey: material.key))
        XCTAssertThrowsError(try publish(actor))
        try store.lock()
        try store.logout(expected: store.state().revision)
        XCTAssertNil(keys.values[old.header.keyID])
        XCTAssertNotNil(keys.values[targetRecoveryKeyID])
        store = try SnapshotStore(directory: directory, keys: keys)
        XCTAssertThrowsError(try publish(actor))
        let p = try proof(binding)
        let pending = try store.targetRecovery(operation: "targetRecoveryPending", scope: actor, expected: store.state().revision, unlockKey: material.key, binding: nil, summary: nil, phase: nil, vault: vault(actor), session: session, material: material, login: p)
        XCTAssertEqual(pending.1.map(\.binding), [binding])
        let next = try store.publish([], scope: actor, expected: p.expectedRevision, passwordUnlock: material, session: session, vault: vault(actor), targetResolution: p)
        XCTAssertNoThrow(try store.withCurrentLease(next) {})
        XCTAssertEqual(try store.files.targetRecords(store.state())[0].phase, "resolved")
    }
    func testForeignTargetDoesNotEraseActorAndCannotPublishOldTarget() throws {
        let old = try publish(actor)
        let (binding, summary) = try record(target)
        XCTAssertTrue(try begin(binding, summary).noLocalTarget)
        XCTAssertEqual(try store.state().snapshot?.header.id, old.header.id)
        XCTAssertNoThrow(try store.unlockWithPassword(scope: actor, expected: store.state().revision, unlockKey: material.key))
        _ = try publish(actor)
        XCTAssertEqual(try store.files.targetRecords(store.state()).count, 1)
        let p = try proof(binding)
        _ = try store.targetRecovery(operation: "targetRecoveryVerify", scope: actor, expected: p.expectedRevision, unlockKey: material.key, binding: binding, summary: nil, phase: nil, resolution: p, vault: vault(target), session: session, material: material)
        XCTAssertEqual(try store.state().snapshot?.header.scope, actor)
        try store.logout(expected: store.state().revision)
        XCTAssertThrowsError(try store.publish([], scope: target, expected: store.state().revision, passwordUnlock: material, session: Data("old-session".utf8), vault: vault(target)))
        let fresh = try publish(target)
        XCTAssertNoThrow(try store.withCurrentLease(fresh) {})
        XCTAssertEqual(try store.files.targetRecords(store.state())[0].phase, "resolved")
    }
    func testUnknownTargetInvitationAndIdempotentBinding() throws {
        _ = try publish(actor)
        let unknown = SnapshotScope(server: actor.server, account: "")
        let (binding, summary) = try record(unknown, required: false)
        _ = try begin(binding, summary)
        let revision = try store.state().revision
        _ = try begin(binding, summary)
        XCTAssertEqual(try store.state().revision, revision)
        let bad = TargetRecoveryBinding(operationId: binding.operationId, actor: actor, target: unknown, storageRevision: binding.storageRevision, hostEpoch: 4, authorizationEpoch: 7, summaryHash: binding.summaryHash)
        XCTAssertThrowsError(try begin(bad, summary))
        XCTAssertNoThrow(try store.unlockWithPassword(scope: actor, expected: revision, unlockKey: material.key))
        _ = try store.targetRecovery(operation: "targetRecoveryResult", scope: actor, expected: revision, unlockKey: material.key, binding: binding, summary: nil, phase: "unknown")
        XCTAssertThrowsError(try store.targetRecovery(operation: "targetRecoveryResult", scope: actor, expected: store.state().revision, unlockKey: material.key, binding: binding, summary: nil, phase: "not-dispatched"))
    }
    func testMissingKeyCorruptVersionAndPlaintextExclusion() throws {
        _ = try publish(actor)
        let (binding, summary) = try record(target)
        _ = try begin(binding, summary)
        let url = directory.appendingPathComponent("snapshot-v1.json")
        let data = try Data(contentsOf: url)
        for value in ["never-plaintext@example.invalid", "private-impact", binding.operationId, summary.base64EncodedString()] { XCTAssertNil(data.range(of: Data(value.utf8))) }
        let key = keys.values.removeValue(forKey: targetRecoveryKeyID)!
        XCTAssertThrowsError(try store.state())
        XCTAssertThrowsError(try publish(actor))
        keys.values[targetRecoveryKeyID] = key
        var state = try store.state()
        state.targetRecovery = TargetRecoveryEnvelope(version: 2, sealed: state.targetRecovery!.sealed)
        XCTAssertThrowsError(try store.files.write(state))
        state.targetRecovery = TargetRecoveryEnvelope(version: 1, sealed: Data(repeating: 3, count: 60))
        try store.files.write(state)
        XCTAssertThrowsError(try store.state())
    }
    func testMultipleOperationsRequireEachVerificationAndPreserveOtherTarget() throws {
        _ = try publish(actor)
        let (first, firstRaw) = try record(target)
        _ = try begin(first, firstRaw)
        let (second, secondRaw) = try record(target,id:String(repeating:"b",count:32))
        _ = try begin(second, secondRaw)
        let thirdTarget = SnapshotScope(server:actor.server,account:"third")
        let (third, thirdRaw) = try record(thirdTarget,id:String(repeating:"d",count:32))
        _ = try begin(third, thirdRaw)
        let firstProof = try proof(first)
        _ = try store.targetRecovery(operation:"targetRecoveryVerify",scope:actor,expected:firstProof.expectedRevision,unlockKey:material.key,binding:first,summary:nil,phase:nil,resolution:firstProof,vault:vault(target),session:session,material:material)
        try store.logout(expected:store.state().revision)
        XCTAssertThrowsError(try publish(target))
        let secondProof = try proof(second)
        _ = try store.targetRecovery(operation:"targetRecoveryVerify",scope:target,expected:secondProof.expectedRevision,unlockKey:material.key,binding:second,summary:nil,phase:nil,resolution:secondProof,vault:vault(target),session:session,material:material,login:secondProof)
        let complete = try publish(target)
        XCTAssertNoThrow(try store.withCurrentLease(complete) {})
        let records = try store.files.targetRecords(store.state())
        XCTAssertEqual(records.first(where:{$0.binding == first})?.phase,"resolved")
        XCTAssertEqual(records.first(where:{$0.binding == second})?.phase,"resolved")
        XCTAssertEqual(records.first(where:{$0.binding == third})?.phase,"prepared")
    }
    func testRuntimeActorBlocksForeignLocalTargetAndLocalAuthenticationResolves() throws {
        var protected = vault(target)
        protected.version = 2
        protected.pendingPolicyMutations = [PendingPolicyMutation(organizationId:"org-1",policyType:15,mutationId:"mutation-1")]
        protected.quarantinedOrganizations = ["org-2"]
        let old = try store.publish([],scope:target,expected:"empty-v1",passwordUnlock:material,session:session,vault:protected)
        let (binding, summary) = try record(target)
        let authority = RuntimeRecoveryAuthority(scope:actor,generation:2,deadlineUnixMS:20000,leaseID:"fixture-runtime-recovery",operationID:binding.operationId,summaryHash:binding.summaryHash)
        store = try SnapshotStore(directory:directory,keys:keys,runtimeRecoveryAuthorizer:{ input in
            guard input.scope == self.actor, input.generation == 2, input.leaseID == authority.leaseID,
                  input.operationID == binding.operationId, input.summaryHash == binding.summaryHash else { throw SnapshotError.expired }
        })
        let result = try store.targetRecovery(operation:"targetRecoveryBegin",scope:actor,expected:old.revision,unlockKey:Data(),binding:binding,summary:summary,phase:nil,runtime:authority)
        XCTAssertFalse(result.1[0].noLocalTarget)
        XCTAssertEqual(result.0.snapshot?.sealed,try store.state().snapshot?.sealed)
        XCTAssertEqual(result.0.snapshot?.header.id,old.header.id)
        XCTAssertThrowsError(try store.withCurrentLease(old) {})
        XCTAssertThrowsError(try store.unlockWithPassword(scope:target,expected:result.0.revision,unlockKey:material.key))
        keys.cancelUI = true
        XCTAssertThrowsError(try store.inspectLocalTarget(binding:binding,expected:result.0.revision))
        XCTAssertEqual(try store.files.targetRecords(store.state())[0].phase,"prepared")
        keys.cancelUI = false
        let projection = try store.inspectLocalTarget(binding:binding,expected:result.0.revision)
        XCTAssertEqual(projection.1.pendingPolicyMutations,protected.pendingPolicyMutations)
        XCTAssertNil(projection.2)
        var freshMaterial = material; freshMaterial.key = Data(repeating:88,count:32)
        let base = try proof(binding)
        let p = TargetRecoveryResolution(kind:base.kind,binding:binding,expectedRevision:base.expectedRevision,target:target,vaultHash:base.vaultHash,sessionHash:base.sessionHash,unlockHash:targetDigest(freshMaterial.key),authorityHash:base.authorityHash,keyHash:base.keyHash,membershipHash:base.membershipHash,mfaHash:base.mfaHash,confirmationHash:base.confirmationHash,authenticationEpoch:9)
        XCTAssertThrowsError(try store.publish([],scope:target,expected:p.expectedRevision,passwordUnlock:freshMaterial,session:session,vault:vault(target),targetResolution:p))
        let complete = try store.resolveLocalTarget(proof:p,credentials:[],material:freshMaterial,session:session,vault:vault(target))
        XCTAssertEqual(complete.vault?.pendingPolicyMutations,protected.pendingPolicyMutations)
        XCTAssertEqual(complete.vault?.quarantinedOrganizations,protected.quarantinedOrganizations)
        XCTAssertNoThrow(try store.unlockWithPassword(scope:target,expected:complete.revision,unlockKey:freshMaterial.key))
        XCTAssertThrowsError(try store.unlockWithPassword(scope:target,expected:complete.revision,unlockKey:material.key))
    }
    func testAccountJournalAndPolicyCoexistWithoutCrossClearing() throws {
        var isolated = vault(actor)
        isolated.version = 2
        isolated.pendingPolicyMutations = [PendingPolicyMutation(organizationId: "org-1", policyType: 15, mutationId: "mutation-1")]
        isolated.quarantinedOrganizations = ["org-2"]
        let old = try store.publish([], scope: actor, expected: "empty-v1", passwordUnlock: material, session: session, vault: isolated)
        let raw = try JSONSerialization.data(withJSONObject: ["version":1, "operationId":String(repeating:"c",count:32), "scope":["server":actor.server,"account":actor.account], "kind":"rotate-user-key", "oldRevision":old.revision, "oldSession":session.base64EncodedString(), "oldVault":try snapshotJSON(isolated).base64EncodedString(), "oldUnlock":["config":["email":material.config.email,"kdf":["kdf":0,"kdfIterations":5000,"kdfMemory":0,"kdfParallelism":0]],"key":material.key.base64EncodedString()], "newUserKey":Data(repeating:1,count:64).base64EncodedString(), "newWrappedKey":"wrapped", "request":Data("{}".utf8).base64EncodedString()])
        let account = AccountRecoveryBinding(operationId:String(repeating:"c",count:32),oldRevision:old.revision,epoch:1,recordHash:recoveryDigest(raw))
        _ = try store.accountRecovery(operation:"accountRecoveryBegin",scope:actor,expected:old.revision,unlockKey:material.key,binding:account,record:raw)
        let (binding, summary) = try record(actor)
        _ = try begin(binding, summary)
        let queried = try store.accountRecovery(operation:"accountRecoveryQuery",scope:actor,expected:store.state().revision,unlockKey:material.key,binding:account)
        XCTAssertEqual(queried.1?.record,raw)
        XCTAssertEqual(try store.inspectLocalTarget(binding:binding,expected:store.state().revision).2?.record,raw)
        let p = try proof(binding)
        XCTAssertThrowsError(try store.resolveLocalTarget(proof:p,credentials:[],material:material,session:session,vault:vault(actor))) { error in
            XCTAssertEqual(error as? SnapshotError,.accountRecoveryRequired)
        }
        XCTAssertThrowsError(try store.publish([],scope:actor,expected:p.expectedRevision,passwordUnlock:material,session:session,vault:vault(actor),targetResolution:p))
        let resolution = AccountRecoveryResolution(binding:account,mode:"verified",userConfirmed:true,authorityVerified:true,resourcesVerified:true,vaultHash:recoveryDigest(vault(actor).sync))
        let next = try store.accountRecovery(operation:"accountRecoveryResolve",scope:actor,expected:store.state().revision,unlockKey:material.key,binding:account,resolution:resolution,credentials:[],material:material,session:session,vault:vault(actor)).0
        XCTAssertTrue(next.recoveryOnly)
        XCTAssertThrowsError(try store.unlockWithPassword(scope:actor,expected:next.revision,unlockKey:material.key))
        let finalProof = try proof(binding)
        let complete = try store.publish([],scope:actor,expected:finalProof.expectedRevision,passwordUnlock:material,session:session,vault:vault(actor),includeVault:true,targetResolution:finalProof)
        XCTAssertEqual(complete.vault?.pendingPolicyMutations,isolated.pendingPolicyMutations)
        XCTAssertEqual(complete.vault?.quarantinedOrganizations,isolated.quarantinedOrganizations)
        XCTAssertNoThrow(try store.withCurrentLease(complete) {})
    }
    func testResolvedProjectionTracksAuthorizedPolicyClearAndSurvivesLogout() throws {
        let mutation = PendingPolicyMutation(organizationId:"org-1",policyType:15,mutationId:"mutation-1")
        var protected = vault(actor); protected.version = 2
        protected.pendingPolicyMutations = [mutation]; protected.quarantinedOrganizations = ["org-2"]
        _ = try store.publish([],scope:actor,expected:store.state().revision,passwordUnlock:material,session:session,vault:protected)
        let (binding,summary) = try record(actor)
        _ = try begin(binding,summary)
        let resolution = try proof(binding)
        let recovered = try store.publish([],scope:actor,expected:resolution.expectedRevision,passwordUnlock:material,session:session,vault:vault(actor),includeVault:true,targetResolution:resolution)
        XCTAssertEqual(recovered.vault?.pendingPolicyMutations,[mutation])
        let cleared = try store.publish([],scope:actor,expected:recovered.revision,passwordUnlock:material,session:session,vault:vault(actor),includeVault:true,clearingPolicy:mutation)
        XCTAssertTrue(cleared.vault?.pendingPolicyMutations?.isEmpty ?? false)
        let history = try store.files.targetRecords(store.state())[0]
        XCTAssertEqual(history.phase,"resolved")
        XCTAssertTrue(history.protection?.pendingPolicyMutations.isEmpty ?? false)
        XCTAssertEqual(history.protection?.quarantinedOrganizations,["org-2"])
        try store.logout(expected:cleared.revision)
        let reopened = try store.publish([],scope:actor,expected:store.state().revision,passwordUnlock:material,session:session,vault:vault(actor),includeVault:true)
        XCTAssertTrue(reopened.vault?.pendingPolicyMutations?.isEmpty ?? false)
        XCTAssertEqual(reopened.vault?.quarantinedOrganizations,["org-2"])
    }
    func testRuntimeBootstrapQueryIncludesForeignActorTargetWithoutWrites() throws {
        _ = try publish(actor)
        let (blocked, blockedSummary) = try record(target)
        _ = try begin(blocked, blockedSummary)
        let unrelated = SnapshotScope(server: actor.server, account: "unrelated")
        let (other, otherSummary) = try record(unrelated, id: String(repeating: "b", count: 32))
        _ = try begin(other, otherSummary)
        let queryID = String(repeating: "d", count: 32)
        let query = try JSONSerialization.data(withJSONObject: ["purpose":"mygo-runtime-target-block-query-v1", "queryId":queryID])
        let authority = RuntimeRecoveryAuthority(scope: target, generation: 10, deadlineUnixMS: 20000, leaseID: "fixture-query-lease", operationID: queryID, summaryHash: targetDigest(query))
        store = try SnapshotStore(directory: directory, keys: keys, runtimeRecoveryAuthorizer: { input in
            guard input.scope == self.target, input.generation == authority.generation,
                  input.operationID == queryID, input.summaryHash == authority.summaryHash else { throw SnapshotError.stale }
        })
        let before = try store.state()
        // The mutation-scoped API intentionally filters this foreign operation.
        XCTAssertTrue(try store.targetRecovery(operation:"targetRecoveryPending",scope:target,expected:before.revision,unlockKey:Data(),binding:nil,summary:nil,phase:nil,runtime:authority).1.isEmpty)
        let found = try store.targetRecovery(operation:"targetRecoveryRuntimePending",scope:target,expected:before.revision,unlockKey:Data(),binding:nil,summary:nil,phase:nil,runtime:authority)
        XCTAssertEqual(found.1.map(\.binding.operationId), [blocked.operationId])
        XCTAssertEqual(found.0.revision, before.revision)
        XCTAssertEqual(try store.state().snapshot?.header.id, before.snapshot?.header.id)
        let attempted = TargetRecoveryBinding(operationId:queryID,actor:target,target:target,storageRevision:before.revision,hostEpoch:8,authorizationEpoch:9,summaryHash:targetDigest(query))
        XCTAssertThrowsError(try store.targetRecovery(operation:"targetRecoveryBegin",scope:target,expected:before.revision,unlockKey:Data(),binding:attempted,summary:query,phase:nil,runtime:authority))
        XCTAssertThrowsError(try store.targetRecovery(operation:"targetRecoveryRuntimePending",scope:target,expected:before.revision,unlockKey:Data(),binding:attempted,summary:query,phase:nil,runtime:authority))
        XCTAssertThrowsError(try store.targetRecovery(operation:"targetRecoveryRuntimePending",scope:target,expected:"stale",unlockKey:Data(),binding:nil,summary:nil,phase:nil,runtime:authority))
        XCTAssertThrowsError(try store.targetRecovery(operation:"targetRecoveryRuntimePending",scope:actor,expected:before.revision,unlockKey:material.key,binding:nil,summary:nil,phase:nil))
        XCTAssertEqual(try store.state().revision, before.revision)
        XCTAssertEqual(try store.files.targetRecords(store.state()).count, 2)
    }
    func testFailedWriteAndMissingEvidenceKeepOriginalBarrier() throws {
        _ = try publish(actor)
        let (binding, summary) = try record(actor)
        let before = try store.state().revision
        keys.failCreate = true
        XCTAssertThrowsError(try begin(binding, summary))
        XCTAssertEqual(try store.state().revision, before)
        keys.failCreate = false
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: directory.path)
        XCTAssertThrowsError(try begin(binding, summary))
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        XCTAssertEqual(try store.state().revision, before)
        _ = try begin(binding, summary)
        XCTAssertThrowsError(try store.publish([], scope: actor, expected: store.state().revision, passwordUnlock: material, session: session, vault: vault(actor)))
        let p = try proof(binding)
        keys.failCreate = true
        XCTAssertThrowsError(try store.publish([], scope: actor, expected: p.expectedRevision, passwordUnlock: material, session: session, vault: vault(actor), targetResolution: p))
        XCTAssertEqual(try store.files.targetRecords(store.state())[0].phase, "prepared")
        keys.failCreate = false
        let p2 = try proof(binding)
        _ = try store.publish([], scope: actor, expected: p2.expectedRevision, passwordUnlock: material, session: session, vault: vault(actor), targetResolution: p2)
    }
}
