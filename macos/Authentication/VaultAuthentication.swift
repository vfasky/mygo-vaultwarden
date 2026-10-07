// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import AuthenticationServices
import Foundation

func b64(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

// The platform requests below do not request any WebAuthn extensions. Emit the
// actual empty result, never an invented AppID success. Vaultwarden 1.37.4's
// PublicKeyCredentialCopy requires an object-valued top-level `extensions`.
// Keep this pure encoder shared by the system callback and serialization tests.
enum VaultCredentialResponse {
    case assertion(authenticatorData: Data, signature: Data, userHandle: Data)
    case registration(attestationObject: Data)
}

func encodeVaultCredential(id: Data, clientDataJSON: Data, response: VaultCredentialResponse) throws -> Data {
    var fields: [String: Any] = ["clientDataJSON": b64(clientDataJSON)]
    switch response {
    case let .assertion(authenticatorData, signature, userHandle):
        fields["authenticatorData"] = b64(authenticatorData)
        fields["signature"] = b64(signature)
        fields["userHandle"] = b64(userHandle)
    case let .registration(attestationObject):
        fields["attestationObject"] = b64(attestationObject)
    }
    return try JSONSerialization.data(withJSONObject: [
        "id": b64(id), "rawId": b64(id), "type": "public-key",
        "extensions": [String: Any](), "response": fields
    ])
}

// Retain one bridge per UI authentication lease. Call cancel on lock/switch.
// Integration must configure signed associated domains (webcredentials:RP).
@available(macOS 13.0, *)
@MainActor
final class VaultWebAuthn: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private var controller: ASAuthorizationController?
    private var completion: ((Result<Data, Error>) -> Void)?
    private let window: NSWindow
    private var timeout: Task<Void, Never>?
    init(window: NSWindow) { self.window = window }
    func start(rp: String, challenge: Data, userID: Data?, userName: String?, allowed: [Data], excluded: [Data] = [], completion: @escaping (Result<Data, Error>) -> Void) {
        cancel()
        self.completion = completion
        guard !rp.isEmpty, challenge.count >= 16 else { finish(.failure(NSError(domain: "MyGo.Authentication", code: 1))); return }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rp)
        let request: ASAuthorizationRequest
        if let userID = userID, let userName = userName {
            let registration = provider.createCredentialRegistrationRequest(challenge: challenge, name: userName, userID: userID)
            registration.userVerificationPreference = .preferred
            if #available(macOS 14.0, *) {
                registration.excludedCredentials = excluded.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
            } else if !excluded.isEmpty {
                finish(.failure(NSError(domain: "MyGo.Authentication", code: 5))); return
            }
            request = registration
        } else {
            let assertion = provider.createCredentialAssertionRequest(challenge: challenge)
            assertion.allowedCredentials = allowed.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
            assertion.userVerificationPreference = .preferred
            request = assertion
        }
        let controller = ASAuthorizationController(authorizationRequests: [request])
        self.controller = controller
        controller.delegate = self
        controller.presentationContextProvider = self
        timeout = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: 120_000_000_000) } catch { return }
            self?.cancel()
        }
        controller.performRequests()
    }
    func cancel() {
        controller?.cancel()
        finish(.failure(NSError(domain: ASAuthorizationError.errorDomain, code: ASAuthorizationError.canceled.rawValue)))
    }
    private func finish(_ result: Result<Data, Error>) {
        let callback = completion
        completion = nil; controller = nil; timeout?.cancel(); timeout = nil
        callback?(result)
    }
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { window }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        guard controller === self.controller else { return }
        finish(.failure(error))
    }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard controller === self.controller else { return }
        do {
            let encoded: Data
            if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
                encoded = try encodeVaultCredential(id: credential.credentialID, clientDataJSON: credential.rawClientDataJSON,
                    response: .assertion(authenticatorData: credential.rawAuthenticatorData, signature: credential.signature, userHandle: credential.userID))
            } else if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration, let attestation = credential.rawAttestationObject {
                encoded = try encodeVaultCredential(id: credential.credentialID, clientDataJSON: credential.rawClientDataJSON,
                    response: .registration(attestationObject: attestation))
            } else { finish(.failure(NSError(domain: "MyGo.Authentication", code: 2))); return }
            finish(.success(encoded))
        } catch { finish(.failure(error)) }
    }
}

@available(macOS 12.0, *)
@MainActor
final class VaultAuthenticationBrowser: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let window: NSWindow
    private var session: ASWebAuthenticationSession?
    private var generation: UInt64 = 0
    private var completion: ((Result<URL, Error>) -> Void)?
    init(window: NSWindow) { self.window = window }
    func start(url: URL, callbackScheme: String, completion: @escaping (Result<URL, Error>) -> Void) {
        cancel(); generation &+= 1
        self.completion = completion
        let active = generation
        let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme) { [weak self] url, error in
            Task { @MainActor in
                guard let self = self, self.generation == active else { return }
                self.session = nil
                self.generation &+= 1
                let callback = self.completion; self.completion = nil
                if let url = url { callback?(.success(url)) }
                else { callback?(.failure(error ?? NSError(domain: "MyGo.Authentication", code: 3))) }
            }
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = true
        self.session = session
        if !session.start() { self.session = nil; self.completion = nil; generation &+= 1; completion(.failure(NSError(domain: "MyGo.Authentication", code: 4))) }
    }
    func cancel() {
        generation &+= 1; session?.cancel(); session = nil
        let callback = completion; completion = nil
        callback?(.failure(NSError(domain: ASWebAuthenticationSessionError.errorDomain, code: ASWebAuthenticationSessionError.canceledLogin.rawValue)))
    }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { window }
}
