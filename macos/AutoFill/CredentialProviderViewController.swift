// SPDX-License-Identifier: GPL-3.0-only
// AuthenticationServices flow informed by KeePassium (GPLv3); see THIRD_PARTY_NOTICES.md.
import AppKit
import AuthenticationServices
import LocalAuthentication
import OSLog

@objc(CredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private struct Service {
        let identifier: String
        let isURL: Bool
        init(_ value: ASCredentialServiceIdentifier) { identifier = value.identifier; isURL = value.type == .URL }
    }
    private enum Request {
        case configuration
        case list([Service])
        case identity(String, Service)
    }
    private enum Action { case list, configure, fill(String?) }
    private var request: Request = .configuration
    private var lease: SnapshotLease?
    private var authentication: LAContext?
    private var serial = UUID()
    private var finished = false
    private var busy = false
    private var message = ""
    private var search = ""
    private var page = 0
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private let logger = Logger(subsystem: "yz.sh.mygo-vaultwarden.autofill", category: "provider")

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 500, height: 400))
        preferredContentSize = NSSize(width: 500, height: 620)
    }
    override func viewDidLoad() {
        super.viewDidLoad()
        let distributed = DistributedNotificationCenter.default()
        let changes = distributed.addObserver(forName: SnapshotStore.changeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.invalidateLocal(L10n.t("autofill.err_snapshot_changed"))
        }
        observers.append((distributed, changes))
        let screen = distributed.addObserver(forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
            self?.screenLocked()
        }
        observers.append((distributed, screen))
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.sessionDidResignActiveNotification, NSWorkspace.screensDidSleepNotification] {
            observers.append((workspace, workspace.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in self?.screenLocked() }))
        }
    }
    deinit {
        authentication?.invalidate()
        for (center, token) in observers { center.removeObserver(token) }
    }
    override func viewDidDisappear() {
        super.viewDidDisappear()
        serial = UUID()
        authentication?.invalidate()
        authentication = nil
        lease = nil
    }

    private func begin(_ request: Request) {
        loadViewIfNeeded()
        self.request = request
        finished = false
        invalidateLocal("")
        logger.notice("Credential request opened; snapshot access requires authentication")
    }
    override func prepareInterfaceForExtensionConfiguration() { begin(.configuration) }
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        begin(.list(serviceIdentifiers.map(Service.init)))
    }
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        guard credentialRequest.type == .password else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed)); return
        }
        // Never prompt or use an in-memory key on the noninteractive callback.
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        guard credentialRequest.type == .password,
              let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity,
              let record = identity.recordIdentifier else {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound)); return
        }
        begin(.identity(record, Service(identity.serviceIdentifier)))
    }
    private func screenLocked() {
        invalidateLocal(L10n.t("autofill.err_system_locked"))
        DispatchQueue.global(qos: .userInitiated).async { try? SnapshotStore.sharedContainer().lock() }
    }
    private func invalidateLocal(_ reason: String) {
        guard !finished else { return }
        serial = UUID()
        authentication?.invalidate()
        authentication = nil
        lease = nil
        search = ""; page = 0
        busy = false
        message = reason
        render()
    }
    private func matches(_ credential: VaultCredential) -> Bool {
        switch request {
        case .configuration: return false
        case .list(let services):
            return !services.isEmpty && services.contains { credential.matches(serviceIdentifier: $0.identifier, isURL: $0.isURL) }
        case .identity(_, let service):
            return credential.quickFillMatches(serviceIdentifier: service.identifier, isURL: service.isURL)
        }
    }
    private func render() {
        view.subviews.forEach { $0.removeFromSuperview() }
        let stack = NSStackView()
        stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: view.bottomAnchor, constant: -24)
        ])
        func text(_ value: String, title: Bool = false) {
            let label = NSTextField(wrappingLabelWithString: value)
            label.font = .systemFont(ofSize: title ? 22 : 13, weight: title ? .semibold : .regular)
            stack.addArrangedSubview(label)
            label.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        func button(_ value: String, selector: Selector, tag: Int = 0) {
            let button = NSButton(title: value, target: self, action: selector)
            button.tag = tag; button.bezelStyle = .rounded; button.isEnabled = !busy
            stack.addArrangedSubview(button)
        }
        text("MyGo Vaultwarden", title: true)
        do {
            let state = try SnapshotStore.sharedContainer().state()
            if state.snapshot == nil {
                text(L10n.t("autofill.no_snapshot"))
                if case .configuration = request { button(L10n.t("autofill.finish_configuration"), selector: #selector(configure)) }
            } else {
                text(String(format: L10n.t("autofill.snapshot_description"), state.snapshot!.header.count))
                switch request {
                case .configuration: button(L10n.t("autofill.authenticate_update"), selector: #selector(configure))
                case .identity: button(L10n.t("autofill.authenticate_fill"), selector: #selector(fillIdentity))
                case .list:
                    if let lease {
                        let field = NSSearchField(frame: NSRect(x: 0, y: 0, width: 440, height: 28))
                        field.placeholderString = L10n.t("autofill.search_hint")
                        field.stringValue = search
                        field.sendsWholeSearchString = true
                        field.isEnabled = !busy
                        field.target = self; field.action = #selector(searchChanged(_:))
                        stack.addArrangedSubview(field)
                        let matches = lease.credentials.enumerated().filter {
                            self.matches($0.element) && (search.isEmpty || ($0.element.title + " " + $0.element.username).localizedCaseInsensitiveContains(search))
                        }
                        if matches.isEmpty { text(L10n.t("autofill.no_matching_credentials")) }
                        page = min(page, max(0, (matches.count - 1) / 5))
                        for (index, credential) in matches.dropFirst(page * 5).prefix(5) {
                            button("\(credential.title) · \(credential.username)", selector: #selector(fillSelection(_:)), tag: index)
                        }
                        if page > 0 { button(L10n.t("autofill.previous_page"), selector: #selector(changePage(_:)), tag: -1) }
                        if (page + 1) * 5 < matches.count { button(L10n.t("autofill.next_page"), selector: #selector(changePage(_:)), tag: 1) }
                    } else { button(L10n.t("autofill.authenticate_view"), selector: #selector(showCredentials)) }
                }
            }
        } catch { text((error as? SnapshotError ?? .configuration).message) }
        if !message.isEmpty { text(message) }
        let cancel = NSButton(title: L10n.t("autofill.cancel"), target: self, action: #selector(cancelRequest))
        cancel.bezelStyle = .rounded; cancel.keyEquivalent = "\u{1b}"
        stack.addArrangedSubview(cancel)
    }
    @objc private func searchChanged(_ field: NSSearchField) { search = field.stringValue; page = 0; render() }
    @objc private func changePage(_ button: NSButton) { page = max(0, page + button.tag); render() }
    @objc private func configure() {
        if let store = try? SnapshotStore.sharedContainer(), let state = try? store.state(), state.snapshot == nil {
            busy = true; render()
            let attempt = serial
            SnapshotIndex.schedule(store: store, lease: nil) { [weak self] success in
                DispatchQueue.main.async { self?.finishConfiguration(success, attempt: attempt) }
            }
        } else { authenticate(.configure) }
    }
    @objc private func showCredentials() { authenticate(.list) }
    @objc private func fillIdentity() { authenticate(.fill(nil)) }
    @objc private func fillSelection(_ button: NSButton) {
        guard let lease, lease.credentials.indices.contains(button.tag) else { return }
        authenticate(.fill(lease.credentials[button.tag].id))
    }
    private func authenticate(_ action: Action) {
        guard !busy, !finished else { return }
        let attempt = UUID(); serial = attempt
        let context = LAContext(); authentication = context
        let expectedRevision = lease?.revision
        busy = true; message = L10n.t("auth.status_waiting"); render()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let store = try SnapshotStore.sharedContainer()
                guard let scope = try store.state().snapshot?.header.scope else { throw SnapshotError.unavailable }
                let unlocked = try store.unlock(scope: scope, context: context, allowUI: true)
                context.invalidate()
                DispatchQueue.main.async {
                    guard let self, self.serial == attempt, !self.finished else { return }
                    self.authentication = nil
                    do {
                        if let expectedRevision, expectedRevision != unlocked.revision { throw SnapshotError.stale }
                        try store.withCurrentLease(unlocked) {}
                        switch action {
                        case .list:
                            self.lease = unlocked; self.busy = false; self.message = L10n.t("autofill.select_credential_hint"); self.render()
                            DispatchQueue.main.asyncAfter(deadline: .now() + 60) { [weak self] in
                                if self?.serial == attempt { self?.invalidateLocal(L10n.t("auth.err_expired")) }
                            }
                        case .configure:
                            SnapshotIndex.schedule(store: store, lease: unlocked) { [weak self] success in
                                DispatchQueue.main.async { self?.finishConfiguration(success, attempt: attempt) }
                            }
                        case .fill(let selectedID):
                            let id: String?
                            if case .identity(let record, _) = self.request {
                                id = SnapshotIndex.credentialID(recordID: record, snapshotID: unlocked.header.id)
                            } else { id = selectedID }
                            guard let id, let credential = unlocked.credentials.first(where: { $0.id == id }), self.matches(credential) else {
                                throw SnapshotError.stale
                            }
                            try store.withCurrentLease(unlocked) {
                                self.finished = true; self.lease = nil
                                self.extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: credential.username, password: credential.password), completionHandler: nil)
                                self.logger.notice("Authenticated snapshot credential submitted to system")
                            }
                        }
                    } catch { self.fail(error, attempt: attempt) }
                }
            } catch {
                context.invalidate()
                DispatchQueue.main.async { self?.fail(error, attempt: attempt) }
            }
        }
    }
    private func finishConfiguration(_ success: Bool, attempt: UUID) {
        guard serial == attempt, !finished else { return }
        if success {
            finished = true; lease = nil
            extensionContext.completeExtensionConfigurationRequest()
            logger.notice("Snapshot identity configuration acknowledged")
        } else { busy = false; message = L10n.t("autofill.err_update_incomplete"); render() }
    }
    private func fail(_ error: Error, attempt: UUID) {
        guard serial == attempt, !finished else { return }
        authentication?.invalidate(); authentication = nil; lease = nil; busy = false
        message = (error as? SnapshotError ?? .configuration).message
        render()
    }
    @objc private func cancelRequest() {
        finished = true; serial = UUID(); authentication?.invalidate(); authentication = nil; lease = nil
        extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
    }
}
