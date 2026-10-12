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
    // A single-credential fill starts system authentication once, as soon as the sheet is visible.
    private var pendingAutoFill = false
    private var message = ""
    private var search = ""
    private var page = 0
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private let logger = Logger(subsystem: "yz.sh.mygo-vaultwarden.autofill", category: "provider")

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 420))
        preferredContentSize = NSSize(width: 420, height: 420)
    }
    override func viewDidLoad() {
        super.viewDidLoad()
        let distributed = DistributedNotificationCenter.default()
        let changes = distributed.addObserver(forName: SnapshotStore.changeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.snapshotChanged()
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
    override func viewDidAppear() {
        super.viewDidAppear()
        startPendingAutoFill()
    }
    override func viewDidDisappear() {
        super.viewDidDisappear()
        pendingAutoFill = false
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
        if case .identity = request {
            pendingAutoFill = true
            if view.window != nil { DispatchQueue.main.async { [weak self] in self?.startPendingAutoFill() } }
        } else { pendingAutoFill = false }
    }
    private func startPendingAutoFill() {
        guard pendingAutoFill, case .identity = request, !busy, !finished else { return }
        pendingAutoFill = false
        // Without a snapshot the sheet only explains the missing data; nothing to authenticate.
        guard (try? SnapshotStore.sharedContainer().state().snapshot) != nil else { return }
        authenticate(.fill(nil))
    }
    // Unlocked or in-flight work is discarded on any snapshot change; an idle sheet only refreshes.
    private func snapshotChanged() {
        guard !finished else { return }
        if lease != nil || busy { invalidateLocal(L10n.t("autofill.err_snapshot_changed")) } else { render() }
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
    private func appIcon() -> NSImage {
        Bundle.main.image(forResource: "AppIcon") ?? NSImage(named: NSImage.applicationIconName) ?? NSImage()
    }
    private func render() {
        view.subviews.forEach { $0.removeFromSuperview() }

        let icon = NSImageView(image: appIcon())
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.translatesAutoresizingMaskIntoConstraints = false
        let title = NSTextField(labelWithString: "MyGo Vaultwarden")
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        let subtitle = NSTextField(labelWithString: L10n.t("autofill.subtitle"))
        subtitle.font = .systemFont(ofSize: 12); subtitle.textColor = .secondaryLabelColor
        let titles = NSStackView(views: [title, subtitle])
        titles.orientation = .vertical; titles.alignment = .leading; titles.spacing = 2
        let header = NSStackView(views: [icon, titles])
        header.orientation = .horizontal; header.alignment = .centerY; header.spacing = 14
        icon.widthAnchor.constraint(equalToConstant: 56).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 56).isActive = true

        let body = NSStackView()
        body.orientation = .vertical; body.alignment = .leading; body.spacing = 12

        func text(_ value: String, secondary: Bool = false) {
            let label = NSTextField(wrappingLabelWithString: value)
            label.font = .systemFont(ofSize: 13)
            label.textColor = secondary ? .secondaryLabelColor : .labelColor
            body.addArrangedSubview(label)
            label.widthAnchor.constraint(equalTo: body.widthAnchor).isActive = true
        }
        func button(_ value: String, selector: Selector, tag: Int = 0, primary: Bool = false) {
            let button = NSButton(title: value, target: self, action: selector)
            button.tag = tag; button.bezelStyle = .rounded; button.controlSize = .large; button.isEnabled = !busy
            if primary { button.keyEquivalent = "\r" }
            body.addArrangedSubview(button)
            button.widthAnchor.constraint(equalTo: body.widthAnchor).isActive = true
        }
        do {
            let state = try SnapshotStore.sharedContainer().state()
            if state.snapshot == nil {
                text(L10n.t("autofill.no_snapshot"))
                if case .configuration = request { button(L10n.t("autofill.finish_configuration"), selector: #selector(configure), primary: true) }
            } else {
                text(String(format: L10n.t("autofill.snapshot_description"), state.snapshot!.header.count), secondary: true)
                switch request {
                case .configuration: button(L10n.t("autofill.authenticate_update"), selector: #selector(configure), primary: true)
                case .identity: button(L10n.t("autofill.authenticate_fill"), selector: #selector(fillIdentity), primary: true)
                case .list:
                    if let lease {
                        let field = NSSearchField()
                        field.placeholderString = L10n.t("autofill.search_hint")
                        field.stringValue = search
                        field.sendsWholeSearchString = true
                        field.isEnabled = !busy
                        field.target = self; field.action = #selector(searchChanged(_:))
                        body.addArrangedSubview(field)
                        field.widthAnchor.constraint(equalTo: body.widthAnchor).isActive = true
                        let matches = lease.credentials.enumerated().filter {
                            self.matches($0.element) && (search.isEmpty || ($0.element.title + " " + $0.element.username).localizedCaseInsensitiveContains(search))
                        }
                        if matches.isEmpty { text(L10n.t("autofill.no_matching_credentials"), secondary: true) }
                        page = min(page, max(0, (matches.count - 1) / 5))
                        for (index, credential) in matches.dropFirst(page * 5).prefix(5) {
                            button("\(credential.title) · \(credential.username)", selector: #selector(fillSelection(_:)), tag: index)
                        }
                        if page > 0 { button(L10n.t("autofill.previous_page"), selector: #selector(changePage(_:)), tag: -1) }
                        if (page + 1) * 5 < matches.count { button(L10n.t("autofill.next_page"), selector: #selector(changePage(_:)), tag: 1) }
                    } else { button(L10n.t("autofill.authenticate_view"), selector: #selector(showCredentials), primary: true) }
                }
            }
        } catch { text((error as? SnapshotError ?? .configuration).message) }
        if !message.isEmpty { text(message, secondary: true) }

        let divider = NSBox(); divider.boxType = .separator
        let cancel = NSButton(title: L10n.t("autofill.cancel"), target: self, action: #selector(cancelRequest))
        cancel.bezelStyle = .rounded; cancel.controlSize = .large; cancel.keyEquivalent = "\u{1b}"
        let footer = NSStackView(views: [NSView(), cancel])
        footer.orientation = .horizontal

        let stack = NSStackView(views: [header, divider, body])
        stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false
        footer.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack); view.addSubview(footer)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -28),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 40),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: footer.topAnchor, constant: -16),
            divider.widthAnchor.constraint(equalTo: stack.widthAnchor),
            body.widthAnchor.constraint(equalTo: stack.widthAnchor),
            footer.leadingAnchor.constraint(equalTo: stack.leadingAnchor),
            footer.trailingAnchor.constraint(equalTo: stack.trailingAnchor),
            footer.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -24)
        ])
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
                                if AutoFillPreferences.copyTOTP, let totp = credential.totp, !totp.isEmpty {
                                    do {
                                        let code = try TOTP.generate(totp, now: Date()).code
                                        if !NativeSensitivePasteboard(NSPasteboard.general).replace(secret: code, owner: UUID().uuidString) {
                                            self.logger.error("Verification code clipboard write failed")
                                        }
                                    } catch { self.logger.error("Verification code generation failed") }
                                }
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
