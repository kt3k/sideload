import Foundation
import SwiftUI
import UIKit

/// UI state and the actions of the User Interface (ios/SPEC.md Section 10).
@MainActor
final class AppModel: ObservableObject {
    @Published var apps: [AppRecord] = []
    @Published var busy = false
    @Published var status = ""
    @Published var log: [String] = []
    @Published var alert: String?
    @Published var needsCode = false
    @Published var teams: [Team] = []
    @Published var device: DeviceInfo?

    /// The pending 2FA answer, shared with the core's thread.
    private nonisolated let prompt = CodePrompt()

    init() {
        Task { await reload() }
    }

    func reload() async {
        apps = await CoreClient.apps()
        await Notifications.scheduleExpiryWarning(apps: apps)
    }

    // MARK: - 2FA

    /// Called on the core's thread; blocks until the sheet is answered.
    nonisolated func askCode() -> String? {
        DispatchQueue.main.async {
            MainActor.assumeIsolated { self.needsCode = true }
        }
        return prompt.wait()
    }

    /// `code` nil cancels the login.
    func answerCode(_ code: String?) {
        needsCode = false
        prompt.answer(code)
    }

    // MARK: - Running operations

    private func appendLog(_ level: LogLevel, _ message: String) {
        switch level {
        case .phase:
            status = message
            log.append("== \(message)")
        case .warn:
            log.append("warning: \(message)")
        case .debug:
            log.append("debug: \(message)")
        case .info:
            status = message
            log.append(message)
        }
    }

    /// Runs `op` with the UI's log, 2FA prompt and busy state.
    private func run(_ op: String, args: [String: Any] = [:], withAccount: Bool) async -> CoreResponse {
        busy = true
        status = ""
        log = []
        UIApplication.shared.isIdleTimerDisabled = true
        defer {
            busy = false
            UIApplication.shared.isIdleTimerDisabled = false
        }
        let response = await CoreClient.send(
            op, args: args, withAccount: withAccount,
            onLog: { [weak self] level, message in
                DispatchQueue.main.async {
                    MainActor.assumeIsolated { self?.appendLog(level, message) }
                }
            },
            askCode: { [weak self] in self?.askCode() })
        if let error = response.error {
            log.append("error[\(error.code)]\(error.phase.map { " (\($0))" } ?? ""): \(error.message)")
        }
        return response
    }

    private func requireAccount() -> Bool {
        if CoreClient.hasAccount && !Settings.anisetteServer.isEmpty { return true }
        alert = "Enter your Apple ID, password and an anisette server in Settings first."
        return false
    }

    func install(_ url: URL) async {
        guard requireAccount() else { return }
        guard let copy = importCopy(of: url) else { return }
        defer { try? FileManager.default.removeItem(at: copy.deletingLastPathComponent()) }
        let response = await run("install", args: ["ipa": copy.path], withAccount: true)
        if let app = response.decode(AppRecord.self, at: "app") {
            alert = "Installed \(app.name)."
        } else if let error = response.error {
            alert = error.localizedDescription
        }
        await reload()
    }

    func refresh(_ bundleIds: [String]?) async {
        guard requireAccount() else { return }
        var args: [String: Any] = [:]
        if let bundleIds { args["bundle_ids"] = bundleIds }
        let response = await run("refresh", args: args, withAccount: true)
        let results = response.decode([RefreshAppResult].self, at: "apps") ?? []
        alert = Refresher.summary(results: results, error: response.error)
        await reload()
    }

    func forget(_ app: AppRecord) async {
        let response = await CoreClient.send("forget", args: ["bundle_id": app.bundleId])
        if let error = response.error { alert = error.localizedDescription }
        await reload()
    }

    func importPairing(_ url: URL) async {
        guard let copy = importCopy(of: url) else { return }
        defer { try? FileManager.default.removeItem(at: copy.deletingLastPathComponent()) }
        let response = await CoreClient.send("import_pairing", args: ["path": copy.path])
        if let error = response.error {
            alert = error.localizedDescription
        } else {
            alert = "Imported the pairing file. Turn on the VPN and check the connection."
        }
    }

    func checkConnection() async {
        let response = await run("connect", withAccount: false)
        device = response.decode(DeviceInfo.self)
        if let device {
            alert = "Connected to \(device.name) (iOS \(device.productVersion))."
        } else if let error = response.error {
            alert = error.localizedDescription
        }
    }

    func testLogin() async {
        guard requireAccount() else { return }
        let response = await run("login", withAccount: true)
        teams = response.decode([Team].self, at: "teams") ?? []
        if let error = response.error {
            alert = error.localizedDescription
        } else {
            alert = "Logged in. Teams: " + teams.map { "\($0.name ?? "?") (\($0.teamId))" }.joined(separator: ", ")
        }
    }

    func logOut() {
        Keychain.set(nil, for: Keychain.password)
        Keychain.set(nil, for: Keychain.session)
        alert = "Removed the saved password and session."
    }

    /// Copies a picked or opened file into a private temporary folder.
    private func importCopy(of url: URL) -> URL? {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let dest = dir.appendingPathComponent(url.lastPathComponent)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: url, to: dest)
            return dest
        } catch {
            alert = "Cannot read \(url.lastPathComponent): \(error.localizedDescription)"
            return nil
        }
    }
}

/// A blocking hand-off of one 2FA answer between the UI and the core thread.
final class CodePrompt: @unchecked Sendable {
    private let lock = NSLock()
    private let signal = DispatchSemaphore(value: 0)
    private var value: String?

    func wait() -> String? {
        signal.wait()
        lock.lock()
        defer { lock.unlock() }
        let v = value
        value = nil
        return v
    }

    func answer(_ code: String?) {
        lock.lock()
        value = code
        lock.unlock()
        signal.signal()
    }
}
