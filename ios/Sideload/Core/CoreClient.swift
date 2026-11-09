import Foundation

/// User settings kept in UserDefaults (not secrets).
enum Settings {
    static let defaults = UserDefaults.standard

    static var appleId: String {
        get { defaults.string(forKey: "appleId") ?? "" }
        set { defaults.set(newValue, forKey: "appleId") }
    }
    static var teamId: String {
        get { defaults.string(forKey: "teamId") ?? "" }
        set { defaults.set(newValue, forKey: "teamId") }
    }
    static var anisetteServer: String {
        get { defaults.string(forKey: "anisetteServer") ?? "" }
        set { defaults.set(newValue, forKey: "anisetteServer") }
    }
    static var deviceHost: String {
        get { defaults.string(forKey: "deviceHost") ?? "" }
        set { defaults.set(newValue, forKey: "deviceHost") }
    }

    /// Unattended refreshes only touch apps expiring within this window
    /// (ios/SPEC.md Section 8).
    static let refreshThreshold: TimeInterval = 2 * 24 * 60 * 60
    static let suggestedAnisetteServer = "https://ani.sidestore.io"
    static let defaultDeviceHost = "10.7.0.1"
}

/// Builds requests (ios/SPEC.md Section 9.1) and stores new sessions.
enum CoreClient {
    /// The data directory (Section 4.1): Application Support/Sideload,
    /// excluded from backups.
    static var dataDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        var dir = base.appendingPathComponent("Sideload", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try? FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        return dir
    }

    static func config() -> [String: Any] {
        var c: [String: Any] = [
            "data_dir": dataDirectory.path,
            "self_bundle": Bundle.main.bundlePath,
        ]
        let anisette = Settings.anisetteServer.trimmingCharacters(in: .whitespaces)
        if !anisette.isEmpty { c["anisette_server"] = anisette }
        let host = Settings.deviceHost.trimmingCharacters(in: .whitespaces)
        if !host.isEmpty { c["device_host"] = host }
        return c
    }

    static func account() -> [String: Any] {
        var a: [String: Any] = ["apple_id": Settings.appleId.trimmingCharacters(in: .whitespaces)]
        if let p = Keychain.get(Keychain.password) { a["password"] = p }
        if let s = Keychain.get(Keychain.session) { a["session"] = s }
        let team = Settings.teamId.trimmingCharacters(in: .whitespaces)
        if !team.isEmpty { a["team_id"] = team }
        return a
    }

    static var hasAccount: Bool {
        !Settings.appleId.isEmpty && Keychain.get(Keychain.password) != nil
    }

    /// Sends `op`; saves any new session in the keychain.
    static func send(_ op: String,
                     args: [String: Any] = [:],
                     withAccount: Bool = false,
                     onLog: @escaping (LogLevel, String) -> Void = { _, _ in },
                     askCode: (() -> String?)? = nil) async -> CoreResponse {
        var request: [String: Any] = ["op": op, "config": config(), "args": args]
        if withAccount { request["account"] = account() }
        let response = await SideloadCore.call(request, onLog: onLog, askCode: askCode)
        if let session = response.session {
            Keychain.set(session, for: Keychain.session)
        }
        return response
    }

    static func apps() async -> [AppRecord] {
        await send("apps").decode([AppRecord].self, at: "apps") ?? []
    }
}
