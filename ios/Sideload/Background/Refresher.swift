import Foundation

/// Unattended refresh (ios/SPEC.md Section 8): never asks for input.
enum Refresher {
    /// Refreshes apps expiring within `within` seconds (all with nil) and
    /// returns a one-line summary.
    static func run(within: TimeInterval?) async -> String {
        guard CoreClient.hasAccount else {
            return "Sideload has no Apple account yet. Open the app and enter it in Settings."
        }
        var args: [String: Any] = [:]
        if let within { args["within"] = Int(within) }
        let response = await CoreClient.send("refresh", args: args, withAccount: true, askCode: nil)
        let results = response.decode([RefreshAppResult].self, at: "apps") ?? []
        await Notifications.scheduleExpiryWarning(apps: await CoreClient.apps())
        return summary(results: results, error: response.error)
    }

    static func summary(results: [RefreshAppResult], error: CoreError?) -> String {
        let refreshed = results.filter { $0.ok && $0.action != "skipped" }.map(\.name)
        let failed = results.filter { !$0.ok }
        if let error, failed.isEmpty {
            return "Refresh failed: \(error.localizedDescription)"
        }
        var parts: [String] = []
        if refreshed.isEmpty && failed.isEmpty {
            parts.append("Nothing needed a refresh.")
        }
        if !refreshed.isEmpty {
            parts.append("Refreshed \(refreshed.joined(separator: ", ")).")
        }
        if let first = failed.first {
            let names = failed.map(\.name).joined(separator: ", ")
            parts.append("Failed: \(names) (\(first.error?.localizedDescription ?? "unknown error")).")
        }
        return parts.joined(separator: " ")
    }
}
