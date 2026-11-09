import AppIntents

/// The automation entry point (ios/SPEC.md Section 8, entry point 2):
/// usable from a Shortcuts personal automation, without opening the app.
struct RefreshAppsIntent: AppIntent {
    static var title: LocalizedStringResource = "Refresh Apps"
    static var description = IntentDescription(
        "Refreshes the apps installed with Sideload that expire within 2 days. Needs the loopback VPN to be on.")
    static var openAppWhenRun: Bool = false

    @Parameter(title: "Refresh All", description: "Refresh every app, not only those expiring soon.",
               default: false)
    var all: Bool

    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let summary = await Refresher.run(within: all ? nil : Settings.refreshThreshold)
        return .result(value: summary, dialog: IntentDialog(stringLiteral: summary))
    }
}

struct SideloadShortcuts: AppShortcutsProvider {
    @AppShortcutsBuilder
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: RefreshAppsIntent(),
                    phrases: ["Refresh apps with \(.applicationName)"],
                    shortTitle: "Refresh Apps",
                    systemImageName: "arrow.clockwise")
    }
}
