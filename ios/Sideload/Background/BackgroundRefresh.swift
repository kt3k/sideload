import BackgroundTasks
import Foundation

/// Opportunistic background refresh (ios/SPEC.md Section 8, entry point 3).
enum BackgroundRefresh {
    /// Listed in Info.plist `BGTaskSchedulerPermittedIdentifiers`.
    static let identifier = "io.github.kt3k.sideload.refresh"

    /// Must run before the app finishes launching.
    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            handle(task)
        }
    }

    static func schedule() {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 6 * 60 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    private static func handle(_ task: BGTask) {
        schedule()
        let work = Task {
            _ = await Refresher.run(within: Settings.refreshThreshold)
            task.setTaskCompleted(success: true)
        }
        task.expirationHandler = {
            // The core cannot be interrupted mid-call; report failure.
            work.cancel()
            task.setTaskCompleted(success: false)
        }
    }
}
