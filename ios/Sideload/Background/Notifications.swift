import Foundation
import UserNotifications

/// Expiry warning (ios/SPEC.md Section 8, entry point 4).
enum Notifications {
    private static let expiryId = "expiry-warning"

    static func requestAuthorization() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// Schedules one notification a day before the earliest expiry,
    /// replacing the previous one.
    static func scheduleExpiryWarning(apps: [AppRecord]) async {
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [expiryId])
        guard let soonest = apps.compactMap({ app in app.expiry.map { (app, $0) } })
            .min(by: { $0.1 < $1.1 })
        else { return }
        let fireAt = soonest.1.addingTimeInterval(-24 * 60 * 60)
        guard fireAt > Date() else { return }

        let content = UNMutableNotificationContent()
        content.title = "\(soonest.0.name) expires tomorrow"
        content.body = "Automatic refresh has not succeeded. Turn on the VPN and open Sideload to refresh."
        let components = Calendar.current.dateComponents(
            [.year, .month, .day, .hour, .minute], from: fireAt)
        let trigger = UNCalendarNotificationTrigger(dateMatching: components, repeats: false)
        try? await center.add(UNNotificationRequest(identifier: expiryId, content: content, trigger: trigger))
    }
}
