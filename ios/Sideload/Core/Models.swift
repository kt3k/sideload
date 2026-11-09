import Foundation

/// A managed app (ios/SPEC.md Section 4.5).
struct AppRecord: Decodable, Identifiable, Equatable {
    let bundleId: String
    let originalBundleId: String
    let name: String
    let version: String?
    let teamId: String
    let certificateSha256: String?
    let profileExpires: Double?
    let installedAt: Double?
    let refreshedAt: Double?
    let source: String

    var id: String { bundleId }
    var isSelf: Bool { source == "self" }
    var expiry: Date? { profileExpires.map { Date(timeIntervalSince1970: $0) } }
}

struct RefreshAppResult: Decodable, Identifiable {
    let bundleId: String
    let name: String
    let ok: Bool
    let action: String?
    let error: CoreError?

    var id: String { bundleId }
}

struct DeviceInfo: Decodable {
    let udid: String
    let name: String
    let productVersion: String
}

struct Team: Decodable, Identifiable {
    let teamId: String
    let name: String?

    var id: String { teamId }
}
