import SwiftUI
import UniformTypeIdentifiers

struct AppsView: View {
    @EnvironmentObject var model: AppModel
    @State private var importing = false

    static let ipaType = UTType(filenameExtension: "ipa") ?? .data

    var body: some View {
        NavigationStack {
            List {
                if model.apps.isEmpty {
                    Text("No apps yet. Tap + to install an IPA.")
                        .foregroundStyle(.secondary)
                }
                ForEach(model.apps) { app in
                    AppRow(app: app)
                        .swipeActions(edge: .trailing) {
                            if !app.isSelf {
                                Button("Forget", role: .destructive) {
                                    Task { await model.forget(app) }
                                }
                            }
                            Button("Refresh") {
                                Task { await model.refresh([app.bundleId]) }
                            }
                            .tint(.blue)
                        }
                }
            }
            .refreshable { await model.reload() }
            .safeAreaInset(edge: .bottom) { BusyBanner() }
            .navigationTitle("Sideload")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Refresh All") { Task { await model.refresh(nil) } }
                        .disabled(model.busy)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { importing = true } label: { Image(systemName: "plus") }
                        .disabled(model.busy)
                        .accessibilityLabel("Install an IPA")
                }
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [Self.ipaType]) { result in
                if case .success(let url) = result {
                    Task { await model.install(url) }
                }
            }
        }
    }
}

struct AppRow: View {
    let app: AppRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(app.name).font(.headline)
                if let version = app.version {
                    Text(version).font(.subheadline).foregroundStyle(.secondary)
                }
                if app.isSelf {
                    Text("this app").font(.caption2)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.quaternary, in: Capsule())
                }
            }
            Text(app.bundleId).font(.caption).foregroundStyle(.secondary)
            ExpiryText(expiry: app.expiry)
        }
        .padding(.vertical, 2)
    }
}

struct ExpiryText: View {
    let expiry: Date?

    var body: some View {
        if let expiry {
            let left = expiry.timeIntervalSinceNow
            let text = left <= 0
                ? "Expired"
                : "Expires " + RelativeDateTimeFormatter().localizedString(for: expiry, relativeTo: Date())
            Text(text)
                .font(.footnote)
                .foregroundStyle(left < 24 * 60 * 60 ? Color.red : (left < 3 * 24 * 60 * 60 ? .orange : .secondary))
        } else {
            Text("Expiry unknown").font(.footnote).foregroundStyle(.secondary)
        }
    }
}
