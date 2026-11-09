import SwiftUI

@main
struct SideloadApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        BackgroundRefresh.register()
        Notifications.requestAuthorization()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .onOpenURL { url in
                    Task {
                        switch url.pathExtension.lowercased() {
                        case "ipa": await model.install(url)
                        case "mobiledevicepairing", "plist": await model.importPairing(url)
                        default: model.alert = "Sideload cannot open \(url.lastPathComponent)."
                        }
                    }
                }
        }
        .onChange(of: scenePhase) { phase in
            if phase == .background { BackgroundRefresh.schedule() }
        }
    }
}
