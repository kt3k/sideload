import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage("appleId") private var appleId = ""
    @AppStorage("teamId") private var teamId = ""
    @AppStorage("anisetteServer") private var anisetteServer = ""
    @AppStorage("anisetteMode") private var anisetteMode = "remote"
    @AppStorage("deviceHost") private var deviceHost = ""
    @State private var password = ""
    @State private var hasPassword = Keychain.get(Keychain.password) != nil
    @State private var importingPairing = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Apple ID", text: $appleId)
                        .textContentType(.username)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField(hasPassword ? "Password (saved)" : "Password", text: $password)
                        .textContentType(.password)
                        .onSubmit(savePassword)
                    TextField("Team ID (optional)", text: $teamId)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                    Button("Save Password and Test Login") {
                        savePassword()
                        Task { await model.testLogin() }
                    }
                    .disabled(model.busy || appleId.isEmpty || (password.isEmpty && !hasPassword))
                    Button("Log Out", role: .destructive) {
                        model.logOut()
                        hasPassword = false
                    }
                } header: {
                    Text("Apple Account")
                } footer: {
                    Text("The password is kept in this device's keychain so that apps can be refreshed automatically. It is sent only to Apple.")
                }

                Section {
                    Picker("Generate", selection: $anisetteMode) {
                        Text("On Device (Experimental)").tag("local")
                        Text("Remote Server").tag("remote")
                    }
                    .disabled(model.busy)
                    if anisetteMode == "remote" {
                        TextField("https://...", text: $anisetteServer)
                            .keyboardType(.URL)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        if anisetteServer.isEmpty {
                            Button("Use \(Settings.suggestedAnisetteServer)") {
                                anisetteServer = Settings.suggestedAnisetteServer
                            }
                        }
                    }
                    Button("Check Anisette") { Task { await model.checkAnisette() } }
                        .disabled(model.busy || (anisetteMode == "remote" && anisetteServer.trimmingCharacters(in: .whitespaces).isEmpty))
                } header: {
                    Text("Anisette")
                } footer: {
                    if anisetteMode == "local" {
                        Text("Experimental. Generates Apple's device identification data on this device. Initial setup downloads Apple components and contacts Apple. Keep this app open for the first check. This verifies data generation, not Apple account sign-in. Your Apple ID and password are not needed for this check.")
                    } else {
                        Text("An anisette server is a third party that generates Apple's device identification data for logging in. It does not receive your password. Local failures never switch to a remote server automatically.")
                    }
                }

                Section {
                    TextField(Settings.defaultDeviceHost, text: $deviceHost)
                        .keyboardType(.numbersAndPunctuation)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Import Pairing File") { importingPairing = true }
                    Button("Check Connection") { Task { await model.checkConnection() } }
                        .disabled(model.busy)
                    if let device = model.device {
                        LabeledContent("Device", value: device.name)
                        LabeledContent("iOS", value: device.productVersion)
                        LabeledContent("UDID", value: device.udid)
                    }
                } header: {
                    Text("Device Connection")
                } footer: {
                    Text("Sideload talks to this device through a loopback VPN such as LocalDevVPN; turn it on before installing or refreshing. The pairing file is put here by `sideload install Sideload.ipa` or `sideload sidestore pairing-file` on a computer; a file from another tool can be imported.")
                }

                Section {
                    Text("To refresh automatically, create a personal automation in the Shortcuts app (for example daily, or when the device starts charging) that turns on the VPN and runs Sideload's \"Refresh Apps\" action.")
                        .font(.footnote)
                    if let url = URL(string: "shortcuts://") {
                        Link("Open Shortcuts", destination: url)
                    }
                } header: {
                    Text("Automatic Refresh")
                }

                Section {
                    LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?")
                    LabeledContent("Bundle ID", value: Bundle.main.bundleIdentifier ?? "?")
                } header: {
                    Text("About")
                }
            }
            .safeAreaInset(edge: .bottom) { BusyBanner() }
            .navigationTitle("Settings")
            .fileImporter(isPresented: $importingPairing, allowedContentTypes: [.data, .propertyList]) { result in
                if case .success(let url) = result {
                    Task { await model.importPairing(url) }
                }
            }
        }
    }

    private func savePassword() {
        guard !password.isEmpty else { return }
        Keychain.set(password, for: Keychain.password)
        Keychain.set(nil, for: Keychain.session)
        password = ""
        hasPassword = true
    }
}
