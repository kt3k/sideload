import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        TabView {
            AppsView()
                .tabItem { Label("Apps", systemImage: "square.stack.3d.up") }
            LogView()
                .tabItem { Label("Log", systemImage: "text.alignleft") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
        .sheet(isPresented: Binding(get: { model.needsCode }, set: { shown in
            if !shown && model.needsCode { model.answerCode(nil) }
        })) {
            TwoFactorView()
                .environmentObject(model)
        }
        .alert("Sideload", isPresented: Binding(get: { model.alert != nil },
                                                set: { if !$0 { model.alert = nil } })) {
            Button("OK") { model.alert = nil }
        } message: {
            Text(model.alert ?? "")
        }
    }
}

struct TwoFactorView: View {
    @EnvironmentObject var model: AppModel
    @State private var code = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Verification code", text: $code)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                } footer: {
                    Text("Enter the code Apple sent to your trusted device or phone. If a code has already arrived, use it before requesting another.")
                }
                Section {
                    Button("Send a New Code") { model.answerCode("resend") }
                }
            }
            .navigationTitle("Two-Factor Authentication")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { model.answerCode(nil) }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Verify") { model.answerCode(code) }
                        .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .onAppear { code = "" }
        }
        .interactiveDismissDisabled()
    }
}

/// A banner with the current phase while an operation runs.
struct BusyBanner: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        if model.busy {
            HStack(spacing: 12) {
                ProgressView()
                Text(model.status.isEmpty ? "Working..." : model.status)
                    .font(.footnote)
                    .lineLimit(2)
                Spacer()
            }
            .padding(12)
            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
            .padding(.horizontal)
        }
    }
}
