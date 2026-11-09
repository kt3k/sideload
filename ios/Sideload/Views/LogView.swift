import SwiftUI

struct LogView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(model.log.isEmpty ? "No operation has run yet." : model.log.joined(separator: "\n"))
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .safeAreaInset(edge: .bottom) { BusyBanner() }
            .navigationTitle("Log")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Copy") { UIPasteboard.general.string = model.log.joined(separator: "\n") }
                        .disabled(model.log.isEmpty)
                }
            }
        }
    }
}
