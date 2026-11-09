import Foundation

/// Log levels of `sideload_core.h`.
enum LogLevel: Int32 {
    case debug = 0, info = 1, warn = 2, phase = 3
}

/// An error reported by the core (ios/SPEC.md Section 9.2).
struct CoreError: Error, Decodable, LocalizedError, Equatable {
    let code: String
    let phase: String?
    let message: String

    var errorDescription: String? {
        if let phase { return "\(message) [\(code) in \(phase)]" }
        return "\(message) [\(code)]"
    }
}

/// A decoded response: `ok`, the raw `result`, the error and a new session.
struct CoreResponse {
    let ok: Bool
    let result: Any?
    let error: CoreError?
    let session: String?

    static func failure(_ message: String) -> CoreResponse {
        CoreResponse(ok: false, result: nil,
                     error: CoreError(code: "internal_error", phase: nil, message: message),
                     session: nil)
    }

    /// Decodes `result[key]` (or the whole result when `key` is nil).
    func decode<T: Decodable>(_ type: T.Type, at key: String? = nil) -> T? {
        guard var value = result else { return nil }
        if let key {
            guard let dict = value as? [String: Any], let inner = dict[key] else { return nil }
            value = inner
        }
        // Only arrays and objects are decoded; check first, because
        // `data(withJSONObject:)` raises on anything else.
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value)
        else { return nil }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try? decoder.decode(T.self, from: data)
    }
}

/// Holds the Swift callbacks while a C call runs.
private final class CallbackBox {
    let onLog: (LogLevel, String) -> Void
    let askCode: (() -> String?)?

    init(onLog: @escaping (LogLevel, String) -> Void, askCode: (() -> String?)?) {
        self.onLog = onLog
        self.askCode = askCode
    }
}

/// The bridge to the Rust core (`sideload_call`).
enum SideloadCore {
    /// Runs one request synchronously. Call it off the main thread.
    static func callBlocking(_ request: [String: Any],
                             onLog: @escaping (LogLevel, String) -> Void,
                             askCode: (() -> String?)?) -> CoreResponse {
        guard let data = try? JSONSerialization.data(withJSONObject: request),
              let json = String(data: data, encoding: .utf8)
        else { return .failure("cannot encode the request") }

        let box = CallbackBox(onLog: onLog, askCode: askCode)
        let context = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<CallbackBox>.fromOpaque(context).release() }

        let callbacks = SideloadCallbacks(
            context: context,
            log: { context, level, message in
                guard let context, let message else { return }
                let box = Unmanaged<CallbackBox>.fromOpaque(context).takeUnretainedValue()
                box.onLog(LogLevel(rawValue: level) ?? .info, String(cString: message))
            },
            two_factor_code: { context in
                guard let context else { return nil }
                let box = Unmanaged<CallbackBox>.fromOpaque(context).takeUnretainedValue()
                guard let code = box.askCode?() else { return nil }
                return strdup(code)
            }
        )

        guard let raw = json.withCString({ sideload_call($0, callbacks) }) else {
            return .failure("the core returned nothing")
        }
        defer { sideload_string_free(raw) }
        return parse(String(cString: raw))
    }

    /// Runs one request on a background queue.
    static func call(_ request: [String: Any],
                     onLog: @escaping (LogLevel, String) -> Void = { _, _ in },
                     askCode: (() -> String?)? = nil) async -> CoreResponse {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: callBlocking(request, onLog: onLog, askCode: askCode))
            }
        }
    }

    static func parse(_ text: String) -> CoreResponse {
        guard let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return .failure("the core returned invalid JSON") }
        var error: CoreError?
        if let e = object["error"] as? [String: Any] {
            error = CoreError(code: e["code"] as? String ?? "internal_error",
                              phase: e["phase"] as? String,
                              message: e["message"] as? String ?? "")
        }
        return CoreResponse(ok: object["ok"] as? Bool ?? false,
                            result: object["result"],
                            error: error,
                            session: object["session"] as? String)
    }
}
