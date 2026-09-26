import CStogas
import Foundation

public struct TransportOptions: Encodable, Sendable {
    public var environment: String
    public var security: String
    public var maxConnections: UInt32
    public var baseURL: String?

    public init(environment: String = "prod", security: String = "tls", maxConnections: UInt32 = 4, baseURL: String? = nil) {
        self.environment = environment
        self.security = security
        self.maxConnections = maxConnections
        self.baseURL = baseURL
    }

    enum CodingKeys: String, CodingKey {
        case environment, security
        case maxConnections = "max_connections"
        case baseURL = "base_url"
    }
}

public enum VerificationError: Error, Equatable {
    case native(code: String, message: String)
    case closed
    case unsupportedABI
    case invalidResponse
}

/// A reusable confidential transport. Startup and refresh perform blocking setup work.
/// Use its URL with an HTTP client with automatic retries and proxies disabled.
public final class Transport: @unchecked Sendable {
    public let baseURL: URL
    private let lock = NSLock()
    // The lock serializes every use and release of this native handle.
    private var handle: OpaquePointer?

    public init(options: TransportOptions = .init()) throws {
        guard stogas_verifier_abi_version() == 1 else { throw VerificationError.unsupportedABI }
        let bytes = try JSONEncoder().encode(options)
        var pointer: OpaquePointer?
        let response = bytes.withUnsafeBytes { buffer in
            stogas_transport_start(buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count, &pointer)
        }
        do {
            let value: Started = try nativeResult(response)
            guard let pointer, let url = URL(string: value.baseURL) else { throw VerificationError.invalidResponse }
            self.baseURL = url
            self.handle = pointer
        } catch {
            if let pointer { stogas_transport_free(pointer) }
            throw error
        }
    }

    /// Refresh evidence without repeating any inference.
    @discardableResult public func refresh() throws -> Bool {
        try lock.withLock {
            guard let handle else { throw VerificationError.closed }
            return try nativeResult(stogas_transport_refresh(handle))
        }
    }

    /// Finish HTTP clients first. Native cleanup waits at most five seconds and runs once.
    public func close() {
        lock.withLock {
            if let handle {
                self.handle = nil
                stogas_transport_close(handle)
                stogas_transport_free(handle)
            }
        }
    }

    deinit { if let handle { stogas_transport_free(handle) } }
}

private struct Started: Decodable {
    let baseURL: String
    enum CodingKeys: String, CodingKey { case baseURL = "base_url" }
}

private struct NativeEnvelope<Value: Decodable>: Decodable {
    let ok: Bool
    let value: Value?
    let error: String?
    let code: String?
}

private func nativeResult<Value: Decodable>(_ pointer: UnsafeMutablePointer<CChar>?) throws -> Value {
    guard let pointer else { throw VerificationError.invalidResponse }
    defer { stogas_verifier_string_free(pointer) }
    let data = Data(String(cString: pointer).utf8)
    let envelope = try JSONDecoder().decode(NativeEnvelope<Value>.self, from: data)
    guard envelope.ok else {
        guard let code = envelope.code, let message = envelope.error else { throw VerificationError.invalidResponse }
        throw VerificationError.native(code: code, message: message)
    }
    guard let value = envelope.value else { throw VerificationError.invalidResponse }
    return value
}
