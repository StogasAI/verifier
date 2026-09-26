import Foundation
import StogasVerifier

final class NoRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

@main struct Example {
    static func main() async throws {
        let environment = ProcessInfo.processInfo.environment
        // An explicit URL can also use a separately managed verifier CLI.
        let transport: Transport?
        if environment["STOGAS_BASE_URL"] == nil {
            transport = try await Task.detached { try Transport() }.value
        } else {
            transport = nil
        }
        defer { transport?.close() }
        let base = environment["STOGAS_BASE_URL"] ?? transport!.baseURL.absoluteString
        guard let key = environment["STOGAS_API_KEY"],
              let model = environment["STOGAS_MODEL"],
              let url = URL(string: base + "/chat/completions") else {
            throw URLError(.badURL)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.timeoutIntervalForRequest = 45 * 60
        configuration.timeoutIntervalForResource = 45 * 60
        let session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer " + key, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "model": model, "messages": [["role": "user", "content": "Say hello in one sentence."]], "stream": true
        ])
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        // The verifier releases Chat Completions' terminal marker only after verification.
        // URLSession may accept an interrupted chunked body as EOF, so EOF alone is not success.
        var completed = false
        for try await line in bytes.lines {
            try Task.checkCancellation()
            if line == "data: [DONE]" { completed = true }
            else if line.hasPrefix("data:") {
                let data = Data(line.dropFirst(5).utf8)
                let event = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                guard event != nil, event?["error"] == nil else { throw URLError(.badServerResponse) }
            }
            print(line)
        }
        try Task.checkCancellation()
        guard completed else { throw URLError(.networkConnectionLost) }
    }
}
