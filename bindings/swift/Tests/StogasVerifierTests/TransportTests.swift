import Foundation
import XCTest
@testable import StogasVerifier

final class TransportTests: XCTestCase {
    func testNativeErrors() {
        for options in [TransportOptions(environment: "unsupported"), .init(security: "unsupported"), .init(maxConnections: 0)] {
            XCTAssertThrowsError(try Transport(options: options)) { error in
                guard case VerificationError.native(let code, _) = error else { return XCTFail("Expected native error, got \(error)") }
                XCTAssertFalse(code.isEmpty)
            }
        }
    }

    func testStagingLifetime() throws {
        guard ProcessInfo.processInfo.environment["STOGAS_NATIVE_STAGING_TEST"] == "1" else {
            throw XCTSkip("Requires explicit staging evidence qualification")
        }
        let transport = try Transport(options: .init(environment: "staging", security: "e2ee"))
        defer { transport.close() }
        XCTAssertEqual(transport.baseURL.host, "127.0.0.1")
        XCTAssertTrue(transport.baseURL.path.hasSuffix("/v1"))
        _ = try transport.refresh()
        transport.close()
        transport.close()
        XCTAssertThrowsError(try transport.refresh()) { error in
            XCTAssertEqual(error as? VerificationError, .closed)
        }
    }
}
