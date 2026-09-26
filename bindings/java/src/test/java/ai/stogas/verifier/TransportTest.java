package ai.stogas.verifier;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

class TransportTest {
    @Test void rejectsInvalidConfigurationWithNativeCodes() {
        for (var options : java.util.List.of(Map.of("security", "unsupported"), Map.of("environment", "unsupported"), Map.of("max_connections", 0))) {
            var error = assertThrows(Transport.VerificationException.class, () -> new Transport(options));
            assertFalse(error.code().isEmpty());
        }
    }
    @Test void realTransportClosesOnceAndGuardsCalls() {
        assumeTrue("1".equals(System.getenv("STOGAS_NATIVE_STAGING_TEST")));
        Transport transport;
        try (var opened = new Transport(Map.of("environment", "staging", "security", "e2ee"))) {
            transport = opened;
            assertEquals("127.0.0.1", opened.baseUrl().getHost());
            var one = CompletableFuture.runAsync(opened::refresh);
            var two = CompletableFuture.runAsync(opened::refresh);
            CompletableFuture.allOf(one, two).join();
        }
        transport.close();
        assertThrows(IllegalStateException.class, transport::refresh);
    }
}
