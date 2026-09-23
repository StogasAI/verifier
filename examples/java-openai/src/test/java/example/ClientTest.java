package example;

import com.openai.models.chat.completions.ChatCompletionCreateParams;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ClientTest {
    @Test void errorsAndRedirectsNeverReplayInference() throws Exception {
        for (boolean async : new boolean[]{false, true}) {
            for (int status : new int[]{200, 301, 302, 303, 307, 308, 408, 429, 503}) {
                var calls = new AtomicInteger();
                var path = new AtomicReference<String>();
                var authorization = new AtomicReference<String>();
                var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
                server.createContext("/", exchange -> {
                    calls.incrementAndGet();
                    path.set(exchange.getRequestURI().getPath());
                    authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
                    exchange.getRequestBody().readAllBytes();
                    exchange.getResponseHeaders().set("Location", "/must-not-follow");
                    exchange.getResponseHeaders().set("Retry-After", "0");
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    byte[] body = (status == 200
                            ? "{\"id\":\"example\",\"object\":\"chat.completion\",\"created\":1,\"model\":\"example\",\"choices\":[]}"
                            : "{\"error\":{\"message\":\"unavailable\",\"type\":\"provider_unavailable\"}}")
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(status, body.length);
                    try (var out = exchange.getResponseBody()) { out.write(body); }
                });
                server.start();
                var client = Main.client("http://127.0.0.1:" + server.getAddress().getPort() + "/cap/v1", "test-key");
                try {
                    var request = ChatCompletionCreateParams.builder().model("example").addUserMessage("hello").build();
                    if (status == 200) assertEquals("example", (async
                        ? client.async().chat().completions().create(request).join()
                        : client.chat().completions().create(request)).id());
                    else assertThrows(Exception.class, () -> {
                        if (async) client.async().chat().completions().create(request).join();
                        else client.chat().completions().create(request);
                    });
                    assertEquals(1, calls.get(), "status " + status);
                    assertEquals("/cap/v1/chat/completions", path.get());
                    assertEquals("Bearer test-key", authorization.get());
                } finally { client.close(); server.stop(0); }
            }
        }
    }
}
