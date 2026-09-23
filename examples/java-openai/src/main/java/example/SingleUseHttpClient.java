package example;

import com.openai.core.RequestOptions;
import com.openai.core.http.HttpClient;
import com.openai.core.http.HttpRequest;
import com.openai.core.http.HttpRequestBody;
import com.openai.core.http.HttpResponse;
import java.io.OutputStream;
import java.util.concurrent.CompletableFuture;

/** Prevents the HTTP engine from replaying an inference body. */
public record SingleUseHttpClient(HttpClient delegate) implements HttpClient {
    private static HttpRequest singleUse(HttpRequest request) {
        var body = request.body();
        if (body == null) return request;
        return request.toBuilder().body(new HttpRequestBody() {
            public void writeTo(OutputStream output) { body.writeTo(output); }
            public String contentType() { return body.contentType(); }
            public long contentLength() { return body.contentLength(); }
            public boolean repeatable() { return false; }
            public void close() { body.close(); }
        }).build();
    }
    public HttpResponse execute(HttpRequest request, RequestOptions options) {
        return delegate.execute(singleUse(request), options);
    }
    public CompletableFuture<HttpResponse> executeAsync(HttpRequest request, RequestOptions options) {
        return delegate.executeAsync(singleUse(request), options);
    }
    public void close() { delegate.close(); }
}
