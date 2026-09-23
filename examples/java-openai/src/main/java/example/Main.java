package example;

import ai.stogas.verifier.Transport;
import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.models.chat.completions.ChatCompletionCreateParams;
import java.net.Proxy;
import java.time.Duration;

public final class Main {
    static OpenAIClient client(String baseUrl, String key) {
        return OpenAIOkHttpClient.builder()
                .baseUrl(baseUrl)
                .apiKey(key)
                .maxRetries(0)
                .followRedirects(false)
                .proxy(Proxy.NO_PROXY)
                .timeout(Duration.ofMinutes(45))
                .build();
    }

    public static void main(String[] args) {
        // An explicit URL can also use a separately managed verifier CLI.
        String external = System.getenv("STOGAS_BASE_URL");
        try (var transport = external == null ? new Transport() : null) {
            var client = client(external == null ? transport.baseUrl().toString() : external, System.getenv("STOGAS_API_KEY"));
            try {
                var request = ChatCompletionCreateParams.builder()
                    .model(System.getenv("STOGAS_MODEL"))
                    .addUserMessage("Say hello in one sentence.")
                    .build();
                try (var response = client.chat().completions().createStreaming(request)) {
                    response.stream().forEach(chunk -> chunk.choices().forEach(choice ->
                            choice.delta().content().ifPresent(System.out::print)));
                }
            } finally { client.close(); }
        }
    }
}
