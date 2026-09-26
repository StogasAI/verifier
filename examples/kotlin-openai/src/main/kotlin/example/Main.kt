package example

import ai.stogas.verifier.Transport
import com.openai.client.okhttp.OpenAIOkHttpClient
import com.openai.core.RequestOptions
import com.openai.core.http.HttpClient
import com.openai.core.http.HttpRequest
import com.openai.core.http.HttpRequestBody
import java.io.OutputStream
import com.openai.models.chat.completions.ChatCompletionCreateParams
import java.net.Proxy
import java.time.Duration

class SingleUseHttpClient(private val delegate: HttpClient) : HttpClient by delegate {
    private fun singleUse(request: HttpRequest): HttpRequest {
        val body = request.body ?: return request
        return request.toBuilder().body(object : HttpRequestBody {
            override fun writeTo(output: OutputStream) = body.writeTo(output)
            override fun contentType() = body.contentType()
            override fun contentLength() = body.contentLength()
            override fun repeatable() = false
            override fun close() = body.close()
        }).build()
    }
    override fun execute(request: HttpRequest, options: RequestOptions) =
        delegate.execute(singleUse(request), options)
    override fun executeAsync(request: HttpRequest, options: RequestOptions) =
        delegate.executeAsync(singleUse(request), options)
}

fun main() {
    // Set an explicit URL only when using a separately managed verifier CLI.
    val external = System.getenv("STOGAS_BASE_URL")
    (if (external == null) Transport() else null).use { transport ->
        val client = OpenAIOkHttpClient.builder()
            .baseUrl(external ?: transport!!.baseUrl().toString())
            .apiKey(System.getenv("STOGAS_API_KEY"))
            .maxRetries(0)
            .followRedirects(false)
            .proxy(Proxy.NO_PROXY)
            .timeout(Duration.ofMinutes(45))
            .build()
            .withOptions { options -> options.httpClient(SingleUseHttpClient(options.build().httpClient)) }
        try {
            val request = ChatCompletionCreateParams.builder()
                .model(System.getenv("STOGAS_MODEL"))
                .addUserMessage("Say hello in one sentence.")
                .build()
            client.chat().completions().createStreaming(request).use { response ->
                response.stream().forEach { chunk ->
                    chunk.choices().forEach { choice ->
                        choice.delta().content().ifPresent { print(it) }
                    }
                }
            }
        } finally {
            client.close()
        }
    }
}
