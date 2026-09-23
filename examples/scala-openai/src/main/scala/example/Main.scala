package example

import ai.stogas.verifier.Transport
import com.openai.client.OpenAIClient
import com.openai.client.okhttp.OpenAIOkHttpClient
import com.openai.core.RequestOptions
import com.openai.core.http.{HttpClient, HttpRequest, HttpRequestBody}
import java.io.OutputStream
import com.openai.models.chat.completions.ChatCompletionCreateParams
import java.net.Proxy
import java.time.Duration
import scala.util.Using

final class SingleUseHttpClient(delegate: HttpClient) extends HttpClient:
  private def singleUse(request: HttpRequest): HttpRequest =
    val body = request.body()
    if body == null then request
    else request.toBuilder().body(new HttpRequestBody:
      def writeTo(output: OutputStream): Unit = body.writeTo(output)
      def contentType(): String = body.contentType()
      def contentLength(): Long = body.contentLength()
      def repeatable(): Boolean = false
      def close(): Unit = body.close()
    ).build()
  def execute(request: HttpRequest, options: RequestOptions) =
    delegate.execute(singleUse(request), options)
  def executeAsync(request: HttpRequest, options: RequestOptions) =
    delegate.executeAsync(singleUse(request), options)
  def close(): Unit = delegate.close()

object Main:
  given Using.Releasable[OpenAIClient] with
    def release(client: OpenAIClient): Unit = client.close()

  def main(args: Array[String]): Unit =
    Using.Manager { use =>
      // An explicit URL can use a separately managed verifier CLI.
      val external = Option(System.getenv("STOGAS_BASE_URL"))
      val transport = if external.isEmpty then Some(use(new Transport())) else None
      val client = use(OpenAIOkHttpClient.builder()
        .baseUrl(external.getOrElse(transport.get.baseUrl().toString))
        .apiKey(System.getenv("STOGAS_API_KEY"))
        .maxRetries(0)
        .followRedirects(false)
        .proxy(Proxy.NO_PROXY)
        .timeout(Duration.ofMinutes(45))
        .build().withOptions(options => options.httpClient(new SingleUseHttpClient(options.build().httpClient()))))
      val request = ChatCompletionCreateParams.builder()
        .model(System.getenv("STOGAS_MODEL"))
        .addUserMessage("Say hello in one sentence.")
        .build()
      val response = use(client.chat().completions().createStreaming(request))
      response.stream().forEach(chunk =>
        chunk.choices().forEach(choice =>
          choice.delta().content().ifPresent(text => print(text))))
    }.get
