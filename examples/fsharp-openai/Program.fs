open System
open System.Net.Http
open System.Threading
open System.ClientModel
open System.ClientModel.Primitives
open OpenAI
open OpenAI.Chat
open Stogas.Verifier

let run () = task {
    // An explicit URL can use a separately managed verifier CLI.
    let external = Environment.GetEnvironmentVariable("STOGAS_BASE_URL")
    use transport = if isNull external then new Transport() else null
    let baseUrl = if isNull external then transport.BaseUrl else Uri(external)
    use cancellation = new CancellationTokenSource()
    Console.CancelKeyPress.Add(fun event -> event.Cancel <- true; cancellation.Cancel())
    use http = new HttpClient(new SocketsHttpHandler(UseProxy = false, AllowAutoRedirect = false))
    http.Timeout <- TimeSpan.FromMinutes(45.0)
    let options = OpenAIClientOptions(
        Endpoint = baseUrl,
        Transport = new HttpClientPipelineTransport(http),
        RetryPolicy = new ClientRetryPolicy(0),
        NetworkTimeout = TimeSpan.FromMinutes(45.0))
    let client = ChatClient(
        Environment.GetEnvironmentVariable("STOGAS_MODEL"),
        ApiKeyCredential(Environment.GetEnvironmentVariable("STOGAS_API_KEY")), options)
    let messages: ChatMessage array = [| UserChatMessage("Say hello in one sentence.") |]
    let updates = client.CompleteChatStreamingAsync(messages, cancellationToken = cancellation.Token)
    use iterator = updates.GetAsyncEnumerator(cancellation.Token)
    let mutable reading = true
    while reading do
        let! hasNext = iterator.MoveNextAsync()
        reading <- hasNext
        if hasNext then
            for part in iterator.Current.ContentUpdate do Console.Write(part.Text)
    cancellation.Token.ThrowIfCancellationRequested()
}

[<EntryPoint>]
let main _ =
    run().GetAwaiter().GetResult()
    0
