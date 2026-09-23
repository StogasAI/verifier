using OpenAI;
using OpenAI.Chat;
using System.ClientModel;
using System.ClientModel.Primitives;
using Stogas.Verifier;

// An explicit URL can also use a separately managed verifier CLI.
string? external = Environment.GetEnvironmentVariable("STOGAS_BASE_URL");
using var transport = external is null ? new Transport() : null;
var baseUrl = external is null ? transport!.BaseUrl : new Uri(external);
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancellation.Cancel(); };
using var http = new HttpClient(new SocketsHttpHandler
{
    UseProxy = false,
    AllowAutoRedirect = false
}) { Timeout = TimeSpan.FromMinutes(45) };
var client = new ChatClient(
    Environment.GetEnvironmentVariable("STOGAS_MODEL")!,
    new ApiKeyCredential(Environment.GetEnvironmentVariable("STOGAS_API_KEY")!),
    new OpenAIClientOptions
    {
        Endpoint = baseUrl,
        Transport = new HttpClientPipelineTransport(http),
        RetryPolicy = new ClientRetryPolicy(maxRetries: 0),
        NetworkTimeout = TimeSpan.FromMinutes(45)
    });

var updates = client.CompleteChatStreamingAsync(
    [new UserChatMessage("Say hello in one sentence.")],
    cancellationToken: cancellation.Token);
await foreach (var update in updates)
{
    foreach (var part in update.ContentUpdate) Console.Write(part.Text);
}
cancellation.Token.ThrowIfCancellationRequested();
