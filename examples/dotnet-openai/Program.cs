using OpenAI;
using OpenAI.Chat;
using System.ClientModel;
using System.ClientModel.Primitives;

// Start `stogas-verify serve`; use its complete printed capability URL.
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
        Endpoint = new Uri(Environment.GetEnvironmentVariable("STOGAS_BASE_URL")!),
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
