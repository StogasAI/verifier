using Stogas.Verifier;

foreach (var options in new[] {
    new TransportOptions { Security = "unsupported" },
    new TransportOptions { Environment = "unsupported" },
    new TransportOptions { MaxConnections = 0 },
})
{
    try
    {
        using var rejected = new Transport(options);
        throw new Exception("Invalid configuration opened a transport.");
    }
    catch (VerificationException error) when (error.Code.Length > 0) { }
}

// Opt-in staging qualification only downloads public evidence; it sends no inference.
if (Environment.GetEnvironmentVariable("STOGAS_NATIVE_STAGING_TEST") == "1")
{
    using var transport = new Transport(new TransportOptions { Environment = "staging", Security = "e2ee" });
    if (!transport.BaseUrl.IsLoopback || transport.BaseUrl.Scheme != "http") throw new Exception("Wrong local endpoint.");
    await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => Task.Run(() => transport.Refresh())));
    transport.Dispose();
    transport.Dispose();
    try { transport.Refresh(); throw new Exception("Disposed transport accepted a call."); }
    catch (ObjectDisposedException) { }
}
Console.WriteLine("Installed native transport package passed.");
