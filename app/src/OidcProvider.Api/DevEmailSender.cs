using System.Collections.Concurrent;
using OidcProvider.Core.Services;

namespace OidcProvider.Api;

// Development email sink: logs each message and keeps the last body per address so the
// signup/verify/reset flows can be driven (and tested) without a real mail server.
// PRODUCTION must replace this with an SMTP/provider-backed IEmailSender.
public sealed class DevEmailSender : IEmailSender
{
    private static readonly ConcurrentDictionary<string, string> Last = new();
    private readonly ILogger<DevEmailSender> _log;
    public DevEmailSender(ILogger<DevEmailSender> log) => _log = log;

    public Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
        Last[to] = body;
        // Don't log the body — it carries the single-use verify/reset link token. The full body
        // stays in the in-memory sink (read it via /dev/emails/{address}); logs get only the subject.
        _log.LogInformation("DEV EMAIL queued | {Subject}", subject);
        return Task.CompletedTask;
    }

    public static string? LastBody(string to) => Last.TryGetValue(to, out var b) ? b : null;
}
