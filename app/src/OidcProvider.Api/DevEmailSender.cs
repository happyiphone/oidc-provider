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
        _log.LogInformation("DEV EMAIL → {To} | {Subject} | {Body}", to, subject, body);
        return Task.CompletedTask;
    }

    public static string? LastBody(string to) => Last.TryGetValue(to, out var b) ? b : null;
}
