using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using OidcProvider.Core.Services;

namespace OidcProvider.Api;

// Bound from the "Email" config section. Mode selects the IEmailSender at startup:
// "Dev" → DevEmailSender (in-memory sink), "Smtp" → SmtpEmailSender (this file).
public sealed class EmailOptions
{
    public string Mode { get; set; } = "Dev";
    public string From { get; set; } = "no-reply@oidc.local";
    public string FromName { get; set; } = "OIDC Provider";
    public SmtpOptions Smtp { get; set; } = new();

    public sealed class SmtpOptions
    {
        public string Host { get; set; } = "localhost";
        public int Port { get; set; } = 25;
        public string? User { get; set; }
        public string? Password { get; set; }
        // None | StartTls | StartTlsWhenAvailable | SslOnConnect | Auto. Maps to MailKit's
        // SecureSocketOptions; default Auto picks STARTTLS/implicit-TLS by port + advertisement.
        public string Security { get; set; } = "Auto";
    }
}

// Production transactional-email sender (verification + password-reset links) over SMTP via
// MailKit. The body the onboarding flow produces is plain text containing a link, so we send it
// as text/plain. Failures propagate to the caller — the onboarding endpoints decide how to react.
public sealed class SmtpEmailSender : IEmailSender
{
    private readonly EmailOptions _opts;
    private readonly ILogger<SmtpEmailSender> _log;

    public SmtpEmailSender(IOptions<EmailOptions> opts, ILogger<SmtpEmailSender> log)
        => (_opts, _log) = (opts.Value, log);

    public async Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
        var msg = new MimeMessage();
        msg.From.Add(new MailboxAddress(_opts.FromName, _opts.From));
        msg.To.Add(MailboxAddress.Parse(to));
        msg.Subject = subject;
        msg.Body = new TextPart("plain") { Text = body };

        using var client = new SmtpClient();
        await client.ConnectAsync(_opts.Smtp.Host, _opts.Smtp.Port, ParseSecurity(_opts.Smtp.Security), ct);
        if (!string.IsNullOrEmpty(_opts.Smtp.User))
            await client.AuthenticateAsync(_opts.Smtp.User, _opts.Smtp.Password, ct);
        await client.SendAsync(msg, ct);
        await client.DisconnectAsync(quit: true, ct);
        _log.LogInformation("SMTP email sent | {Subject}", subject); // don't log recipient (PII)
    }

    private static SecureSocketOptions ParseSecurity(string s) => s switch
    {
        "None" => SecureSocketOptions.None,
        "StartTls" => SecureSocketOptions.StartTls,
        "StartTlsWhenAvailable" => SecureSocketOptions.StartTlsWhenAvailable,
        "SslOnConnect" => SecureSocketOptions.SslOnConnect,
        _ => SecureSocketOptions.Auto,
    };
}
