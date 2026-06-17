using System.Security.Cryptography;
using StackExchange.Redis;

namespace OidcProvider.Core.Services;

// Transactional email (verification + password-reset links). Production wires SMTP/SendGrid;
// dev uses a sink that captures messages so flows can be driven without a mail server.
public interface IEmailSender
{
    Task SendAsync(string to, string subject, string body, CancellationToken ct = default);
}

// Single-use, expiring link tokens (email verification, password reset) kept in Redis,
// namespaced by purpose. Token -> userId; consuming deletes it.
public interface ITokenLinkStore
{
    Task<string> CreateAsync(string purpose, Guid userId, TimeSpan ttl, CancellationToken ct = default);
    Task<Guid?> ConsumeAsync(string purpose, string token, CancellationToken ct = default);
}

public sealed class RedisTokenLinkStore : ITokenLinkStore
{
    private readonly IDatabase _redis;
    public RedisTokenLinkStore(IConnectionMultiplexer mux) => _redis = mux.GetDatabase();

    public async Task<string> CreateAsync(string purpose, Guid userId, TimeSpan ttl, CancellationToken ct = default)
    {
        var token = Base64UrlText.Encode(RandomNumberGenerator.GetBytes(32)); // high-entropy, unguessable
        await _redis.StringSetAsync(Key(purpose, token), userId.ToString(), ttl);
        return token;
    }

    public async Task<Guid?> ConsumeAsync(string purpose, string token, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token)) return null;
        var v = await _redis.StringGetDeleteAsync(Key(purpose, token));   // atomic single-use
        return v.HasValue && Guid.TryParse(v!, out var id) ? id : null;
    }

    private static string Key(string purpose, string token) => $"link:{purpose}:{token}";
}
