using StackExchange.Redis;

namespace OidcProvider.Core.Services;

// Brute-force protection: count failed login attempts per key (username, optionally + IP)
// in a sliding window; lock out once the threshold is hit. Reset on success.
public interface ILoginThrottle
{
    Task<bool> IsLockedAsync(string key, CancellationToken ct = default);
    Task RecordFailureAsync(string key, CancellationToken ct = default);
    Task ResetAsync(string key, CancellationToken ct = default);
}

public sealed class RedisLoginThrottle : ILoginThrottle
{
    private readonly IDatabase _redis;
    private const int MaxFailures = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    public RedisLoginThrottle(IConnectionMultiplexer mux) => _redis = mux.GetDatabase();

    public async Task<bool> IsLockedAsync(string key, CancellationToken ct = default)
    {
        var v = await _redis.StringGetAsync(K(key));
        return v.HasValue && (long)v >= MaxFailures;
    }

    public async Task RecordFailureAsync(string key, CancellationToken ct = default)
    {
        var n = await _redis.StringIncrementAsync(K(key));
        if (n == 1) await _redis.KeyExpireAsync(K(key), Window); // start the window on first failure
    }

    public Task ResetAsync(string key, CancellationToken ct = default) => _redis.KeyDeleteAsync(K(key));

    private static string K(string key) => $"loginfail:{key.ToLowerInvariant()}";
}
