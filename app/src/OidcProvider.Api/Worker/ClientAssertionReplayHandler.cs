using OpenIddict.Abstractions;
using OpenIddict.Server;
using StackExchange.Redis;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api.Worker;

// RFC 7523 §3 / OAuth BCP: a private_key_jwt client assertion's `jti` must be single-use.
// OpenIddict validates the assertion's signature/aud/exp; this adds replay protection by
// recording each jti in Redis until the assertion expires and rejecting a reuse.
public sealed class ClientAssertionReplayHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessAuthenticationContext>
{
    private readonly IDatabase _redis;
    public ClientAssertionReplayHandler(IConnectionMultiplexer mux) => _redis = mux.GetDatabase();

    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessAuthenticationContext context)
    {
        if (context.EndpointType != OpenIddictServerEndpointType.Token) return;
        if (context.ClientAssertionPrincipal is not { } p) return;   // not a private_key_jwt client

        var jti = p.GetClaim(Claims.JwtId);
        if (string.IsNullOrEmpty(jti)) return;

        var exp = p.GetExpirationDate();
        var ttl = exp is { } e && e > DateTimeOffset.UtcNow ? e - DateTimeOffset.UtcNow : TimeSpan.FromMinutes(5);
        // SET NX EX — false if the jti was already used within its lifetime.
        if (!await _redis.StringSetAsync($"cajti:{jti}", "1", ttl, When.NotExists))
            context.Reject(
                error: Errors.InvalidClient,
                description: "Replayed client assertion (jti already used).",
                uri: null);
    }
}
