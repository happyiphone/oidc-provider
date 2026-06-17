using Microsoft.Extensions.Diagnostics.HealthChecks;
using OidcProvider.Core.Data;
using StackExchange.Redis;

namespace OidcProvider.Api;

// Readiness = can we actually serve? Postgres reachable AND Redis reachable. Fail closed
// (a degraded dependency should pull the instance from the load balancer, not 500 users).
public sealed class ReadinessCheck : IHealthCheck
{
    private readonly AuthDbContext _db;
    private readonly IConnectionMultiplexer _redis;
    public ReadinessCheck(AuthDbContext db, IConnectionMultiplexer redis) => (_db, _redis) = (db, redis);

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            if (!await _db.Database.CanConnectAsync(ct))
                return HealthCheckResult.Unhealthy("postgres unreachable");
            await _redis.GetDatabase().PingAsync();
            return HealthCheckResult.Healthy();
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy(ex.Message);
        }
    }
}
