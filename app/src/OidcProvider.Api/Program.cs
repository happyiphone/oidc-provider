using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OidcProvider.Api;
using OidcProvider.Api.Signing;
using OidcProvider.Api.Worker;
using OidcProvider.Core.Data;
using OidcProvider.Core.Services;
using OidcProvider.Core.Signing;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using StackExchange.Redis;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;

// ---- Data: Postgres + OpenIddict's protocol tables -------------------------
builder.Services.AddDbContext<AuthDbContext>(o =>
{
    o.UseNpgsql(cfg.GetConnectionString("Postgres"));
    o.UseOpenIddict();
});

// ---- Redis (ephemeral store, ADR-0006) -------------------------------------
builder.Services.AddSingleton<IConnectionMultiplexer>(
    _ => ConnectionMultiplexer.Connect(cfg.GetConnectionString("Redis")!));

// ---- Domain services -------------------------------------------------------
builder.Services.Configure<OidcSigningConfig>(cfg.GetSection("Oidc:Signing"));
// ADR-0005/0010: PPID derivation key is long-lived + KMS-guarded in prod. REQUIRE it
// outside Development — never silently fall back to a hardcoded key (would let anyone
// reconstruct/correlate pairwise subjects). [security review finding #3]
var ppidKey = cfg["Oidc:PpidKeyBase64"];
if (string.IsNullOrEmpty(ppidKey))
{
    if (!builder.Environment.IsDevelopment())
        throw new InvalidOperationException(
            "Oidc:PpidKeyBase64 must be set outside Development (pairwise-subject derivation key).");
    ppidKey = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("dev-ppid-derivation-key-32bytes!!"));
}
builder.Services.AddSingleton(new PpidOptions { DerivationKeyBase64 = ppidKey });
builder.Services.AddScoped<IPairwiseSubjects, PairwiseSubjects>();
builder.Services.AddScoped<IConsentStore, ConsentStore>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<ISigningKeyStore, EfSigningKeyStore>();
builder.Services.AddScoped<IOpenIddictTokenManagerFacade, TokenFamilyFacade>();
builder.Services.AddScoped<IAuditLog, EfAuditLog>();          // threat T16 — tamper-evident audit
builder.Services.AddSingleton<IUserSession, RedisUserSession>();
builder.Services.AddSingleton<ITotpService, TotpService>();
builder.Services.AddSingleton(new WebAuthnConfig
{
    RpId = cfg["Oidc:WebAuthn:RpId"] ?? "localhost",
    Origin = cfg["Oidc:WebAuthn:Origin"] ?? "http://localhost:8081",
});
builder.Services.AddSingleton<IWebAuthnService, WebAuthnService>();

// ---- Cookie auth for the login/consent UI ----------------------------------
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/account/login";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        // Secure in prod; SameAsRequest in dev so the cookie works over plain-HTTP local/test.
        o.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
    });

// ---- OpenIddict ------------------------------------------------------------
builder.Services.AddOpenIddict()
    .AddCore(o => o.UseEntityFrameworkCore().UseDbContext<AuthDbContext>())
    .AddServer(o =>
    {
        // Endpoints (method names target OpenIddict 5.x; pin per your version).
        o.SetAuthorizationEndpointUris("authorize")
         .SetTokenEndpointUris("token")
         .SetUserInfoEndpointUris("userinfo")
         .SetIntrospectionEndpointUris("introspect")
         .SetRevocationEndpointUris("revoke")
         .SetEndSessionEndpointUris("logout")
         .SetPushedAuthorizationEndpointUris("par"); // RFC 9126 (ADR-0009)

        // ADR-0001: only the safe grants. Implicit / password deliberately absent.
        o.AllowAuthorizationCodeFlow()
         .AllowRefreshTokenFlow()
         .AllowClientCredentialsFlow();

        // ADR-0001/0011: PKCE mandatory; OpenIddict enforces S256.
        o.RequireProofKeyForCodeExchange();

        o.RegisterScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "api");

        // Lifetimes (threat T3) + rolling refresh with reuse leeway (ADR-0007).
        o.SetAccessTokenLifetime(TimeSpan.FromMinutes(cfg.GetValue("Oidc:AccessTokenLifetimeMinutes", 10)));
        o.SetRefreshTokenLifetime(TimeSpan.FromDays(cfg.GetValue("Oidc:RefreshTokenLifetimeDays", 14)));
        o.SetRefreshTokenReuseLeeway(TimeSpan.FromSeconds(cfg.GetValue("Oidc:RefreshReuseLeewaySeconds", 15)));

        // ADR-0004: standard, verifiable JWT access tokens (no encryption).
        o.DisableAccessTokenEncryption();

        // ADR-0007: rolling refresh tokens with server-side records so reuse is detectable;
        // the handler escalates a detected reuse to family-wide revocation (threat T4).
        o.UseReferenceRefreshTokens();
        o.AddEventHandler<OpenIddictServerEvents.ProcessAuthenticationContext>(
            b => b.UseScopedHandler<RefreshReuseHandler>());

        // ADR-0009 (when supported by your OpenIddict version): require PAR + DPoP per client.
        // o.RequirePushedAuthorizationRequests();

        // Signing keys are injected lazily by SigningOptionsSetup (Dev or KMS).
        var aspnet = o.UseAspNetCore()
         .EnableAuthorizationEndpointPassthrough()   // our AuthorizeController handles login/consent
         .EnableTokenEndpointPassthrough()           // our TokenController augments token issuance
         .EnableUserInfoEndpointPassthrough()
         .EnableEndSessionEndpointPassthrough();

        // Dev only: allow plain HTTP. NEVER do this in production (ADR/threat model).
        if (builder.Environment.IsDevelopment())
            aspnet.DisableTransportSecurityRequirement();
    })
    .AddValidation(o => { o.UseLocalServer(); o.UseAspNetCore(); });

// KMS / Dev signing credentials (ADR-0005).
builder.Services.AddSingleton<IConfigureOptions<OpenIddictServerOptions>, SigningOptionsSetup>();
if (cfg["Oidc:Signing:Mode"]?.Equals("Kms", StringComparison.OrdinalIgnoreCase) == true)
{
    builder.Services.AddSingleton<Amazon.KeyManagementService.IAmazonKeyManagementService>(_ =>
    {
        var kc = new Amazon.KeyManagementService.AmazonKeyManagementServiceConfig();
        var url = cfg["Oidc:Signing:Kms:ServiceUrl"];
        if (!string.IsNullOrEmpty(url))   // local-kms / LocalStack: explicit endpoint + basic creds
        {
            kc.ServiceURL = url;
            kc.AuthenticationRegion = cfg["Oidc:Signing:Kms:Region"] ?? "us-east-1";
            return new Amazon.KeyManagementService.AmazonKeyManagementServiceClient(
                new Amazon.Runtime.BasicAWSCredentials("test", "test"), kc);
        }
        kc.RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(cfg["Oidc:Signing:Kms:Region"] ?? "us-east-1");
        return new Amazon.KeyManagementService.AmazonKeyManagementServiceClient(kc); // real KMS: ambient creds
    });
    builder.Services.AddHostedService<KeyRotationService>();   // 3-state rotation (ADR-0005)
}

builder.Services.AddControllersWithViews();

// Liveness/readiness probes. Readiness pings Postgres + Redis (fail closed if either is down).
builder.Services.AddHealthChecks()
    .AddCheck<ReadinessCheck>("ready", tags: ["ready"]);

// Rate limiting on the abuse-prone endpoints (threat T15). Per-IP fixed window on /token
// and /par only; everything else is unlimited. Reject with 429.
var rateLimit = cfg.GetValue("Oidc:RateLimit:PerMinute",
    builder.Environment.IsDevelopment() ? 100_000 : 60);
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        var path = ctx.Request.Path;
        if (path.StartsWithSegments("/token") || path.StartsWithSegments("/par"))
            return RateLimitPartition.GetFixedWindowLimiter(
                ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions
                { PermitLimit = rateLimit, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
        return RateLimitPartition.GetNoLimiter("unlimited");
    });
});

var app = builder.Build();

// Honor X-Forwarded-Proto/Host from a TLS-terminating reverse proxy so the discovery
// issuer + endpoint URLs are correct (https) behind nginx/ingress (also lets OpenIddict
// see the external https origin). Dev trusts any proxy; prod should pin KnownProxies.
var fwd = new Microsoft.AspNetCore.Builder.ForwardedHeadersOptions
{
    ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
                     | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto
                     | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedHost,
};
if (app.Environment.IsDevelopment()) { fwd.KnownNetworks.Clear(); fwd.KnownProxies.Clear(); }
app.UseForwardedHeaders(fwd);

// Security headers, incl. clickjacking defense for login/consent UI (threat T14).
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["Content-Security-Policy"] = "frame-ancestors 'none'";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    await next();
});

app.UseRateLimiter();          // /token + /par per-IP limit (threat T15)
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Liveness: process is up. Readiness: dependencies reachable (fail closed).
app.MapHealthChecks("/health/live", new() { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new() { Predicate = c => c.Tags.Contains("ready") });

// Dev convenience: migrate + seed a demo client/user/signing key.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    // Dev: create schema from the model directly. Production: generate EF migrations
    // (`dotnet ef migrations add Initial`) and call MigrateAsync() instead — see README.
    if (app.Environment.IsDevelopment())
    {
        await db.Database.EnsureCreatedAsync();
        // Demo clients/users with known secrets — DEVELOPMENT ONLY. Never seed these in
        // production (would ship usable credentials). [security review finding #1]
        await DbSeeder.SeedAsync(scope.ServiceProvider, app.Configuration);
    }
    else
    {
        await db.Database.MigrateAsync();
    }

    // KMS mode bootstrap: ensure an ACTIVE signing key exists before the first request
    // (the rotation worker only publishes `next` then promotes later). [ADR-0005]
    if (cfg["Oidc:Signing:Mode"]?.Equals("Kms", StringComparison.OrdinalIgnoreCase) == true)
    {
        var store = scope.ServiceProvider.GetRequiredService<ISigningKeyStore>();
        if (await store.GetByStatusAsync(OidcProvider.Core.Entities.KeyStatus.Active) is null)
        {
            var kms = scope.ServiceProvider
                .GetRequiredService<Amazon.KeyManagementService.IAmazonKeyManagementService>();
            var created = await kms.CreateKeyAsync(new Amazon.KeyManagementService.Model.CreateKeyRequest
            {
                KeySpec = Amazon.KeyManagementService.KeySpec.ECC_NIST_P256,
                KeyUsage = Amazon.KeyManagementService.KeyUsageType.SIGN_VERIFY,
            });
            var keyId = created.KeyMetadata.KeyId;
            var pub = await kms.GetPublicKeyAsync(new Amazon.KeyManagementService.Model.GetPublicKeyRequest { KeyId = keyId });
            await store.InsertAsync(new OidcProvider.Core.Entities.SigningKeyRecord
            {
                Kid = "k-" + Guid.NewGuid().ToString("n")[..12],
                Alg = "ES256",
                KmsKeyRef = keyId,
                PublicKeyDer = pub.PublicKey.ToArray(),
                Status = OidcProvider.Core.Entities.KeyStatus.Active,
                NotBefore = DateTimeOffset.UtcNow,
            });
        }
    }
}

app.Run();

// Exposed so the integration-test host (WebApplicationFactory<Program>) can boot the app.
public partial class Program { }
