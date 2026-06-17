using OidcProvider.Core;
using OidcProvider.Core.Data;
using OidcProvider.Core.Entities;
using OidcProvider.Core.Services;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api;

// Dev seed: one demo confidential client (code+PKCE+refresh), a demo user, and the
// per-client policy. Production registers clients via /register (RFC 7591) or admin.
public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider sp, IConfiguration cfg)
    {
        var apps = sp.GetRequiredService<IOpenIddictApplicationManager>();
        var db = sp.GetRequiredService<AuthDbContext>();

        const string clientId = "demo-web";
        if (await apps.FindByClientIdAsync(clientId) is null)
        {
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = "demo-secret-dev-only",        // ADR-0008: prefer private_key_jwt in prod
                ClientType = ClientTypes.Confidential,
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Demo Web App",
                RedirectUris = { new Uri("http://localhost:5000/callback") }, // EXACT match (T2/T12)
                PostLogoutRedirectUris = { new Uri("http://localhost:5000/signed-out") },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.PushedAuthorization, // RFC 9126 (ADR-0009)
                    Permissions.Endpoints.EndSession,          // RP-initiated logout
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email, Permissions.Scopes.Profile,
                    Permissions.Prefixes.Scope + "openid",
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess, // enable refresh tokens (ADR-0007)
                },
                Requirements = { Requirements.Features.ProofKeyForCodeExchange }, // PKCE mandatory (ADR-0011)
            });
        }

        if (!db.ClientPolicies.Any(p => p.ClientId == clientId))
        {
            db.ClientPolicies.Add(new ClientPolicy
            { ClientId = clientId, SectorIdentifier = "demo-web", SubjectType = "pairwise" });
        }

        if (!db.Users.Any(u => u.Username == "alice"))
        {
            db.Users.Add(new AppUser
            {
                Username = "alice",
                Email = "alice@example.com",
                EmailVerified = true,
                PasswordHash = UserService.Hash("password123!"),
                ProfileClaimsJson = "{\"name\":\"Alice Example\"}",
            });
        }

        // bob has TOTP enrolled → login forces MFA step-up (ADR acr/amr). Fixed dev secret.
        if (!db.Users.Any(u => u.Username == "bob"))
        {
            db.Users.Add(new AppUser
            {
                Username = "bob",
                Email = "bob@example.com",
                EmailVerified = true,
                PasswordHash = UserService.Hash("password123!"),
                ProfileClaimsJson = "{\"name\":\"Bob Example\"}",
                MfaMethods =
                {
                    new UserMfaMethod
                    {
                        Kind = MfaKind.Totp,
                        SecretRef = "JBSWY3DPEHPK3PXP", // Base32 dev secret (RFC 6238)
                        Label = "Authenticator app",
                    }
                }
            });
        }

        // dave: password-only user reserved for the password-change test (isolated mutation).
        if (!db.Users.Any(u => u.Username == "dave"))
        {
            db.Users.Add(new AppUser
            {
                Username = "dave", Email = "dave@example.com", EmailVerified = true,
                PasswordHash = UserService.Hash("password123!"),
                ProfileClaimsJson = "{\"name\":\"Dave Example\"}",
            });
        }

        // carol has a WebAuthn credential enrolled → login routes to the security-key step.
        // Public key is X(32)||Y(32) for the seeded P-256 credential; private key lives only
        // in the test's software authenticator (real enrollment would run attestation).
        if (!db.Users.Any(u => u.Username == "carol"))
        {
            var x = Base64UrlText.Decode("I0lHnssp6dHswZwNlEx4WIQf_6FE5ogTZ5m_JEzg-No");
            var y = Base64UrlText.Decode("mpdst-DG205AycM7jL7QaE5J9Xh7iKHZHMgutQ1pM2Y");
            var pub = new byte[64];
            Array.Copy(x, 0, pub, 0, 32); Array.Copy(y, 0, pub, 32, 32);
            db.Users.Add(new AppUser
            {
                Username = "carol",
                Email = "carol@example.com",
                EmailVerified = true,
                PasswordHash = UserService.Hash("password123!"),
                ProfileClaimsJson = "{\"name\":\"Carol Example\"}",
                MfaMethods =
                {
                    new UserMfaMethod
                    {
                        Kind = MfaKind.WebAuthn,
                        SecretRef = "ZGVtby1jcmVkZW50aWFsLWlkLWNhcm9sLTAwMDE", // credentialId (b64url)
                        PublicKey = pub,
                        Label = "Security key",
                    }
                }
            });
        }

        // Machine client for client-credentials (load-test hot path; no UI).
        const string svc = "svc-loadtest";
        if (await apps.FindByClientIdAsync(svc) is null)
        {
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = svc,
                ClientSecret = "svc-secret-dev-only",
                ClientType = ClientTypes.Confidential,
                DisplayName = "Load-test service client",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + "api",
                },
            });
        }

        // Loopback IdP client — lets the provider federate to ITSELF for dev/demo of the
        // external-login flow (its redirect is the OIDC handler's callback path).
        const string fed = "federation-loopback";
        if (await apps.FindByClientIdAsync(fed) is null)
        {
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = fed,
                ClientSecret = "fed-secret-dev-only",
                ClientType = ClientTypes.Confidential,
                ConsentType = ConsentTypes.Implicit,   // first-party loopback: skip the consent screen
                DisplayName = "Federation loopback",
                RedirectUris = { new Uri("http://localhost:8081/signin-oidc-external") },
                Permissions =
                {
                    Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                    Permissions.Endpoints.PushedAuthorization, // the .NET OIDC handler uses PAR
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Prefixes.Scope + "openid",
                    Permissions.Scopes.Email, Permissions.Scopes.Profile, // OIDC handler requests profile
                },
                Requirements = { Requirements.Features.ProofKeyForCodeExchange },
            });
        }

        // private_key_jwt client (RFC 7523 asymmetric client auth, no shared secret).
        const string pkjwt = "svc-pkjwt";
        if (await apps.FindByClientIdAsync(pkjwt) is null)
        {
            var jwks = new Microsoft.IdentityModel.Tokens.JsonWebKeySet();
            jwks.Keys.Add(new Microsoft.IdentityModel.Tokens.JsonWebKey
            {
                Kty = "EC", Crv = "P-256", Alg = "ES256", Use = "sig", Kid = "pkjwt-1",
                X = "K9vx4pd6X_clUoclhaILMQVQjx8v57tfSKx5sCLWDoc",
                Y = "6fQbBWFN5c1EvYcGGKFeSWRdndEMAm3P-VUpIAJZocU",
            });
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = pkjwt,
                ClientType = ClientTypes.Confidential,
                DisplayName = "private_key_jwt service client",
                JsonWebKeySet = jwks,                          // asymmetric client auth keys
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + "api",
                },
            });
        }

        // DPoP-required machine client (ADR-0009 per-client enforcement).
        const string svcDpop = "svc-dpop";
        if (await apps.FindByClientIdAsync(svcDpop) is null)
        {
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = svcDpop,
                ClientSecret = "svc-dpop-secret-dev-only",
                ClientType = ClientTypes.Confidential,
                DisplayName = "DPoP-required service client",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + "api",
                },
            });
        }
        if (!db.ClientPolicies.Any(p => p.ClientId == svcDpop))
            db.ClientPolicies.Add(new ClientPolicy { ClientId = svcDpop, DpopBound = true });

        await db.SaveChangesAsync();
    }
}
