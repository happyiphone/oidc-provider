using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;
using OidcProvider.Core.Data;
using OidcProvider.Core.Entities;
using OidcProvider.Core.Signing;
using StackExchange.Redis;

namespace OidcProvider.Core.Services;

// ----------------------------------------------------------------------------
// ADR-0010 — pairwise subject identifiers (PPID), persisted + deterministically derived.
// ----------------------------------------------------------------------------
public interface IPairwiseSubjects
{
    Task<string> ForAsync(Guid userId, string sectorIdentifier, CancellationToken ct = default);
}

public sealed class PairwiseSubjects : IPairwiseSubjects
{
    private readonly AuthDbContext _db;
    private readonly byte[] _derivationKey;   // long-lived, KMS-guarded in prod (ADR-0005)

    public PairwiseSubjects(AuthDbContext db, PpidOptions opt)
    {
        _db = db;
        _derivationKey = Convert.FromBase64String(opt.DerivationKeyBase64);
    }

    public async Task<string> ForAsync(Guid userId, string sector, CancellationToken ct = default)
    {
        var existing = await _db.SubjectIdentifiers
            .FindAsync(new object[] { userId, sector }, ct);
        if (existing is not null) return existing.Ppid;

        // Deterministic: HMAC(derivationKey, sector || userId) → opaque, stable, unlinkable.
        var mac = new HMACSHA256(_derivationKey);
        var ppid = Base64UrlText.Encode(
            mac.ComputeHash(Encoding.UTF8.GetBytes(sector + "|" + userId)));

        _db.SubjectIdentifiers.Add(new SubjectIdentifier
        { UserId = userId, SectorIdentifier = sector, Ppid = ppid });
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException) // concurrent first login for the same (user, sector) [code review #4]
        {
            // The derivation is deterministic, so the winning row holds the same ppid.
            _db.ChangeTracker.Clear();
            var raced = await _db.SubjectIdentifiers.FindAsync(new object[] { userId, sector }, ct);
            return raced?.Ppid ?? ppid;
        }
        return ppid;
    }
}

public sealed class PpidOptions { public string DerivationKeyBase64 { get; set; } = ""; }

// ----------------------------------------------------------------------------
// ACR policy — decide the required authentication context (e.g. force MFA).
// ----------------------------------------------------------------------------
public static class AcrPolicy
{
    public const string Mfa = "urn:acr:mfa";
    public const string Pwd = "urn:acr:pwd";

    // Ordered ladder: a session satisfies a required acr when its rank is >= required's.
    // Add new tiers here (e.g. a phishing-resistant level) without touching comparisons.
    public static int Rank(string acr) => acr switch { Mfa => 2, Pwd => 1, _ => 0 };

    public static string Resolve(IEnumerable<string>? requestedAcrValues, bool userHasMfa)
    {
        var requested = requestedAcrValues?.ToHashSet() ?? new();
        if (requested.Contains(Mfa) || userHasMfa) return Mfa;  // step-up if available/asked
        return Pwd;
    }
}

// ----------------------------------------------------------------------------
// Consent store (ADR / threat T8).
// ----------------------------------------------------------------------------
public interface IConsentStore
{
    Task<Consent?> GetActiveAsync(Guid userId, string clientId, CancellationToken ct = default);
    Task<IReadOnlyList<Consent>> ListActiveAsync(Guid userId, CancellationToken ct = default);
    Task RecordAsync(Guid userId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default);
    Task RevokeAsync(Guid userId, string clientId, CancellationToken ct = default);
}

public sealed class ConsentStore : IConsentStore
{
    private readonly AuthDbContext _db;
    public ConsentStore(AuthDbContext db) => _db = db;

    public Task<Consent?> GetActiveAsync(Guid userId, string clientId, CancellationToken ct = default)
        => _db.Consents.FirstOrDefaultAsync(
            c => c.UserId == userId && c.ClientId == clientId && c.RevokedAt == null
              && (c.ExpiresAt == null || c.ExpiresAt > DateTimeOffset.UtcNow), ct);

    public async Task<IReadOnlyList<Consent>> ListActiveAsync(Guid userId, CancellationToken ct = default)
        => await _db.Consents.Where(c => c.UserId == userId && c.RevokedAt == null
              && (c.ExpiresAt == null || c.ExpiresAt > DateTimeOffset.UtcNow))
            .OrderBy(c => c.ClientId).ToListAsync(ct);

    public async Task RecordAsync(Guid userId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default)
    {
        // Look up by (user, client) regardless of revoked state — there's a unique index on
        // that pair, so a previously-revoked row must be REACTIVATED, not duplicated.
        var existing = await _db.Consents
            .FirstOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId, ct);
        if (existing is null)
        {
            _db.Consents.Add(new Consent { UserId = userId, ClientId = clientId, ScopesGranted = scopes.ToList() });
        }
        else
        {
            existing.ScopesGranted = existing.RevokedAt is null
                ? existing.ScopesGranted.Union(scopes).ToList()   // active: add new scopes
                : scopes.ToList();                                // revoked → re-grant fresh
            existing.RevokedAt = null;
            existing.GrantedAt = DateTimeOffset.UtcNow;
        }
        await _db.SaveChangesAsync(ct);
    }

    public async Task RevokeAsync(Guid userId, string clientId, CancellationToken ct = default)
    {
        var c = await GetActiveAsync(userId, clientId, ct);
        if (c is not null) { c.RevokedAt = DateTimeOffset.UtcNow; await _db.SaveChangesAsync(ct); }
    }
}

// ----------------------------------------------------------------------------
// User session — Redis-backed, short TTL (ADR-0006). Holds auth time / acr / amr.
// Anti-fixation: a fresh SessionId is minted on each successful login (threat T13).
// ----------------------------------------------------------------------------
public sealed record UserSessionData(Guid UserId, DateTimeOffset AuthTime, string Acr, string[] Amr)
{
    public bool SatisfiesAcr(string required) => AcrPolicy.Rank(Acr) >= AcrPolicy.Rank(required);
}

public interface IUserSession
{
    Task<UserSessionData?> GetAsync(string sessionId, CancellationToken ct = default);
    Task<string> CreateAsync(UserSessionData data, TimeSpan ttl, CancellationToken ct = default);
    Task RevokeAsync(string sessionId, CancellationToken ct = default);
    Task RevokeAllForUserAsync(Guid userId, CancellationToken ct = default); // "log out everywhere"
}

public sealed class RedisUserSession : IUserSession
{
    private readonly IDatabase _redis;
    public RedisUserSession(IConnectionMultiplexer mux) => _redis = mux.GetDatabase();

    public async Task<UserSessionData?> GetAsync(string sessionId, CancellationToken ct = default)
    {
        var v = await _redis.StringGetAsync(Key(sessionId));
        return v.IsNullOrEmpty ? null
            : System.Text.Json.JsonSerializer.Deserialize<UserSessionData>(v!);
    }

    public async Task<string> CreateAsync(UserSessionData data, TimeSpan ttl, CancellationToken ct = default)
    {
        var sid = Base64UrlText.Encode(RandomNumberGenerator.GetBytes(32)); // fresh id → anti-fixation
        await _redis.StringSetAsync(Key(sid), System.Text.Json.JsonSerializer.Serialize(data), ttl);
        // Index sid under the user so we can revoke every session on credential change/logout-all.
        await _redis.SetAddAsync(UserKey(data.UserId), sid);
        await _redis.KeyExpireAsync(UserKey(data.UserId), ttl + TimeSpan.FromMinutes(5));
        return sid;
    }

    public async Task RevokeAsync(string sessionId, CancellationToken ct = default)
    {
        // Best-effort remove from the user index too (look up the owner first).
        if (await GetAsync(sessionId, ct) is { } s) await _redis.SetRemoveAsync(UserKey(s.UserId), sessionId);
        await _redis.KeyDeleteAsync(Key(sessionId));
    }

    public async Task RevokeAllForUserAsync(Guid userId, CancellationToken ct = default)
    {
        var sids = await _redis.SetMembersAsync(UserKey(userId));
        foreach (var sid in sids) await _redis.KeyDeleteAsync(Key(sid!));
        await _redis.KeyDeleteAsync(UserKey(userId));
    }

    private static string Key(string sid) => $"sess:{sid}";
    private static string UserKey(Guid userId) => $"user:sids:{userId}";
}

// ----------------------------------------------------------------------------
// Users + passwords. PBKDF2 here for zero extra deps; swap argon2id in production.
// ----------------------------------------------------------------------------
public interface IUserService
{
    Task<AppUser?> ValidatePasswordAsync(string username, string password, CancellationToken ct = default);
    Task<AppUser?> GetAsync(Guid id, CancellationToken ct = default);
    Task<AppUser?> FindByEmailAsync(string email, CancellationToken ct = default);
    Task<AppUser?> CreateUserAsync(string username, string email, string password, CancellationToken ct = default);
    Task MarkEmailVerifiedAsync(Guid userId, CancellationToken ct = default);
    Task ResetPasswordAsync(Guid userId, string newPassword, CancellationToken ct = default);
    Task<bool> ChangePasswordAsync(Guid userId, string current, string newPassword, CancellationToken ct = default);
    Task RevokeAllForUserAsync(Guid userId, CancellationToken ct = default); // credential change (tree c)
    Task SaveAsync(CancellationToken ct = default);                          // persist tracked changes
    Task AddMfaMethodAsync(UserMfaMethod method, CancellationToken ct = default);
}

public sealed class UserService : IUserService
{
    private readonly AuthDbContext _db;
    private readonly IOpenIddictTokenManagerFacade _tokens; // see Signing/TokenFamily.cs
    private readonly IUserSession _sessions;
    public UserService(AuthDbContext db, IOpenIddictTokenManagerFacade tokens, IUserSession sessions)
        => (_db, _tokens, _sessions) = (db, tokens, sessions);

    public async Task<AppUser?> ValidatePasswordAsync(string username, string password, CancellationToken ct = default)
    {
        var u = await _db.Users.Include(x => x.MfaMethods)
            .FirstOrDefaultAsync(x => x.Username == username && x.IsActive, ct);
        if (u?.PasswordHash is null) return null;
        return Verify(password, u.PasswordHash) ? u : null;
    }

    public Task<AppUser?> GetAsync(Guid id, CancellationToken ct = default)
        => _db.Users.Include(x => x.MfaMethods).FirstOrDefaultAsync(x => x.Id == id, ct);

    public Task<AppUser?> FindByEmailAsync(string email, CancellationToken ct = default)
        => _db.Users.FirstOrDefaultAsync(x => x.Email == email && x.IsActive, ct);

    public async Task<AppUser?> CreateUserAsync(string username, string email, string password, CancellationToken ct = default)
    {
        if (password.Length < 8) return null;
        if (await _db.Users.AnyAsync(x => x.Username == username || x.Email == email, ct)) return null; // taken
        var u = new AppUser
        {
            Username = username, Email = email, EmailVerified = false, IsActive = true,
            PasswordHash = Hash(password), ProfileClaimsJson = "{}",
        };
        _db.Users.Add(u);
        try { await _db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { return null; } // unique race
        return u;
    }

    public async Task MarkEmailVerifiedAsync(Guid userId, CancellationToken ct = default)
    {
        var u = await _db.Users.FindAsync(new object[] { userId }, ct);
        if (u is not null && !u.EmailVerified) { u.EmailVerified = true; await _db.SaveChangesAsync(ct); }
    }

    public async Task ResetPasswordAsync(Guid userId, string newPassword, CancellationToken ct = default)
    {
        var u = await _db.Users.FindAsync(new object[] { userId }, ct);
        if (u is null) return;
        u.PasswordHash = Hash(newPassword);
        await _db.SaveChangesAsync(ct);
        await RevokeAllForUserAsync(userId, ct);   // a reset invalidates everything (tree (c))
    }

    // Verify current password, set the new one, then revoke everything (tokens + sessions)
    // issued under the old credential. Caller re-establishes the current device's session.
    public async Task<bool> ChangePasswordAsync(Guid userId, string current, string newPassword, CancellationToken ct = default)
    {
        var u = await _db.Users.FindAsync(new object[] { userId }, ct);
        if (u?.PasswordHash is null || !Verify(current, u.PasswordHash)) return false;
        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 8) return false;
        u.PasswordHash = Hash(newPassword);
        await _db.SaveChangesAsync(ct);
        await RevokeAllForUserAsync(userId, ct);   // bump CredentialsChangedAt + revoke all
        return true;
    }

    public Task SaveAsync(CancellationToken ct = default) => _db.SaveChangesAsync(ct);

    public async Task AddMfaMethodAsync(UserMfaMethod method, CancellationToken ct = default)
    {
        _db.MfaMethods.Add(method);                  // explicit Added state → INSERT
        await _db.SaveChangesAsync(ct);
    }

    // Credential change → invalidate everything issued before now (threat tree (c) / AC-c-*).
    public async Task RevokeAllForUserAsync(Guid userId, CancellationToken ct = default)
    {
        var u = await _db.Users.FindAsync(new object[] { userId }, ct);
        if (u is null) return;
        u.CredentialsChangedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);
        // Tokens are keyed by the PAIRWISE sub (PPID), not userId — revoke across every PPID
        // the user has (one per sector/client), else nothing matches. [ADR-0010]
        var ppids = await _db.SubjectIdentifiers.Where(s => s.UserId == userId)
            .Select(s => s.Ppid).ToListAsync(ct);
        foreach (var ppid in ppids) await _tokens.RevokeAllForSubjectAsync(ppid, ct);
        await _sessions.RevokeAllForUserAsync(userId, ct);             // every browser session
    }

    // Argon2id (OWASP-recommended). Params: 64 MiB, 3 passes, parallelism 4 — a reasonable
    // interactive-login baseline. Stored as argon2id$m=..,t=..,p=..$salt$hash (PHC-ish).
    private const int MemKiB = 65536, Iterations = 3, Parallelism = 4, HashLen = 32;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Argon2(password, salt, MemKiB, Iterations, Parallelism, HashLen);
        return $"argon2id$m={MemKiB},t={Iterations},p={Parallelism}$" +
               $"{Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    private static bool Verify(string password, string stored)
    {
        var p = stored.Split('$');
        if (p.Length != 4 || p[0] != "argon2id") return false;
        var prm = p[1].Split(',').Select(kv => int.Parse(kv.Split('=')[1])).ToArray(); // m,t,p
        var salt = Convert.FromBase64String(p[2]);
        var expected = Convert.FromBase64String(p[3]);
        var actual = Argon2(password, salt, prm[0], prm[1], prm[2], expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] Argon2(string password, byte[] salt, int memKiB, int iters, int par, int len)
    {
        using var a = new Konscious.Security.Cryptography.Argon2id(Encoding.UTF8.GetBytes(password))
        { Salt = salt, MemorySize = memKiB, Iterations = iters, DegreeOfParallelism = par };
        return a.GetBytes(len);
    }
}
