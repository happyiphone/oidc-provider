using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using OidcProvider.Core.Entities;

namespace OidcProvider.Core.Data;

public sealed class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<UserMfaMethod> MfaMethods => Set<UserMfaMethod>();
    public DbSet<SubjectIdentifier> SubjectIdentifiers => Set<SubjectIdentifier>();
    public DbSet<Consent> Consents => Set<Consent>();
    public DbSet<ClientPolicy> ClientPolicies => Set<ClientPolicy>();
    public DbSet<SigningKeyRecord> SigningKeys => Set<SigningKeyRecord>();
    public DbSet<AuditEntry> AuditLog => Set<AuditEntry>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        // OpenIddict's own protocol tables (applications/authorizations/tokens/scopes).
        b.UseOpenIddict();

        b.Entity<AppUser>(e =>
        {
            e.HasIndex(x => x.Email).IsUnique();
            e.HasIndex(x => x.Username).IsUnique();
            e.HasMany(x => x.MfaMethods).WithOne(m => m.User!).HasForeignKey(m => m.UserId);
        });

        b.Entity<SubjectIdentifier>(e =>
        {
            e.HasKey(x => new { x.UserId, x.SectorIdentifier });
            e.HasIndex(x => new { x.SectorIdentifier, x.Ppid }).IsUnique();
        });

        b.Entity<Consent>(e =>
        {
            e.HasIndex(x => new { x.UserId, x.ClientId }).IsUnique();
            e.Property(x => x.ScopesGranted)
                .HasConversion(
                    v => string.Join(' ', v),
                    v => v.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList(),
                    new ValueComparer<List<string>>(
                        (a, b) => a!.SequenceEqual(b!),
                        c => c.Aggregate(0, (h, s) => HashCode.Combine(h, s.GetHashCode())),
                        c => c.ToList()));
        });

        b.Entity<ClientPolicy>(e => e.HasKey(x => x.ClientId));

        b.Entity<SigningKeyRecord>(e =>
        {
            e.HasKey(x => x.Kid);
            // ADR-0005 invariant: at most one ACTIVE signing key (partial unique index).
            e.HasIndex(x => x.Status)
             .HasFilter("\"Status\" = 1")          // 1 == KeyStatus.Active
             .IsUnique();
        });

        b.Entity<AuditEntry>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).UseIdentityAlwaysColumn();
            e.HasIndex(x => x.OccurredAt);
        });
    }
}
