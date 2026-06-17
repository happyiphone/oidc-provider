using OidcProvider.Core.Services;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Core.Signing;

// ADR-0007 / threat T4 + tree (c). Implemented over OpenIddict's token + authorization
// managers. An OpenIddict "authorization" is the grant; its tokens are the rotation
// chain (the "family"). Revoking the authorization revokes the whole family.
public sealed class TokenFamilyFacade : IOpenIddictTokenManagerFacade
{
    private readonly IOpenIddictTokenManager _tokens;
    private readonly IOpenIddictAuthorizationManager _authorizations;
    private readonly IAuditLog _audit;

    public TokenFamilyFacade(IOpenIddictTokenManager tokens,
                             IOpenIddictAuthorizationManager authorizations, IAuditLog audit)
        => (_tokens, _authorizations, _audit) = (tokens, authorizations, audit);

    // Reuse of a redeemed refresh token detected → kill the entire family.
    public async Task RevokeFamilyAsync(string authorizationId, CancellationToken ct = default)
    {
        var auth = await _authorizations.FindByIdAsync(authorizationId, ct);
        if (auth is null) return;
        await _authorizations.TryRevokeAsync(auth, ct);             // marks authorization revoked
        await foreach (var token in _tokens.FindByAuthorizationIdAsync(authorizationId, ct))
            await _tokens.TryRevokeAsync(token, ct);                // and every token under it
        await _audit.WriteAsync("family.revoked", clientId: await _authorizations.GetApplicationIdAsync(auth, ct),
            detail: new { authorizationId }, ct: ct);               // threat T16
    }

    // Credential change → revoke every authorization for the subject (tree (c) / AC-c-1).
    public async Task RevokeAllForSubjectAsync(string subject, CancellationToken ct = default)
    {
        await foreach (var auth in _authorizations.FindBySubjectAsync(subject, ct))
        {
            var id = await _authorizations.GetIdAsync(auth, ct);
            if (id is not null) await RevokeFamilyAsync(id, ct);   // reuse the family-revoke path
        }
    }
}
