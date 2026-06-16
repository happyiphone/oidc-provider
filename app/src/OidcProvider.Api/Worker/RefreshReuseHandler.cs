using OidcProvider.Core.Signing;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace OidcProvider.Api.Worker;

// ADR-0007 / threat T4. With reference refresh tokens enabled, OpenIddict tracks each
// refresh token's status. When a token that has already been redeemed (rolled out) is
// presented again, that is a breach signal: we revoke the WHOLE family (the authorization
// and all its tokens), not just the one token.
//
// NOTE: OpenIddict already REJECTS a reused refresh token with invalid_grant out of the
// box; this handler adds the family-wide revocation on top. The exact event/context
// surface is OpenIddict-version-specific — this targets the 5.x ProcessAuthentication
// stage. Pin to your version and verify the context property names against the abuse
// test AC-T4-1/AC-T4-2.
public sealed class RefreshReuseHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessAuthenticationContext>
{
    private readonly IOpenIddictTokenManager _tokens;
    private readonly IOpenIddictTokenManagerFacade _family;

    public RefreshReuseHandler(IOpenIddictTokenManager tokens, IOpenIddictTokenManagerFacade family)
        => (_tokens, _family) = (tokens, family);

    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessAuthenticationContext context)
    {
        // Only interested in refresh-token redemption at the token endpoint.
        if (context.EndpointType != OpenIddictServerEndpointType.Token) return;
        if (context.Request?.IsRefreshTokenGrantType() != true) return;

        // The principal resolved from the presented refresh token. OpenIddict already
        // rejects an outright-reused token; here we additionally inspect the backing
        // token entry's status and, if it has been redeemed (rolled out) yet is being
        // presented again, escalate to FAMILY-wide revocation.
        var tokenId = context.RefreshTokenPrincipal?.GetTokenId();
        if (tokenId is null) return;

        var token = await _tokens.FindByIdAsync(tokenId);
        if (token is null) return;

        var status = await _tokens.GetStatusAsync(token);
        if (string.Equals(status, OpenIddictConstants.Statuses.Redeemed, StringComparison.OrdinalIgnoreCase))
        {
            var authorizationId = await _tokens.GetAuthorizationIdAsync(token);
            if (authorizationId is not null)
                await _family.RevokeFamilyAsync(authorizationId);   // <-- family-wide kill (T4)
        }
    }
}
