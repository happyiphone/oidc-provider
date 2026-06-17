using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api;

// Single source of truth for which claims land in the id_token vs the access token.
// Shared by the authorize and token endpoints so the policy can't drift between them.
public static class OidcDestinations
{
    public static IEnumerable<string> For(Claim claim) => claim.Type switch
    {
        Claims.Name or Claims.Email or Claims.EmailVerified
            => new[] { Destinations.IdentityToken },
        "acr" or "amr"
            => new[] { Destinations.IdentityToken, Destinations.AccessToken },
        _ => new[] { Destinations.AccessToken },
    };
}
