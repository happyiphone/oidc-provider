namespace OidcProvider.Api.Models;

public sealed class LoginViewModel
{
    public string? ReturnUrl { get; set; }
    public string? Error { get; set; }
    public string? FederationName { get; set; }   // shows a "Log in with <name>" button when set
}

public sealed class MfaViewModel
{
    public string? ReturnUrl { get; set; }
    public string? Error { get; set; }
}

public sealed class ConsentRow
{
    public string ClientId { get; set; } = "";
    public IReadOnlyList<string> Scopes { get; set; } = Array.Empty<string>();
}

public sealed class ConsentsListViewModel
{
    public IReadOnlyList<ConsentRow> Consents { get; set; } = Array.Empty<ConsentRow>();
}

public sealed class ConsentViewModel
{
    public string ClientId { get; set; } = "";
    public IReadOnlyList<string> Scopes { get; set; } = Array.Empty<string>();
    // Original authorization parameters echoed as hidden inputs so the POST body carries
    // them (OpenIddict reads the authorization request from the form on POST).
    public IReadOnlyList<KeyValuePair<string, string>> Parameters { get; set; }
        = Array.Empty<KeyValuePair<string, string>>();
}
