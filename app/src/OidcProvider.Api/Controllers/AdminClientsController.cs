using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace OidcProvider.Api.Controllers;

// Admin client management. Gated behind an admin API key (separate trust domain from
// end-user auth). Lets an operator inspect and remove clients — including ones created via
// dynamic registration (RFC 7591). Update is intentionally limited; re-register for big changes.
[ApiController]
[Route("/admin/clients")]
public sealed class AdminClientsController : Controller
{
    private readonly IOpenIddictApplicationManager _apps;
    private readonly IConfiguration _cfg;
    public AdminClientsController(IOpenIddictApplicationManager apps, IConfiguration cfg)
        => (_apps, _cfg) = (apps, cfg);

    private bool Authorized()
    {
        var key = _cfg["Oidc:Admin:ApiKey"];
        return !string.IsNullOrEmpty(key) &&
               Request.Headers.Authorization.ToString().Equals("Bearer " + key, StringComparison.Ordinal);
    }

    [HttpGet]
    public async Task<IActionResult> List()
    {
        if (!Authorized()) return Unauthorized();
        var result = new List<object>();
        await foreach (var app in _apps.ListAsync())
            result.Add(await SummaryAsync(app));
        return Ok(result);
    }

    [HttpGet("{clientId}")]
    public async Task<IActionResult> Get(string clientId)
    {
        if (!Authorized()) return Unauthorized();
        var app = await _apps.FindByClientIdAsync(clientId);
        return app is null ? NotFound() : Ok(await SummaryAsync(app));
    }

    [HttpDelete("{clientId}")]
    public async Task<IActionResult> Delete(string clientId)
    {
        if (!Authorized()) return Unauthorized();
        var app = await _apps.FindByClientIdAsync(clientId);
        if (app is null) return NotFound();
        await _apps.DeleteAsync(app);
        return NoContent();
    }

    private async Task<object> SummaryAsync(object app) => new
    {
        client_id = await _apps.GetClientIdAsync(app),
        display_name = await _apps.GetDisplayNameAsync(app),
        client_type = await _apps.GetClientTypeAsync(app),
        redirect_uris = await _apps.GetRedirectUrisAsync(app),
        permissions = await _apps.GetPermissionsAsync(app),
    };
}
