using Microsoft.AspNetCore.Mvc;
using OidcProvider.Core.Services;

namespace OidcProvider.Api.Controllers;

// Self-service onboarding: signup → email verification → password reset. Public endpoints
// (no session), so antiforgery is ignored here (a production UI adds antiforgery + CAPTCHA);
// the security comes from single-use, high-entropy, expiring link tokens and not leaking
// account existence on forgot-password.
[ApiController]
public sealed class OnboardingController : Controller
{
    private const string VerifyPurpose = "verify-email";
    private const string ResetPurpose = "reset-pw";

    private readonly IUserService _users;
    private readonly ITokenLinkStore _links;
    private readonly IEmailSender _email;
    private readonly IAuditLog _audit;
    public OnboardingController(IUserService users, ITokenLinkStore links, IEmailSender email, IAuditLog audit)
        => (_users, _links, _email, _audit) = (users, links, email, audit);

    private string Base => $"{Request.Scheme}://{Request.Host}";

    [HttpPost("/account/signup"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Signup([FromForm] string? username, [FromForm] string? email, [FromForm] string? password)
    {
        var user = await _users.CreateUserAsync(username ?? "", email ?? "", password ?? "");
        if (user is null) return BadRequest(new { error = "signup_failed", error_description = "Username/email taken or password too weak." });

        var token = await _links.CreateAsync(VerifyPurpose, user.Id, TimeSpan.FromHours(24));
        await _email.SendAsync(user.Email!, "Verify your email",
            $"Confirm your account: {Base}/account/verify?token={token}");
        await _audit.WriteAsync("user.signup", user.Id);
        return Ok(new { status = "verification_email_sent" });
    }

    [HttpGet("/account/verify")]
    public async Task<IActionResult> Verify([FromQuery] string? token)
    {
        var userId = await _links.ConsumeAsync(VerifyPurpose, token ?? "");
        if (userId is null) return BadRequest("Invalid or expired verification link.");
        await _users.MarkEmailVerifiedAsync(userId.Value);
        await _audit.WriteAsync("email.verified", userId);
        return Content("Email verified. You can now sign in.", "text/plain");
    }

    [HttpPost("/account/forgot-password"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> ForgotPassword([FromForm] string? email)
    {
        var user = await _users.FindByEmailAsync(email ?? "");
        if (user is not null)   // never reveal whether the address exists
        {
            var token = await _links.CreateAsync(ResetPurpose, user.Id, TimeSpan.FromHours(1));
            await _email.SendAsync(user.Email!, "Reset your password",
                $"Reset link (valid 1h): {Base}/account/reset-password?token={token}");
        }
        return Ok(new { status = "if_the_account_exists_an_email_was_sent" });
    }

    [HttpPost("/account/reset-password"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> ResetPassword([FromForm] string? token, [FromForm] string? newPassword)
    {
        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 8)
            return BadRequest(new { error = "weak_password" });
        var userId = await _links.ConsumeAsync(ResetPurpose, token ?? "");
        if (userId is null) return BadRequest(new { error = "invalid_token" });
        await _users.ResetPasswordAsync(userId.Value, newPassword);   // sets pw + revokes all tokens/sessions
        await _audit.WriteAsync("password.reset", userId);
        return Ok(new { status = "password_reset" });
    }
}
