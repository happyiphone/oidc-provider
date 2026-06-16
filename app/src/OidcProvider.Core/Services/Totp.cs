using System.Security.Cryptography;

namespace OidcProvider.Core.Services;

// RFC 6238 TOTP (RFC 4226 HOTP over a time counter). HMAC-SHA1, 6 digits, 30s step.
// Secrets are Base32 (RFC 4648). This is a real verifier, not a stub — it replaces the
// "accept any code" placeholder in the MFA step. WebAuthn would be a parallel verifier.
public interface ITotpService
{
    bool Verify(string base32Secret, string code, int window = 1);
    string Generate(string base32Secret, long? unixTime = null); // for tests/provisioning
}

public sealed class TotpService : ITotpService
{
    private const int Digits = 6;
    private const int StepSeconds = 30;

    public bool Verify(string base32Secret, string code, int window = 1)
    {
        if (string.IsNullOrWhiteSpace(code)) return false;
        code = code.Trim();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // Accept +/- `window` steps to tolerate clock skew (RFC 6238 §5.2).
        for (var i = -window; i <= window; i++)
        {
            var candidate = Compute(base32Secret, now + i * StepSeconds);
            if (CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(candidate),
                    System.Text.Encoding.ASCII.GetBytes(code)))
                return true;
        }
        return false;
    }

    public string Generate(string base32Secret, long? unixTime = null)
        => Compute(base32Secret, unixTime ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    private static string Compute(string base32Secret, long unixTime)
    {
        var counter = unixTime / StepSeconds;
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);

        using var hmac = new HMACSHA1(Base32Decode(base32Secret));
        var hash = hmac.ComputeHash(counterBytes);

        var offset = hash[^1] & 0x0F;                       // dynamic truncation (RFC 4226 §5.3)
        var binary = ((hash[offset] & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   |  (hash[offset + 3] & 0xFF);
        var otp = binary % (int)Math.Pow(10, Digits);
        return otp.ToString().PadLeft(Digits, '0');
    }

    private static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        input = input.TrimEnd('=').ToUpperInvariant().Replace(" ", "");
        var bits = 0; var value = 0; var output = new List<byte>();
        foreach (var c in input)
        {
            var idx = alphabet.IndexOf(c);
            if (idx < 0) continue;
            value = (value << 5) | idx; bits += 5;
            if (bits >= 8) { output.Add((byte)((value >> (bits - 8)) & 0xFF)); bits -= 8; }
        }
        return output.ToArray();
    }
}
