namespace OidcProvider.Core;

// Single source of truth for unpadded URL-safe Base64 (RFC 4648 §5), used by WebAuthn,
// pairwise subjects, session ids, and seeding. Previously hand-rolled in 4 places.
public static class Base64UrlText
{
    public static string Encode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        s += new string('=', (4 - s.Length % 4) % 4);
        return Convert.FromBase64String(s);
    }
}
