namespace RazorPagesComJWT.Configurations;

public class JWT
{
    public required string SymmetricSecurityKey { get; set; }
    public required string RSAPrivateKey { get; set; }
    public required string RSAPublicKey { get; set; }
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public required int ExpirationLifetime { get; set; }
}
