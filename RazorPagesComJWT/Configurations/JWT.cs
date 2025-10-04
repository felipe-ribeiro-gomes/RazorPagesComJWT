namespace RazorPagesComJWT.Configurations;

public class JWT
{
    public required string SigningKey { get; set; }
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public required int ExpirationLifetime { get; set; }
}
