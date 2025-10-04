using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RazorPagesComJWT.Configurations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace RazorPagesComJWT.Pages
{
    public class LoginModel : PageModel
    {
        private readonly JWT _jwt;

        [BindProperty]
        public string? Username { get; set; }
        
        [BindProperty]
        public string? Password { get; set; }
        
        public string? ErrorMessage { get; set; }

        public LoginModel(IOptions<JWT> jwt)
        {
            _jwt = jwt.Value;
        }

        public IActionResult OnPost()
        {
            if (Username == "usuario" && Password == "senha123")
            {
                var token = GenerateJwtToken(Username);
                GenerateCookie(token);
                return RedirectToPage("/Index");
            }

            ErrorMessage = "Usuário ou senha inválidos";
            return Page();
        }

        private SigningCredentials GetSymmetricSigningCredentials()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SymmetricSecurityKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            return credentials;
        }

        private SigningCredentials GetRSASigningCredentials()
        {
            // Suponha que você tenha a chave privada em base64 (do passo 1)
            string privateKeyBase64 = _jwt.RSAPrivateKey;
            var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
            RSA rsaPrivate = RSA.Create();
            rsaPrivate.ImportPkcs8PrivateKey(privateKeyBytes, out _);
            var credentials = new SigningCredentials(new RsaSecurityKey(rsaPrivate), SecurityAlgorithms.RsaSha256);

            return credentials;
        }

        private string GenerateJwtToken(string username)
        {
            //var credentials = GetSymmetricSigningCredentials();
            var credentials = GetRSASigningCredentials();

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddSeconds(_jwt.ExpirationLifetime),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private void GenerateCookie(string token, DateTime? expiration = null)
        {
            Response.Cookies.Append("AuthToken", token, new CookieOptions
            {
                HttpOnly = true, // HttpOnly para segurança
                Secure = true, // usar HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = expiration
            });
        }
    }
}
