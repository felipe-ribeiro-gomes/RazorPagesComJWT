using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RazorPagesComJWT.Configurations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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

        public IActionResult OnGet(string token)
        {
            if (string.IsNullOrEmpty(token))
                return Page();

            if (ValidateToken(token))
            {
                GenerateCookie(token);
                return RedirectToPage("/Index");
            }

            ErrorMessage = "Token inválido";
            return Page();
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

        private SigningCredentials GetJwtSigningCredentials()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SigningKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            return credentials;
        }

        private string GenerateJwtToken(string username)
        {
            var credentials = GetJwtSigningCredentials();
            
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

        private bool ValidateToken(string token)
        {
            var credentials = GetJwtSigningCredentials();
            var tokenHandler = new JwtSecurityTokenHandler();
            
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = credentials.Key,
                    ValidateIssuer = true,
                    ValidIssuer = _jwt.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _jwt.Audience,
                    ValidateLifetime = true, // valida expiração
                    ClockSkew = TimeSpan.Zero // sem tolerância de tempo extra
                }, out SecurityToken validatedToken);
                
                // Se chegou aqui, token é válido
                return true;
            }
            catch
            {
                // Token inválido, expirado ou mal formado
                return false;
            }
        }
    }
}
