using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RazorPagesComJWT.Pages
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public string Username { get; set; }
        
        [BindProperty]
        public string Password { get; set; }
        
        public string ErrorMessage { get; set; }

        public IActionResult OnGet(string token)
        {
            if (string.IsNullOrEmpty(token))
                return Page();

            if (ValidateToken(token))
            {
                GenerateCookie(token);
                return RedirectToPage("/Index");
            }

            ErrorMessage = "Token inv�lido";
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

            ErrorMessage = "Usu�rio ou senha inv�lidos";
            return Page();
        }

        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("sua-chave-secreta-muito-segura-e-complexa"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            var token = new JwtSecurityToken(
                issuer: "sua-aplicacao",
                audience: "seus-usuarios",
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private void GenerateCookie(string token, DateTime? expiration = null)
        {
            Response.Cookies.Append("AuthToken", token, new CookieOptions
            {
                HttpOnly = true, // HttpOnly para seguran�a
                Secure = true, // usar HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = expiration
            });
        }

        private bool ValidateToken(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("sua-chave-secreta-muito-segura-e-complexa"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var tokenHandler = new JwtSecurityTokenHandler();
            
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = credentials.Key,
                    ValidateIssuer = true,
                    ValidIssuer = "sua-aplicacao",
                    ValidateAudience = true,
                    ValidAudience = "seus-usuarios",
                    ValidateLifetime = true, // valida expira��o
                    ClockSkew = TimeSpan.Zero // sem toler�ncia de tempo extra
                }, out SecurityToken validatedToken);
                
                // Se chegou aqui, token � v�lido
                return true;
            }
            catch
            {
                // Token inv�lido, expirado ou mal formado
                return false;
            }
        }
    }
}
