using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RazorPagesComJWT.Pages
{
    public class LogoutModel : PageModel
    {
        public IActionResult OnGet()
        {
            // Remove o cookie do token JWT
            Response.Cookies.Delete("AuthToken");

            // Opcional: limpar sessão, cookies adicionais, etc.
            // Redireciona para a página de login
            return RedirectToPage("/Login");
        }
    }
}
