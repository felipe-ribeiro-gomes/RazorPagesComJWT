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

            // Opcional: limpar sess�o, cookies adicionais, etc.
            // Redireciona para a p�gina de login
            return RedirectToPage("/Login");
        }
    }
}
