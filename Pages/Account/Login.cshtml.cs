using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SimuNikiCakes.Pages.Account
{
    public class LoginModel : PageModel
    {
		[BindProperty]
		[Required]
		[Display(Name ="Email Address")]
		public string EmailAddress { get; set; }

		[Required]
		[BindProperty]
		[DataType(DataType.Password)]
		public string Password { get; set; }

		public IActionResult OnPost()
		{
			var isValidUser = EmailAddress == "admin@gmail.com"
				&& Password == "admin";

			if (!isValidUser)
			{
				ModelState.AddModelError("", "Invalid Username and Password!");
			}

			if (!ModelState.IsValid)
			{
				return Page();
			}

			var scheme = CookieAuthenticationDefaults.AuthenticationScheme;

			var user = new ClaimsPrincipal(
				new ClaimsIdentity(
					new[] { new Claim(ClaimTypes.Name, EmailAddress) },
					scheme
					)
				);

			return SignIn(user, scheme);
		}

		public async Task<IActionResult> OnPostLogoutAsync()
		{
			await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

			return RedirectToPage("Index");
		}
	}
}