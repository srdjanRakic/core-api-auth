using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Auth.Controllers
{
	[Route("api/[controller]")]
	public class AuthController : Controller
    {
		[HttpPost("token")]
        public IActionResult Token()
        {
			var header = Request.Headers["Authorization"];

			if (header.ToString().StartsWith("Basic"))
			{
				var credValue = header.ToString().Substring("Basic ".Length).Trim();
				var usernameAndPassEncoded = Encoding.UTF8.GetString(Convert.FromBase64String(credValue));
				var userNameAndPass = usernameAndPassEncoded.Split(":");

				// check in DB username and pass exists
				if (userNameAndPass[0] == "Admin" && userNameAndPass[1] == "pass")
				{
					var claimsData = new[] { new Claim(ClaimTypes.Name, userNameAndPass[0]) };
					var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("aadadaghasdsagghhgd"));
					var signInCred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

					var token = new JwtSecurityToken(
							issuer: "tripx.se",
							audience: "tripx.se",
							expires: DateTime.Now.AddMinutes(10),
							claims: claimsData,
							signingCredentials: signInCred
						);

					var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

					return Ok(tokenString);
				}
			}

			return BadRequest("Wrong request");
		
        }
    }
}