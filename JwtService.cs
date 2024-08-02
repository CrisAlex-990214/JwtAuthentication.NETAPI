using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtNetApi
{
    public class JwtService
    {
        public string GenerateToken(User user, string secret)
        {
            var signinCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret)),
                SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = GetClaims(user),
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = signinCredentials
            };

            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateToken(tokenDescriptor);

            return handler.WriteToken(token);
        }

        private ClaimsIdentity GetClaims(User user) =>
            new(
                [
                 new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                 new(ClaimTypes.Email, user.Email),
                ]
                );
    }
}
