using API.Interfaces;
using API.Entities;
using SQLitePCL;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace API.Services;

public class TokenService(IConfiguration config) : ITokenService
{
    public string CreateToken(AppUser user)
    {
        string tokenKey = config["TokenKey"] ?? throw new Exception("Cannot access tokenKey from appSettings");
        if (tokenKey.Length < 64) throw new Exception("Your tokenKey needs to be longer");
        SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(tokenKey));

        IList<Claim> claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.UserName)
        };

        SigningCredentials creds = new(key, SecurityAlgorithms.HmacSha512Signature);

        SecurityTokenDescriptor tokenDescriptor = new()
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = creds
        };

        JwtSecurityTokenHandler tokenHandler = new();

        SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}
