using Microsoft.AspNetCore.Authentication;

namespace backend
{
    public class BasicAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public string Realm { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }
    }
}
