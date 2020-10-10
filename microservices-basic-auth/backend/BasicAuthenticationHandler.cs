using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace backend
{
    public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationSchemeOptions>
    {
        public BasicAuthenticationHandler(IOptionsMonitor<BasicAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(this.HandleAuthenticate());

        private AuthenticateResult HandleAuthenticate()
        {
            var authHeader = this.Request.Headers["Authorization"];
            var basicScheme = AuthenticationSchemes.Basic.ToString();
            if (string.IsNullOrEmpty(authHeader))
            {
                this.Response.Headers.Add("WWW-Authenticate", $"{basicScheme} realm=\"{this.Options.Realm}\"");
                return AuthenticateResult.Fail("No authorization header");
            }

            try
            {
                var authHeaderValue = AuthenticationHeaderValue.Parse(authHeader);
                if (!authHeaderValue.Scheme.Equals(basicScheme, StringComparison.OrdinalIgnoreCase))
                {
                    this.Response.Headers.Add("WWW-Authenticate", $"{basicScheme} realm=\"{this.Options.Realm}\"");
                    return AuthenticateResult.Fail("Only basic scheme allowed");
                }

                var credentials = Encoding.UTF8
                    .GetString(Convert.FromBase64String(authHeaderValue.Parameter ?? string.Empty))
                    .Split(':', 2);

                if (credentials[0].Equals(this.Options.Username) && credentials[1].Equals(this.Options.Password))
                {
                    var principal = new ClaimsPrincipal(
                        new ClaimsIdentity(
                            new[]
                            {
                                new Claim(ClaimsIdentity.DefaultNameClaimType, credentials[0])
                            },
                            "Password"));

                    return AuthenticateResult.Success(new AuthenticationTicket(principal, basicScheme));
                }

                return AuthenticateResult.Fail("Unauthorized");
            }
            catch (FormatException ex)
            {
                return AuthenticateResult.Fail(ex);
            }
        }
    }
}
