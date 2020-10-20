using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ImageGallery.Client.HttpHandlers
{
   
    /// <summary>
    /// Custom Delegating handler that´ll be responsible for adding the access token
    /// is a cleaner reusable.
    /// </summary>
    /* A good stratagy is to use the refresh token to get a new access to open when the current access has almost expired
     * or has effectively expired. Preferable, we want to do this at a centralized location. We don´t want to repeat code 
     * for this in all our controller actions, and we already have a good place to put this in
     */
    public class BearerTokenHandler: DelegatingHandler
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IHttpClientFactory _httpClientFactory;

        public BearerTokenHandler(IHttpContextAccessor httpContextAccessor, IHttpClientFactory httpClientFactory)
        {
            _httpContextAccessor = httpContextAccessor?? 
                throw new ArgumentException(nameof(httpContextAccessor));
            _httpClientFactory = httpClientFactory ??
                throw new ArgumentException(nameof(httpClientFactory));
        }

        protected  override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var accessToken =await GetAccessTokenAsync();

            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                request.SetBearerToken(accessToken);
            }
            return await base.SendAsync(request, cancellationToken);
        }
        /// <summary>
        /// This method be responsible for returning a non-expired access token, we´re going to 
        /// check whether the access token has almost expired,and if that´s the case, we´re going to refresh it
        /// </summary>
        /// <returns></returns>
        public async Task<string> GetAccessTokenAsync()
        {
            //get the expires_at value & parse it
            var expiresAt = await _httpContextAccessor.HttpContext.GetTokenAsync("expires_at");
            var expiresAtAsDateTimeOffset = DateTimeOffset.Parse(expiresAt, CultureInfo.InvariantCulture);
            //That means that if the access token expires in 60 seconds or less, were going to renew it.
            if (expiresAtAsDateTimeOffset.AddSeconds(-60).ToUniversalTime() > DateTime.UtcNow)
            {
                //no need to refresh, return the access token 
                return await _httpContextAccessor.
                    HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            }
            //if it didn´t check out, we need to use our IDPclient to get a new token ç
            var idpClient = _httpClientFactory.CreateClient("IDPClient");
            //get the discorery document.
            var discoveryResponse = await idpClient.GetDiscoveryDocumentAsync();
            // refresh the tokens
            var refreshToken = await _httpContextAccessor
                       .HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);
            var refreshResponse = await idpClient.RequestRefreshTokenAsync(new RefreshTokenRequest
                {
                    Address = discoveryResponse.TokenEndpoint,
                    ClientId = "imagegalleryclient",
                    ClientSecret = "secret",
                    RefreshToken = refreshToken,
                });

            // store the tokens             
            var updatedTokens = new List<AuthenticationToken>();
            updatedTokens.Add(new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.IdToken,
                Value = refreshResponse.IdentityToken
            });
            updatedTokens.Add(new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.AccessToken,
                Value = refreshResponse.AccessToken
            });
            updatedTokens.Add(new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.RefreshToken,
                Value = refreshResponse.RefreshToken
            });
            updatedTokens.Add(new AuthenticationToken
            {
                Name = "expires_at",
                //we use "o" to format it. as this will format the date in the round-trip format
                Value = (DateTime.UtcNow + TimeSpan.FromSeconds(refreshResponse.ExpiresIn)).
                        ToString("o", CultureInfo.InvariantCulture)
            });
            // get authenticate result, containing the current principal & 
            // properties
            var currentAuthenticateResult = await _httpContextAccessor
                .HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // store the updated tokens
            currentAuthenticateResult.Properties.StoreTokens(updatedTokens);

            // sign in
            await _httpContextAccessor.HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                currentAuthenticateResult.Principal,
                currentAuthenticateResult.Properties);

            return refreshResponse.AccessToken;
        }
    }
}
