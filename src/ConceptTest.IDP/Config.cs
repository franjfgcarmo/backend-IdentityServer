// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace ConceptTest.IDP
{
    public static class Config
    {
        //Ids is a set of identity-related resources. These map to claims of a user,
        //like first name and last name.
        public static IEnumerable<IdentityResource> Ids =>
            new IdentityResource[]
            { 
                // OpenId has been added. which maps to 
                //a sbclaim also known as the user´s identifier.
                new IdentityResources.OpenId(),
                // this maps to profile-related claims like given_name and
                //family_name, and those happend to be the two additional claims we 
                //gave our users.
                new IdentityResources.Profile(),
                new IdentityResources.Address(),
                /*We need to create a new Identity scope. The role scope isn´t one
                 of the standard defined OpenId Connect scopes. So we can´t refer
                to this in the same wasy as we refer to IdentityResourses. We create
                new IdentityResource.*/
                new IdentityResource(
                    "roles",
                    "Your role(s)",
                    new List<string>(){ "role"}),
                new IdentityResource(
                    "country",
                    "The country you're living in",
                    new List<string>() { "country" }),
                new IdentityResource(
                    "subscriptionlevel",
                    "Your subscription level",
                    new List<string>() { "subscriptionlevel" })
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                //add new API resource to the list of scope
                new ApiScope(
                    "imagegalleryapi",
                    "Image Gallery API"/*, 
                    new List<string>(){ "role"}*/),
                

            };
        public static IEnumerable<ApiResource> ApiResources =>
        new ApiResource[]
        {
              new ApiResource(
                  "imagegalleryapi",
                  "Image Gallery API",
                  new List<string>() { "role" })
              {
                  ApiSecrets = { new Secret("apisecret".Sha256()) }
              }
        };

        public static List<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile() ,// <-- usefull
                new IdentityResources.Address()
            };
        }
        public static IEnumerable<Client> Clients =>
            new Client[] 
            {
                new Client
                {
                    //AccessTokenType = AccessTokenType.Reference,
                    //IdentityTokenLifetime=,//It´s to the number of seconds the tokens is valid, default 5 minutes.
                    //AuthorizationCodeLifetime=,//It´s exchanged for one or more tokens when the token endpoint is called.
                    //That´s something that happens during the initial flow, is it also warants a low lifetime, as we
                    // don´t want to allow using this code for longer than required
                    AccessTokenLifetime=120,// You can set that via the AcessTokenLifetime property. The default is 1 hour. Let´s set that 
                    //to a much lover value, say 2 minutes, or 120 seconds
                    AllowOfflineAccess=true,
                    ///AbsoluteRefreshTokenLifetime = //The expiration time is fixed. The default is 30 days.
                    //RefreshTokenExpiration = TokenExpiration.Sliding,//but refresh tokens don´t have to have an basolute lifetime. Sliding expiration is possible as well
                    //SlidingRefreshTokenLifetime = //The  amount of time specified by the SlidingRefreshTokenLifetime property value, But it will
                    // never exceed the AbsoluteRefreshTokenLifetime
                    UpdateAccessTokenClaimsOnRefresh= true,//imagine the case where one of the use´s claim is changed, say the address. By default, the 
                    //claims in the access token stay as is when refreshing them. So if a refresh token has a value of 30 days, in a worst-case
                    //scenario, those changes won´t be reflected in the access token for 30 days. By setting this property to true, they will
                    //be, That´s if for the identiy provider.
                    ClientName="Image Gallery",
                    ClientId="imagegalleryclient",
                    AllowedGrantTypes = GrantTypes.Code,
                    RequirePkce=true,
                    RedirectUris = new List<string>()
                    { 
                        "https://localhost:44389/signin-oidc"
                    }, 
                    PostLogoutRedirectUris = new List<string>()
                    {
                        "https://localhost:44389/signout-callback-oidc"
                    },
                    AllowedScopes={ 
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Address,
                        "roles",
                        "imagegalleryapi",//clients can request it.  
                        "country",
                        "subscriptionlevel"
                    },
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    }

                }
            };
    }
}