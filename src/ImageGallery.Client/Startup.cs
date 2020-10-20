using IdentityModel;
using ImageGallery.Client.HttpHandlers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace ImageGallery.Client
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            /* That mapping dictionary, that's the default inbound claim type map on
             * the JWT security token handler. 
             */
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
                 .AddJsonOptions(opts => opts.JsonSerializerOptions.PropertyNamingPolicy = null);
            /*Add new policies to AddAuthorization on the service object.
             * here we can call addpolicy on these options to add a new policy
             */
            services.AddAuthorization(authorizationOptions =>
            {
                authorizationOptions.AddPolicy(
                    "CanOrderFrame",//name
                    policyBuilder =>
                    {
                        policyBuilder.RequireAuthenticatedUser();
                        //we state that we require the claim country and that
                        // we require its value to be "be". If multiple values would
                        //be okay, we cans just add them next to each other, for example: ,"nl",...
                        policyBuilder.RequireClaim("country", "be");
                        policyBuilder.RequireClaim("subscriptionlevel", "PayingUser");

                    });
            });
            /*
             * Register HttpContextAccessor and handler.
             */
            services.AddHttpContextAccessor();
            services.AddTransient<BearerTokenHandler>();
            // create an HttpClient used for accessing the API
            services.AddHttpClient("APIClient", client =>
            {
                client.BaseAddress = new Uri("https://localhost:44366/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            }).AddHttpMessageHandler<BearerTokenHandler>();//we need to do is ensure that our API client uses this handler

            // create an HttpClient used for accessing the IDP
            services.AddHttpClient("IDPClient", client =>
            {
                client.BaseAddress = new Uri("https://localhost:5001/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            });
            services.AddAuthentication(options =>
            {
                /*We seee that actually refers to a string value of cookies. This is a value we can choose, but it should 
                 * correspond to the logical name for a particular authentication scheme. We could manually input that string value
                 * but working with one of the predefined constains is nicer when ther are available. By setting this value,
                 * we can sign in to the scheme, sign out from it, read sheme-related information and so on. All by referring to 
                 * this cookie name. It´s not strictly necessary in our case, but I prefer to explicitly set this so we can get 
                 * a better understanding of what´s going on. Moreover, if you´re hosting different apps on the same domain, you´ll 
                 * want to ensure that these have a different scheme name so their cookies don´t interfere with each other.
                 */
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options=>
                {
                    options.AccessDeniedPath = "/Authorization/AccessDenied";
                }
                )
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.Authority = "https://localhost:5001/";
                    options.ClientId = "imagegalleryclient";
                    options.ResponseType = "code";
                    // options.UsePkce = false;
                    /*Remember that redirect URI we set al level of the indentity provider? we set it to localhost 
                     https://localhost:44389/signin-oidc . That´s the value used by default by the openID Connect
                    middleware. If you have a good reason to change it, you can do so via this property. But we are quite okay
                    with the default value*/
                    //options.CallbackPath = new PathString("...")                      
                    /*This isn´t necessary, because this claims are added by default.
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    */
                    options.Scope.Add("address");
                    options.Scope.Add("roles");
                    /*we have to do is add the resource scope to the requested list of scopes*/
                    options.Scope.Add("imagegalleryapi");
                    //policies
                    options.Scope.Add("subscriptionlevel");
                    options.Scope.Add("country");
                    options.Scope.Add("offline_access");
                    //options.ClaimActions.Remove("nbf");
                    options.ClaimActions.DeleteClaim("sid");
                    options.ClaimActions.DeleteClaim("idp");
                    options.ClaimActions.DeleteClaim("s_hash");
                    options.ClaimActions.DeleteClaim("auth_time");
                    /*The role claim isn´t mapped by default either and that's why 
                     * it's not inclued either.*/
                    options.ClaimActions.MapUniqueJsonKey("role", "role");
                    //Policies
                    options.ClaimActions.MapUniqueJsonKey("subscriptionlevel", "subscriptionlevel");
                    options.ClaimActions.MapUniqueJsonKey("country", "country");
                    options.SaveTokens = true;
                    options.ClientSecret = "secret";
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = JwtClaimTypes.GivenName,
                        RoleClaimType = JwtClaimTypes.Role,
                    };
                });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseStaticFiles();
 
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Shared/Error");
                // The default HSTS value is 30 days. You may want to change this for
                // production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Gallery}/{action=Index}/{id?}");
            });
        }
    }
}
