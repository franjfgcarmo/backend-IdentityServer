using AutoMapper;
using IdentityModel.AspNetCore.OAuth2Introspection;
using IdentityServer4.AccessTokenValidation;
using ImageGallery.API.Authorization;
using ImageGallery.API.Entities;
using ImageGallery.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;

namespace ImageGallery.API
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        
        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers()
                     .AddJsonOptions(opts => opts.JsonSerializerOptions.PropertyNamingPolicy = null);
            
            services.AddHttpContextAccessor();
            services.AddScoped<IAuthorizationHandler, MustOwnImageHandler>();
            services.AddAuthorization(authorizationOptions =>
            {
                authorizationOptions.AddPolicy(
                    "MustOwnImage",
                    policyBuilder =>
                    {
                        policyBuilder.RequireAuthenticatedUser();
                        policyBuilder.AddRequirements(
                              new MustOwnImageRequirement());
                    });
            });
            /*https://docs.identityserver.io/en/latest/topics/apis.html?highlight=Bearer
             * https://docs.identityserver.io/en/latest/quickstarts/1_client_credentials.html?highlight=Bearer
             * 
                validate the incoming token to make sure it is coming from a trusted issuer
                validate that the token is valid to be used with this api (aka audience)
                We register access token Validation, middleware.
             */

            services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
                .AddIdentityServerAuthentication(options =>
                {
                    options.Authority = "https://localhost:5001";
                    options.ApiName = "imagegalleryapi";
                    options.ApiSecret = "apisecret";
                });

            //services.AddAuthentication("Bearer")
            //  .AddJwtBearer(options =>
            //  {
            //      options.Authority = "https://localhost:5001/";
            //      options.Audience = "imagegalleryapi";
            //      options.TokenValidationParameters = new TokenValidationParameters
            //      {
            //          ValidateAudience = false,
            //      };
            //  });
            //.AddOAuth2Introspection(OAuth2IntrospectionDefaults.AuthenticationScheme, options =>
            //{
            //    options.Authority = "https://localhost:5001/";
            //    options.ClientId = "imagegalleryapi";
            //    options.ClientSecret = "apisecret";
            //}); 

            // register the DbContext on the container, getting the connection string from
            // appSettings (note: use this during development; in a production environment,
            // it's better to store the connection string in an environment variable)
            services.AddDbContext<GalleryContext>(options =>
            {
                options.UseSqlServer(
                    Configuration["ConnectionStrings:ImageGalleryDBConnectionString"]);
            });

            // register the repository
            services.AddScoped<IGalleryRepository, GalleryRepository>();

            // register AutoMapper-related services
            services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler(appBuilder =>
                {
                    appBuilder.Run(async context =>
                    {
                        // ensure generic 500 status code on fault.
                        context.Response.StatusCode = StatusCodes.Status500InternalServerError; ;
                        await context.Response.WriteAsync("An unexpected fault happened. Try again later.");
                    });
                });
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
                endpoints.MapControllers();
            });
        }
    }
}
