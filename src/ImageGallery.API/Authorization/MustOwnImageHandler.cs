﻿using ImageGallery.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ImageGallery.API.Authorization
{
    public class MustOwnImageHandler : AuthorizationHandler<MustOwnImageRequirement>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IGalleryRepository _galleryRepository;

        public MustOwnImageHandler(IHttpContextAccessor httpContextAccessor,
            IGalleryRepository galleryRepository)
        {
            _httpContextAccessor = httpContextAccessor??
                throw new ArgumentException(nameof(httpContextAccessor));
            _galleryRepository = galleryRepository ??
                throw new ArgumentException(nameof(galleryRepository));
        }

        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, 
            MustOwnImageRequirement requirement)
        {
            var imageId = _httpContextAccessor.HttpContext.GetRouteValue("id").ToString();
            if (!Guid.TryParse(imageId, out Guid imageIdAsGuid))
            {
                context.Fail();
                return Task.CompletedTask;
            }
            //var ownerId = context.User.Claims.
            //    FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var ownerId = context.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            if (!_galleryRepository.IsImageOwner(imageIdAsGuid, ownerId))
            {
                context.Fail();
                return Task.CompletedTask;
            }
            //all checks out.
            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }
}
