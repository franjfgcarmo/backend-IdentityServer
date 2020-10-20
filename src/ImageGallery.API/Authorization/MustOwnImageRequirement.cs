using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ImageGallery.API.Authorization
{
    /// <summary>
    /// This requirement can be used for storing additional contextual information.
    /// If we were to make a requirement staging that a user needs to be from a specific country,
    /// we could input the value for the country to match as a constructor parameter, but or for requirement
    /// there´s no need for any code here. We do need a handler though.
    /// </summary>
    public class MustOwnImageRequirement : IAuthorizationRequirement
    {
        public MustOwnImageRequirement()
        {
        }
    }
}
