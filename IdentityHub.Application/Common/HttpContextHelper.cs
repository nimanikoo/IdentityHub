using Microsoft.AspNetCore.Http;

namespace IdentityHub.Application.Common;

public static class HttpContextHelper
{
    private static IHttpContextAccessor _accessor;

    public static void Configure(IHttpContextAccessor accessor)
    {
        _accessor = accessor;
    }

    public static HttpContext Current => _accessor.HttpContext!;
}