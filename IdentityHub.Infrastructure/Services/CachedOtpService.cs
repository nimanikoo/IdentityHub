using IdentityHub.Application.Common.Interfaces;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace IdentityHub.Infrastructure.Services;

public class CachedOtpService : IOtpService
{
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<CachedOtpService> _logger;

    public CachedOtpService(IMemoryCache memoryCache, ILogger<CachedOtpService> logger)
    {
        _memoryCache = memoryCache;
        _logger = logger;
    }

    public async Task<string> GenerateOtpAsync(string userId, string phoneNumber)
    {
        var code = Random.Shared.Next(100000, 999999).ToString();
        var key = $"OTP_{phoneNumber}";

        var cacheOptions = new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(TimeSpan.FromMinutes(2));

        _memoryCache.Set(key, code, cacheOptions);
        _logger.LogWarning(">>> OTP Code for {PhoneNumber} is: {Code} <<<", phoneNumber, code);

        return code;
    }


    public async Task<bool> ValidateOtpAsync(string phoneNumber, string code)
    {
        var key = $"OTP_{phoneNumber}";
        if (_memoryCache.TryGetValue(key, out string? cachedCode))
        {
            if (cachedCode == code)
            {
                _memoryCache.Remove(key);
                return true;
            }
        }
        return false;
    }
}