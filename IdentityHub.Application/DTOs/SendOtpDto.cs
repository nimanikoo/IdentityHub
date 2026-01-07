namespace IdentityHub.Application.DTOs;

public record SendOtpDto
{
    public string PhoneNumber { get; set; }
}