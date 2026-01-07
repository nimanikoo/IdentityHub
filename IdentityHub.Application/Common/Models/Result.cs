namespace IdentityHub.Application.Common.Models;

public class Result<T>
{
    public bool Succeeded { get; private set; }
    public T Data { get; private set; }
    public string Error { get; private set; }
    public string ErrorDescription { get; private set; }

    public static Result<T> Success(T data) => new Result<T> { Succeeded = true, Data = data };
    
    public static Result<T> Failure(string error, string description) 
        => new Result<T> { Succeeded = false, Error = error, ErrorDescription = description };
}