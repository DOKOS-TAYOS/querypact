namespace Sav.Domain.Errors;

public sealed class SavException : Exception
{
    public SavException(string code, string message)
        : base(message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        Code = code;
    }

    public string Code { get; }
}
