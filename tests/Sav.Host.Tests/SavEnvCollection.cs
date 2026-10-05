namespace Sav.Host.Tests;

/// <summary>
/// Serializes tests that mutate process-wide environment variables (SAV_MODE / HMAC).
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SavEnvCollectionDefinition
{
    public const string Name = "SavEnv";
}

[Collection(SavEnvCollectionDefinition.Name)]
public abstract class SavEnvTestBase
{
}
