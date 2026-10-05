using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Targets;

namespace Sav.Infrastructure.Postgres.Tests.Targets;

public sealed class TargetAliasResolverTests
{
    [Fact]
    public void Resolve_returns_fingerprint_from_alias_and_env_var_name_not_dsn()
    {
        string envVar = "SAV_TEST_ALIAS_DSN_" + Guid.NewGuid().ToString("N");
        string dsn = "Host=secret-host;Username=u;Password=super-secret-password;Database=db";
        Environment.SetEnvironmentVariable(envVar, dsn);
        try
        {
            TargetsBindingOptions options = new(new Dictionary<string, string>
            {
                ["prod_ro"] = envVar,
            });
            TargetAliasResolver resolver = new(options);

            TargetAlias alias = resolver.Resolve("prod_ro");

            Assert.Equal("prod_ro", alias.Alias);
            Assert.False(string.IsNullOrWhiteSpace(alias.Fingerprint));
            Assert.DoesNotContain("secret-host", alias.Fingerprint, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("super-secret-password", alias.Fingerprint, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(dsn, alias.Fingerprint, StringComparison.OrdinalIgnoreCase);

            TargetAlias again = resolver.Resolve("prod_ro");
            Assert.Equal(alias.Fingerprint, again.Fingerprint);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVar, null);
        }
    }

    [Fact]
    public void Case_insensitive_aliases_produce_the_same_target_fingerprint()
    {
        string envVar = "SAV_TEST_ALIAS_CASE_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(envVar, "Host=local;Username=u;Password=p;Database=db");
        try
        {
            TargetAliasResolver resolver = new(new TargetsBindingOptions(
                new Dictionary<string, string> { ["prod_ro"] = envVar }));

            TargetAlias lower = resolver.Resolve("prod_ro");
            TargetAlias upper = resolver.Resolve("PROD_RO");
            TargetAlias mixed = resolver.Resolve("PrOd_Ro");

            Assert.Equal(lower.Fingerprint, upper.Fingerprint);
            Assert.Equal(lower.Fingerprint, mixed.Fingerprint);
            Assert.Equal("PROD_RO", upper.Alias);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVar, null);
        }
    }

    [Fact]
    public void Resolve_unknown_alias_is_typed_failure()
    {
        TargetAliasResolver resolver = new(new TargetsBindingOptions(new Dictionary<string, string>()));
        SavException ex = Assert.Throws<SavException>(() => resolver.Resolve("missing"));
        Assert.Equal(SavErrorCode.AliasUnknown, ex.Code);
    }

    [Fact]
    public void Resolve_missing_env_value_is_typed_failure_without_echoing_env_name_as_dsn()
    {
        string envVar = "SAV_TEST_MISSING_DSN_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(envVar, null);
        TargetsBindingOptions options = new(new Dictionary<string, string>
        {
            ["prod_ro"] = envVar,
        });
        TargetAliasResolver resolver = new(options);

        SavException ex = Assert.Throws<SavException>(() => resolver.Resolve("prod_ro"));
        Assert.Equal(SavErrorCode.AliasDsnMissing, ex.Code);
        Assert.DoesNotContain("Host=", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
