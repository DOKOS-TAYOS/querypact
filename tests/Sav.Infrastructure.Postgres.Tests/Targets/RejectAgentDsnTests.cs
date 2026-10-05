using System.Reflection;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Infrastructure.Postgres.Targets;

namespace Sav.Infrastructure.Postgres.Tests.Targets;

public sealed class RejectAgentDsnTests
{
    [Theory]
    [InlineData("Host=evil;Username=a;Password=b;Database=db")]
    [InlineData("postgresql://user:pass@host:5432/db")]
    [InlineData("postgres://user:pass@host/db")]
    public void Resolver_rejects_alias_names_that_look_like_connection_strings(string fakeAlias)
    {
        TargetAliasResolver resolver = new(new TargetsBindingOptions(new Dictionary<string, string>
        {
            ["prod_ro"] = "SAV_TARGET_PROD_RO_DSN",
        }));

        SavException ex = Assert.Throws<SavException>(() => resolver.Resolve(fakeAlias));
        Assert.Equal(SavErrorCode.AliasLooksLikeDsn, ex.Code);
        Assert.DoesNotContain("Password=", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("pass@", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ITargetAliasResolver_accepts_only_alias_name_string()
    {
        MethodInfo method = typeof(ITargetAliasResolver).GetMethod(nameof(ITargetAliasResolver.Resolve))!;
        ParameterInfo[] parameters = method.GetParameters();
        Assert.Single(parameters);
        Assert.Equal(typeof(string), parameters[0].ParameterType);
        Assert.Equal("aliasName", parameters[0].Name);
    }

    [Fact]
    public void AliasConnectionFactory_does_not_expose_dsn_setter_api()
    {
        Assert.Null(typeof(AliasConnectionFactory).GetMethod("CreateFromDsn"));
        Assert.Null(typeof(AliasConnectionFactory).GetMethod("CreateFromConnectionString"));
        Assert.Null(typeof(ITargetAliasResolver).GetMethod("ResolveFromDsn"));
    }
}
