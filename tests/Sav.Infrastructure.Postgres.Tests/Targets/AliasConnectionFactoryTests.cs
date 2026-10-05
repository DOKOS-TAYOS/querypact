using System.Reflection;
using Npgsql;
using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Targets;

namespace Sav.Infrastructure.Postgres.Tests.Targets;

public sealed class AliasConnectionFactoryTests
{
    [Fact]
    public void Create_builds_unopened_connection_from_env_dsn_only()
    {
        string envVar = "SAV_TEST_CONN_DSN_" + Guid.NewGuid().ToString("N");
        string dsn = "Host=127.0.0.1;Port=5432;Username=sav_ro;Password=pw;Database=sav";
        Environment.SetEnvironmentVariable(envVar, dsn);
        try
        {
            TargetsBindingOptions options = new(new Dictionary<string, string>
            {
                ["local_ro"] = envVar,
            });
            TargetAliasResolver resolver = new(options);
            AliasConnectionFactory factory = new(options);
            TargetAlias alias = resolver.Resolve("local_ro");

            using NpgsqlConnection connection = factory.Create(alias);

            Assert.Equal(System.Data.ConnectionState.Closed, connection.State);
            Assert.Contains("127.0.0.1", connection.ConnectionString, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVar, null);
        }
    }

    [Fact]
    public void Create_has_no_raw_connection_string_overload()
    {
        MethodInfo[] methods = typeof(AliasConnectionFactory)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Where(m => m.Name == "Create")
            .ToArray();

        Assert.Single(methods);
        ParameterInfo[] parameters = methods[0].GetParameters();
        Assert.Single(parameters);
        Assert.Equal(typeof(TargetAlias), parameters[0].ParameterType);
    }

    [Fact]
    public void Create_unknown_alias_fingerprint_binding_fails_closed()
    {
        AliasConnectionFactory factory = new(new TargetsBindingOptions(new Dictionary<string, string>()));
        SavException ex = Assert.Throws<SavException>(
            () => factory.Create(new TargetAlias("ghost", "fp")));
        Assert.Equal(SavErrorCode.AliasUnknown, ex.Code);
    }
}
