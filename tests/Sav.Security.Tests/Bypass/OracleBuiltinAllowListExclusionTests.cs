using Sav.Infrastructure.Postgres.Oracle;

namespace Sav.Security.Tests.Bypass;

public sealed class OracleBuiltinAllowListExclusionTests
{
    [Theory]
    [InlineData("pg_read_file")]
    [InlineData("pg_read_binary_file")]
    [InlineData("dblink")]
    [InlineData("dblink_exec")]
    [InlineData("lo_import")]
    [InlineData("lo_export")]
    [InlineData("pg_ls_dir")]
    public void Dangerous_functions_are_absent_from_oracle_wrapper_builtin_allow_list(string functionName)
    {
        Assert.Empty(OracleWrapperBuiltinFunctionAllowList.Allowed);
        Assert.DoesNotContain(
            functionName,
            OracleWrapperBuiltinFunctionAllowList.Allowed,
            StringComparer.OrdinalIgnoreCase);
        Assert.False(OracleWrapperBuiltinFunctionAllowList.IsAllowed(functionName));
    }

    [Fact]
    public void Allow_list_is_frozen_empty_set()
    {
        Assert.Empty(OracleWrapperBuiltinFunctionAllowList.Allowed);
        Assert.IsAssignableFrom<IReadOnlySet<string>>(OracleWrapperBuiltinFunctionAllowList.Allowed);
    }
}
