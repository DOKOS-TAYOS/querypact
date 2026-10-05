using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests;

public sealed class ScaffoldSmokeTests
{
    [Fact]
    public void Postgres_assembly_name_is_Sav_Infrastructure_Postgres()
    {
        Assert.Equal(
            "Sav.Infrastructure.Postgres",
            typeof(LibPgQuerySqlParser).Assembly.GetName().Name);
    }
}
