using Sav.Domain.Errors;
using Sav.Infrastructure.Postgres.Oracle;

namespace Sav.Security.Tests.Surface;

public sealed class AffectedRowsExactShapeTests
{
    [Fact]
    public void Affected_rows_template_is_direct_dml_without_select_wrapper()
    {
        const string dml = "UPDATE t SET x = 1 WHERE id = 2";
        string command = OracleSqlBoundary.BuildAffectedRowsCommand(dml);

        Assert.Equal(dml, command);
        Assert.DoesNotContain("EXISTS", command, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SELECT", command, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(
            dml,
            OracleSqlTemplate.Wrap(OracleSqlTemplateKind.AffectedRowsDirectDml, "  " + dml + "  "));
    }

    [Fact]
    public void Multi_statement_dml_is_rejected()
    {
        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildAffectedRowsCommand("DELETE FROM t; DROP TABLE t"));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }
}
