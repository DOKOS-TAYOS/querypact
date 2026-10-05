using Npgsql;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Targets;

[Collection(nameof(PostgresRoCollection))]
public sealed class TargetPrivilegeInspectorTests
{
    private readonly PostgresRoFixture _fixture;
    private readonly TargetPrivilegeInspector _inspector = new();

    public TargetPrivilegeInspectorTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Dedicated_readonly_alias_passes_strict_preflight()
    {
        TargetPrivilegeReport report = await InspectAliasAsync(PostgresRoFixture.RoAlias, strict: true);

        Assert.True(report.Passed);
        Assert.Empty(report.Errors);
        Assert.Empty(report.Warnings);
    }

    [Fact]
    public async Task Writable_grants_with_readonly_transactions_warn_in_standard_and_fail_in_strict()
    {
        TargetPrivilegeReport standard =
            await InspectAliasAsync(PostgresRoFixture.WriterReadOnlyAlias, strict: false);
        TargetPrivilegeReport strict =
            await InspectAliasAsync(PostgresRoFixture.WriterReadOnlyAlias, strict: true);

        Assert.True(standard.Passed);
        Assert.Empty(standard.Errors);
        Assert.Contains("table_write_access", standard.Warnings);
        Assert.False(strict.Passed);
        Assert.Empty(strict.Errors);
        Assert.Contains("table_write_access", strict.Warnings);
    }

    [Fact]
    public async Task Strict_detects_grants_on_noninherited_roles_reachable_through_set_role()
    {
        await using NpgsqlConnection connection =
            new AliasConnectionFactory(_fixture.Binding)
                .Create(_fixture.Resolve(PostgresRoFixture.SettableWriterAlias));
        await connection.OpenAsync();

        await using NpgsqlCommand direct = new(
            "SELECT has_table_privilege('public.side_effect_sink', 'INSERT')",
            connection);
        Assert.False(Assert.IsType<bool>(await direct.ExecuteScalarAsync()));

        TargetPrivilegeReport report =
            await _inspector.InspectAsync(connection, strict: true, CancellationToken.None);

        Assert.False(report.Passed);
        Assert.Contains("table_write_access", report.Warnings);
    }

    [Fact]
    public async Task Strict_includes_non_reserved_schema_names_starting_with_pg()
    {
        TargetPrivilegeReport report =
            await InspectAliasAsync(PostgresRoFixture.PgdataWriterAlias, strict: true);

        Assert.False(report.Passed);
        Assert.Contains("table_write_access", report.Warnings);
    }

    [Fact]
    public async Task Only_insert_grant_is_exempted_on_canary_table()
    {
        TargetPrivilegeReport report =
            await InspectAliasAsync(PostgresRoFixture.ProbeOvergrantAlias, strict: true);

        Assert.False(report.Passed);
        Assert.Contains("table_write_access", report.Warnings);
    }

    [Fact]
    public async Task Writable_transaction_default_is_a_mandatory_error()
    {
        TargetPrivilegeReport report = await InspectAliasAsync(PostgresRoFixture.WriterAlias, strict: false);

        Assert.False(report.Passed);
        Assert.Contains("transaction_not_read_only", report.Errors);
    }

    [Fact]
    public async Task Missing_probe_and_insert_grant_are_mandatory_errors()
    {
        TargetPrivilegeReport missing =
            await InspectAliasAsync(PostgresRoFixture.NoProbeAlias, strict: false);
        TargetPrivilegeReport noGrant =
            await InspectAliasAsync(PostgresRoFixture.NoInsertAlias, strict: false);

        Assert.False(missing.Passed);
        Assert.Contains("probe_missing_or_insert_denied", missing.Errors);
        Assert.False(noGrant.Passed);
        Assert.Contains("probe_missing_or_insert_denied", noGrant.Errors);
    }

    [Fact]
    public async Task Admin_role_is_rejected_even_in_standard_mode()
    {
        await using NpgsqlConnection connection = new(_fixture.AdminConnectionString);
        await connection.OpenAsync();

        TargetPrivilegeReport report =
            await _inspector.InspectAsync(connection, strict: false, CancellationToken.None);

        Assert.False(report.Passed);
        Assert.Contains("privileged_role", report.Errors);
    }

    private async Task<TargetPrivilegeReport> InspectAliasAsync(string alias, bool strict)
    {
        await using NpgsqlConnection connection =
            new AliasConnectionFactory(_fixture.Binding).Create(_fixture.Resolve(alias));
        await connection.OpenAsync();
        return await _inspector.InspectAsync(connection, strict, CancellationToken.None);
    }
}
