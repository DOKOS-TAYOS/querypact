using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Catalog;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Catalog;

[Collection(nameof(PostgresRoCollection))]
public sealed class SchemaFingerprintGuardTests
{
    private readonly PostgresRoFixture _fixture;

    public SchemaFingerprintGuardTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Unchanged_schema_yields_stable_fingerprint_and_ensure_succeeds()
    {
        await EnsureRelationAsync();

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("fp_guard_items");

        TargetSchemaFingerprint first = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);
        TargetSchemaFingerprint second = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(first.Value));
        Assert.Equal(first.Value, second.Value);

        await guard.EnsureUnchangedAsync(
            session,
            alias,
            analysis,
            first,
            DateTimeOffset.UtcNow,
            CancellationToken.None);
    }

    [Fact]
    public async Task Schema_drift_throws_schema_changed()
    {
        await EnsureRelationAsync();

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("fp_guard_items");
        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);

        await _fixture.ExecuteAdminAsync(
            """
            ALTER TABLE public.fp_guard_items ADD COLUMN drift_col text;
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(() =>
            guard.EnsureUnchangedAsync(
                session,
                alias,
                analysis,
                baseline,
                DateTimeOffset.UtcNow,
                CancellationToken.None));

        Assert.Equal(SavErrorCode.SchemaChanged, ex.Code);
    }

    [Fact]
    public async Task Mixed_case_relation_fingerprint_targets_the_exact_relation()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS public."FpGuardMixedCase";
            DROP TABLE IF EXISTS public.fpguardmixedcase;
            CREATE TABLE public."FpGuardMixedCase" (id integer);
            CREATE TABLE public.fpguardmixedcase (id integer);
            GRANT SELECT ON public."FpGuardMixedCase", public.fpguardmixedcase TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("FpGuardMixedCase");
        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);

        await _fixture.ExecuteAdminAsync(
            "ALTER TABLE public.fpguardmixedcase ADD COLUMN lower_only text;");

        await guard.EnsureUnchangedAsync(
            session,
            alias,
            analysis,
            baseline,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        await _fixture.ExecuteAdminAsync(
            "ALTER TABLE public.\"FpGuardMixedCase\" ADD COLUMN mixed_only text;");

        SavException ex = await Assert.ThrowsAsync<SavException>(() =>
            guard.EnsureUnchangedAsync(
                session,
                alias,
                analysis,
                baseline,
                DateTimeOffset.UtcNow,
                CancellationToken.None));

        Assert.Equal(SavErrorCode.SchemaChanged, ex.Code);

        await _fixture.ExecuteAdminAsync(
            "DROP TABLE IF EXISTS public.\"FpGuardMixedCase\"; DROP TABLE IF EXISTS public.fpguardmixedcase;");
    }

    [Fact]
    public async Task Case_distinct_relations_are_not_collapsed_in_batch_fingerprint()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS public."FpGuardCasePair";
            DROP TABLE IF EXISTS public.fpguardcasepair;
            CREATE TABLE public."FpGuardCasePair" (id integer);
            CREATE TABLE public.fpguardcasepair (id integer);
            GRANT SELECT ON public."FpGuardCasePair", public.fpguardcasepair TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession underlying =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(underlying);

        await new SchemaFingerprintGuard().CaptureBaselineAsync(
            session,
            alias,
            AnalysisFor("FpGuardCasePair", "fpguardcasepair"),
            CancellationToken.None);

        Assert.Equal(1, session.ReaderCalls);
        Assert.Contains("WITH requested", session.Queries[0], StringComparison.Ordinal);
        Assert.Contains("\"FpGuardCasePair\"", session.Queries[0], StringComparison.Ordinal);
        Assert.Contains("\"fpguardcasepair\"", session.Queries[0], StringComparison.Ordinal);

        await _fixture.ExecuteAdminAsync(
            "DROP TABLE IF EXISTS public.\"FpGuardCasePair\"; DROP TABLE IF EXISTS public.fpguardcasepair;");
    }

    [Fact]
    public async Task One_safe_relation_uses_the_single_relation_query_at_each_checkpoint()
    {
        await EnsureRelationAsync();

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession underlying =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(underlying);
        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("fp_guard_items");

        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);
        await guard.EnsureUnchangedAsync(
            session,
            alias,
            analysis,
            baseline,
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        await guard.EnsureUnchangedAsync(
            session,
            alias,
            analysis,
            baseline,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.Equal(3, session.ReaderCalls);
        Assert.All(session.Queries, query =>
        {
            Assert.DoesNotContain("WITH requested", query, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("to_regclass('\"fp_guard_items\"')", query, StringComparison.Ordinal);
            Assert.Contains("a.atttypid::text", query, StringComparison.Ordinal);
            Assert.Contains("a.attnotnull::text", query, StringComparison.Ordinal);
            Assert.Contains("a.attcollation::text", query, StringComparison.Ordinal);
            Assert.Contains("a.attidentity::text", query, StringComparison.Ordinal);
            Assert.Contains("a.attgenerated::text", query, StringComparison.Ordinal);
            Assert.Contains("pg_get_expr", query, StringComparison.Ordinal);
            Assert.Contains("pg_get_constraintdef", query, StringComparison.Ordinal);
            Assert.Contains("pg_get_viewdef", query, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Multiple_relations_use_one_reader_per_checkpoint_and_remain_stable()
    {
        await EnsureRelationAsync();
        await _fixture.ExecuteAdminAsync(
            "DROP TABLE IF EXISTS public.fp_guard_other; CREATE TABLE public.fp_guard_other (id integer); GRANT SELECT ON public.fp_guard_other TO sav_ro;");

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession underlying =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(underlying);
        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("fp_guard_items", "fp_guard_other");

        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);
        await guard.EnsureUnchangedAsync(
            session,
            alias,
            analysis,
            baseline,
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        await guard.EnsureUnchangedAsync(
            session,
            alias,
            analysis,
            baseline,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.Equal(3, session.ReaderCalls);
        Assert.All(session.Queries, query =>
        {
            Assert.Contains("WITH requested", query, StringComparison.Ordinal);
            Assert.Contains("fp_guard_other", query, StringComparison.Ordinal);
            Assert.Contains("a.attcollation::text", query, StringComparison.Ordinal);
            Assert.Contains("a.attidentity::text", query, StringComparison.Ordinal);
            Assert.Contains("a.attgenerated::text", query, StringComparison.Ordinal);
            Assert.Contains("pg_get_viewdef", query, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Drift_in_any_multiple_relation_throws_schema_changed()
    {
        await EnsureRelationAsync();
        await _fixture.ExecuteAdminAsync(
            "DROP TABLE IF EXISTS public.fp_guard_other; CREATE TABLE public.fp_guard_other (id integer); GRANT SELECT ON public.fp_guard_other TO sav_ro;");

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("fp_guard_items", "fp_guard_other");
        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);

        await _fixture.ExecuteAdminAsync("ALTER TABLE public.fp_guard_other ADD COLUMN drift_col text;");

        SavException ex = await Assert.ThrowsAsync<SavException>(() =>
            guard.EnsureUnchangedAsync(
                session,
                alias,
                analysis,
                baseline,
                DateTimeOffset.UtcNow,
                CancellationToken.None));

        Assert.Equal(SavErrorCode.SchemaChanged, ex.Code);
    }

    [Fact]
    public async Task Collation_drift_throws_schema_changed()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS public.fp_guard_collation;
            CREATE TABLE public.fp_guard_collation (
              value text COLLATE "C"
            );
            GRANT SELECT ON public.fp_guard_collation TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("fp_guard_collation");
        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);

        await _fixture.ExecuteAdminAsync(
            "ALTER TABLE public.fp_guard_collation ALTER COLUMN value TYPE text COLLATE \"POSIX\";");

        SavException ex = await Assert.ThrowsAsync<SavException>(() =>
            guard.EnsureUnchangedAsync(
                session,
                alias,
                analysis,
                baseline,
                DateTimeOffset.UtcNow,
                CancellationToken.None));

        Assert.Equal(SavErrorCode.SchemaChanged, ex.Code);
    }

    [Fact]
    public async Task View_definition_drift_throws_schema_changed_when_shape_is_unchanged()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP VIEW IF EXISTS public.fp_guard_semantic_view;
            DROP TABLE IF EXISTS public.fp_guard_view_source;
            CREATE TABLE public.fp_guard_view_source (id integer);
            CREATE VIEW public.fp_guard_semantic_view AS
              SELECT id FROM public.fp_guard_view_source WHERE id > 0;
            GRANT SELECT ON public.fp_guard_semantic_view TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("fp_guard_semantic_view");
        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);

        await _fixture.ExecuteAdminAsync(
            """
            CREATE OR REPLACE VIEW public.fp_guard_semantic_view AS
              SELECT id FROM public.fp_guard_view_source WHERE id >= 0;
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(() =>
            guard.EnsureUnchangedAsync(
                session,
                alias,
                analysis,
                baseline,
                DateTimeOffset.UtcNow,
                CancellationToken.None));

        Assert.Equal(SavErrorCode.SchemaChanged, ex.Code);
    }

    [Fact]
    public async Task Qualified_unqualified_and_missing_relations_keep_their_fingerprint_behavior()
    {
        await EnsureRelationAsync();
        await _fixture.ExecuteAdminAsync("DROP TABLE IF EXISTS public.fp_guard_missing;");

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        SchemaFingerprintGuard guard = new();
        SqlAnalysis qualifiedAndUnqualified = AnalysisFor("fp_guard_items", "public.fp_guard_items");
        TargetSchemaFingerprint stable = await guard.CaptureBaselineAsync(
            session,
            alias,
            qualifiedAndUnqualified,
            CancellationToken.None);
        await guard.EnsureUnchangedAsync(
            session,
            alias,
            qualifiedAndUnqualified,
            stable,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        SqlAnalysis missing = AnalysisFor("fp_guard_missing");
        TargetSchemaFingerprint missingBaseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            missing,
            CancellationToken.None);
        TargetSchemaFingerprint repeatedMissing = await guard.CaptureBaselineAsync(
            session,
            alias,
            missing,
            CancellationToken.None);
        Assert.Equal(missingBaseline.Value, repeatedMissing.Value);

        await _fixture.ExecuteAdminAsync(
            "CREATE TABLE public.fp_guard_missing (id integer); GRANT SELECT ON public.fp_guard_missing TO sav_ro;");
        SavException ex = await Assert.ThrowsAsync<SavException>(() =>
            guard.EnsureUnchangedAsync(
                session,
                alias,
                missing,
                missingBaseline,
                DateTimeOffset.UtcNow,
                CancellationToken.None));
        Assert.Equal(SavErrorCode.SchemaChanged, ex.Code);
    }

    [Fact]
    public async Task Unsafe_relation_material_is_fail_closed_and_never_enters_generated_sql()
    {
        await EnsureRelationAsync();

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession underlying =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(underlying);
        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor(
            "fp_guard_items",
            "fp_guard_items; DROP TABLE public.sav_ro_probe");

        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);
        await guard.EnsureUnchangedAsync(
            session,
            alias,
            analysis,
            baseline,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.Equal(2, session.ReaderCalls);
        Assert.All(
            session.Queries,
            query =>
            {
                Assert.DoesNotContain("WITH requested", query, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("DROP TABLE", query, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(
                    "fp_guard_items; DROP TABLE public.sav_ro_probe",
                    query,
                    StringComparison.OrdinalIgnoreCase);
            });
    }

    [Fact]
    public async Task Unsafe_only_relations_do_not_call_the_catalog_reader()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession underlying =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(underlying);
        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("bad name; DROP TABLE public.sav_ro_probe");

        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);
        await guard.EnsureUnchangedAsync(
            session,
            alias,
            analysis,
            baseline,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.Equal(0, session.ReaderCalls);
    }

    [Fact]
    public async Task Wall_clock_threshold_throws_schema_changed()
    {
        await EnsureRelationAsync();

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SchemaFingerprintGuard guard = new(maxPipelineWallClock: TimeSpan.FromMilliseconds(1));
        SqlAnalysis analysis = AnalysisFor("fp_guard_items");
        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);

        DateTimeOffset started = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(5);
        SavException ex = await Assert.ThrowsAsync<SavException>(() =>
            guard.EnsureUnchangedAsync(session, alias, analysis, baseline, started, CancellationToken.None));

        Assert.Equal(SavErrorCode.SchemaChanged, ex.Code);
        Assert.Contains("wall-clock", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CaptureBaseline_propagates_cancellation()
    {
        await EnsureRelationAsync();

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("fp_guard_items");
        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            guard.CaptureBaselineAsync(session, alias, analysis, cts.Token));
    }

    [Fact]
    public async Task EnsureUnchanged_propagates_cancellation()
    {
        await EnsureRelationAsync();

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SchemaFingerprintGuard guard = new();
        SqlAnalysis analysis = AnalysisFor("fp_guard_items");
        TargetSchemaFingerprint baseline = await guard.CaptureBaselineAsync(
            session,
            alias,
            analysis,
            CancellationToken.None);

        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            guard.EnsureUnchangedAsync(
                session,
                alias,
                analysis,
                baseline,
                DateTimeOffset.UtcNow,
                cts.Token));
    }

    private async Task EnsureRelationAsync()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS public.fp_guard_items;
            CREATE TABLE public.fp_guard_items (
              id int PRIMARY KEY,
              payload text NOT NULL
            );
            GRANT SELECT ON public.fp_guard_items TO sav_ro;
            """);
    }

    private static SqlAnalysis AnalysisFor(params string[] tables) =>
        new(
            new SqlIr(
                dialect: "postgresql",
                statementTypes: ["Select"],
                tablesRead: tables,
                tablesWritten: [],
                columnsRead: ["id"],
                columnsWritten: [],
                functions: [],
                hasMultipleStatements: false,
                hasDynamicSql: false,
                unresolvedObjects: [],
                riskCodes: [],
                normalizedSql: "SELECT id FROM " + string.Join(", ", tables),
                fingerprint: "fp"),
            IsParsable: true);

    private sealed class CountingSession : IReadOnlySession
    {
        private readonly IReadOnlySession _inner;

        public CountingSession(IReadOnlySession inner) => _inner = inner;

        public int ReaderCalls { get; private set; }

        public List<string> Queries { get; } = [];

        public Task ExecuteAsync(string sql, CancellationToken cancellationToken) =>
            _inner.ExecuteAsync(sql, cancellationToken);

        public Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
            string sql,
            IReadOnlyList<OracleScalarColumn> allowedColumns,
            CancellationToken cancellationToken)
        {
            ReaderCalls++;
            Queries.Add(sql);
            return _inner.ExecuteReaderAsync(sql, allowedColumns, cancellationToken);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
