using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Targets;

namespace Sav.Infrastructure.Postgres.Tests.Oracle;

public sealed class QueryEquivalentBatchingTests
{
    private const string LeftSql = "SELECT id, code FROM eq_items WHERE id <= 2";
    private const string RightSql = "SELECT id, code FROM eq_items WHERE id BETWEEN 1 AND 2";
    private static readonly DisclosureProfile Disclosure = new("strict", false, false, false, false);

    [Fact]
    public async Task Batch_session_executes_both_directions_in_one_statement_snapshot()
    {
        FakeBatchSession session = new();

        PropertyResult result = Assert.Single(await CreateOracle().EvaluateAsync(CreateRequest(session), CancellationToken.None));

        Assert.Equal(new PropertyResult("query_equivalent", PropertyStatus.Pass, null), result);
        Assert.Equal(0, session.ReaderCalls);
        Assert.Equal(1, session.BatchCalls);
        OracleBatchReadCommand command = Assert.Single(session.Commands);
        Assert.StartsWith("SELECT CASE WHEN ((SELECT COUNT(*)::bigint AS v FROM ( ( " + LeftSql + " ) EXCEPT ALL", command.Sql);
        Assert.Contains("( " + RightSql + " ) ) AS diff) = 0 AND (SELECT COUNT(*)::bigint AS v FROM ( ( " + RightSql + " ) EXCEPT ALL", command.Sql);
        Assert.Contains("( " + LeftSql + " ) ) AS diff) = 0) THEN 0 ELSE 1 END::bigint AS v", command.Sql);
        Assert.Equal([OracleSqlTemplate.LongVColumn], command.AllowedColumns);
    }

    [Fact]
    public async Task Public_interface_only_session_uses_one_reader_call()
    {
        FakeSession session = new();

        PropertyResult result = Assert.Single(await CreateOracle().EvaluateAsync(CreateRequest(session), CancellationToken.None));

        Assert.Equal(new PropertyResult("query_equivalent", PropertyStatus.Pass, null), result);
        Assert.Equal(1, session.ReaderCalls);
    }

    [Fact]
    public async Task Nonzero_combined_difference_fails_without_exposing_count()
    {
        FakeBatchSession session = new() { DifferenceCount = 1 };

        PropertyResult result = Assert.Single(await CreateOracle().EvaluateAsync(CreateRequest(session), CancellationToken.None));

        Assert.Equal(new PropertyResult("query_equivalent", PropertyStatus.Fail, SavErrorCode.NotEquivalent), result);
    }

    [Fact]
    public async Task Malformed_combined_result_fails_as_query_failed()
    {
        FakeBatchSession session = new() { MalformedResult = true };

        PropertyResult result = Assert.Single(await CreateOracle().EvaluateAsync(CreateRequest(session), CancellationToken.None));

        Assert.Equal(new PropertyResult("query_equivalent", PropertyStatus.Fail, SavErrorCode.QueryFailed), result);
        Assert.Equal(1, session.BatchCalls);
        Assert.Equal(0, session.ReaderCalls);
    }

    [Fact]
    public async Task Batch_query_failure_does_not_retry_sequentially()
    {
        FakeBatchSession session = new() { BatchFailure = new SavException(SavErrorCode.QueryFailed, "query_failed") };

        PropertyResult result = Assert.Single(await CreateOracle().EvaluateAsync(CreateRequest(session), CancellationToken.None));

        Assert.Equal(new PropertyResult("query_equivalent", PropertyStatus.Fail, SavErrorCode.QueryFailed), result);
        Assert.Equal(1, session.BatchCalls);
        Assert.Equal(0, session.ReaderCalls);
    }

    [Fact]
    public async Task Batch_cancellation_propagates_without_fallback()
    {
        using CancellationTokenSource cancellation = new();
        FakeBatchSession session = new() { BatchFailure = new OperationCanceledException(cancellation.Token) };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => CreateOracle().EvaluateAsync(CreateRequest(session), cancellation.Token));

        Assert.Equal(1, session.BatchCalls);
        Assert.Equal(0, session.ReaderCalls);
    }

    private static PropertyOracle CreateOracle() => new(new TestRedactor());

    private static PropertyEvaluationRequest CreateRequest(IReadOnlySession session)
    {
        SqlIr ir = new(
            "postgresql", ["Select"], ["eq_items"], [], ["id", "code"], [], [],
            false, false, [], [], LeftSql, "query-equivalent-batch-test");
        return new PropertyEvaluationRequest(
            ExecutionEnvironment.RealReadOnlyAlias,
            ir,
            [new QueryEquivalentSpec()],
            LeftSql,
            LeftSql,
            RightSql,
            null,
            session,
            null,
            null,
            Disclosure,
            rightIr: new SqlIr(
                "postgresql", ["Select"], ["eq_items"], [], ["id", "code"], [], [],
                false, false, [], [], RightSql, "query-equivalent-batch-test-right"));
    }

    private sealed class FakeBatchSession : FakeSession, IOracleBatchReadSession
    {
        public int BatchCalls { get; private set; }
        public Exception? BatchFailure { get; init; }
        public long DifferenceCount { get; init; }
        public bool MalformedResult { get; init; }
        public IReadOnlyList<OracleBatchReadCommand> Commands { get; private set; } = [];

        public Task<IReadOnlyList<IReadOnlyList<OracleScalarRow>>> ExecuteBatchAsync(
            IReadOnlyList<OracleBatchReadCommand> commands,
            CancellationToken cancellationToken)
        {
            BatchCalls++;
            Commands = commands.ToArray();
            if (BatchFailure is not null)
            {
                return Task.FromException<IReadOnlyList<IReadOnlyList<OracleScalarRow>>>(BatchFailure);
            }

            IReadOnlyList<OracleScalarRow> rows = MalformedResult
                ? []
                : [new OracleScalarRow(null, DifferenceCount, null)];
            return Task.FromResult<IReadOnlyList<IReadOnlyList<OracleScalarRow>>>([rows]);
        }
    }

    private class FakeSession : IReadOnlySession
    {
        public int ReaderCalls { get; private set; }

        public Task ExecuteAsync(string sql, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
            string sql,
            IReadOnlyList<OracleScalarColumn> allowedColumns,
            CancellationToken cancellationToken)
        {
            ReaderCalls++;
            return Task.FromResult<IReadOnlyList<OracleScalarRow>>([new OracleScalarRow(null, 0, null)]);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class TestRedactor : IRedactor
    {
        public string RedactText(string input, DisclosureProfile profile) => input;

        public T RedactObject<T>(T value, DisclosureProfile profile) => value;
    }
}
