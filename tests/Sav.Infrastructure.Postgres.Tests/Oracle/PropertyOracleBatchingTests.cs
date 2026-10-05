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

public sealed class PropertyOracleBatchingTests
{
    private const string Sql = "SELECT id, payload FROM plan_items WHERE id <= 100";
    private static readonly DisclosureProfile Disclosure = new("strict", false, false, false, false);

    [Fact]
    public async Task P1_uses_one_ordinary_reader_without_batching()
    {
        FakeBatchSession session = new();
        IReadOnlyList<PropertyResult> results = await CreateOracle().EvaluateAsync(CreateRequest(session, [new QuerySucceedsSpec()]), CancellationToken.None);

        Assert.Equal([new PropertyResult("query_succeeds", PropertyStatus.Pass, null)], results);
        Assert.Equal(1, session.ReaderCalls);
        Assert.Equal(0, session.BatchCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task P2_and_P4_batch_once_in_property_order_and_preserve_results(bool p4)
    {
        FakeBatchSession session = new();
        PropertySpec[] specs = p4
            ? [new QuerySucceedsSpec(), new EmptyResultSpec(), new UniqueSpec("id"), new NonNullSpec("payload")]
            : [new QuerySucceedsSpec(), new EmptyResultSpec()];

        IReadOnlyList<PropertyResult> results = await CreateOracle().EvaluateAsync(CreateRequest(session, specs), CancellationToken.None);

        Assert.Equal(0, session.ReaderCalls);
        Assert.Equal(1, session.BatchCalls);
        Assert.Equal(specs.Length, session.LastCommands.Count);
        Assert.Contains("SELECT COUNT(q)::bigint", session.LastCommands[0].Sql);
        Assert.Contains("SELECT NOT EXISTS", session.LastCommands[1].Sql);
        if (p4)
        {
            Assert.Contains("COUNT(DISTINCT", session.LastCommands[2].Sql);
            Assert.Contains("IS NULL", session.LastCommands[3].Sql);
        }

        PropertyResult[] expected = p4
            ? [new("query_succeeds", PropertyStatus.Pass, null), new("empty_result", PropertyStatus.Fail, "empty_expected_rows"), new("unique", PropertyStatus.Pass, null), new("non_null", PropertyStatus.Pass, null)]
            : [new("query_succeeds", PropertyStatus.Pass, null), new("empty_result", PropertyStatus.Fail, "empty_expected_rows")];
        Assert.Equal(expected, results);
    }

    [Fact]
    public async Task Invalid_batch_command_falls_back_to_sequential_property_results()
    {
        FakeBatchSession session = new();
        IReadOnlyList<PropertyResult> results = await CreateOracle().EvaluateAsync(
            CreateRequest(session, [new QuerySucceedsSpec(), new UniqueSpec("id; DROP TABLE plan_items")]),
            CancellationToken.None);

        Assert.Equal(0, session.BatchCalls);
        Assert.Equal(1, session.ReaderCalls);
        Assert.Equal(new PropertyResult("query_succeeds", PropertyStatus.Pass, null), results[0]);
        Assert.Equal(new PropertyResult("unique", PropertyStatus.Error, SavErrorCode.UnsafeIdentifier), results[1]);
    }

    [Fact]
    public async Task Batch_failure_discards_partial_results_and_returns_sequential_results()
    {
        PropertySpec[] specs = [new QuerySucceedsSpec(), new EmptyResultSpec(), new UniqueSpec("id"), new NonNullSpec("payload")];
        FakeBatchSession failedBatch = new() { BatchFailure = new SavException(SavErrorCode.QueryFailed, "query_failed") };
        IReadOnlyList<PropertyResult> fallbackResults = await CreateOracle().EvaluateAsync(CreateRequest(failedBatch, specs), CancellationToken.None);
        FakeSession sequential = new();
        IReadOnlyList<PropertyResult> sequentialResults = await CreateOracle().EvaluateAsync(CreateRequest(sequential, specs), CancellationToken.None);

        Assert.Equal(sequentialResults, fallbackResults);
        Assert.Equal(1, failedBatch.BatchCalls);
        Assert.Equal(4, failedBatch.ReaderCalls);
    }

    [Fact]
    public async Task Batch_cancellation_propagates_without_fallback()
    {
        FakeBatchSession session = new() { BatchFailure = new OperationCanceledException() };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CreateOracle().EvaluateAsync(
            CreateRequest(session, [new QuerySucceedsSpec(), new EmptyResultSpec()]), CancellationToken.None));

        Assert.Equal(1, session.BatchCalls);
        Assert.Equal(0, session.ReaderCalls);
    }

    [Fact]
    public async Task Function_bearing_ir_and_public_interface_only_session_use_sequential_path()
    {
        FakeBatchSession batchSession = new();
        PropertyOracle functionOracle = new(new TestRedactor(), ["allowed_function"]);
        IReadOnlyList<PropertyResult> functionResults = await functionOracle.EvaluateAsync(
            CreateRequest(batchSession, [new QuerySucceedsSpec(), new EmptyResultSpec()], ["allowed_function"]), CancellationToken.None);
        FakeSession publicOnlySession = new();
        IReadOnlyList<PropertyResult> publicResults = await CreateOracle().EvaluateAsync(
            CreateRequest(publicOnlySession, [new QuerySucceedsSpec(), new EmptyResultSpec()]), CancellationToken.None);

        Assert.Equal(0, batchSession.BatchCalls);
        Assert.Equal(2, batchSession.ReaderCalls);
        Assert.Equal(2, publicOnlySession.ReaderCalls);
        Assert.Equal(functionResults, publicResults);
    }

    [Fact]
    public async Task Ephemeral_property_does_not_enter_real_session_batch_path()
    {
        FakeBatchSession session = new();
        PropertyEvaluationRequest request = CreateRequest(session, [new AffectedRowsSpec(1, 1)], environment: ExecutionEnvironment.EphemeralContainer);

        IReadOnlyList<PropertyResult> results = await CreateOracle().EvaluateAsync(request, CancellationToken.None);

        Assert.Equal(0, session.BatchCalls);
        Assert.Equal(0, session.ReaderCalls);
        Assert.Equal(new PropertyResult("affected_rows", PropertyStatus.Error, SavErrorCode.SessionRequired), Assert.Single(results));
    }

    private static PropertyOracle CreateOracle() => new(new TestRedactor());

    private static PropertyEvaluationRequest CreateRequest(
        IReadOnlySession session,
        IReadOnlyList<PropertySpec> specs,
        IReadOnlyList<string>? functions = null,
        ExecutionEnvironment environment = ExecutionEnvironment.RealReadOnlyAlias)
    {
        SqlIr ir = new("postgresql", ["Select"], ["plan_items"], [], ["id", "payload"], [], functions ?? [], false, false, [], [], Sql, "batch-test");
        return new PropertyEvaluationRequest(environment, ir, specs, Sql, null, null, null, session, null, null, Disclosure);
    }

    private sealed class FakeBatchSession : FakeSession, IOracleBatchReadSession
    {
        public int BatchCalls { get; private set; }
        public Exception? BatchFailure { get; init; }
        public IReadOnlyList<OracleBatchReadCommand> LastCommands { get; private set; } = [];

        public Task<IReadOnlyList<IReadOnlyList<OracleScalarRow>>> ExecuteBatchAsync(
            IReadOnlyList<OracleBatchReadCommand> commands,
            CancellationToken cancellationToken)
        {
            BatchCalls++;
            LastCommands = commands.ToArray();
            if (BatchFailure is not null)
            {
                return Task.FromException<IReadOnlyList<IReadOnlyList<OracleScalarRow>>>(BatchFailure);
            }

            return Task.FromResult<IReadOnlyList<IReadOnlyList<OracleScalarRow>>>(commands.Select(GetRows).ToArray());
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
            return Task.FromResult(GetRows(new OracleBatchReadCommand(sql, allowedColumns)));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private static IReadOnlyList<OracleScalarRow> GetRows(OracleBatchReadCommand command)
    {
        if (command.Sql.Contains("NOT EXISTS", StringComparison.Ordinal))
        {
            return [new OracleScalarRow(false, null, null)];
        }

        if (command.Sql.Contains("IS NULL", StringComparison.Ordinal))
        {
            return [new OracleScalarRow(null, 0, null)];
        }

        if (command.Sql.Contains("COUNT(DISTINCT", StringComparison.Ordinal))
        {
            return [];
        }

        return [new OracleScalarRow(null, 1, null)];
    }

    private sealed class TestRedactor : Sav.Application.Abstractions.IRedactor
    {
        public string RedactText(string input, DisclosureProfile profile) => input;

        public T RedactObject<T>(T value, DisclosureProfile profile) => value;
    }
}
