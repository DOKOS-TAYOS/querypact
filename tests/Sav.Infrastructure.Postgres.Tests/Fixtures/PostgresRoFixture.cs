using Npgsql;
using Sav.Application.Abstractions;
using Sav.Domain.Policies;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Redaction;
using Sav.Infrastructure.Postgres.Targets;
using Testcontainers.PostgreSql;

namespace Sav.Infrastructure.Postgres.Tests.Fixtures;

public sealed class PostgresRoFixture : IAsyncLifetime
{
    public const string RoAlias = "tc_ro";
    public const string WriterAlias = "tc_writer";
    public const string WriterReadOnlyAlias = "tc_writer_readonly";
    public const string SettableWriterAlias = "tc_settable_writer";
    public const string PgdataWriterAlias = "tc_pgdata_writer";
    public const string ProbeOvergrantAlias = "tc_probe_overgrant";
    public const string NoProbeAlias = "tc_noprobe";
    public const string NoInsertAlias = "tc_noinsert";

    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:16-alpine")
        .WithDatabase("sav")
        .WithUsername("postgres")
        .WithPassword("postgres")
        .Build();

    private readonly string _envSuffix = Guid.NewGuid().ToString("N");
    private readonly List<string> _ownedEnvVars = [];

    public TargetsBindingOptions Binding { get; private set; } =
        new(new Dictionary<string, string>());

    public IRedactor Redactor { get; } = new PostgresErrorRedactor(new StrictRedactor());

    public string AdminConnectionString => _container.GetConnectionString();

    public UnsafeAliasRegistry UnsafeAliases { get; } = new();

    public DisclosureProfile StrictDisclosure { get; } = new(
        "strict",
        IncludePlanSummary: false,
        IncludeObjectNames: false,
        IncludeTimings: false,
        IncludeRowCounts: false);

    public async Task InitializeAsync()
    {
        await _container.StartAsync();
        await using NpgsqlConnection admin = new(_container.GetConnectionString());
        await admin.OpenAsync();

        await using (NpgsqlCommand createDb = new("CREATE DATABASE sav_noprobe OWNER postgres", admin))
        {
            await createDb.ExecuteNonQueryAsync();
        }

        await using (NpgsqlCommand setup = new(
                   """
                   CREATE TABLE public.sav_ro_probe (probe_key text);
                   CREATE TABLE public.side_effect_sink (v text);
                   CREATE SCHEMA pgdata;
                   CREATE TABLE pgdata.audit (v text);

                   DO $$
                   BEGIN
                     CREATE ROLE sav_ro LOGIN PASSWORD 'ro_password';
                     CREATE ROLE sav_writer LOGIN PASSWORD 'writer_password';
                     CREATE ROLE sav_writer_readonly LOGIN PASSWORD 'writer_ro_password';
                     CREATE ROLE sav_delegate NOLOGIN NOINHERIT;
                     CREATE ROLE sav_settable LOGIN NOINHERIT PASSWORD 'settable_password';
                     CREATE ROLE sav_pgdata_writer LOGIN PASSWORD 'pgdata_password';
                     CREATE ROLE sav_probe_overgrant LOGIN PASSWORD 'probe_overgrant_password';
                     CREATE ROLE sav_noprobe LOGIN PASSWORD 'noprobe_password';
                     CREATE ROLE sav_noinsert LOGIN PASSWORD 'noinsert_password';
                   EXCEPTION WHEN duplicate_object THEN NULL;
                   END $$;

                   ALTER ROLE sav_ro SET default_transaction_read_only = on;
                   ALTER ROLE sav_writer SET default_transaction_read_only = off;
                   ALTER ROLE sav_writer_readonly SET default_transaction_read_only = on;
                   ALTER ROLE sav_settable SET default_transaction_read_only = on;
                   ALTER ROLE sav_pgdata_writer SET default_transaction_read_only = on;
                   ALTER ROLE sav_probe_overgrant SET default_transaction_read_only = on;
                   GRANT sav_delegate TO sav_settable WITH INHERIT FALSE, SET TRUE;
                   ALTER ROLE sav_noprobe SET default_transaction_read_only = on;
                   ALTER ROLE sav_noinsert SET default_transaction_read_only = off;

                   GRANT CONNECT ON DATABASE sav
                       TO sav_ro, sav_writer, sav_writer_readonly, sav_settable,
                          sav_pgdata_writer, sav_probe_overgrant, sav_noinsert;
                   GRANT CONNECT ON DATABASE sav_noprobe TO sav_noprobe;

                   REVOKE ALL ON SCHEMA public FROM PUBLIC;
                   GRANT USAGE ON SCHEMA public
                       TO sav_ro, sav_writer, sav_writer_readonly, sav_settable,
                          sav_pgdata_writer, sav_probe_overgrant, sav_noinsert;
                   GRANT USAGE ON SCHEMA pgdata TO sav_pgdata_writer;
                   GRANT SELECT, INSERT ON public.sav_ro_probe TO sav_ro;
                   GRANT SELECT, INSERT ON public.sav_ro_probe TO sav_writer;
                   GRANT SELECT, INSERT ON public.sav_ro_probe TO sav_writer_readonly;
                   GRANT SELECT, INSERT ON public.sav_ro_probe
                       TO sav_settable, sav_pgdata_writer, sav_probe_overgrant;
                   GRANT UPDATE ON public.sav_ro_probe TO sav_probe_overgrant;
                   GRANT SELECT ON public.sav_ro_probe TO sav_noinsert;
                   GRANT SELECT, INSERT ON public.side_effect_sink TO sav_writer;
                   GRANT SELECT, INSERT ON public.side_effect_sink TO sav_writer_readonly;
                   GRANT INSERT ON public.side_effect_sink TO sav_delegate;
                   GRANT INSERT ON pgdata.audit TO sav_pgdata_writer;

                   CREATE TABLE public.plan_items (
                     id int PRIMARY KEY,
                     payload text NOT NULL
                   );
                   INSERT INTO public.plan_items(id, payload)
                   SELECT g, 'row-' || g::text FROM generate_series(1, 1000) g;
                   GRANT SELECT ON public.plan_items TO sav_ro;
                   """,
                   admin))
        {
            await setup.ExecuteNonQueryAsync();
        }

        string host = _container.Hostname;
        ushort port = _container.GetMappedPublicPort(5432);

        string roEnv = "SAV_TC_RO_DSN_" + _envSuffix;
        string writerEnv = "SAV_TC_WRITER_DSN_" + _envSuffix;
        string writerRoEnv = "SAV_TC_WRITER_RO_DSN_" + _envSuffix;
        string settableEnv = "SAV_TC_SETTABLE_DSN_" + _envSuffix;
        string pgdataEnv = "SAV_TC_PGDATA_DSN_" + _envSuffix;
        string probeOvergrantEnv = "SAV_TC_PROBE_OVERGRANT_DSN_" + _envSuffix;
        string noProbeEnv = "SAV_TC_NOPROBE_DSN_" + _envSuffix;
        string noInsertEnv = "SAV_TC_NOINSERT_DSN_" + _envSuffix;

        SetOwnedEnv(roEnv, BuildDsn(host, port, "sav_ro", "ro_password", "sav"));
        SetOwnedEnv(writerEnv, BuildDsn(host, port, "sav_writer", "writer_password", "sav"));
        SetOwnedEnv(writerRoEnv, BuildDsn(host, port, "sav_writer_readonly", "writer_ro_password", "sav"));
        SetOwnedEnv(settableEnv, BuildDsn(host, port, "sav_settable", "settable_password", "sav"));
        SetOwnedEnv(pgdataEnv, BuildDsn(host, port, "sav_pgdata_writer", "pgdata_password", "sav"));
        SetOwnedEnv(probeOvergrantEnv, BuildDsn(host, port, "sav_probe_overgrant", "probe_overgrant_password", "sav"));
        SetOwnedEnv(noProbeEnv, BuildDsn(host, port, "sav_noprobe", "noprobe_password", "sav_noprobe"));
        SetOwnedEnv(noInsertEnv, BuildDsn(host, port, "sav_noinsert", "noinsert_password", "sav"));

        Binding = new TargetsBindingOptions(new Dictionary<string, string>
        {
            [RoAlias] = roEnv,
            [WriterAlias] = writerEnv,
            [WriterReadOnlyAlias] = writerRoEnv,
            [SettableWriterAlias] = settableEnv,
            [PgdataWriterAlias] = pgdataEnv,
            [ProbeOvergrantAlias] = probeOvergrantEnv,
            [NoProbeAlias] = noProbeEnv,
            [NoInsertAlias] = noInsertEnv,
        });
    }

    public async Task DisposeAsync()
    {
        foreach (string env in _ownedEnvVars)
        {
            Environment.SetEnvironmentVariable(env, null);
        }

        _ownedEnvVars.Clear();
        await _container.DisposeAsync();
    }

    public TargetAlias Resolve(string alias)
    {
        return new TargetAliasResolver(Binding).Resolve(alias);
    }

    public ReadOnlySessionFactory CreateFactory(
        ReadOnlySessionOptions? options = null,
        ReadOnlySessionGuard? guard = null)
    {
        ReadOnlySessionOptions sessionOptions = options ?? new ReadOnlySessionOptions
        {
            Disclosure = StrictDisclosure,
            StatementTimeout = TimeSpan.FromSeconds(3),
            LockTimeout = TimeSpan.FromSeconds(1),
        };

        ReadOnlySessionFactory? factory = null;
        ReadOnlySessionGuard sessionGuard = guard ?? new ReadOnlySessionGuard(
            Redactor,
            StrictDisclosure,
            UnsafeAliases,
            canaryOverride: null,
            rollbackOverride: null,
            applyReadOnlyTransaction: true,
            onAliasPanic: alias => factory!.DisposePoolWithoutReuse(alias));

        factory = new ReadOnlySessionFactory(
            new AliasConnectionFactory(Binding),
            sessionGuard,
            Redactor,
            sessionOptions,
            UnsafeAliases);
        return factory;
    }

    public async Task ExecuteAdminAsync(string sql)
    {
        await using NpgsqlConnection admin = new(_container.GetConnectionString());
        await admin.OpenAsync();
        await using NpgsqlCommand command = new(sql, admin);
        await command.ExecuteNonQueryAsync();
    }

    private void SetOwnedEnv(string name, string value)
    {
        Environment.SetEnvironmentVariable(name, value);
        _ownedEnvVars.Add(name);
    }

    private static string BuildDsn(string host, ushort port, string user, string password, string database)
    {
        return $"Host={host};Port={port};Username={user};Password={password};Database={database};SSL Mode=Disable";
    }
}

[CollectionDefinition(nameof(PostgresRoCollection))]
public sealed class PostgresRoCollection : ICollectionFixture<PostgresRoFixture>
{
}

[Collection(nameof(PostgresRoCollection))]
public abstract class PostgresRoTestBase
{
    protected PostgresRoTestBase(PostgresRoFixture fixture)
    {
        Fixture = fixture;
    }

    protected PostgresRoFixture Fixture { get; }
}
