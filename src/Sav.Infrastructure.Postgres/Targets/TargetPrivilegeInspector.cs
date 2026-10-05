using Npgsql;

namespace Sav.Infrastructure.Postgres.Targets;

/// <summary>
/// Advisory operator preflight. This checks catalog-visible privileges on a newly opened
/// alias connection; it is not an authorization boundary or a proof that functions are pure.
/// The runtime read-only transaction guard remains mandatory.
/// </summary>
public sealed class TargetPrivilegeInspector
{
    // A NOINHERIT membership can still grant writes after SET ROLE. Inspect grants
    // held by every role reachable through SET, not only current effective grants.
    private const string ReachableRoles = """
        WITH reachable_roles AS (
            SELECT r.oid
            FROM pg_roles AS r
            WHERE r.rolname = current_user
               OR pg_has_role(current_user, r.oid, 'SET')
        )
        """;

    public async Task<TargetPrivilegeReport> InspectAsync(
        NpgsqlConnection connection,
        bool strict,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        cancellationToken.ThrowIfCancellationRequested();

        List<string> errors = [];
        List<string> warnings = [];

        string transactionMode = await ReadTransactionModeAsync(connection, cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(transactionMode, "on", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("transaction_not_read_only");
        }

        // Include inherited privileges and roles reachable with SET ROLE. Do not report
        // role names or catalog object names in the diagnostic output.
        if (await QueryFlagAsync(
                connection,
                """
                SELECT COALESCE(bool_or(
                    (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication
                     OR r.rolbypassrls OR r.rolname IN (
                         'pg_write_server_files', 'pg_execute_server_program',
                         'pg_write_all_data', 'pg_database_owner'))
                    AND (r.rolname = current_user
                         OR pg_has_role(current_user, r.oid, 'USAGE')
                         OR pg_has_role(current_user, r.oid, 'SET'))
                ), false)
                FROM pg_roles AS r
                """,
                cancellationToken).ConfigureAwait(false))
        {
            errors.Add("privileged_role");
        }

        if (!await QueryFlagAsync(
                connection,
                """
                SELECT COALESCE(
                    has_table_privilege(to_regclass('public.sav_ro_probe')::oid, 'INSERT'), false)
                """,
                cancellationToken).ConfigureAwait(false))
        {
            errors.Add("probe_missing_or_insert_denied");
        }

        if (await QueryFlagAsync(
                connection,
                ReachableRoles + "\n" + """
                SELECT EXISTS (
                    SELECT 1
                    FROM reachable_roles AS reach
                    CROSS JOIN pg_class AS c
                    JOIN pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE n.nspname <> 'information_schema'
                      AND left(n.nspname, 3) <> 'pg_'
                      AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                      AND (
                          pg_has_role(reach.oid, c.relowner, 'USAGE')
                          OR pg_has_role(reach.oid, c.relowner, 'SET')
                          OR has_table_privilege(reach.oid, c.oid, 'UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                          OR has_any_column_privilege(reach.oid, c.oid, 'UPDATE, REFERENCES')
                          OR (
                              c.oid <> COALESCE(to_regclass('public.sav_ro_probe')::oid, 0::oid)
                              AND (
                                  has_table_privilege(reach.oid, c.oid, 'INSERT')
                                  OR has_any_column_privilege(reach.oid, c.oid, 'INSERT')
                              )
                          )
                      )
                )
                """,
                cancellationToken).ConfigureAwait(false))
        {
            warnings.Add("table_write_access");
        }

        if (await QueryFlagAsync(
                connection,
                ReachableRoles + "\n" + """
                SELECT EXISTS (
                    SELECT 1
                    FROM reachable_roles AS reach
                    CROSS JOIN pg_class AS c
                    JOIN pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE n.nspname <> 'information_schema'
                      AND left(n.nspname, 3) <> 'pg_'
                      AND c.relkind = 'S'
                      AND (
                          has_sequence_privilege(reach.oid, c.oid, 'UPDATE, USAGE')
                          OR pg_has_role(reach.oid, c.relowner, 'USAGE')
                          OR pg_has_role(reach.oid, c.relowner, 'SET')
                      )
                )
                """,
                cancellationToken).ConfigureAwait(false))
        {
            warnings.Add("sequence_write_access");
        }

        if (await QueryFlagAsync(
                connection,
                ReachableRoles + "\n" + """
                SELECT EXISTS (
                    SELECT 1
                    FROM reachable_roles AS reach
                    WHERE has_database_privilege(
                        reach.oid,
                        (SELECT d.oid FROM pg_database AS d WHERE d.datname = current_database()),
                        'CREATE')
                ) OR EXISTS (
                    SELECT 1
                    FROM reachable_roles AS reach
                    CROSS JOIN pg_namespace AS n
                    WHERE n.nspname <> 'information_schema'
                      AND left(n.nspname, 3) <> 'pg_'
                      AND has_schema_privilege(reach.oid, n.oid, 'CREATE')
                )
                """,
                cancellationToken).ConfigureAwait(false))
        {
            warnings.Add("create_access");
        }

        if (await QueryFlagAsync(
                connection,
                ReachableRoles + "\n" + """
                SELECT EXISTS (
                    SELECT 1
                    FROM reachable_roles AS reach
                    CROSS JOIN pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname <> 'information_schema'
                      AND left(n.nspname, 3) <> 'pg_'
                      AND p.prosecdef
                      AND has_function_privilege(reach.oid, p.oid, 'EXECUTE')
                )
                """,
                cancellationToken).ConfigureAwait(false))
        {
            warnings.Add("security_definer_executable");
        }

        return new TargetPrivilegeReport(
            Passed: errors.Count == 0 && (!strict || warnings.Count == 0),
            Strict: strict,
            Errors: errors,
            Warnings: warnings);
    }

    private static async Task<string> ReadTransactionModeAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new("SHOW transaction_read_only", connection)
        {
            CommandTimeout = 10,
        };
        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return result?.ToString() ?? string.Empty;
    }

    private static async Task<bool> QueryFlagAsync(
        NpgsqlConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(sql, connection) { CommandTimeout = 10 };
        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return result is bool value
            ? value
            : throw new InvalidOperationException("Privilege catalog query did not return a boolean.");
    }
}

/// <summary>
/// Stable, name-free findings. Warnings are advisory in standard mode and reject in strict mode.
/// Errors reject in both modes.
/// </summary>
public sealed record TargetPrivilegeReport(
    bool Passed,
    bool Strict,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings);
