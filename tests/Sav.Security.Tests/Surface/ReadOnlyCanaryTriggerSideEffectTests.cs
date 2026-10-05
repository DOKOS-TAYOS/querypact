using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Security.Tests.Surface;

public sealed class ReadOnlyCanaryTriggerSideEffectTests
{
    [Fact]
    public async Task Trigger_write_outside_probe_with_successful_canary_refuses_role_not_read_only()
    {
        // Residual threat (documented): triggers may write outside sav_ro_probe before rollback.
        // Operators must not grant trigger-write privileges that escape the probe.
        await using PostgresRoFixture fixture = new();
        await fixture.InitializeAsync();

        await fixture.ExecuteAdminAsync(
            """
            CREATE OR REPLACE FUNCTION public.sav_ro_probe_side_effect()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
              INSERT INTO public.side_effect_sink(v) VALUES (NEW.probe_key);
              RETURN NEW;
            END;
            $$;

            DROP TRIGGER IF EXISTS sav_ro_probe_trg ON public.sav_ro_probe;
            CREATE TRIGGER sav_ro_probe_trg
            AFTER INSERT ON public.sav_ro_probe
            FOR EACH ROW EXECUTE FUNCTION public.sav_ro_probe_side_effect();

            GRANT EXECUTE ON FUNCTION public.sav_ro_probe_side_effect() TO sav_writer;
            """);

        ReadOnlySessionGuard guard = new(
            fixture.Redactor,
            fixture.StrictDisclosure,
            new UnsafeAliasRegistry(),
            canaryOverride: null,
            rollbackOverride: null,
            applyReadOnlyTransaction: false,
            onAliasPanic: null);

        await using ReadOnlySessionFactory factory = fixture.CreateFactory(guard: guard);
        TargetAlias alias = fixture.Resolve(PostgresRoFixture.WriterAlias);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => factory.OpenReadOnlySessionAsync(alias, CancellationToken.None));

        Assert.Equal(SavErrorCode.RoleNotReadOnly, ex.Code);

        // Document residual: side_effect_sink may retain rows if trigger fired before rollback
        // confirmation semantics; session is still refused.
    }
}
