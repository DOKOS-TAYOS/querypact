using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Application.Attestations;
using Sav.Application.Migrations;
using Sav.Application.Verify;
using Sav.Domain.Errors;
using Sav.Host.Configuration;
using Sav.Infrastructure.Config;
using Sav.Infrastructure.Config.Paths;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Postgres.Catalog;
using Sav.Infrastructure.Postgres.Migrations;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Plans;
using Sav.Infrastructure.Postgres.Redaction;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Composition;

/// <summary>
/// Dependency registrations for the AnalyzeOnly and Full host profiles.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSavAnalyzeOnly(
        this IServiceCollection services,
        SavModeOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton(options);
        services.AddSingleton(options.ToConfigRootOptions());
        services.AddSingleton<IConfigPathResolver, ConfigPathResolver>();
        services.AddSingleton<IPolicyLoader, YamlPolicyLoader>();
        services.AddSingleton<IContractLoader, YamlContractLoader>();
        services.AddSingleton<IPolicyEngine, YamlPolicyEngine>();
        services.AddSingleton<ISqlParser, LibPgQuerySqlParser>();
        services.AddSingleton<StrictRedactor>();
        services.AddSingleton<IRedactor>(sp =>
            new PostgresErrorRedactor(sp.GetRequiredService<StrictRedactor>()));
        services.AddSingleton<IAnalyzeSqlUseCase, AnalyzeSqlUseCase>();

        return services;
    }

    public static IServiceCollection AddSavFull(
        this IServiceCollection services,
        SavModeOptions options,
        byte[] hmacKey)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(hmacKey);

        if (hmacKey.Length < 32)
        {
            throw new SavException(
                SavErrorCode.AttestationHmacKeyTooWeak,
                $"{SavErrorCode.AttestationHmacKeyTooWeak}: Key must be at least 32 bytes after decode.");
        }

        AddSavAnalyzeOnly(services, options);

        byte[] keyCopy = hmacKey.ToArray();
        services.AddSingleton(keyCopy);

        string storeRoot = string.IsNullOrWhiteSpace(options.AttestationStoreRoot)
            ? SavModeOptions.DefaultAttestationStoreRoot()
            : options.AttestationStoreRoot;
        if (!Path.IsPathRooted(storeRoot))
        {
            throw new SavException(
                SavErrorCode.PathNotAllowed,
                $"{SavErrorCode.PathNotAllowed}: Sav:AttestationStoreRoot must be absolute.");
        }

        TargetsBindingOptions targets = new(options.AliasToDsnEnvVar);
        services.AddSingleton(targets);
        services.AddSingleton(new ReadOnlySessionOptions());
        services.AddSingleton<UnsafeAliasRegistry>();
        services.AddSingleton<MinimalStrictRedactor>();
        services.AddSingleton(sp =>
            new ReadOnlySessionGuard(
                sp.GetRequiredService<IRedactor>(),
                sp.GetRequiredService<ReadOnlySessionOptions>().Disclosure,
                sp.GetRequiredService<UnsafeAliasRegistry>()));
        services.AddSingleton<AliasConnectionFactory>();
        services.AddSingleton<IReadOnlySessionFactory, ReadOnlySessionFactory>();
        services.AddSingleton<ITargetAliasResolver, TargetAliasResolver>();
        services.AddSingleton<ICatalogResolver, PgCatalogResolver>();
        services.AddSingleton<IPlanProvider, ExplainPlanProvider>();
        services.AddSingleton<IPropertyOracle, PropertyOracle>();
        services.AddSingleton<ISchemaFingerprintGuard, SchemaFingerprintGuard>();
        services.AddSingleton<IShadowMigrationRunner, ShadowMigrationRunner>();
        services.AddSingleton<IAttestationMac, AttestationHmac>();
        services.AddSingleton<AttestationFactory>();
        services.AddSingleton<IAttestationStore>(sp =>
            new FileAttestationStore(
                storeRoot,
                sp.GetRequiredService<IAttestationMac>(),
                sp.GetRequiredService<byte[]>()));
        services.AddSingleton<VerificationPipeline>();
        services.AddSingleton<IVerifyQueryUseCase, VerifyQueryUseCase>();
        services.AddSingleton<IGetAttestationUseCase, GetAttestationUseCase>();
        services.AddSingleton<IVerifyEquivalenceUseCase, VerifyEquivalenceUseCase>();
        services.AddSingleton<IVerifyMigrationUseCase, VerifyMigrationUseCase>();

        return services;
    }

    public static IServiceCollection AddSavByProfile(
        this IServiceCollection services,
        SavModeOptions options,
        byte[]? hmacKey)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        return options.Mode switch
        {
            DiProfile.AnalyzeOnly => services.AddSavAnalyzeOnly(options),
            DiProfile.Full => services.AddSavFull(
                options,
                hmacKey ?? throw new SavException(
                    SavErrorCode.AttestationHmacKeyMissing,
                    $"{SavErrorCode.AttestationHmacKeyMissing}: HMAC key is missing.")),
            _ => throw new InvalidOperationException($"Unknown DI profile: {options.Mode}"),
        };
    }

    public static byte[] RequireHmacKeyFromEnvironment()
    {
        return AttestationHmacKeyDecoder.Decode(
            Environment.GetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName));
    }
}
